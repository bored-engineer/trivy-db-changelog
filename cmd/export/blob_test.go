package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// flakyRegistry serves one blob, but each response sends at most chunk
// bytes and then aborts the connection (like GHCR's stream resets).
func flakyRegistry(t *testing.T, blob []byte, chunk int, requests *atomic.Int32) name.Repository {
	t.Helper()
	old := resumeBackoff
	resumeBackoff = time.Millisecond
	t.Cleanup(func() { resumeBackoff = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v2/test/blobs/") {
			http.NotFound(w, r)
			return
		}
		requests.Add(1)
		off := 0
		if rg := r.Header.Get("Range"); rg != "" {
			off, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rg, "bytes="), "-"))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, len(blob)-1, len(blob)))
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(blob)-off))
		if off > 0 {
			w.WriteHeader(http.StatusPartialContent)
		}
		end := min(off+chunk, len(blob))
		w.Write(blob[off:end])
		if end < len(blob) {
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler) // drop the connection mid-body
		}
	}))
	t.Cleanup(srv.Close)
	reg, err := name.NewRegistry(strings.TrimPrefix(srv.URL, "http://"), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return reg.Repo("test")
}

func digestOf(b []byte) v1.Hash {
	h, _, _ := v1.SHA256(bytes.NewReader(b))
	return h
}

func TestResumableBlobResumesAfterResets(t *testing.T) {
	blob := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64KiB
	var requests atomic.Int32
	repo := flakyRegistry(t, blob, 10000, &requests)

	b, err := openBlob(context.Background(), repo, digestOf(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("got %d bytes, want the original %d", len(got), len(blob))
	}
	if n := requests.Load(); n < 7 {
		t.Fatalf("only %d requests; the resets weren't exercised", n)
	}
}

func TestResumableBlobDigestMismatch(t *testing.T) {
	blob := []byte("hello world")
	var requests atomic.Int32
	repo := flakyRegistry(t, blob, len(blob), &requests)
	wrong := v1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", sha256.Sum256([]byte("other")))}

	b, err := openBlob(context.Background(), repo, wrong, int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(b); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("err = %v, want a digest mismatch", err)
	}
}

func TestLayerReaderGunzips(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("tar bytes"))
	zw.Close()
	var requests atomic.Int32
	repo := flakyRegistry(t, gz.Bytes(), 7, &requests)

	b, err := openBlob(context.Background(), repo, digestOf(gz.Bytes()), int64(gz.Len()))
	if err != nil {
		t.Fatal(err)
	}
	// Same sniffing layerReader does, on the resumable stream.
	r, err := gzip.NewReader(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "tar bytes" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// A connection that stops sending mid-body (no reset, no EOF) is dropped
// after idleTimeout and resumed, rather than hanging the export.
func TestResumableBlobResumesAfterStall(t *testing.T) {
	oldIdle, oldBackoff := idleTimeout, resumeBackoff
	idleTimeout, resumeBackoff = 200*time.Millisecond, time.Millisecond
	t.Cleanup(func() { idleTimeout, resumeBackoff = oldIdle, oldBackoff })
	blob := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			return
		}
		off := 0
		if rg := r.Header.Get("Range"); rg != "" {
			off, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rg, "bytes="), "-"))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, len(blob)-1, len(blob)))
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(blob)-off))
		if off > 0 {
			w.WriteHeader(http.StatusPartialContent)
		}
		if requests.Add(1) == 1 {
			w.Write(blob[:1000])
			w.(http.Flusher).Flush()
			<-r.Context().Done() // stall until the client gives up
			return
		}
		w.Write(blob[off:])
	}))
	t.Cleanup(srv.Close)
	reg, err := name.NewRegistry(strings.TrimPrefix(srv.URL, "http://"), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openBlob(context.Background(), reg.Repo("test"), digestOf(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var got []byte
	go func() { got, err = io.ReadAll(b); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("download hung on the stalled connection")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("got %d bytes, want the original %d", len(got), len(blob))
	}
	if n := requests.Load(); n != 2 {
		t.Fatalf("%d requests, want 2 (the stalled one, then a resume)", n)
	}
}

// The resume budget is per stretch without progress, not per download.
func TestResumableBlobResumeBudgetResetsWithProgress(t *testing.T) {
	old := resumeProgress
	resumeProgress = 1000
	t.Cleanup(func() { resumeProgress = old })
	blob := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64KiB
	var requests atomic.Int32
	repo := flakyRegistry(t, blob, 2000, &requests) // 33 resets > maxResumes
	b, err := openBlob(context.Background(), repo, digestOf(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("got %d bytes, want the original %d", len(got), len(blob))
	}
	if n := requests.Load(); n <= maxResumes {
		t.Fatalf("only %d requests; the budget wasn't exercised", n)
	}
}
