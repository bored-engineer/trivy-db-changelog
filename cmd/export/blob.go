package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// maxResumes bounds how many times one blob download may be reopened in a
// row without real progress: the count starts over once resumeProgress
// bytes have been read since the last failure, so a long download through
// a flaky CDN isn't failed for interruptions spread across its length.
const maxResumes = 20

// resumeProgress is how much must be read after a failure for the resume
// count to start over.
var resumeProgress int64 = 64 << 20

// idleTimeout drops a connection that has sent nothing for this long
// (including while waiting for the response headers), so a stalled
// download is resumed instead of hanging until the job's timeout - which
// would also lose every other export on that runner, since they're
// pushed together at the end.
var idleTimeout = 60 * time.Second

// resumeBackoff is the base delay before reopening (scaled by attempt).
var resumeBackoff = 2 * time.Second

// setupAttempts bounds how many times withRetry tries a registry request.
const setupAttempts = 5

// setupBackoff is the base delay between withRetry's attempts (scaled by
// attempt).
var setupBackoff = 5 * time.Second

// withRetry retries the registry requests made before any data is read
// (the manifest, and the token handshake for the blob): a transient
// failure there, like a dial timeout to ghcr.io, would otherwise fail the
// whole export. Nothing has been written to stdout yet at that point, so a
// retry is always safe. The blob download itself resumes instead (see
// resumableBlob).
func withRetry[T any](ctx context.Context, what string, fn func() (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		v, err := fn()
		if err == nil || attempt >= setupAttempts || ctx.Err() != nil {
			return v, err
		}
		log.Printf("%s failed (%v); retrying (%d/%d)", what, err, attempt, setupAttempts-1)
		select {
		case <-time.After(time.Duration(attempt) * setupBackoff):
		case <-ctx.Done():
			return v, err
		}
	}
}

// resumableBlob streams a registry blob, reopening the download at the
// current offset (an HTTP Range request) whenever the connection fails
// mid-stream, and verifies the blob's sha256 once fully read.
//
// Why: GHCR's CDN occasionally resets a download mid-stream ("stream error:
// stream ID 1; PROTOCOL_ERROR"), which grype-db-changelog saw for ~1 in 10 of
// its multi-GB exports. trivy-db's layer is far smaller, but a reset still
// wastes the whole export, and go-containerregistry's own layer reader can't
// resume.
type resumableBlob struct {
	ctx     context.Context
	client  *http.Client
	url     string
	size    int64
	want    v1.Hash
	off     int64
	body    io.ReadCloser
	sum     hash.Hash
	resumes int
	// failedAt is the offset of the last failure (see resumeProgress).
	failedAt int64
	// idle cancels the current request when it fires (see idleTimeout);
	// reset on every read that returns data.
	idle   *time.Timer
	cancel context.CancelFunc
}

func openBlob(ctx context.Context, repo name.Repository, digest v1.Hash, size int64) (*resumableBlob, error) {
	auth, err := authn.DefaultKeychain.Resolve(repo)
	if err != nil {
		return nil, fmt.Errorf("resolving credentials failed: %w", err)
	}
	rt, err := transport.NewWithContext(ctx, repo.Registry, auth, http.DefaultTransport, []string{repo.Scope(transport.PullScope)})
	if err != nil {
		return nil, fmt.Errorf("transport.NewWithContext failed: %w", err)
	}
	if digest.Algorithm != "sha256" {
		return nil, fmt.Errorf("unsupported digest algorithm %q", digest.Algorithm)
	}
	return &resumableBlob{
		ctx:    ctx,
		client: &http.Client{Transport: rt},
		url:    fmt.Sprintf("%s://%s/v2/%s/blobs/%s", repo.Registry.Scheme(), repo.RegistryStr(), repo.RepositoryStr(), digest),
		size:   size,
		want:   digest,
		sum:    sha256.New(),
	}, nil
}

func (b *resumableBlob) open() error {
	ctx, cancel := context.WithCancel(b.ctx)
	b.cancel = cancel
	b.idle = time.AfterFunc(idleTimeout, cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
	if err != nil {
		return err
	}
	if b.off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", b.off))
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	wantStatus := http.StatusOK
	if b.off > 0 {
		wantStatus = http.StatusPartialContent
	}
	if resp.StatusCode != wantStatus {
		resp.Body.Close()
		return fmt.Errorf("GET blob at offset %d: status %s, want %d", b.off, resp.Status, wantStatus)
	}
	if b.off > 0 {
		// A 206 for some other range would splice the wrong bytes in; fail
		// here (and retry) rather than rely on the final digest check.
		if cr, want := resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-", b.off); !strings.HasPrefix(cr, want) {
			resp.Body.Close()
			return fmt.Errorf("GET blob at offset %d: Content-Range %q, want %q...", b.off, cr, want)
		}
	}
	b.body = resp.Body
	return nil
}

// stop releases the current request's context and idle timer.
func (b *resumableBlob) stop() {
	if b.idle != nil {
		b.idle.Stop()
		b.idle = nil
	}
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil
	}
}

// fail closes the current connection and decides whether to retry.
func (b *resumableBlob) fail(err error) error {
	if b.body != nil {
		b.body.Close()
		b.body = nil
	}
	b.stop()
	if b.off-b.failedAt >= resumeProgress {
		b.resumes = 0
	}
	b.failedAt = b.off
	if b.ctx.Err() != nil || b.resumes >= maxResumes {
		return fmt.Errorf("blob download failed at byte %d of %d (after %d resumes): %w", b.off, b.size, b.resumes, err)
	}
	b.resumes++
	log.Printf("blob download interrupted at byte %d of %d (%v); resuming (%d/%d)", b.off, b.size, err, b.resumes, maxResumes)
	select {
	case <-time.After(time.Duration(min(b.resumes, 10)) * resumeBackoff):
	case <-b.ctx.Done():
	}
	return nil
}

func (b *resumableBlob) Read(p []byte) (int, error) {
	for {
		if b.off >= b.size {
			if got := hex.EncodeToString(b.sum.Sum(nil)); got != b.want.Hex {
				return 0, fmt.Errorf("blob digest mismatch: got sha256:%s, want %s", got, b.want)
			}
			return 0, io.EOF
		}
		if b.body == nil {
			if err := b.open(); err != nil {
				if err := b.fail(err); err != nil {
					return 0, err
				}
				continue
			}
		}
		n, err := b.body.Read(p)
		if n > 0 {
			b.idle.Reset(idleTimeout)
		}
		if int64(n) > b.size-b.off {
			return 0, fmt.Errorf("blob longer than its declared %d bytes", b.size)
		}
		b.sum.Write(p[:n])
		b.off += int64(n)
		if err == io.EOF && b.off < b.size {
			err = io.ErrUnexpectedEOF
		}
		if err != nil && err != io.EOF {
			if ferr := b.fail(err); ferr != nil {
				return n, ferr
			}
		}
		if n > 0 {
			return n, nil
		}
	}
}

func (b *resumableBlob) Close() error {
	defer b.stop()
	if b.body != nil {
		return b.body.Close()
	}
	return nil
}

// layerReader returns the layer's uncompressed contents (gzip layers are
// decompressed; plain tar layers are passed through), read via a
// resumableBlob. Fully draining it verifies the blob's digest.
func layerReader(ctx context.Context, repo name.Repository, layer v1.Layer) (io.Reader, io.Closer, error) {
	digest, err := layer.Digest()
	if err != nil {
		return nil, nil, fmt.Errorf("(v1.Layer).Digest failed: %w", err)
	}
	size, err := layer.Size()
	if err != nil {
		return nil, nil, fmt.Errorf("(v1.Layer).Size failed: %w", err)
	}
	blob, err := withRetry(ctx, "connecting to the registry", func() (*resumableBlob, error) {
		return openBlob(ctx, repo, digest, size)
	})
	if err != nil {
		return nil, nil, err
	}
	br := bufio.NewReader(blob)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			blob.Close()
			return nil, nil, fmt.Errorf("gzip.NewReader failed: %w", err)
		}
		// Drain past gzip's end too, so the digest check runs.
		return io.MultiReader(zr, br), blob, nil
	}
	return br, blob, nil
}
