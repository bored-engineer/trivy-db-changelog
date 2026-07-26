package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

// Iterate over each key in the database and print it
func dump(b *bbolt.Bucket, keys ...string) error {
	// Recurse into each bucket
	if err := b.ForEachBucket(func(key []byte) error {
		return dump(b.Bucket(key), append(keys, string(key))...)
	}); err != nil {
		return fmt.Errorf("(*bbolt.Bucket).ForEachBucket for %s failed: %w", path.Join(keys...), err)
	}
	// Iterate over each key/value pair
	if err := b.ForEach(func(key []byte, val []byte) error {
		// Skip empty values
		if len(val) == 0 {
			return nil
		}
		// Parse the JSON so we can manipulate it as needed
		var parsedVal map[string]any
		if err := json.Unmarshal(val, &parsedVal); err != nil {
			return fmt.Errorf("json.Unmarshal failed: %w", err)
		}
		// Pretty-print the JSON as YAML instead for better diffs
		prettyVal, err := yaml.Marshal(parsedVal)
		if err != nil {
			return fmt.Errorf("yaml.Marshal failed: %w", err)
		}
		// Emit the filemodify line with inline contents
		fmt.Printf("M 100644 inline %s/%s.yaml\n", path.Join(keys...), string(key))
		fmt.Printf("data %d\n%s\n", len(prettyVal), string(prettyVal))
		return nil
	}); err != nil {
		return fmt.Errorf("(*bbolt.Bucket).ForEach for %s failed: %w", path.Join(keys...), err)
	}
	return nil
}

func export(ctx context.Context, ref name.Reference) error {
	// Fetch the image from the OCI registry
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("remote.Image failed: %w", err)
	}
	dgst, err := img.Digest()
	if err != nil {
		return fmt.Errorf("(v1.Image).Digest failed: %w", err)
	}
	dgstRef := ref.Context().Digest(dgst.String())

	// Verify the image is a single-layer trivy DB
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("(v1.Image).Layers failed: %w", err)
	} else if len(layers) != 1 {
		return fmt.Errorf("(v1.Image).Layers unexpected length: %d", len(layers))
	}
	mediaType, err := layers[0].MediaType()
	if err != nil {
		return fmt.Errorf("(v1.Layer).MediaType failed: %w", err)
	} else if mediaType != "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip" {
		return fmt.Errorf("(v1.Layer).MediaType unexpected: %s", mediaType)
	}

	// Stream the layer contents
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return fmt.Errorf("(v1.Layer).Uncompressed failed: %w", err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			log.Printf("(io.ReadCloser).Close failed: %v", err)
		}
	}()

	// Will contain the extracted 'trivy.db' file
	dbFile, err := os.CreateTemp("", "trivy-*.db")
	if err != nil {
		return fmt.Errorf("os.CreateTemp failed: %w", err)
	}
	defer func() {
		if err := os.Remove(dbFile.Name()); err != nil {
			log.Printf("os.Remove failed: %v", err)
		}
	}()

	// Will contain the parsed 'metadata.json' file
	var metadata struct {
		Version      int
		UpdatedAt    time.Time
		NextUpdate   time.Time
		DownloadedAt time.Time
	}

	// Parse the tarball contents
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("(tar.Reader).Next failed: %w", err)
		}
		switch hdr.Name {
		case "trivy.db":
			_, err := io.Copy(dbFile, tr)
			if err != nil {
				return fmt.Errorf("io.Copy failed: %w", err)
			}
		case "metadata.json":
			b, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("io.ReadAll failed: %w", err)
			}
			if err := json.Unmarshal(b, &metadata); err != nil {
				return fmt.Errorf("json.Unmarshal failed: %w", err)
			}
			if metadata.Version != 2 {
				return fmt.Errorf("metadata.Version unexpected: %d", metadata.Version)
			}
		default:
			return fmt.Errorf("unexpected file in tarball: %s", hdr.Name)
		}
	}

	// Open the database
	db, err := bbolt.Open(dbFile.Name(), 0600, nil)
	if err != nil {
		return fmt.Errorf("bolt.Open failed: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("(bbolt.DB).Close failed: %v", err)
		}
	}()

	// Reset the ref so the commit below replaces any existing history instead of extending it
	fmt.Printf("reset refs/raw/%s\n", dgstRef.String())
	// Start a new commit for refs/raw/<digest>
	fmt.Printf("commit refs/raw/%s\n", dgstRef.String())
	// The committer is a boilerplate 'trivy-db-changelog' user with the GitHub Actions bot email
	fmt.Printf("committer trivy-db-changelog <41898282+github-actions[bot]@users.noreply.github.com> %d +0000\n", metadata.UpdatedAt.Unix())
	// The commit message is the exact image reference
	message := fmt.Sprintf("%s: %s", metadata.UpdatedAt.Format(time.RFC3339), dgstRef.String())
	fmt.Printf("data %d\n%s\n", len(message), message)

	// Delete all existing files so we're starting fresh (filedeleteall)
	fmt.Printf("deleteall\n")

	// Loop over each bucket in the database
	if err := db.View(func(tx *bbolt.Tx) error {
		if err := tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			// Ignore the RedHat CPE bucket as it's used for index lookups
			switch string(name) {
			case "Red Hat CPE":
				return nil
			}
			if err := dump(b, string(name)); err != nil {
				return fmt.Errorf("dump failed: %w", err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("(*bbolt.Tx).ForEach failed: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("(*bbolt.DB).View failed: %w", err)
	}

	return nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <image>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	ref, err := name.ParseReference(os.Args[1])
	if err != nil {
		log.Fatalf("name.ParseReference failed: %v", err)
	}

	if err := export(ctx, ref); err != nil {
		log.Fatal(err)
	}
}
