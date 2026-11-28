package main

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"go.etcd.io/bbolt"
	"gopkg.in/yaml.v3"
)

// stdout receives the fast-import stream (a variable for tests).
var stdout io.Writer = os.Stdout

// redHatCPEs loads the index->CPE lookup table Red Hat OVAL/CSAF use to avoid
// repeating CPE strings in every advisory entry (see "Red Hat CPE"/cpe bucket
// upstream), so dump can undo that space optimization and inline the real CPEs.
func redHatCPEs(tx *bbolt.Tx) (map[int]string, error) {
	cpes := map[int]string{}
	root := tx.Bucket([]byte("Red Hat CPE"))
	if root == nil {
		return cpes, nil
	}
	b := root.Bucket([]byte("cpe"))
	if b == nil {
		return cpes, nil
	}
	if err := b.ForEach(func(key, val []byte) error {
		idx, err := strconv.Atoi(string(key))
		if err != nil {
			return fmt.Errorf("strconv.Atoi failed for %q: %w", key, err)
		}
		var cpe string
		if err := json.Unmarshal(val, &cpe); err != nil {
			return fmt.Errorf("json.Unmarshal failed: %w", err)
		}
		cpes[idx] = cpe
		return nil
	}); err != nil {
		return nil, fmt.Errorf("(*bbolt.Bucket).ForEach failed: %w", err)
	}
	return cpes, nil
}

// severityNames and statusNames mirror the fixed enum tables trivy-db encodes
// as bare ints to save space (pkg/types.SeverityNames / pkg/types.Statuses).
// Unlike the Red Hat CPE indices, these need no DB lookup: the mapping is static.
var (
	severityNames = []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	statusNames   = []string{
		"unknown",
		"not_affected",
		"affected",
		"fixed",
		"under_investigation",
		"will_not_fix",
		"fix_deferred",
		"end_of_life",
	}
)

// enumName resolves a float64-decoded JSON number against a fixed enum table,
// falling back to the raw number formatted as a string if it's out of range.
func enumName(names []string, n float64) string {
	if i := int(n); i >= 0 && i < len(names) {
		return names[i]
	}
	return fmt.Sprintf("%v", n)
}

// resolveEnums walks a parsed JSON value, undoing the space optimizations
// trivy-db applies before storage: "Affected" (Red Hat OVAL/CSAF only) holds
// CPE indices instead of CPE strings, "Severity"/"Status" hold enum ints
// instead of their names, and "VendorSeverity" is a map of the same Severity
// ints keyed by source.
func resolveEnums(val any, cpes map[int]string) any {
	switch v := val.(type) {
	case map[string]any:
		for key, item := range v {
			switch {
			case key == "Affected":
				if indices, ok := item.([]any); ok {
					resolved := make([]string, len(indices))
					for i, index := range indices {
						if n, ok := index.(float64); ok {
							if cpe, ok := cpes[int(n)]; ok {
								resolved[i] = cpe
								continue
							}
						}
						resolved[i] = fmt.Sprintf("%v", index)
					}
					v[key] = resolved
					continue
				}
			case key == "Severity":
				if n, ok := item.(float64); ok {
					v[key] = enumName(severityNames, n)
					continue
				}
			case key == "Status":
				if n, ok := item.(float64); ok {
					v[key] = enumName(statusNames, n)
					continue
				}
			case key == "VendorSeverity":
				// map[SourceID]Severity: per-source severities, same enum, one level deeper
				if bySource, ok := item.(map[string]any); ok {
					for source, sev := range bySource {
						if n, ok := sev.(float64); ok {
							bySource[source] = enumName(severityNames, n)
						}
					}
					continue
				}
			}
			v[key] = resolveEnums(item, cpes)
		}
		return v
	case []any:
		for i, item := range v {
			v[i] = resolveEnums(item, cpes)
		}
		return v
	default:
		return val
	}
}

// bucketPath maps a top-level bbolt bucket name to its path in the export.
// trivy-db itself names a bucket "ecosystem::source" when it's a
// language-ecosystem advisory source (see its pkg/db.forEach, which treats
// "::" as a prefix-scan marker); every other bucket is an OS distro's
// advisories, keyed by plain vendor/release name. Grouping on that existing
// convention (rather than a hand-maintained vendor list) keeps the ~230
// top-level buckets trivy-db currently has down to a handful of directories,
// and classifies any future new source without needing an update here.
// "vulnerability" and "data-source" are trivy-db's two core, cross-cutting
// buckets (not tied to one source) and are left at the root.
func bucketPath(name string) []string {
	switch name {
	case "vulnerability", "data-source":
		return []string{name}
	}
	if ecosystem, source, ok := strings.Cut(name, "::"); ok {
		return []string{"packages", ecosystem, source}
	}
	return []string{"os", name}
}

// cveID matches a CVE identifier case-insensitively, so it can be
// canonicalized to its one true (uppercase) form: trivy-db's own upstream
// sources disagree on casing for otherwise-identical CVE records (GitHub
// Security Advisory entries use lowercase, NVD/OS vendor feeds use
// uppercase), which would otherwise land in two files whose paths differ
// only by case.
var cveID = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]+$`)

// normalizeKey canonicalizes one bucket key before it becomes a path
// segment, so upstream case variance never produces two distinct paths for
// what is really the same identifier. A leaf key (the final path segment,
// a vulnerability ID) is uppercased if it's a CVE ID - its one valid form
// - and left alone otherwise, since every other ID format observed here is
// already consistently cased. Every other key - an OS or language-
// ecosystem package/module name - is lowercased unconditionally: it's a
// vendor- or registry-supplied name with no canonical case of its own, and
// several (NuGet package IDs by spec, GitHub-hosted Go module paths and Red
// Hat RPM names in practice) are already observed with the same logical
// name cased differently across trivy-db's own sources.
func normalizeKey(key string, isLeaf bool) string {
	if isLeaf {
		if cveID.MatchString(key) {
			return strings.ToUpper(key)
		}
		return key
	}
	return strings.ToLower(key)
}

// validSegment reports whether a normalized bucket key is safe to use as one
// path segment. Keys may legitimately contain "/" (Go module paths like
// "github.com/foo/bar" become nested directories), but path.Join would
// quietly resolve "." and ".." segments, moving a record outside its bucket's
// directory, and a control character (a newline, say) would corrupt the
// fast-import stream. Refused outright instead of guessed at.
func validSegment(key string) bool {
	if key == "" || strings.HasPrefix(key, "/") || strings.ContainsFunc(key, unicode.IsControl) {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// quoted is a string yaml.v3 can't write as a block scalar: a multi-line
// string starting with whitespace. yaml.v3 gives those a block scalar that's
// either unparseable or reads back as a different string (a leading newline
// is dropped), so it's written double-quoted instead, which always
// round-trips.
type quoted string

func (q quoted) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(q), Style: yaml.DoubleQuotedStyle}, nil
}

// needsQuotes reports whether yaml.v3 would write s as a broken block scalar.
func needsQuotes(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsSpace(r) && strings.ContainsRune(s, '\n')
}

// quotedKeys is a map with a key needsQuotes is true of: yaml.v3 gets those
// wrong as keys too, so the map is written by hand with sorted keys and the
// troublesome ones double-quoted. Only such (vanishingly rare) maps take
// this path, so every other map keeps yaml.v3's own key order.
type quotedKeys map[string]any

func (m quotedKeys) MarshalYAML() (any, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}
		if needsQuotes(k) {
			key.Style = yaml.DoubleQuotedStyle
		}
		var val yaml.Node
		if err := val.Encode(m[k]); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, key, &val)
	}
	return node, nil
}

// protectStrings wraps every string (and map) yaml.v3 can't safely write
// in the types above.
func protectStrings(v any) any {
	switch v := v.(type) {
	case map[string]any:
		quote := false
		for k, val := range v {
			v[k] = protectStrings(val)
			quote = quote || needsQuotes(k)
		}
		if quote {
			return quotedKeys(v)
		}
		return v
	case []any:
		for i, val := range v {
			v[i] = protectStrings(val)
		}
		return v
	case string:
		if needsQuotes(v) {
			return quoted(v)
		}
		return v
	default:
		return v
	}
}

// leaves accumulates every resolved leaf value by its final export path
// across an entire export, merging on write: normalizeKey can map two
// distinct bucket keys onto the same path, which a plain overwrite would
// resolve arbitrarily (whichever bbolt happened to iterate last) instead
// of predictably.
//
// It is keyed by the case-folded path, not the path itself: the changelog is
// checked out on case-insensitive filesystems (macOS and Windows defaults),
// where two paths differing only by case silently overwrite each other.
// normalizeKey removes the known variance up front, but this is the safety
// net for anything it doesn't know about (a non-CVE leaf ID cased two ways,
// say): such paths merge into the first one seen instead of coexisting.
// Unlike grype-db-changelog, which fails the export on such a collision,
// merging keeps the changelog chain moving - it is chained strictly in
// order, so a failed export would hold back every later digest.
type leaves map[string]*leaf

// leaf is one output file: the first-seen spelling of its path, and its
// merged value.
type leaf struct {
	path string
	val  map[string]any
}

// mergeLeaf folds incoming into l[leafPath], which may already hold a
// value from an earlier-processed bucket key that normalized to the same
// path - bbolt iterates bucket keys in byte-sorted order, so "earlier"
// means the more-canonical key whenever one exists (ASCII uppercase sorts
// before lowercase). A field equal on both sides is a no-op. A field
// present as a list on both sides is unioned, deduplicating items
// (confirmed the right call for the one real family of these: Red Hat's
// OpenEXR package-name casing contributing separate, non-overlapping
// "Entries" lists under the same identifier). Any other differing field
// keeps whichever value arrived first - there's no generally-correct way
// to pick between two disagreeing upstream facts (confirmed for the one
// real family of these: AlmaLinux kernel FixedVersion conflicts) - and the
// drop is logged so it stays visible.
func (l leaves) mergeLeaf(leafPath string, incoming map[string]any) {
	fold := strings.ToLower(leafPath)
	entry, ok := l[fold]
	if !ok {
		l[fold] = &leaf{path: leafPath, val: incoming}
		return
	}
	if entry.path != leafPath {
		log.Printf("export: %q and %q differ only by case; merging into the first", leafPath, entry.path)
	}
	existing := entry.val
	for key, newVal := range incoming {
		oldVal, ok := existing[key]
		if !ok {
			existing[key] = newVal
			continue
		}
		if reflect.DeepEqual(oldVal, newVal) {
			continue
		}
		if oldList, ok := oldVal.([]any); ok {
			if newList, ok := newVal.([]any); ok {
				for _, item := range newList {
					dup := false
					for _, existingItem := range oldList {
						if reflect.DeepEqual(existingItem, item) {
							dup = true
							break
						}
					}
					if !dup {
						oldList = append(oldList, item)
					}
				}
				existing[key] = oldList
				continue
			}
		}
		log.Printf("export: %s: keeping existing %q, dropping conflicting value from a case-duplicate key", entry.path, key)
	}
}

// emit parses and resolves one leaf key/value pair's stored JSON, undoing
// trivy-db's storage optimizations so the changelog is human-readable, and
// merges it into out under its normalized path.
func emit(cpes map[int]string, out leaves, val []byte, keys ...string) error {
	// Skip empty values
	if len(val) == 0 {
		return nil
	}
	for _, key := range keys {
		if !validSegment(key) {
			return fmt.Errorf("unusable key %q in %q", key, path.Join(keys...))
		}
	}
	// Parse the JSON so we can manipulate it as needed
	var parsedVal map[string]any
	if err := json.Unmarshal(val, &parsedVal); err != nil {
		return fmt.Errorf("json.Unmarshal failed: %w", err)
	}
	// Undo trivy-db's storage optimizations so the changelog is human-readable
	parsedVal = resolveEnums(parsedVal, cpes).(map[string]any)
	out.mergeLeaf(path.Join(keys...), parsedVal)
	return nil
}

// dump recurses through a bucket's nested sub-buckets, calling emit for
// every leaf key/value pair under the given path prefix.
func dump(b *bbolt.Bucket, cpes map[int]string, out leaves, keys ...string) error {
	// Recurse into each bucket
	if err := b.ForEachBucket(func(key []byte) error {
		return dump(b.Bucket(key), cpes, out, append(keys, normalizeKey(string(key), false))...)
	}); err != nil {
		return fmt.Errorf("(*bbolt.Bucket).ForEachBucket for %s failed: %w", path.Join(keys...), err)
	}
	// Iterate over each key/value pair
	if err := b.ForEach(func(key []byte, val []byte) error {
		return emit(cpes, out, val, append(keys, normalizeKey(string(key), true))...)
	}); err != nil {
		return fmt.Errorf("(*bbolt.Bucket).ForEach for %s failed: %w", path.Join(keys...), err)
	}
	return nil
}

func export(ctx context.Context, ref name.Reference) error {
	// Fetch the image from the OCI registry
	img, err := withRetry(ctx, "fetching the manifest", func() (v1.Image, error) {
		return remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	})
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
	// Resumes on connection resets and verifies the blob's digest once drained
	rc, closer, err := layerReader(ctx, ref.Context(), layers[0])
	if err != nil {
		return fmt.Errorf("opening the layer failed: %w", err)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			log.Printf("(io.ReadCloser).Close failed: %v", err)
		}
	}()

	// Will contain the extracted 'trivy.db' file, in a directory of its own
	// that's removed whole
	tmpDir, err := os.MkdirTemp("", "trivy-db-*")
	if err != nil {
		return fmt.Errorf("os.MkdirTemp failed: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Printf("os.RemoveAll failed: %v", err)
		}
	}()
	dbFile, err := os.Create(filepath.Join(tmpDir, "trivy.db"))
	if err != nil {
		return fmt.Errorf("os.Create failed: %w", err)
	}

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

	// Read to the very end - past the tar trailer and any padding - so the
	// blob's digest gets verified before anything is committed
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("reading the rest of the layer failed: %w", err)
	}
	if err := dbFile.Close(); err != nil {
		return fmt.Errorf("(*os.File).Close failed: %w", err)
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

	// Replace refs/raw/<digest> with the exported contents (":" is invalid in ref names)
	refName := "refs/raw/" + strings.ReplaceAll(dgstRef.DigestStr(), ":", "-")
	// "feature done": fast-import refuses to update any ref unless the stream
	// ends with an explicit "done" (written by main only after export returns
	// successfully). Without it, an export that dies mid-stream - a registry
	// hiccup, say - leaves fast-import to commit the truncated snapshot as if
	// it were complete, and the pipe hides the failure unless the shell runs
	// with pipefail.
	fmt.Fprintf(stdout, "feature done\n")
	fmt.Fprintf(stdout, "reset %s\n", refName)
	fmt.Fprintf(stdout, "commit %s\n", refName)
	// The committer is a boilerplate 'trivy-db-changelog' user with the GitHub Actions bot email
	fmt.Fprintf(stdout, "committer trivy-db-changelog <41898282+github-actions[bot]@users.noreply.github.com> %d +0000\n", metadata.UpdatedAt.Unix())
	// The commit message is the exact image reference
	message := fmt.Sprintf("%s: %s", metadata.UpdatedAt.Format(time.RFC3339), dgstRef.String())
	fmt.Fprintf(stdout, "data %d\n%s\n", len(message), message)

	// Delete all existing files so we're starting fresh (filedeleteall)
	fmt.Fprintf(stdout, "deleteall\n")

	// Loop over each bucket in the database, buffering every leaf in out
	// instead of writing it immediately: normalizeKey can map two distinct
	// bucket keys onto the same path (see leaves/mergeLeaf), so every write
	// has to go through one merge step before anything is final.
	out := leaves{}
	if err := db.View(func(tx *bbolt.Tx) error {
		// Load the Red Hat CPE index lookup table so dump can inline real CPE
		// strings instead of the space-saving indices Red Hat advisories store
		cpes, err := redHatCPEs(tx)
		if err != nil {
			return fmt.Errorf("redHatCPEs failed: %w", err)
		}
		if err := tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			switch string(name) {
			// Ignore the RedHat CPE bucket itself: "repository"/"nvr" are internal
			// scan-time lookup indices, and "cpe" is now inlined via resolveEnums
			case "Red Hat CPE":
				return nil
			// data-source keys are themselves other top-level bucket names, so
			// they need the same os/packages split bucketPath applies to those
			// buckets, not the literal (unsplit) "data-source" case it returns.
			case "data-source":
				return b.ForEach(func(key, val []byte) error {
					return emit(cpes, out, val, append([]string{"data-source"}, bucketPath(string(key))...)...)
				})
			}
			if err := dump(b, cpes, out, bucketPath(string(name))...); err != nil {
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

	// Write every buffered leaf out, in sorted path order so the export -
	// and its diffs - stay deterministic regardless of Go's randomized map
	// iteration order.
	paths := make([]string, 0, len(out))
	for p := range out {
		paths = append(paths, p)
	}
	sort.Strings(paths) // by folded path, which is as deterministic as any
	for _, p := range paths {
		prettyVal, err := yaml.Marshal(protectStrings(out[p].val))
		if err != nil {
			return fmt.Errorf("yaml.Marshal failed: %w", err)
		}
		// Errors matter: a write that fails (fast-import gone) stops the
		// export rather than rendering every remaining leaf into the void.
		if _, err := fmt.Fprintf(stdout, "M 100644 inline %s.yaml\ndata %d\n%s\n", out[p].path, len(prettyVal), prettyVal); err != nil {
			return fmt.Errorf("writing the fast-import stream failed: %w", err)
		}
	}

	return nil
}

func main() {
	// SIGTERM (timeout, runner shutdown) and SIGPIPE (fast-import died, so
	// stdout's reader is gone) cancel the export like ^C does, instead of
	// killing the process outright: that skips every defer, leaving the temp
	// trivy.db behind. With SIGPIPE caught, writes to the dead pipe return
	// EPIPE, which the export reports.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE)
	defer cancel()

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <image>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	ref, err := name.ParseReference(os.Args[1])
	if err != nil {
		log.Fatalf("name.ParseReference failed: %v", err)
	}

	// Buffered: unbuffered, every record costs several write syscalls.
	// Nothing is flushed on failure, and fast-import commits nothing without
	// the final "done".
	bw := bufio.NewWriterSize(os.Stdout, 1<<20)
	stdout = bw
	if err := export(ctx, ref); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(stdout, "done\n")
	if err := bw.Flush(); err != nil {
		log.Fatalf("writing the fast-import stream failed: %v", err)
	}
}
