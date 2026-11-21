# trivy-db-changelog

A readable, diffable history of
[`aquasecurity/trivy-db`](https://github.com/aquasecurity/trivy-db), the
vulnerability database behind the [Trivy](https://github.com/aquasecurity/trivy)
scanner.

## Why

Trivy pulls its database as a single OCI image,
`ghcr.io/aquasecurity/trivy-db`, rebuilt every 6 hours. Each build overwrites
the last: there's no history, and the on-disk format is a [bbolt](https://github.com/etcd-io/bbolt)
database with several space-saving encodings (enum ints instead of names,
index lookups instead of inlined strings) that make it awkward to read or
diff directly. So there's no way to answer ordinary questions like "when did
this CVE's severity change", "what did Trivy know about this advisory last
week", or "did a scan result change because the vulnerability data changed
underneath it" — all useful when debugging a scanner finding or auditing
upstream's data quality, and all invisible once the next build lands.

This repo re-exports every build of that database, decoded into one
human-readable YAML file per vulnerability record, as real git history: one
commit per historical build, that you can `git log`, `git diff`, and `git
blame` like any other codebase.

## How it works

- **[`cmd/export`](../cmd/export)** downloads one digest of the trivy-db
  image, opens the bbolt database inside it, and walks every bucket,
  resolving the space-saving encodings back into plain values (severity
  names instead of enum ints, inlined CPE strings instead of index lookups,
  etc.) so the output reads the same as the advisory data it came from. It
  prints a [`git fast-import`](https://git-scm.com/docs/git-fast-import)
  stream rather than writing files directly, resetting `refs/raw/<digest>`
  to a fresh orphan commit with one YAML file per record.
- **[`cron.yml`](workflows/cron.yml)** runs every 6 hours (offset to land
  after upstream's own build), diffs the digests upstream has published
  against the `refs/raw/*` refs already exported, and runs
  **[`export.yml`](workflows/export.yml)** for whatever's missing, in
  parallel, up to a per-run cap. `workflow_dispatch` inputs let you widen
  that cap or restrict it to a date range, which is how the initial backfill
  of upstream's history was done.
- **[`update-changelog.sh`](scripts/update-changelog.sh)** then chains each
  newly-exported digest onto the **`changelog`** branch: a linear history
  that reuses the exact snapshot tree from each `refs/raw/<digest>` commit
  (no re-fetching or re-parsing), just re-parented in chronological order.
  That's what turns a pile of disconnected per-digest snapshots into an
  actual changelog you can run `git log -p` or `git diff HEAD~5` against.

## Branches

- **`generator`** — this code (the repository's default branch).
- **`refs/raw/<digest>`** — one orphan commit per exported digest, exactly
  as `cmd/export` produced it. The source of truth; `changelog` is derived
  from these and can always be rebuilt from them.
- **`changelog`** — the same snapshots, chained into one browsable history.
  This README and a thin `.github/workflows/cron.yml` are overlaid onto its
  tip on every update (see that file's header) so the branch stays
  self-explanatory, and so GitHub can still find a workflow here if this is
  ever made the repository's default branch — that workflow just forwards
  to the real one on `generator` via a ref-pinned reusable workflow call
  ([`changelog-dispatcher.yml`](changelog-dispatcher.yml)), so it never
  needs to be kept in sync with actual job logic changes.
