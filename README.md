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

## Example: tracing Java4Shell (CVE-2026-114938)

[Java4Shell](https://calif.io/java4shell) — a pre-auth memory-corruption bug
in OpenJDK's Base64 decoder — is a good illustration of what that actually
buys you: a timeline of who shipped a fix and when, straight from real
history instead of cross-referencing a dozen separate trackers.

```console
$ git log --first-parent --diff-filter=A --format='%cI' changelog -- vulnerability/CVE-2026-114938.yaml
2026-11-18T07:15:21Z
$ git log --first-parent --diff-filter=A --format='%cI' changelog -- 'os/wolfi/openjdk-17/CVE-2026-114938.yaml'
2026-11-19T07:06:49Z
```

| When (UTC)           | What |
|-----------------------|------|
| 2026-11-17            | Disclosed publicly by [Calif](https://calif.io/java4shell); [CVE-2026-114938](https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability) assigned |
| 2026-11-18T07:15:21Z  | Added to trivy-db's `vulnerability` bucket — and to Debian 12 and 13's `openjdk-17`/`openjdk-21` packages — in the very next build after disclosure |
| 2026-11-18T19:07:09Z  | Alpine 3.24 and edge's `openjdk17` |
| 2026-11-19T01:05:40Z  | Ubuntu 24.04 and 26.04's `openjdk-17` |
| 2026-11-19T07:06:49Z  | Wolfi's and Chainguard's `openjdk-17`, and Amazon Linux 2023's `java-17-amazon-corretto` |
| 2026-11-20T01:04:07Z  | Oracle Linux 9's `java-17-openjdk` |

As of this writing, Red Hat's own `java-17-openjdk` had no advisory for it
yet — the same `git log` against `os/Red\ Hat` instead of a guess is how
you'd check whether that's still true.

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

- **`changelog`** — **the repository's default branch.** The same snapshots
  as `refs/raw/<digest>`, chained into one browsable history. This README
  and a thin `.github/workflows/cron.yml` are overlaid onto its tip on every
  update (see that file's header) so the branch stays self-explanatory, and
  so GitHub can still find a workflow here now that this is the default
  branch — that workflow just forwards to the real one on `generator` via a
  ref-pinned reusable workflow call
  ([`changelog-dispatcher.yml`](changelog-dispatcher.yml)), so it never
  needs to be kept in sync with actual job logic changes.
- **`generator`** — this code: the exporter, the cron automation, and this
  README. Not the default branch, but everything above actually lives here.
- **`refs/raw/<digest>`** — one orphan commit per exported digest, exactly
  as `cmd/export` produced it. The source of truth; `changelog` is derived
  from these and can always be rebuilt from them.
