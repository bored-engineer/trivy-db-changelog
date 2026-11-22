#!/usr/bin/env bash
# Appends the digests in $DIGESTS (a JSON array of "sha256:..." strings, as
# produced by the cron workflow's discover job, oldest first) onto the
# "changelog" branch: one commit per digest, reusing the exact tree that
# cmd/export already built under refs/raw/<digest>, chained chronologically
# (plain single parent) instead of left as disconnected orphan commits.
# Each commit's message carries an "Export-Commit: <sha>" trailer pointing
# at the refs/raw/<digest> commit it reused the tree from, so that link is
# still discoverable (grep the trailer, or `git log --grep`) without making
# it a real parent.
#
# A trailing commit overlays README.md and a thin .github/workflows/cron.yml
# on top so the branch stays browsable and, if it's ever made the repo's
# default branch, GitHub can still find a workflow here to run on schedule.
# That workflow (changelog-dispatcher.yml) just forwards to the real
# implementation on "generator" via a ref-pinned reusable workflow call, so
# this overlay only needs that one small, rarely-changing file - never a
# synced copy of every workflow. This is re-applied every run so it's always
# at the tip, not buried under newer digests. Its own "Export-Commit:"
# trailer points at the exact "generator" commit these files were read from.
#
# Deliberately kept to a plain single-parent chain, not a 2-parent merge
# into refs/raw/<digest>/generator (an earlier design here): every commit in
# this chain reuses its parent's *exact* tree for everything but the path(s)
# it actually changes, which makes it TREESAME to the previous commit for
# any path it didn't touch - but a merge's second parent here would be
# TREESAME to the *whole* tree (we deliberately reuse it unchanged), and
# that's enough to make git's default history simplification collapse
# `git log -- <path>` (even "--diff-filter=A") down to whichever orphan
# refs/raw/<digest> commit it last visited, rather than the real first
# appearance in the chain - confirmed by reproducing it directly. Only
# `git log --first-parent -- <path>` gave the right answer, which isn't
# something a browsing human would know to reach for. A linear chain has no
# such ambiguity: ordinary `git log -- <path>` just works.
#
# Deliberately avoids fetching the full history: only the changelog branch's
# current tip commit (no tree) and each new digest's commit+tree (no blobs)
# are pulled, so a run's network cost stays proportional to the few digests
# it's adding, not to the size of the branch's history.
#
# Run from the repository root (e.g. $GITHUB_WORKSPACE); creates and removes
# a "work" subdirectory there to build the branch in.
set -euo pipefail

# Belt-and-suspenders: if a git command ever ends up needing credentials
# this script didn't supply, fail fast with a clear error instead of
# blocking on an interactive prompt that can never be answered here - which
# is what silently ate a full 6-hour job timeout before this was caught.
export GIT_TERMINAL_PROMPT=0

: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_TOKEN:?}"
: "${DIGESTS:?}"

BOT_NAME="trivy-db-changelog"
BOT_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

# actions/checkout's injected credentials are scoped (via includeIf.gitdir:)
# to the outer checkout's own .git dir and its worktrees - "work" below is a
# separate, independent `git init`, so it never inherits them. Without this,
# the final push has no auth at all: over HTTPS that doesn't fail fast, it
# hangs indefinitely waiting on a credential prompt that never arrives,
# until the job's default 6-hour timeout kills it (confirmed: this is
# exactly what happened on both real runs that ever exercised this script -
# zero log output after the env dump, cancelled at the 6h mark each time).
remote="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}"
scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readme="$scripts_dir/../README.md"
dispatcher="$scripts_dir/../changelog-dispatcher.yml"
# The commit actually checked out here (not $GITHUB_SHA, which the runner
# sets from the triggering event and - now that "changelog" is the repo's
# default branch - points there, not at generator, for schedule/dispatch
# runs regardless of this job's own `ref: generator` checkout).
generator_sha="$(git -C "$scripts_dir" rev-parse HEAD)"

for attempt in 1 2 3; do
  rm -rf work && git init -q work
  (
    cd work

    # Current changelog tip, if any (no tree/blobs: we only chain onto its
    # hash, never read its contents).
    git fetch -q --filter=tree:0 --depth=1 "$remote" refs/heads/changelog:refs/heads/changelog 2>/dev/null || true
    parent=$(git rev-parse --verify --quiet refs/heads/changelog || true)

    while read -r digest; do
      ref="refs/raw/${digest/sha256:/sha256-}"
      # A matrix leg exporting this digest may have failed (fail-fast is
      # off): skip it here rather than aborting the whole run, since it'll
      # just get picked up again (and chained in) by a future cron run.
      if ! git fetch -q --filter=blob:none "$remote" "$ref:$ref"; then
        echo "skipping $digest: export did not produce $ref" >&2
        continue
      fi
      tree=$(git rev-parse "$ref^{tree}")
      ref_sha=$(git rev-parse "$ref")
      message=$(git log -1 --format=%B "$ref")
      date=$(git log -1 --format=%cI "$ref")
      commit=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" GIT_AUTHOR_DATE="$date" \
               GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" GIT_COMMITTER_DATE="$date" \
               git commit-tree "$tree" ${parent:+-p "$parent"} -m "$message" -m "Export-Commit: $ref_sha")
      parent="$commit"
    done < <(printf '%s' "$DIGESTS" | jq -r '.[]')

    # Overlay README.md and the dispatcher workflow on top of the last
    # digest's tree: the README for human browsing, the dispatcher so
    # GitHub can still find a workflow here if this branch is ever made
    # the repo's default (see the file header for why one small file is
    # enough).
    #
    # Built via ls-tree/mktree (pure SHA-reference plumbing), not
    # read-tree/update-index/write-tree: the latter, on this branch's
    # blob:none-fetched digest trees, was observed triggering git's
    # promisor remote to lazily re-fetch the *entire* snapshot's blob
    # content on demand (a single-digest run turning into a multi-hundred-
    # thousand-object fetch) - confirmed to be what silently ate the full
    # 6-hour job timeout on every run that ever exercised this script.
    # ls-tree/mktree never touch blob content, so this can't recur.
    blob_readme=$(git hash-object -w "$readme")
    blob_dispatcher=$(git hash-object -w "$dispatcher")
    workflows_tree=$(printf '100644 blob %s\tcron.yml\n' "$blob_dispatcher" | git mktree)
    github_tree=$(printf '040000 tree %s\tworkflows\n' "$workflows_tree" | git mktree)
    tree=$(
      { git ls-tree "$(git rev-parse "$parent^{tree}")"
        printf '100644 blob %s\tREADME.md\n' "$blob_readme"
        printf '040000 tree %s\t.github\n' "$github_tree"
      } | git mktree
    )
    tip=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
          GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
          git commit-tree "$tree" -p "$parent" -m "docs: update changelog README and workflows" -m "Export-Commit: $generator_sha")

    git push "$remote" "$tip:refs/heads/changelog"
  ) && exit 0

  echo "push rejected (attempt $attempt), retrying from the new tip..." >&2
done

echo "failed to push changelog branch after 3 attempts" >&2
exit 1
