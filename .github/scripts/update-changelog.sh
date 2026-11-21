#!/usr/bin/env bash
# Appends the digests in $DIGESTS (a JSON array of "sha256:..." strings, as
# produced by the cron workflow's discover job, oldest first) onto the
# "changelog" branch: one commit per digest, reusing the exact tree that
# cmd/export already built under refs/raw/<digest>, chained chronologically
# instead of left as disconnected orphan commits. A trailing commit overlays
# README.md and a thin .github/workflows/cron.yml on top so the branch stays
# browsable and, if it's ever made the repo's default branch, GitHub can
# still find a workflow here to run on schedule. That workflow
# (changelog-dispatcher.yml) just forwards to the real implementation on
# "generator" via a ref-pinned reusable workflow call, so this overlay only
# needs that one small, rarely-changing file - never a synced copy of every
# workflow. This is re-applied every run so it's always at the tip, not
# buried under newer digests.
#
# Deliberately avoids fetching the full history: only the changelog branch's
# current tip commit (no tree) and each new digest's commit+tree (no blobs)
# are pulled, so a run's network cost stays proportional to the few digests
# it's adding, not to the size of the branch's history.
#
# Run from the repository root (e.g. $GITHUB_WORKSPACE); creates and removes
# a "work" subdirectory there to build the branch in.
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${DIGESTS:?}"

BOT_NAME="trivy-db-changelog"
BOT_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

remote="https://github.com/${GITHUB_REPOSITORY}"
scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readme="$scripts_dir/../README.md"
dispatcher="$scripts_dir/../changelog-dispatcher.yml"

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
      message=$(git log -1 --format=%B "$ref")
      date=$(git log -1 --format=%cI "$ref")
      commit=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" GIT_AUTHOR_DATE="$date" \
               GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" GIT_COMMITTER_DATE="$date" \
               git commit-tree "$tree" ${parent:+-p "$parent"} -m "$message")
      parent="$commit"
    done < <(printf '%s' "$DIGESTS" | jq -r '.[]')

    # Overlay README.md and the dispatcher workflow on top of the last
    # digest's tree: the README for human browsing, the dispatcher so
    # GitHub can still find a workflow here if this branch is ever made
    # the repo's default (see the file header for why one small file is
    # enough).
    git read-tree "$(git rev-parse "$parent^{tree}")"
    blob=$(git hash-object -w "$readme")
    git update-index --add --cacheinfo 100644 "$blob" README.md
    blob=$(git hash-object -w "$dispatcher")
    git update-index --add --cacheinfo 100644 "$blob" .github/workflows/cron.yml
    tree=$(git write-tree)
    tip=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
          GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
          git commit-tree "$tree" -p "$parent" -m "docs: update changelog README and workflows")

    git push "$remote" "$tip:refs/heads/changelog"
  ) && exit 0

  echo "push rejected (attempt $attempt), retrying from the new tip..." >&2
done

echo "failed to push changelog branch after 3 attempts" >&2
exit 1
