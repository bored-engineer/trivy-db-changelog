#!/usr/bin/env bash
# Re-exports every trivy-db digest with the current cmd/export, then rebuilds
# the changelog branch from the result. Run from a clone of this repository,
# on a machine with `gh` (authenticated) and push access to origin.
#
#   reexport.sh export    re-export every digest on GitHub Actions
#   reexport.sh rebuild   chain the re-exported snapshots into a fresh
#                         changelog and push it to refs/heads/changelog-rebuild
#   reexport.sh all       export, then rebuild (the default)
#   reexport.sh promote   back up the live changelog, then replace it with
#                         changelog-rebuild (force-push; asks first)
#
# export: for each batch of BATCH_SIZE digests (oldest first) it pushes a
# reexport/<n> branch - this repository's origin/generator commit plus a
# reexport-digests.json - which triggers .github/workflows/reexport.yml. That
# workflow force-replaces each digest's refs/raw/<digest>. At most
# MAX_INFLIGHT batches run at once, failed jobs are re-run, and a batch's
# branch is deleted once it succeeds. Progress is kept in WORKDIR/state, so
# an interrupted run resumes where it left off (rm -r the state dir to
# start over). Everything pushed must already be on origin/generator.
#
# rebuild: fetches every refs/raw/* commit and its trees (never blobs), then
# builds the same single-parent chain update-changelog.sh does for one run,
# but from scratch for every digest, with the same README/dispatcher overlay
# on top. Only plumbing that never reads blob content (ls-tree/mktree/
# commit-tree - see update-changelog.sh for why). Pushed in batches of 1000:
# GitHub hung up on one push of the whole ~12K-commit chain even though the
# transfer itself was tiny. Nothing live changes until `promote`.
set -euo pipefail

WORKDIR="${WORKDIR:-$HOME/trivy-db-reexport}"
BATCH_SIZE="${BATCH_SIZE:-256}"
MAX_INFLIGHT="${MAX_INFLIGHT:-3}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"
START_DATE="${START_DATE:-2022-01-04T18:07:01Z}"
POLL_SECONDS="${POLL_SECONDS:-60}"
PUSH_BATCH="${PUSH_BATCH:-1000}"
REBUILD_BRANCH="changelog-rebuild"

BOT_NAME="trivy-db-changelog"
BOT_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"

ROOT="$(git rev-parse --show-toplevel)"
REMOTE_URL="$(git -C "$ROOT" remote get-url origin)"
REPO="$(cd "$ROOT" && gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
: "${REPO:=bored-engineer/trivy-db-changelog}"
STATE="$WORKDIR/state"
mkdir -p "$STATE"

# stderr: check_batch's stdout is its return value.
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }

# list_digests writes "<created_at>\t<digest>" lines, oldest first, to $1.
list_digests() {
  gh api --paginate 'orgs/aquasecurity/packages/container/trivy-db/versions?per_page=100' --jq '.[]' \
    | jq -r --arg start "$START_DATE" 'select(.created_at > $start) | "\(.created_at)\t\(.name)"' \
    | sort > "$1"
}

batch_name() { printf '%03d' "$1"; }
state_get() { cat "$STATE/$1.$2" 2>/dev/null || true; }
state_set() { printf '%s' "$3" > "$STATE/$1.$2"; }

# start_batch pushes reexport/<n>: origin/generator plus the batch's digests.
start_batch() {
  local n="$1" name; name=$(batch_name "$n")
  local base blob tree commit
  base=$(cat "$STATE/generator.sha")
  blob=$(git -C "$ROOT" hash-object -w "$STATE/batch-$name.json")
  tree=$(
    { git -C "$ROOT" ls-tree "$base^{tree}"
      printf '100644 blob %s\treexport-digests.json\n' "$blob"
    } | git -C "$ROOT" mktree
  )
  # The time is part of the commit, so a restart's re-push is a new commit
  # (pushing an unchanged branch wouldn't trigger the workflow again).
  commit=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
           GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
           git -C "$ROOT" commit-tree "$tree" -p "$base" -m "chore: re-export batch $name")
  git -C "$ROOT" push -q --force origin "$commit:refs/heads/reexport/$name"
  state_set "$name" commit "$commit"
  state_set "$name" started "$(date +%s)"
  state_set "$name" status inflight
  log "batch $name: started ($commit)"
}

# check_batch looks at an in-flight batch's run and settles it if finished.
# Prints "busy" when the caller should keep counting it as in flight.
check_batch() {
  local n="$1" name; name=$(batch_name "$n")
  local commit run status conclusion id attempts
  commit=$(state_get "$name" commit)
  run=$(gh run list -R "$REPO" --workflow reexport.yml --branch "reexport/$name" -L 20 \
          --json databaseId,headSha,status,conclusion \
          --jq "[.[] | select(.headSha == \"$commit\")][0] // empty | \"\(.databaseId) \(.status) \(.conclusion)\"")
  if [ -z "$run" ]; then
    # The push should have created a run within seconds.
    if [ $(( $(date +%s) - $(state_get "$name" started) )) -gt 600 ]; then
      log "batch $name: no workflow run appeared; pushing it again"
      state_set "$name" status ""
      return 0
    fi
    echo busy
    return 0
  fi
  read -r id status conclusion <<<"$run"
  if [ "$status" != completed ]; then
    echo busy
    return 0
  fi
  if [ "$conclusion" = success ]; then
    state_set "$name" status done
    git -C "$ROOT" push -q origin --delete "reexport/$name" || true
    log "batch $name: done (run $id)"
    return 0
  fi
  attempts=$(( $(state_get "$name" attempts | sed 's/^$/0/') + 1 ))
  state_set "$name" attempts "$attempts"
  if [ "$attempts" -ge "$MAX_ATTEMPTS" ]; then
    state_set "$name" status failed
    log "batch $name: FAILED after $attempts attempts (run $id, $conclusion); branch reexport/$name kept"
    return 0
  fi
  log "batch $name: run $id $conclusion; re-running failed jobs (attempt $attempts/$MAX_ATTEMPTS)"
  gh run rerun -R "$REPO" "$id" --failed >/dev/null
  sleep 15
  echo busy
}

do_export() {
  git -C "$ROOT" fetch -q origin generator
  git -C "$ROOT" rev-parse origin/generator > "$STATE/generator.sha"
  log "re-exporting with generator $(cut -c1-12 "$STATE/generator.sha")"
  if ! git -C "$ROOT" cat-file -e "$(cat "$STATE/generator.sha"):.github/workflows/reexport.yml" 2>/dev/null; then
    echo "origin/generator has no .github/workflows/reexport.yml; push it first" >&2
    exit 1
  fi

  # The digest list is fixed for the whole run, so batch numbers stay stable
  # across restarts.
  if [ ! -s "$STATE/digests.tsv" ]; then
    list_digests "$STATE/digests.tsv"
    cut -f2 "$STATE/digests.tsv" | jq -R -s -c --argjson size "$BATCH_SIZE" \
      'split("\n") | map(select(length > 0)) | . as $d | [range(0; length; $size) | $d[.:.+$size]] | to_entries[] | "\(.key)\t\(.value | tojson)"' -r \
      | while IFS=$'\t' read -r n json; do printf '%s\n' "$json" > "$STATE/batch-$(batch_name "$n").json"; done
  fi
  local total; total=$(ls "$STATE"/batch-*.json | wc -l | tr -d ' ')
  log "$(wc -l < "$STATE/digests.tsv" | tr -d ' ') digest(s) in $total batch(es) of up to $BATCH_SIZE"

  while true; do
    local inflight=0 remaining=0 failed=0 n name st
    for ((n = 0; n < total; n++)); do
      name=$(batch_name "$n")
      st=$(state_get "$name" status)
      if [ "$st" = inflight ]; then
        if [ "$(check_batch "$n")" = busy ]; then
          inflight=$((inflight + 1)); remaining=$((remaining + 1)); continue
        fi
        st=$(state_get "$name" status)
      fi
      case "$st" in
        done) ;;
        failed) failed=$((failed + 1)) ;;
        inflight) inflight=$((inflight + 1)); remaining=$((remaining + 1)) ;;
        *)
          remaining=$((remaining + 1))
          if [ "$inflight" -lt "$MAX_INFLIGHT" ]; then
            start_batch "$n"
            inflight=$((inflight + 1))
          fi
          ;;
      esac
    done
    log "progress: $((total - remaining - failed))/$total done, $inflight in flight, $failed failed"
    [ "$remaining" -eq 0 ] && break
    sleep "$POLL_SECONDS"
  done

  if [ "$failed" -gt 0 ]; then
    log "$failed batch(es) failed; fix and re-run (state kept in $STATE; delete a batch's .status file to retry it)"
    return 1
  fi
  log "export complete"
}

do_rebuild() {
  export GIT_TERMINAL_PROMPT=0
  local work="$WORKDIR/rebuild"
  rm -rf "$work" && git init -q "$work"
  cd "$work"
  # Thousands of rapid commit-tree calls would repeatedly trip gc.auto.
  git config gc.auto 0

  git -C "$ROOT" fetch -q origin generator
  local generator_sha; generator_sha=$(git -C "$ROOT" rev-parse origin/generator)

  log "fetching every refs/raw/* commit and tree (no blobs)"
  git fetch -q --filter=blob:none "$REMOTE_URL" '+refs/raw/*:refs/raw/*'
  log "$(git for-each-ref refs/raw | wc -l | tr -d ' ') refs fetched"

  list_digests "$WORKDIR/rebuild-digests.tsv"
  local total; total=$(wc -l < "$WORKDIR/rebuild-digests.tsv" | tr -d ' ')

  local parent="" n=0 pending_missing="" digest ref tree ref_sha message date commit
  while IFS=$'\t' read -r _ digest; do
    ref="refs/raw/${digest/sha256:/sha256-}"
    if ! ref_sha=$(git rev-parse --verify --quiet "$ref"); then
      # Only a not-yet-exported tail (digests newer than the last cron run)
      # is tolerable: the next cron run exports and appends it.
      pending_missing="$pending_missing $digest"
      continue
    fi
    if [ -n "$pending_missing" ]; then
      echo "no refs/raw ref for:$pending_missing - but $digest, which is later, has one; refusing to chain a gap" >&2
      exit 1
    fi
    tree=$(git rev-parse "$ref^{tree}")
    message=$(git log -1 --format=%B "$ref")
    date=$(git log -1 --format=%cI "$ref")
    commit=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" GIT_AUTHOR_DATE="$date" \
             GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" GIT_COMMITTER_DATE="$date" \
             git commit-tree "$tree" ${parent:+-p "$parent"} -m "$message" -m "Export-Commit: $ref_sha")
    parent="$commit"
    n=$((n + 1))
    if [ $((n % PUSH_BATCH)) -eq 0 ]; then
      git push -q --force "$REMOTE_URL" "$parent:refs/heads/$REBUILD_BRANCH"
      log "chained and pushed $n/$total"
    fi
  done < "$WORKDIR/rebuild-digests.tsv"
  [ -n "$parent" ] || { echo "no digests chained" >&2; exit 1; }
  [ -z "$pending_missing" ] || log "not yet exported (left for the next cron run):$pending_missing"

  # Overlay, exactly as update-changelog.sh builds it.
  local blob_readme blob_dispatcher workflows_tree github_tree
  blob_readme=$(git -C "$ROOT" show "$generator_sha:.github/README.md" | git hash-object -w --stdin)
  blob_dispatcher=$(git -C "$ROOT" show "$generator_sha:.github/changelog-dispatcher.yml" | git hash-object -w --stdin)
  workflows_tree=$(printf '100644 blob %s\tcron.yml\n' "$blob_dispatcher" | git mktree)
  github_tree=$(printf '040000 tree %s\tworkflows\n' "$workflows_tree" | git mktree)
  tree=$(
    { git ls-tree "$(git rev-parse "$parent^{tree}")"
      printf '100644 blob %s\tREADME.md\n' "$blob_readme"
      printf '040000 tree %s\t.github\n' "$github_tree"
    } | git mktree
  )
  [ -n "$tree" ] || { echo "failed to build the overlay tree" >&2; exit 1; }
  local tip
  tip=$(GIT_AUTHOR_NAME="$BOT_NAME" GIT_AUTHOR_EMAIL="$BOT_EMAIL" \
        GIT_COMMITTER_NAME="$BOT_NAME" GIT_COMMITTER_EMAIL="$BOT_EMAIL" \
        git commit-tree "$tree" -p "$parent" -m "docs: update changelog README and workflows" -m "Export-Commit: $generator_sha")
  [ -n "$tip" ] || { echo "failed to build the changelog tip" >&2; exit 1; }
  git push -q --force "$REMOTE_URL" "$tip:refs/heads/$REBUILD_BRANCH"
  printf '%s\n' "$tip" > "$STATE/rebuild.tip"
  log "rebuilt $n digest commit(s) + overlay; tip $tip is on origin/$REBUILD_BRANCH"
  log "inspect it, then: $0 promote"
}

do_promote() {
  local tip live
  tip=$(git ls-remote "$REMOTE_URL" "refs/heads/$REBUILD_BRANCH" | cut -f1)
  live=$(git ls-remote "$REMOTE_URL" refs/heads/changelog | cut -f1)
  [ -n "$tip" ] || { echo "origin has no $REBUILD_BRANCH; run rebuild first" >&2; exit 1; }
  echo "This force-replaces origin/changelog (the default branch):"
  echo "  live    $live  (backed up to refs/backup/changelog-$(date -u +%Y%m%d))"
  echo "  new     $tip"
  read -r -p "Type 'promote' to continue: " answer
  [ "$answer" = promote ] || { echo aborted; exit 1; }
  # The backup needs the live tip's objects, which are on the remote only.
  git -C "$ROOT" fetch -q origin "refs/heads/changelog"
  git -C "$ROOT" push -q origin "$live:refs/backup/changelog-$(date -u +%Y%m%d)"
  git -C "$ROOT" push --force origin "$tip:refs/heads/changelog"
  log "promoted"
}

case "${1:-all}" in
  export) do_export ;;
  rebuild) do_rebuild ;;
  all) do_export; do_rebuild ;;
  promote) do_promote ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit 1 ;;
esac
