#!/bin/sh
# Allocate the release tag for the source revision being released, and CREATE it.
#
# WHY IT CREATES THE TAG. The migration plan's rule is that a release job allocates
# serially and then confirms with the atomic result of creating an immutable tag:
# if the tag already exists, the allocation lost a race, and the answer is to
# re-read rather than to overwrite. Creating the tag is the only step that can
# decide a race, so it belongs here rather than in a later step.
#
# TWO RUNS OF THE SAME RELEASE END UP WITH THE SAME TAG, and that is correct
# rather than a collision: the tag points at a source revision, so a rerun resumes
# the number already bound to it. Two runs of DIFFERENT releases end up with
# different tags, because the loser's re-read sees the winner's tag as taken. One
# mechanism covers both, and it is the reason the number is recoverable from the
# repository instead of being remembered in the job.
#
# IT NEVER MOVES A TAG. `git push` refuses to update an existing ref, so a number
# once bound to a source revision stays bound to it — including when the build
# that took it then failed, which is the gap the rule permits.
#
# Usage: allocate-release-tag.sh <line> <scheme> [remote] [max-attempts]
set -eu

line=${1:?a release line, MAJOR.MINOR}
scheme=${2:?a release scheme, product or legacy}
remote=${3:-origin}
max_attempts=${4:-5}

# The revision this release is being built from. Every decision below is about
# binding a number to THIS commit.
sha=$(git rev-parse HEAD)

all_tags() {
  git ls-remote --tags --refs "$remote" | sed 's#.*refs/tags/##'
}
tags_on_this_commit() {
  git ls-remote --tags "$remote" | awk -v sha="$sha" '$1 == sha { sub("^refs/tags/", "", $2); print $2 }'
}

attempt=0
while [ "$attempt" -lt "$max_attempts" ]; do
  # A NUMBER ALREADY BOUND TO THIS REVISION IS RESUMED; otherwise the next patch on
  # the line is allocated. Both are one command, because "resume or allocate" is
  # one decision and splitting it would be a second place knowing the rule.
  tag=$(go run ./deployment/cmd/allocate-release-tag \
    -line "$line" -scheme "$scheme" \
    -existing "$(all_tags)" \
    -on-commit "$(tags_on_this_commit)")

  if git push --quiet "$remote" "$sha:refs/tags/$tag" 2>/dev/null; then
    printf '%s\n' "$tag"
    exit 0
  fi

  # The create failed, which means somebody else bound a number while this run was
  # deciding. Re-read everything and decide again: if it was the SAME release, the
  # next pass resumes its tag; if it was a different one, the next pass sees the
  # number as taken and allocates the one after it.
  attempt=$((attempt + 1))
done

echo "could not bind a release tag for $sha on line $line after $max_attempts attempts" >&2
exit 1
