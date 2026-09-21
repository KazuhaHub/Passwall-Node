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
# Usage: allocate-release-tag.sh <line> [remote] [max-attempts]
set -eu

line=${1:?a release line, MAJOR.MINOR}
remote=${2:-origin}
max_attempts=${3:-5}

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
bound=
while [ "$attempt" -lt "$max_attempts" ]; do
  # A NUMBER ALREADY BOUND TO THIS REVISION IS RESUMED; otherwise the next number
  # on the line is allocated — an INCREMENTAL FIX takes the build segment
  # (4.1.0.1, 4.1.0.2), and the patch advances only when somebody names one. Both are one command, because "resume or allocate" is
  # one decision and splitting it would be a second place knowing the rule.
  tag=$(go run ./deployment/cmd/allocate-release-tag \
    -line "$line" \
    -existing "$(all_tags)" \
    -on-commit "$(tags_on_this_commit)")

  if git push --quiet "$remote" "$sha:refs/tags/$tag" 2>/dev/null; then
    bound=$tag
    break
  fi

  # The create failed, which means somebody else bound a number while this run was
  # deciding. Re-read everything and decide again: if it was the SAME release, the
  # next pass resumes its tag; if it was a different one, the next pass sees the
  # number as taken and allocates the one after it.
  attempt=$((attempt + 1))
done

if [ -z "$bound" ]; then
  echo "could not bind a release tag for $sha on line $line after $max_attempts attempts" >&2
  exit 1
fi

# THE GO MODULE TAG, AT THE SAME REVISION.
#
# A release tag is a git ref; a Go MODULE version is what `go get` resolves, and Go
# reads it from a tag starting with `v`. A module whose path ends in /vMAJOR accepts
# only vMAJOR.*, so this project's module version and its product version are ONE
# NUMBER — v4.0.1 for release/4.0.1 — and deriving the second from the first is what
# keeps them from having to be remembered separately.
#
# IT IS CREATED AFTER THE NUMBER IS BOUND, because the number comes from that
# decision. IT IS NOT PART OF THE RACE: the release tag is what decides a number,
# and a re-run resumes it and retries this tag, so a release that failed here is
# completed rather than renumbered.
#
# A MODULE TAG ALREADY ON ANOTHER REVISION IS REFUSED. That is the module line
# disagreeing with the product line, and neither moving the tag (which would change
# what a dependency version means for anybody who resolved it) nor skipping it
# (which would leave the two lines apart silently) is a decision this script can
# make. The release tag stays bound: it is the number decision, and it is not what
# is wrong.
module_tag="v${bound#release/}"
if ! git push --quiet "$remote" "$sha:refs/tags/$module_tag" 2>/dev/null; then
  if [ "$(git ls-remote "$remote" "refs/tags/$module_tag" | awk '{print $1}')" != "$sha" ]; then
    echo "$tag is bound to $sha, but the Go module tag $module_tag is bound to another revision." >&2
    echo "the module version and the product version have diverged; decide which line is right, then re-run to complete the pair." >&2
    exit 1
  fi
fi

printf '%s\n' "$bound"
