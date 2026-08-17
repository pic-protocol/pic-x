#!/usr/bin/env bash
#
# Cuts a release tag: reads the latest `v<major>.<minor>.<patch>` tag, bumps the patch, and — after
# a `y` at the prompt — creates the annotated tag and pushes it to origin.
#
#   scripts/release.sh          # v0.3.0 -> v0.3.1
#   scripts/release.sh 0.4.0    # tag exactly this version — how a minor or major release is cut
#
# The tag is `v<version>` and its message is `pic-x v<version>`. "Latest" is decided after fetching
# the remote's tags, so a stale checkout cannot re-issue a bump somebody else already pushed. The
# prompt shows what is about to happen — including the workspace version, which the tag does not
# change — and anything other than `y` aborts with nothing created.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -n "$(git status --porcelain)" ]]; then
  echo "the working tree is not clean: commit or stash before releasing" >&2
  exit 1
fi

# The remote decides what "latest" means.
git fetch --tags --quiet origin

latest="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -1)"

if [[ $# -ge 1 && -n "$1" ]]; then
  version="${1#v}"
elif [[ -n "${latest}" ]]; then
  IFS=. read -r major minor patch <<<"${latest#v}"
  version="${major}.${minor}.$((patch + 1))"
else
  # No tag yet: the first release is whatever the workspace already says it is.
  version="$(cargo pkgid --package pic-x | sed 's/.*[@#]//')"
fi

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "\`${version}\` is not a <major>.<minor>.<patch> version" >&2
  exit 1
fi

tag="v${version}"

if git rev-parse --quiet --verify "refs/tags/${tag}" >/dev/null; then
  echo "the tag ${tag} already exists" >&2
  exit 1
fi

workspace_version="$(cargo pkgid --package pic-x | sed 's/.*[@#]//')"
branch="$(git rev-parse --abbrev-ref HEAD)"

echo "release:"
echo "  latest tag    ${latest:-none}"
echo "  new tag       ${tag}"
echo "  message       pic-x v${version}"
echo "  commit        $(git rev-parse --short HEAD) on ${branch}"
echo "  workspace     ${workspace_version}"
if [[ "${workspace_version}" != "${version}" ]]; then
  echo "  NOTE: the workspace says ${workspace_version}, the tag says ${version} — the banner will"
  echo "        not match the tag until Cargo.toml is bumped too"
fi
if [[ "${branch}" != "main" ]]; then
  echo "  NOTE: this is not main"
fi

read -r -p "create and push ${tag}? [y/N] " answer
case "${answer}" in
  y | Y | yes | YES) ;;
  *)
    echo "aborted: nothing was created"
    exit 1
    ;;
esac

git tag --annotate "${tag}" --message "pic-x v${version}"
git push origin "${tag}"

echo "released ${tag}"
