#!/usr/bin/env bash
#
# Cuts a release: reads the latest `v<major>.<minor>.<patch>` tag, bumps the patch, and — after a
# `y` at the prompt — creates the annotated tag, pushes it to origin, and publishes the GitHub
# release with notes.
#
#   scripts/release.sh          # v0.3.0 -> v0.3.1
#   scripts/release.sh 0.4.0    # tag exactly this version — how a minor or major release is cut
#   DRAFT=1 scripts/release.sh  # publish the release as a draft, to edit and release by hand
#   YES=1 scripts/release.sh    # no summary, no question: one line, then the release happens
#
# The tag is `v<version>` and its message is `<product> v<version>`, where the product is the
# repository's name. "Latest" is decided after fetching the remote's tags, so a stale checkout
# cannot re-issue a bump somebody else already pushed. The prompt shows what is about to happen —
# the commits going into the release, and any version bump — and anything other than `y` aborts
# with nothing created.
#
# The release notes are the commit subjects since the previous tag, so work committed straight to
# main is listed too; GitHub's generated "What's Changed" section (merged pull requests) is appended
# under them.
#
# Nothing here is specific to this repository. When a Cargo.toml declares a version — under
# `[workspace.package]` or `[package]`, wherever it sits in the file — the version follows the tag:
# the script bumps it, commits `<product> v<version>` and pushes, and only then tags, so the tagged
# source always builds a binary that reports the version the tag claims. A repository without a
# Cargo.toml skips the bump and just tags.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

product="$(basename "$(pwd)")"

# The version the working tree declares: the first `version = "…"` line after a
# `[workspace.package]` or `[package]` section header. Empty when there is no Cargo.toml, which is
# what makes the bump below optional rather than assumed.
declared_version() {
  [[ -f Cargo.toml ]] || return 0
  awk -F'"' '/^\[(workspace\.)?package\]/ { in_section = 1 }
             in_section && /^version = "/ { print $2; exit }' Cargo.toml
}

if [[ -n "$(git status --porcelain)" ]]; then
  echo "the working tree is not clean: commit or stash before releasing" >&2
  exit 1
fi

# The remote decides what "latest" means.
git fetch --tags --quiet origin

latest="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' | sort -V | tail -1)"
workspace_version="$(declared_version)"

if [[ $# -ge 1 && -n "$1" ]]; then
  version="${1#v}"
elif [[ -n "${latest}" ]]; then
  IFS=. read -r major minor patch <<<"${latest#v}"
  version="${major}.${minor}.$((patch + 1))"
elif [[ -n "${workspace_version}" ]]; then
  # No tag yet: the first release is whatever the working tree already says it is.
  version="${workspace_version}"
else
  echo "no tag to bump and no Cargo.toml to read: name the version, e.g. $0 0.1.0" >&2
  exit 1
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

branch="$(git rev-parse --abbrev-ref HEAD)"

# What the release will say: every commit since the previous tag, newest first.
range="${latest:+${latest}..}HEAD"
notes="$(git log --format='- %s (%h)' "${range}")"

if [[ -n "${YES:-}" ]]; then
  echo "releasing ${tag} — ${product} v${version}, from $(git rev-parse --short HEAD) on ${branch}"
else
  echo "release:"
  echo "  latest tag    ${latest:-none}"
  echo "  new tag       ${tag}"
  echo "  message       ${product} v${version}"
  echo "  commit        $(git rev-parse --short HEAD) on ${branch}"
  echo "  changes since ${latest:-the beginning}:"
  git log --format='    - %s (%h)' "${range}"
fi

# The warnings appear in both modes: YES silences the question, never the risks.
if [[ -n "${workspace_version}" && "${workspace_version}" != "${version}" ]]; then
  echo "  bump          Cargo.toml ${workspace_version} -> ${version}, committed and pushed before tagging"
fi
if [[ "${branch}" != "main" ]]; then
  echo "  NOTE: this is not main"
fi
if [[ -n "${DRAFT:-}" ]]; then
  echo "  NOTE: the release will be a draft — edit and publish it on GitHub"
fi

if [[ -z "${YES:-}" ]]; then
  read -r -p "create ${tag}, push it and publish the release? [y/N] " answer
  case "${answer}" in
    y | Y | yes | YES) ;;
    *)
      echo "aborted: nothing was created"
      exit 1
      ;;
  esac
fi

# The declared version follows the tag, so the tagged source builds a binary that says what the tag
# says. The bump is its own pushed commit, and the tag lands on it.
if [[ -n "${workspace_version}" && "${workspace_version}" != "${version}" ]]; then
  VERSION="${version}" perl -0pi -e \
    's/(\[(?:workspace\.)?package\][^\[]*?^version = ")[^"]*/$1$ENV{VERSION}/ms' Cargo.toml
  if [[ -f Cargo.lock ]]; then
    cargo update --workspace --quiet
  fi
  bumped="$(declared_version)"
  if [[ "${bumped}" != "${version}" ]]; then
    echo "bumping Cargo.toml did not take: it now says \`${bumped}\`, not ${version}" >&2
    exit 1
  fi
  git add Cargo.toml
  if [[ -f Cargo.lock ]]; then
    git add Cargo.lock
  fi
  git commit --quiet --message "${product} v${version}"
  git push --quiet origin HEAD
  echo "bumped the workspace to ${version}"
fi

git tag --annotate "${tag}" --message "${product} v${version}"
git push origin "${tag}"

# The commit list travels as the notes body; GitHub appends its generated "What's Changed" section
# (merged pull requests since --notes-start-tag) underneath.
draft=""
if [[ -n "${DRAFT:-}" ]]; then
  draft="--draft"
fi
start=""
if [[ -n "${latest}" ]]; then
  start="--notes-start-tag ${latest}"
fi
# shellcheck disable=SC2086 # ${draft} and ${start} are deliberate word-split flags
if ! gh release create "${tag}" --title "${product} v${version}" --verify-tag \
  --notes "${notes}" --generate-notes ${start} ${draft}; then
  echo "the tag ${tag} was pushed, but the release page was not created — retry with:" >&2
  echo "  gh release create ${tag} --title \"${product} v${version}\" --verify-tag --generate-notes" >&2
  exit 1
fi

echo "released ${tag}"
