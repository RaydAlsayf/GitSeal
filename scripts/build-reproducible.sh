#!/usr/bin/env sh
set -eu

output=${1:-dist}

# Release callers must materialize the reviewed module graph before invoking
# this script. The build itself is deliberately offline and refuses local Go,
# workspace, and Git authority redirects that could silently change the source
# or dependency graph.
env_bin=$(command -v env) || {
  echo 'env executable is unavailable; cannot inspect the authority environment' >&2
  exit 1
}
grep_bin=$(command -v grep) || {
  echo 'grep executable is unavailable; cannot inspect the authority environment' >&2
  exit 1
}
if "$env_bin" | "$grep_bin" -Eq '^(GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_COMMON_DIR|GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES|GIT_CONFIG|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|GIT_CONFIG_NOSYSTEM|GIT_CONFIG_COUNT|GIT_CONFIG_PARAMETERS|GIT_IMPLICIT_WORK_TREE|GIT_GRAFT_FILE|GIT_NO_REPLACE_OBJECTS|GIT_REPLACE_REF_BASE|GIT_PREFIX|GIT_SHALLOW_FILE|GIT_NAMESPACE|GIT_REFERENCE_BACKEND|GIT_DEFAULT_HASH|GIT_DEFAULT_REF_FORMAT|GIT_INDEX_VERSION|GIT_LITERAL_PATHSPECS|GIT_GLOB_PATHSPECS|GIT_NOGLOB_PATHSPECS|GIT_ICASE_PATHSPECS|GIT_ATTR_SOURCE|GIT_ATTR_NOSYSTEM|GIT_ATTR_GLOBAL|GIT_ATTR_SYSTEM|GIT_QUARANTINE_PATH|GIT_NO_LAZY_FETCH|GIT_EXEC_PATH|GIT_CEILING_DIRECTORIES|GIT_DISCOVERY_ACROSS_FILESYSTEM|GIT_CONFIG_(KEY|VALUE)_[^=]*)=.'; then
  echo 'ambiguous Git authority environment is forbidden for review builds' >&2
  exit 1
fi
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
unset GIT_CONFIG GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM
unset GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_IMPLICIT_WORK_TREE
unset GIT_GRAFT_FILE GIT_NO_REPLACE_OBJECTS GIT_REPLACE_REF_BASE
unset GIT_PREFIX GIT_SHALLOW_FILE GIT_NAMESPACE GIT_REFERENCE_BACKEND
unset GIT_DEFAULT_HASH GIT_DEFAULT_REF_FORMAT GIT_INDEX_VERSION
unset GIT_LITERAL_PATHSPECS GIT_GLOB_PATHSPECS GIT_NOGLOB_PATHSPECS
unset GIT_ICASE_PATHSPECS GIT_ATTR_SOURCE GIT_ATTR_NOSYSTEM
unset GIT_ATTR_GLOBAL GIT_ATTR_SYSTEM GIT_QUARANTINE_PATH GIT_NO_LAZY_FETCH
unset GIT_EXEC_PATH GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_ATTR_NOSYSTEM=1
export GIT_NO_LAZY_FETCH=1
unset GOROOT GOEXPERIMENT GOFIPS140
export GO111MODULE=on
export GODEBUG=
export GOENV=off
export GOFLAGS=-mod=readonly
export GONOPROXY=
export GONOSUMDB=
export GOPRIVATE=
export GOPROXY=off
export GOSUMDB=sum.golang.org
export GOTOOLCHAIN=local
export GOWORK=off
export GOAMD64=v1
export GOARM64=v8.0
export CGO_ENABLED=0
export TZ=UTC

git_bin=$(command -v git) || {
  echo 'git executable is unavailable' >&2
  exit 1
}
go_bin=$(command -v go) || {
  echo 'go executable is unavailable' >&2
  exit 1
}

root=$($git_bin --no-pager --no-optional-locks --no-replace-objects \
  -c core.fsmonitor=false rev-parse --show-toplevel)
cd "$root"

revision=$($git_bin --no-pager --no-optional-locks --no-replace-objects \
  -c core.fsmonitor=false rev-parse --verify 'HEAD^{commit}')
test -n "$revision"

if test -n "$($git_bin --no-pager --no-optional-locks --no-replace-objects \
  -c core.fsmonitor=false status --porcelain=v1 --untracked-files=all --ignored=matching)"; then
  echo 'source tree has modified, untracked, or ignored files; refusing build' >&2
  exit 1
fi

if ! "$go_bin" env GOVERSION | "$grep_bin" -qx 'go1.26.6'; then
  echo 'the exact Go 1.26.6 toolchain is required' >&2
  exit 1
fi

if ! "$go_bin" mod edit -json | "$grep_bin" -q '"Replace": null'; then
  echo 'module replacements are forbidden in a release build' >&2
  exit 1
fi

"$go_bin" mod verify
"$go_bin" list -mod=readonly -deps ./cmd/gitseal >/dev/null

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$($git_bin --no-pager --no-optional-locks --no-replace-objects \
  -c core.fsmonitor=false show -s --format=%ct "$revision")

if test -e "$output"; then
  echo "output path already exists: $output" >&2
  exit 1
fi
mkdir -p "$output"

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  goos=${target%/*}
  goarch=${target#*/}
  suffix=
  if [ "$goos" = windows ]; then suffix=.exe; fi
  name="gitseal_${goos}_${goarch}${suffix}"
  GOOS="$goos" GOARCH="$goarch" "$go_bin" build \
    -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-buildid= -X github.com/raydalsayf/gitseal/internal/cli.SourceRevision=$revision" \
    -o "$output/$name" ./cmd/gitseal
done

cp LICENSE THIRD_PARTY_NOTICES.md "$output/"

(
  cd "$output"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum LICENSE THIRD_PARTY_NOTICES.md gitseal_* | sed 's/ [*]/  /' > SHA256SUMS
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 LICENSE THIRD_PARTY_NOTICES.md gitseal_* > SHA256SUMS
  else
    echo 'neither sha256sum nor shasum is available' >&2
    exit 1
  fi
)
