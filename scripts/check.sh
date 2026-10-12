#!/usr/bin/env bash
#
# Every check CI runs, in one place, so a developer runs exactly what a pull request will:
# formatting, tidy module files, vet, build, the tests under the race detector, and govulncheck,
# for each module - then type-checks the native key-wrapper module for every platform it supports,
# whatever this host is. Stops at the first failure.
#
# Usage (from the repository root, or anywhere):
#   scripts/check.sh                       # every module
#   scripts/check.sh keywrapping/nativev1  # one or more module directories
#
# Environment:
#   CGO_ENABLED            defaults to 1 on macOS and Linux (keywrapping/nativev1 and the race
#                          detector need it); left alone on Windows.
#   HKDFGUARD_CHECK_RACE   0 skips the race detector (no C toolchain on this host).
#   HKDFGUARD_TEST_SERVICE a provisioned native service: the native round trips then run too.
#
# The native round trips (keywrapping/nativev1, integration) are reported as skipped unless this
# host has a provisioned test service; see keywrapping/nativev1/scripts.

set -euo pipefail

cd "$(dirname "$0")/.."

# Pinned, so a CI run is reproducible; the Go module proxy and checksum database verify it.
readonly GOVULNCHECK_VERSION="v1.9.0"

readonly ALL_MODULES=(. cryptoprovider/aesgcm256 keywrapping/nativev1 integration)
modules=("$@")
[[ ${#modules[@]} -gt 0 ]] || modules=("${ALL_MODULES[@]}")

note() { echo; echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

case "$(go env GOOS)" in
    darwin|linux) export CGO_ENABLED="${CGO_ENABLED:-1}" ;;
esac

race=(-race)
[[ ${HKDFGUARD_CHECK_RACE:-1} == 1 ]] || race=()

go version

for module in "${modules[@]}"; do
    [[ -f "${module}/go.mod" ]] || die "${module} is not a module directory"
    (
        cd "${module}"
        name="$(go list -m)"

        note "${name}: formatting"
        unformatted="$(gofmt -l .)"
        [[ -z ${unformatted} ]] || die "not gofmt-formatted:"$'\n'"${unformatted}"

        note "${name}: go.mod and go.sum are tidy"
        go mod tidy -diff

        note "${name}: vet"
        go vet ./...

        note "${name}: build"
        go build ./...

        note "${name}: test"
        go test "${race[@]}" -count=1 ./...

        note "${name}: govulncheck"
        go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
    )
done

note "keywrapping/nativev1: type-checks for every supported platform"
(
    cd keywrapping/nativev1
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet ./...
    GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go vet ./...
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go vet ./...
    GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./...
)

note "all checks passed"
