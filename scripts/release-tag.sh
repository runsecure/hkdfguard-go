#!/usr/bin/env bash
#
# Turns a release tag into the module it releases, and checks that module can be released. Prints
# key=value lines (what the release workflow writes to $GITHUB_OUTPUT):
#
#   module_dir    the module's directory: ".", securefile, cryptoprovider/aesgcm256,
#                 keywrapping/nativev1, keywrapping/awskms, keywrapping/azurekeyvault or
#                 keywrapping/googlekms
#   module_path   its module path
#   artifact      the name of its source archive: hkdfguard-go, hkdfguard-go-aesgcm256, ...
#   version       the tag's version, with the v
#   prerelease    true for a 0.x version or one with a pre-release suffix
#
# Go modules are released by tag alone - the module proxy serves the tagged source - so a tag is:
#
#   vMAJOR.MINOR.PATCH[-suffix]                          the root module
#   cryptoprovider/aesgcm256/vMAJOR.MINOR.PATCH[-suffix] that nested module
#   keywrapping/nativev1/vMAJOR.MINOR.PATCH[-suffix]     that nested module
#   keywrapping/awskms/vMAJOR.MINOR.PATCH[-suffix]       that nested module
#   keywrapping/azurekeyvault/vMAJOR.MINOR.PATCH[-suffix] that nested module
#   keywrapping/googlekms/vMAJOR.MINOR.PATCH[-suffix]    that nested module
#   securefile/vMAJOR.MINOR.PATCH[-suffix]               that nested module
#
# A nested module is refused while its go.mod still points at the root module (or, for
# keywrapping/awskms, keywrapping/azurekeyvault and keywrapping/googlekms, at securefile) with a
# replace directive, or requires a placeholder version of it: a consumer would get a module that
# doesn't build. Remove the replace and require a tagged version first - so the root module, then
# securefile, before keywrapping/awskms, keywrapping/azurekeyvault and keywrapping/googlekms.
#
# Usage: scripts/release-tag.sh <tag>

set -euo pipefail

cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

tag="${1:?usage: scripts/release-tag.sh <tag>}"
readonly SEMVER='v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?'

if [[ ${tag} =~ ^${SEMVER}$ ]]; then
    module_dir="."
    artifact="hkdfguard-go"
elif [[ ${tag} =~ ^(securefile|cryptoprovider/aesgcm256|keywrapping/nativev1|keywrapping/awskms|keywrapping/azurekeyvault|keywrapping/googlekms)/${SEMVER}$ ]]; then
    module_dir="${BASH_REMATCH[1]}"
    artifact="hkdfguard-go-$(basename "${module_dir}")"
else
    die "tag '${tag}' is not vMAJOR.MINOR.PATCH (optionally -suffix), on its own or under securefile/, cryptoprovider/aesgcm256/, keywrapping/nativev1/, keywrapping/awskms/, keywrapping/azurekeyvault/ or keywrapping/googlekms/"
fi
version="${tag##*/}"

gomod="${module_dir}/go.mod"
[[ -f ${gomod} ]] || die "${gomod} does not exist"
module_path="$(cd "${module_dir}" && go list -m)"

expected_path="github.com/runsecure/hkdfguard-go"
[[ ${module_dir} == "." ]] || expected_path="${expected_path}/${module_dir}"
[[ ${module_path} == "${expected_path}" ]] || die "${gomod} declares module '${module_path}', but tag '${tag}' releases '${expected_path}'"

if go mod edit -json "${gomod}" | grep -q '"Replace"'; then
    die "${gomod} has a replace directive; a released module must require a tagged version of every dependency instead"
fi
if grep -q 'v0.0.0-00010101000000-000000000000' "${gomod}"; then
    die "${gomod} requires a placeholder version (v0.0.0-00010101000000-000000000000); require a tagged version instead"
fi

prerelease=false
[[ ${version} == v0.* || ${version} == *-* ]] && prerelease=true

cat <<EOT
module_dir=${module_dir}
module_path=${module_path}
artifact=${artifact}
version=${version}
prerelease=${prerelease}
EOT
