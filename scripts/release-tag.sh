#!/usr/bin/env bash
#
# Turns a release tag into the module it releases, and checks that module can be released. Prints
# key=value lines (what the release workflow writes to $GITHUB_OUTPUT):
#
#   module_dir    the module's directory: ".", securefile, cryptoprovider/aesgcm256,
#                 keywrapping/nativev1, keywrapping/awskms, keywrapping/azurekeyvault,
#                 keywrapping/googlekms, keywrapping/hashicorpvault, cache/awssecretsmanager,
#                 cache/azurekeyvault, cache/googlesecretmanager, cache/hashicorpvault,
#                 cache/filepersecret or integration/configurationresolver
#   module_path   its module path
#   artifact      the name of its source archive: hkdfguard-go, hkdfguard-go-aesgcm256, ...; a
#                 cache module's carries "cache-" (hkdfguard-go-cache-azurekeyvault), so it never
#                 shares a name with the key wrapper for the same service, and
#                 integration/configurationresolver's is hkdfguard-go-integration-configurationresolver
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
#   keywrapping/hashicorpvault/vMAJOR.MINOR.PATCH[-suffix] that nested module
#   cache/<store>/vMAJOR.MINOR.PATCH[-suffix]            that nested module: awssecretsmanager,
#                                                        azurekeyvault, googlesecretmanager,
#                                                        hashicorpvault or filepersecret
#   integration/configurationresolver/vMAJOR.MINOR.PATCH[-suffix] that nested module
#   securefile/vMAJOR.MINOR.PATCH[-suffix]               that nested module
#
# A nested module is refused while its go.mod requires a placeholder version of the root module or
# securefile: a consumer would get a module that doesn't build. Require the version being released
# instead, and tag every module at the same commit, so what a consumer downloads is what was built
# here. The replace directives pointing each of this repository's modules at its own directory may
# stay - Go ignores them in a dependency - but any other replace is refused.
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
elif [[ ${tag} =~ ^(securefile|cryptoprovider/aesgcm256|keywrapping/nativev1|keywrapping/awskms|keywrapping/azurekeyvault|keywrapping/googlekms|keywrapping/hashicorpvault)/${SEMVER}$ ]]; then
    module_dir="${BASH_REMATCH[1]}"
    artifact="hkdfguard-go-$(basename "${module_dir}")"
elif [[ ${tag} =~ ^(cache/(awssecretsmanager|azurekeyvault|googlesecretmanager|hashicorpvault|filepersecret))/${SEMVER}$ ]]; then
    module_dir="${BASH_REMATCH[1]}"
    artifact="hkdfguard-go-cache-${BASH_REMATCH[2]}"
elif [[ ${tag} =~ ^(integration/configurationresolver)/${SEMVER}$ ]]; then
    module_dir="${BASH_REMATCH[1]}"
    artifact="hkdfguard-go-integration-configurationresolver"
else
    die "tag '${tag}' is not vMAJOR.MINOR.PATCH (optionally -suffix), on its own or under securefile/, cryptoprovider/aesgcm256/, keywrapping/nativev1/, keywrapping/awskms/, keywrapping/azurekeyvault/, keywrapping/googlekms/, keywrapping/hashicorpvault/, cache/{awssecretsmanager,azurekeyvault,googlesecretmanager,hashicorpvault,filepersecret}/ or integration/configurationresolver/"
fi
version="${tag##*/}"

gomod="${module_dir}/go.mod"
[[ -f ${gomod} ]] || die "${gomod} does not exist"
module_path="$(cd "${module_dir}" && go list -m)"

expected_path="github.com/runsecure/hkdfguard-go"
[[ ${module_dir} == "." ]] || expected_path="${expected_path}/${module_dir}"
[[ ${module_path} == "${expected_path}" ]] || die "${gomod} declares module '${module_path}', but tag '${tag}' releases '${expected_path}'"

# A replace directive applies only when its module is the one being built, so a consumer never sees
# one: the in-repo replaces that let a module build against this commit's sibling modules may stay.
# Anything else - another module, a remote target, a version on either side, or a path that isn't
# that sibling's own directory - would build here differently from how it builds for a consumer.
repo_root="$(pwd -P)"
while read -r old_path old_version new_path new_version; do
    [[ -n ${old_path} ]] || continue
    [[ ${old_path} == github.com/runsecure/hkdfguard-go || ${old_path} == github.com/runsecure/hkdfguard-go/* ]] ||
        die "${gomod} replaces '${old_path}'; only this repository's own modules may be replaced"
    [[ ${old_version} == - && ${new_version} == - && ${new_path} == .* ]] ||
        die "${gomod} replaces '${old_path}' with '${new_path}'; only a whole module, by its local directory, may be replaced"
    target="$(cd "${module_dir}/${new_path}" 2>/dev/null && pwd -P)" || die "${gomod} replaces '${old_path}' with '${new_path}', which does not exist"
    want="${repo_root}${old_path#github.com/runsecure/hkdfguard-go}"
    [[ ${target} == "${want}" ]] || die "${gomod} replaces '${old_path}' with '${new_path}', not that module's directory in this repository"
# Each replace as "old-path old-version new-path new-version", "-" for a version not given, from
# go mod edit -json's fixed layout: one tab-indented object per replace, Old then New.
done < <(go mod edit -json "${gomod}" | awk '
    /^\t"Replace": \[/ { inreplace = 1; next }
    !inreplace { next }
    /^\t\]/ { inreplace = 0; next }
    /^\t\t\{/ { oldpath = oldversion = newpath = newversion = "-" }
    /"Old": \{/ { side = "old" }
    /"New": \{/ { side = "new" }
    /"Path":/ { gsub(/[",]/, "", $2); if (side == "old") oldpath = $2; else newpath = $2 }
    /"Version":/ { gsub(/[",]/, "", $2); if (side == "old") oldversion = $2; else newversion = $2 }
    /^\t\t\}/ { print oldpath, oldversion, newpath, newversion }
')
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
