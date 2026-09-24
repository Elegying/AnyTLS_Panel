#!/usr/bin/env bash
# Trusted bootstrap: authenticate a release before executing its deployment code.
set -Eeuo pipefail

ensure_cosign() {
    local architecture checksum download temporary
    case "$(uname -m)" in
        x86_64) architecture=amd64; checksum=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 ;;
        aarch64|arm64) architecture=arm64; checksum=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a ;;
        *) printf 'Unsupported signing-tool architecture\n' >&2; return 1 ;;
    esac
    COSIGN="/usr/local/lib/anytls-tools/cosign-v3.1.3"
    if [[ -f "$COSIGN" ]] && [[ "$(sha256sum "$COSIGN" | cut -d' ' -f1)" == "$checksum" ]]; then
        return 0
    fi
    temporary="$RELEASE_TEMP/cosign"
    download="https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$architecture"
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
        --max-filesize 150000000 "$download" -o "$temporary"
    [[ "$(sha256sum "$temporary" | cut -d' ' -f1)" == "$checksum" ]] || return 1
    install -d -o root -g root -m 755 /usr/local/lib/anytls-tools
    install -o root -g root -m 755 "$temporary" "$COSIGN"
}

verify_release() {
    local archive="$1" tag="$2" expected filename
    read -r expected filename < "${archive}.sha256"
    [[ "$expected" =~ ^[a-f0-9]{64}$ && "$filename" == "${archive##*/}" ]] || return 1
    [[ "$(sha256sum "$archive" | cut -d' ' -f1)" == "$expected" ]] || return 1
    timeout 120 "$COSIGN" verify-blob "$archive" \
        --bundle "${archive}.sigstore.json" \
        --certificate-identity "https://github.com/Elegying/AnyTLS_Panel/.github/workflows/release.yml@refs/tags/$tag" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com
}

extract_release() {
    python3 - "$1" "$2" "$3" <<'PY'
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive, output, tag = sys.argv[1:]
prefix = 'AnyTLS_Panel-' + tag.removeprefix('v')
with tarfile.open(archive, 'r:gz') as bundle:
    members = bundle.getmembers()
    if len(members) > 2000 or sum(m.size for m in members) > 32 * 1024 * 1024:
        raise SystemExit('release archive exceeds limits')
    for member in members:
        path = PurePosixPath(member.name)
        if (path.is_absolute() or '..' in path.parts or not path.parts
                or path.parts[0] != prefix or not (member.isfile() or member.isdir())):
            raise SystemExit('unsafe release archive member')
    bundle.extractall(output, members=members, filter='data')
source = Path(output) / prefix
if (source / 'VERSION').read_text().strip() != tag.removeprefix('v'):
    raise SystemExit('release version mismatch')
PY
}

main() (
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || { printf 'Run as root\n' >&2; exit 1; }
    local tag="${1:-}" artifact_dir="${2:-}" archive suffix
    [[ "$#" -ge 1 && "$#" -le 2 && "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
        printf 'Usage: install-release.sh vX.Y.Z [directory-containing-release-assets]\n' >&2
        exit 2
    }
    umask 077
    RELEASE_TEMP="$(mktemp -d /var/tmp/anytls-signed-release.XXXXXX)"
    trap 'rm -rf -- "$RELEASE_TEMP"' EXIT
    archive="$RELEASE_TEMP/AnyTLS_Panel-${tag}.tar.gz"
    for suffix in '' .sha256 .sigstore.json; do
        if [[ -n "$artifact_dir" ]]; then
            [[ -f "$artifact_dir/${archive##*/}$suffix" && ! -L "$artifact_dir/${archive##*/}$suffix" ]]
            # Verification always operates on our private snapshot, not uploader-writable files.
            cp -- "$artifact_dir/${archive##*/}$suffix" "$archive$suffix"
        else
            curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 120 \
                --max-filesize 16777216 \
                "https://github.com/Elegying/AnyTLS_Panel/releases/download/$tag/${archive##*/}$suffix" \
                -o "$archive$suffix"
        fi
    done
    ensure_cosign
    verify_release "$archive" "$tag"
    extract_release "$archive" "$RELEASE_TEMP" "$tag"
    unset ANYTLS_REPO_REF ANYTLS_REPO_URL ANYTLS_REPO_SUBDIR
    # The verified snapshot remains private (0700); do not leak its restrictive
    # creation mask into the runtime virtual environment built by the deployer.
    umask 022
    bash "$RELEASE_TEMP/AnyTLS_Panel-${tag#v}/deploy.sh"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
