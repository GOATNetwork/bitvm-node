#!/usr/bin/env bash
set -euo pipefail

REPO="GOATNetwork/bitvm-node"
API_URL="https://api.github.com/repos/${REPO}/releases"
INSTALL_DIR="./bin"
VERSION_FILE=".bitvm-version"

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  install [VERSION]   Install binaries (default: latest release)
  upgrade [VERSION]   Upgrade binaries if a newer version is available
  version             Show currently installed version

Options:
  --dir DIR           Install directory (default: ./bin)

Examples:
  $(basename "$0") install                # Install latest release
  $(basename "$0") install v0.3.2         # Install specific version
  $(basename "$0") upgrade                # Upgrade to latest release
  $(basename "$0") upgrade v0.3.2         # Upgrade to specific version
  $(basename "$0") version                # Show installed version
EOF
    exit 1
}

# ── Helpers ──────────────────────────────────────────────────────────

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "${os}-${arch}" in
        Linux-x86_64)   echo "x86_64-linux"   ;;
        Darwin-arm64)   echo "aarch64-macos"   ;;
        Darwin-aarch64) echo "aarch64-macos"   ;;
        *) echo "Unsupported platform: ${os}-${arch}" >&2; exit 1 ;;
    esac
}

get_latest_version() {
    local tag
    tag="$(curl -fsSL "${API_URL}/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name".*"\(v[^"]*\)".*/\1/')"
    if [ -z "${tag}" ]; then
        echo "Failed to fetch latest version" >&2
        exit 1
    fi
    echo "${tag}"
}

get_installed_version() {
    if [ -f "${INSTALL_DIR}/${VERSION_FILE}" ]; then
        cat "${INSTALL_DIR}/${VERSION_FILE}"
    else
        echo ""
    fi
}

# Strip leading 'v' and compare semver: returns 0 if $1 > $2
version_gt() {
    local v1="${1#v}" v2="${2#v}"
    [ "$(printf '%s\n%s' "${v1}" "${v2}" | sort -V | tail -1)" != "${v2}" ]
}

do_install() {
    local version="$1"
    local platform
    platform="$(detect_platform)"

    local base_url="https://github.com/${REPO}/releases/download/${version}"

    echo "Platform : $(uname -s) $(uname -m) -> ${platform}"
    echo "Version  : ${version}"
    echo "Install  : ${INSTALL_DIR}"
    echo ""

    local tmpdir
    tmpdir="$(mktemp -d)"
    # Expanded now: the local is gone when the EXIT trap runs.
    trap "rm -rf -- '${tmpdir}'" EXIT

    # Releases up to v0.3.3 still carry the repository's former name.
    local tarball="" candidate
    for candidate in "bitvm-node-${version}-${platform}.tar.gz" \
        "bitvm2-node-${version}-${platform}.tar.gz"; do
        echo "Downloading ${candidate} ..."
        if curl -fsSL -o "${tmpdir}/${candidate}" "${base_url}/${candidate}"; then
            tarball="${candidate}"
            break
        fi
    done
    if [[ -z "${tarball}" ]]; then
        echo "Error: no ${platform} archive in release ${version}" >&2
        exit 1
    fi
    curl -fSL -o "${tmpdir}/${tarball}.sha256" "${base_url}/${tarball}.sha256"

    echo "Verifying checksum ..."
    cd "${tmpdir}"
    # Compare the hash only: older releases list the archive under
    # release-artifacts/, which `-c` cannot find here.
    local expected actual
    expected="$(awk '{print $1}' "${tarball}.sha256")"
    if command -v sha256sum &>/dev/null; then
        actual="$(sha256sum "${tarball}" | awk '{print $1}')"
    elif command -v shasum &>/dev/null; then
        actual="$(shasum -a 256 "${tarball}" | awk '{print $1}')"
    else
        echo "Warning: no sha256sum or shasum found, skipping checksum verification" >&2
        actual="${expected}"
    fi
    if [[ -z "${expected}" || "${actual}" != "${expected}" ]]; then
        echo "Error: checksum mismatch for ${tarball}" >&2
        exit 1
    fi

    mkdir -p "${INSTALL_DIR}"
    echo "Installing to ${INSTALL_DIR} ..."
    tar xzf "${tarball}" -C "${INSTALL_DIR}"
    chmod +x "${INSTALL_DIR}"/*

    # Record installed version
    echo "${version}" > "${INSTALL_DIR}/${VERSION_FILE}"

    echo ""
    echo "Done. Installed ${version}:"
    ls -1 "${INSTALL_DIR}" | grep -v '\.sh$' | grep -v "${VERSION_FILE}"
}

# ── Commands ─────────────────────────────────────────────────────────

cmd_install() {
    local version="${1:-}"
    if [ -z "${version}" ]; then
        echo "Fetching latest version ..."
        version="$(get_latest_version)"
    fi
    do_install "${version}"
}

cmd_upgrade() {
    local target="${1:-}"
    if [ -z "${target}" ]; then
        echo "Fetching latest version ..."
        target="$(get_latest_version)"
    fi

    local current
    current="$(get_installed_version)"

    if [ -z "${current}" ]; then
        echo "No installed version found. Installing ${target} ..."
        do_install "${target}"
        return
    fi

    echo "Installed : ${current}"
    echo "Target    : ${target}"

    if [ "${current}" = "${target}" ]; then
        echo "Already up to date."
        return
    fi

    if version_gt "${target}" "${current}"; then
        echo "Upgrading ${current} -> ${target} ..."
        do_install "${target}"
    else
        echo "Installed version ${current} is newer than or equal to ${target}. Nothing to do."
    fi
}

cmd_version() {
    local current
    current="$(get_installed_version)"
    if [ -z "${current}" ]; then
        echo "Not installed. Run '$(basename "$0") install' first."
    else
        echo "${current}"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────

# Parse --dir option
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) INSTALL_DIR="$2"; shift 2 ;;
        *)     break ;;
    esac
done

# Absolute, since the install runs from a temporary directory.
case "${INSTALL_DIR}" in
    /*) ;;
    *)  INSTALL_DIR="${PWD}/${INSTALL_DIR#./}" ;;
esac

COMMAND="${1:-}"
shift || true

case "${COMMAND}" in
    install) cmd_install "$@" ;;
    upgrade) cmd_upgrade "$@" ;;
    version) cmd_version ;;
    *)       usage ;;
esac
