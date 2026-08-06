#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly suite="${script_dir}/../native_semantic_suite.py"
readonly mode="${1:-}"

if [[ -z "${mode}" ]]; then
  echo "usage: $0 sealed|cold-audit <native_semantic_suite.py arguments>" >&2
  exit 64
fi
shift

reject_fixed_options() {
  local argument
  for argument in "$@"; do
    case "${argument}" in
      --prefix-mode|--prefix-mode=*|--expected-uid|--expected-uid=*)
        echo "launcher-owned option must not be supplied: ${argument}" >&2
        exit 64
        ;;
    esac
  done
}

case "${mode}" in
  cold-audit)
    reject_fixed_options "$@"
    for argument in "$@"; do
      case "${argument}" in
        --expected-gid|--expected-gid=*|--backend-hodll-sha256|--backend-hodll-sha256=*|\
        --sealed-prefix-root|--sealed-prefix-root=*|--tmpfs-staging-root|\
        --tmpfs-staging-root=*|--tmpfs-bytes-per-job|--tmpfs-bytes-per-job=*|\
        --tmpfs-max-jobs|--tmpfs-max-jobs=*|--tmpfs-headroom-bytes|\
        --tmpfs-headroom-bytes=*)
          echo "cold-audit cannot accept sealed-lane option: ${argument}" >&2
          exit 64
          ;;
      esac
    done
    exec python3 "${suite}" \
      --prefix-mode cold-audit \
      --expected-uid "$(id -u)" \
      "$@"
    ;;
  sealed)
    reject_fixed_options "$@"
    for argument in "$@"; do
      case "${argument}" in
        --backend-id|--backend-id=*|--backend-hodll|--backend-hodll=*|\
        --backend-hodll-sha256|--backend-hodll-sha256=*|\
        --expected-gid|--expected-gid=*|--sealed-prefix-root|\
        --sealed-prefix-root=*|--tmpfs-staging-root|--tmpfs-staging-root=*|\
        --tmpfs-bytes-per-job|--tmpfs-bytes-per-job=*|--tmpfs-max-jobs|\
        --tmpfs-max-jobs=*|--tmpfs-headroom-bytes|--tmpfs-headroom-bytes=*|\
        --wine-prefix|--wine-prefix=*)
          echo "launcher-owned option must not be supplied: ${argument}" >&2
          exit 64
          ;;
      esac
    done
    : "${MIEL_FEX_HODLL_SHA256:?set the verified libwow64fex.dll SHA-256}"
    : "${MIEL_SEALED_PREFIX_ROOT:?set the persistent sealed-prefix store}"
    : "${MIEL_NATIVE_TMPFS_ROOT:?set the dedicated bounded tmpfs mount}"
    if [[ "$(findmnt -n -o FSTYPE --target "${MIEL_NATIVE_TMPFS_ROOT}")" != "tmpfs" ]]; then
      echo "MIEL_NATIVE_TMPFS_ROOT is not backed by tmpfs" >&2
      exit 65
    fi
    exec python3 "${suite}" \
      --prefix-mode sealed \
      --backend-id fex \
      --backend-hodll libwow64fex.dll \
      --backend-hodll-sha256 "${MIEL_FEX_HODLL_SHA256}" \
      --expected-uid "$(id -u)" \
      --expected-gid "$(id -g)" \
      --sealed-prefix-root "${MIEL_SEALED_PREFIX_ROOT}" \
      --tmpfs-staging-root "${MIEL_NATIVE_TMPFS_ROOT}" \
      --wine-prefix "${MIEL_NATIVE_TMPFS_ROOT}/wine-prefix-$$" \
      "$@"
    ;;
  *)
    echo "unknown native suite mode: ${mode}" >&2
    exit 64
    ;;
esac
