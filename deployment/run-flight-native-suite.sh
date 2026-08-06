#!/usr/bin/env bash
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly launcher="${repository_root}/tools/miel_vliegt/fex_wine/run_native_suite.sh"
readonly mode="${MIEL_NATIVE_PREFIX_MODE:-cold-audit}"

if [[ "${mode}" == "sealed" ]]; then
  : "${MIEL_NATIVE_TMPFS_ROOT:?sealed mode needs a tmpfs path inside the exact bind mount}"
  : "${MIEL_SEALED_PREFIX_ROOT:?sealed mode needs a persistent prefix store}"
  : "${MIEL_FEX_HODLL_SHA256:?sealed mode needs the verified HoDLL SHA-256}"

  if ! findmnt -n --target "${MIEL_NATIVE_TMPFS_ROOT}" >/dev/null 2>&1 \
      || [[ "$(findmnt -n -o FSTYPE --target "${MIEL_NATIVE_TMPFS_ROOT}")" != "tmpfs" ]]; then
    echo "sealed staging tmpfs must be mounted before the Docker container starts" >&2
    exit 65
  fi
  install -d -m 0700 "${MIEL_SEALED_PREFIX_ROOT}"
elif [[ "${mode}" != "cold-audit" ]]; then
  echo "MIEL_NATIVE_PREFIX_MODE must be cold-audit or sealed" >&2
  exit 64
fi

exec "${launcher}" "${mode}" "$@"
