#!/usr/bin/env bash
# Windows-native suite runner — no Wine, no Docker, no FEX
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_IDENTITY="${REPOSITORY_ROOT}/content/miel_vliegt/source_identity.json"
INITIAL_USER_FIXTURE="${REPOSITORY_ROOT}/tools/miel_vliegt/fixtures/native_dispatch_driver/initial-user0.dat.gz.b64"
OBSERVE_MS=3600000
MAX_RECORDS=1000000

RUN_ROOT=""
PRIVATE_ISO=""

while (($#)); do
  case "$1" in
    --run-root) RUN_ROOT="${2:?}"; shift 2 ;;
    --private-iso) PRIVATE_ISO="${2:?}"; shift 2 ;;
    --image-reference) shift 2 ;;
    *) shift ;;
  esac
done

[[ -n "${RUN_ROOT}" && -n "${PRIVATE_ISO}" ]] || { echo "usage: $0 --run-root <dir> --private-iso <iso>" >&2; exit 64; }

for cmd in 7z unshield python3 sha256sum git tee install; do
  command -v "${cmd}" >/dev/null || { echo "missing: ${cmd}" >&2; exit 69; }
done

mkdir -p "${RUN_ROOT}"

echo "=== Windows native suite starting ==="

# Verify ISO hash
expected_iso_sha="$(python3 -c "import json; print(json.load(open('${SOURCE_IDENTITY}'))['iso']['sha256'])")"
actual_iso_sha="$(sha256sum "${PRIVATE_ISO}" | cut -d' ' -f1)"
[[ "${actual_iso_sha}" == "${expected_iso_sha}" ]] || { echo "ISO hash mismatch" >&2; exit 65; }
echo "ISO hash verified"

# Extract game files
INSTALLER_ROOT="${RUN_ROOT}/private-installer"
EXTRACTED_SYSTEM_ROOT="${RUN_ROOT}/private-system"
mkdir -p "${INSTALLER_ROOT}" "${EXTRACTED_SYSTEM_ROOT}"
7z x -y "-o${INSTALLER_ROOT}" "${PRIVATE_ISO}" >/dev/null
(
  cd "${EXTRACTED_SYSTEM_ROOT}"
  unshield -g "System Files" x "${INSTALLER_ROOT}/data1.cab" || true
)
PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/System_Files"
[[ -d "${PRIVATE_GAME_ROOT}" ]] || { echo "game root not found" >&2; exit 66; }

# Setup directories
GAME_ROOT="${RUN_ROOT}/game"
PROXY_ROOT="${RUN_ROOT}/proxy"
FIXTURE_ROOT="${RUN_ROOT}/fixture"
SUITE_ROOT="${RUN_ROOT}/calibrated-suite"
OUTPUT_ROOT="${RUN_ROOT}/output"
CLEAN_STATE_ROOT="${RUN_ROOT}/game-clean"
mkdir -p "${GAME_ROOT}" "${PROXY_ROOT}" "${FIXTURE_ROOT}"

cp -a "${PRIVATE_GAME_ROOT}/." "${GAME_ROOT}/"
7z e -y "-o${GAME_ROOT}" "${PRIVATE_ISO}" data.up map.up sounds.up Miel.ini

# Resolve observer tools
if [[ -f /opt/miel/native-observer-hook.dll ]]; then
  TOOLS_SRC="/opt/miel"
else
  TOOLS_SRC="${REPOSITORY_ROOT}/tools/miel_vliegt/hangover"
fi

# Copy exe + proxy DLLs
install -m 0600 "${GAME_ROOT}/MulleMeck.exe" "${PROXY_ROOT}/MulleMeck.exe"
install -m 0600 "${TOOLS_SRC}/DINPUT.dll" "${PROXY_ROOT}/DINPUT.dll"
install -m 0600 "${TOOLS_SRC}/native-observer-hook.dll" "${PROXY_ROOT}/native-observer-hook.dll"

# Get real dinput.dll
if [[ -f "${TOOLS_SRC}/dinput-real.dll" ]]; then
  install -m 0600 "${TOOLS_SRC}/dinput-real.dll" "${PROXY_ROOT}/dinput-real.dll"
elif [[ -f "C:/windows/system32/dinput.dll" ]]; then
  install -m 0600 "C:/windows/system32/dinput.dll" "${PROXY_ROOT}/dinput-real.dll"
fi

# Restore user fixture
python3 - "${INITIAL_USER_FIXTURE}" "${FIXTURE_ROOT}/user0.dat" <<'PYFIX'
import base64, gzip, sys
from pathlib import Path
source, target = Path(sys.argv[1]), Path(sys.argv[2])
encoded = "".join(source.read_text(encoding="ascii").split())
target.write_bytes(gzip.decompress(base64.b64decode(encoded, validate=True)))
PYFIX
mkdir -p "${GAME_ROOT}/Data/User"
install -m 0600 "${FIXTURE_ROOT}/user0.dat" "${GAME_ROOT}/Data/User/user0.dat"

# Clean state snapshot
mkdir -p "${CLEAN_STATE_ROOT}"
cp -a "${GAME_ROOT}/." "${CLEAN_STATE_ROOT}/"

# Input paths
declare -A input_paths=(
  [source_executable]="${GAME_ROOT}/MulleMeck.exe"
  [disposable_target]="${PROXY_ROOT}/MulleMeck.exe"
  [user_profile]="${FIXTURE_ROOT}/user0.dat"
  [observer_dll]="${PROXY_ROOT}/native-observer-hook.dll"
  [observer_launcher]="${TOOLS_SRC}/native-observer-launcher.exe"
  [proxy_dinput]="${PROXY_ROOT}/DINPUT.dll"
  [real_dinput]="${PROXY_ROOT}/dinput-real.dll"
  [smoke_executable]="${TOOLS_SRC}/wine-readiness-canary.exe"
  [data_archive]="${GAME_ROOT}/data.up"
  [map_archive]="${GAME_ROOT}/map.up"
  [sounds_archive]="${GAME_ROOT}/sounds.up"
  [miel_ini]="${GAME_ROOT}/Miel.ini"
)

# Compute SHA256
declare -A input_sha256=()
sha256_args=()
identities_tsv="${RUN_ROOT}/input-identities.tsv"
: >"${identities_tsv}"
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  sha="$(sha256sum "${input_paths[${label}]}" | cut -d' ' -f1)"
  input_sha256["${label}"]="${sha}"
  printf '%s\t%s\t%s\n' "${label}" "${sha}" "${input_paths[${label}]}" >>"${identities_tsv}"
  sha256_args+=("--${label//_/-}-sha256" "${sha}")
done

echo "SHA256 args: ${#sha256_args[@]}"

# Run suite — native Windows, no Wine
echo "=== Running suite (native Windows) ==="
set +e
cd "${REPOSITORY_ROOT}"
python3 tools/miel_vliegt/native_semantic_suite.py \
  --prefix-mode cold-audit \
  --expected-uid "$(id -u)" \
  --backend-id native \
  --backend-hodll windows \
  --container-image native \
  --container-image-sha256 native \
  --container-id native \
  --container-mount-root "${RUN_ROOT}" \
  --source-executable "${input_paths[source_executable]}" \
  --disposable-target "${input_paths[disposable_target]}" \
  --game-root "${GAME_ROOT}" \
  --state-root "${GAME_ROOT}" \
  --clean-state-root "${CLEAN_STATE_ROOT}" \
  --user-profile "${input_paths[user_profile]}" \
  --observer-dll "${input_paths[observer_dll]}" \
  --observer-launcher "${input_paths[observer_launcher]}" \
  --proxy-dinput "${input_paths[proxy_dinput]}" \
  --real-dinput "${input_paths[real_dinput]}" \
  --smoke-executable "${input_paths[smoke_executable]}" \
  --suite-root "${SUITE_ROOT}" \
  --output-root "${OUTPUT_ROOT}" \
  --observe-ms "${OBSERVE_MS}" \
  --max-records "${MAX_RECORDS}" \
  "${sha256_args[@]}"
suite_status=$?
set -e

if [[ "${suite_status}" -eq 0 ]]; then
  echo "=== Suite PASSED ==="
else
  echo "=== Suite FAILED (exit ${suite_status}) ==="
fi
exit "${suite_status}"
