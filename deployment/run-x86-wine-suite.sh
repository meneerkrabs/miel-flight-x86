#!/usr/bin/env bash
# Dedicated x86 Wine suite runner — no Docker, no FEX, no complex paths.
# This script handles ONLY the wine backend on ubuntu-latest.
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_IDENTITY="${REPOSITORY_ROOT}/content/miel_vliegt/source_identity.json"
INITIAL_USER_FIXTURE="${REPOSITORY_ROOT}/tools/miel_vliegt/fixtures/native_dispatch_driver/initial-user0.dat.gz.b64"
SUITE_LAUNCHER="${REPOSITORY_ROOT}/deployment/run-flight-native-suite.sh"
OBSERVE_MS=3600000
MAX_RECORDS=1000000

RUN_ROOT=""
PRIVATE_ISO=""

usage() {
  cat <<EOF
usage: $0 --run-root <dir> --private-iso <iso>
EOF
}

while (($#)); do
  case "$1" in
    --run-root) RUN_ROOT="${2:?}"; shift 2 ;;
    --private-iso) PRIVATE_ISO="${2:?}"; shift 2 ;;
    --image-reference) shift 2 ;; # ignored
    *) shift ;;
  esac
done

[[ -n "${RUN_ROOT}" && -n "${PRIVATE_ISO}" ]] || { usage >&2; exit 64; }
[[ "${RUN_ROOT}" == /* && "${PRIVATE_ISO}" == /* ]] || { echo "paths must be absolute" >&2; exit 64; }
[[ ! -e "${RUN_ROOT}" ]] || { echo "run root exists: ${RUN_ROOT}" >&2; exit 73; }

for cmd in 7z unshield python3 sha256sum git tee install Xvfb wine wineboot; do
  command -v "${cmd}" >/dev/null || { echo "missing: ${cmd}" >&2; exit 69; }
done

mkdir -m 0700 "${RUN_ROOT}"
exec > >(tee -a "${RUN_ROOT}/orchestration.log") 2>&1

echo "=== x86 Wine suite starting ==="
echo "REPOSITORY_ROOT=${REPOSITORY_ROOT}"
echo "RUN_ROOT=${RUN_ROOT}"

# Verify ISO hash
expected_iso_sha="$(python3 -c "import json; print(json.load(open('${SOURCE_IDENTITY}'))['iso']['sha256'])")"
actual_iso_sha="$(sha256sum "${PRIVATE_ISO}" | cut -d' ' -f1)"
[[ "${actual_iso_sha}" == "${expected_iso_sha}" ]] || {
  echo "ISO hash mismatch: expected ${expected_iso_sha}, got ${actual_iso_sha}" >&2
  exit 65
}
echo "ISO hash verified: ${actual_iso_sha}"

# Extract game files
INSTALLER_ROOT="${RUN_ROOT}/private-installer"
EXTRACTED_SYSTEM_ROOT="${RUN_ROOT}/private-system"
mkdir -m 0700 "${INSTALLER_ROOT}" "${EXTRACTED_SYSTEM_ROOT}"
7z x -y "-o${INSTALLER_ROOT}" "${PRIVATE_ISO}" >/dev/null
echo "ISO extracted to ${INSTALLER_ROOT}"
echo "Contents:" && ls "${INSTALLER_ROOT}" | head -20

# unshield must run from the output directory
(
  cd "${EXTRACTED_SYSTEM_ROOT}"
  unshield -g "System Files" x "${INSTALLER_ROOT}/data1.cab" || true
)
echo "System files extracted:" && ls "${EXTRACTED_SYSTEM_ROOT}" | head -20

PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/System_Files"
# Try alternate capitalization
if [[ ! -d "${PRIVATE_GAME_ROOT}" ]]; then
  PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/System_files"
fi
if [[ ! -d "${PRIVATE_GAME_ROOT}" ]]; then
  PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/system_files"
fi
[[ -d "${PRIVATE_GAME_ROOT}" ]] || {
  echo "game root not found in ${EXTRACTED_SYSTEM_ROOT}" >&2
  echo "Directory listing:" >&2
  find "${EXTRACTED_SYSTEM_ROOT}" -maxdepth 2 -type d >&2 || true
  exit 66
}
echo "Game root: ${PRIVATE_GAME_ROOT}"

GAME_ROOT="${RUN_ROOT}/game"
PROXY_ROOT="${RUN_ROOT}/proxy"
TOOLS_ROOT="${RUN_ROOT}/tools"
FIXTURE_ROOT="${RUN_ROOT}/fixture"
WINE_PREFIX="${RUN_ROOT}/wine-prefix"
SUITE_ROOT="${RUN_ROOT}/calibrated-suite"
OUTPUT_ROOT="${RUN_ROOT}/output"
CLEAN_STATE_ROOT="${RUN_ROOT}/game-clean"
mkdir -m 0700 "${GAME_ROOT}" "${PROXY_ROOT}" "${TOOLS_ROOT}" "${FIXTURE_ROOT}"

cp -a "${PRIVATE_GAME_ROOT}/." "${GAME_ROOT}/"
7z e -y "-o${GAME_ROOT}" "${PRIVATE_ISO}" data.up map.up sounds.up Miel.ini

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

# Resolve observer tools (prefer /opt/miel from workflow build)
if [[ -f /opt/miel/native-observer-hook.dll ]]; then
  TOOLS_SRC="/opt/miel"
else
  TOOLS_SRC="${REPOSITORY_ROOT}/tools/miel_vliegt/hangover"
fi
echo "Observer tools from: ${TOOLS_SRC}"

# Copy exe and proxy DINPUT.dll to proxy directory
install -m 0600 "${GAME_ROOT}/MulleMeck.exe" "${PROXY_ROOT}/MulleMeck.exe"
install -m 0600 "${TOOLS_SRC}/DINPUT.dll" "${PROXY_ROOT}/DINPUT.dll"

# Clean state snapshot
mkdir -m 0700 "${CLEAN_STATE_ROOT}"
cp -a "${GAME_ROOT}/." "${CLEAN_STATE_ROOT}/"

# Input identities
declare -A input_paths=(
  [source_executable]="${GAME_ROOT}/MulleMeck.exe"
  [disposable_target]="${PROXY_ROOT}/MulleMeck.exe"
  [user_profile]="${FIXTURE_ROOT}/user0.dat"
  [observer_dll]="${TOOLS_SRC}/native-observer-hook.dll"
  [observer_launcher]="${TOOLS_SRC}/native-observer-launcher.exe"
  [proxy_dinput]="${PROXY_ROOT}/DINPUT.dll"
  [real_dinput]="${TOOLS_SRC}/dinput-real.dll"
  [smoke_executable]="${TOOLS_SRC}/wine-readiness-canary.exe"
  [data_archive]="${GAME_ROOT}/data.up"
  [map_archive]="${GAME_ROOT}/map.up"
  [sounds_archive]="${GAME_ROOT}/sounds.up"
  [miel_ini]="${GAME_ROOT}/Miel.ini"
)

# Compute SHA256 for all inputs
declare -A input_sha256=()
for label in "${!input_paths[@]}"; do
  input_sha256["${label}"]="$(sha256sum "${input_paths[${label}]}" | cut -d' ' -f1)"
done

identities_tsv="${RUN_ROOT}/input-identities.tsv"
: >"${identities_tsv}"
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  printf '%s\t%s\t%s\n' "${label}" "${input_sha256[${label}]}" "${input_paths[${label}]}" >>"${identities_tsv}"
done

# Build SHA256 arguments for the suite
sha256_args=()
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  sha256_args+=("--${label//_/-}-sha256" "${input_sha256[${label}]}")
done

# Start Xvfb
echo "=== Starting Xvfb ==="
Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp &
sleep 2
export DISPLAY=:99


# Write runner receipt
write_receipt() {
  local status="$1" suite_exit="$2"
  python3 - "${RUN_ROOT}/runner-receipt.json" "${status}" "${suite_exit}" \
    "${identities_tsv}" "${OUTPUT_ROOT}" "${OBSERVE_MS}" "${MAX_RECORDS}" \
    "$(git -C "${REPOSITORY_ROOT}" rev-parse HEAD)" <<'PY'
import json, sys
from pathlib import Path
(output_path, status, suite_exit, identities_path, suite_output,
 observe_ms, max_records, commit) = sys.argv[1:]
inputs = {}
for line in Path(identities_path).read_text(encoding="utf-8").splitlines():
    label, sha256, path = line.split("\t")
    inputs[label] = {"path": path, "sha256": sha256}
receipt = {
    "schema": 1, "protocol": "miel-vliegt-x86-wine-suite-runner",
    "status": status, "suite_exit_code": int(suite_exit),
    "repository_commit": commit, "observe_ms": int(observe_ms),
    "max_records": int(max_records), "backend": "wine",
    "inputs": inputs, "suite_output_root": suite_output,
}
Path(output_path + ".tmp").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
Path(output_path + ".tmp").replace(output_path)
PY
}

write_receipt RUNNING 0

# Diagnostic: test observer launcher directly
echo "=== DIAGNOSTIC: Observer launcher test ==="
cp -a "${GAME_ROOT}/." "${PROXY_ROOT}/"
cp "${TOOLS_SRC}/DINPUT.dll" "${PROXY_ROOT}/DINPUT.dll"
cp "${TOOLS_SRC}/dinput-real.dll" "${PROXY_ROOT}/dinput-real.dll"
cp "${TOOLS_SRC}/native-observer-hook.dll" "${PROXY_ROOT}/native-observer-hook.dll"
LAUNCHER="${TOOLS_SRC}/native-observer-launcher.exe"
echo "Launcher: ${LAUNCHER}"
ls -la "${LAUNCHER}" || echo "LAUNCHER MISSING"
export WINEPREFIX="${RUN_ROOT}/diag-wine"
export WINEARCH=win32
export WINEDEBUG=warn+all
export WINEDLLOVERRIDES="dinput=n,b"
export MIEL_REAL_DINPUT="${PROXY_ROOT}/dinput-real.dll"
export MIEL_OBSERVER_DLL="${PROXY_ROOT}/native-observer-hook.dll"
cd "${PROXY_ROOT}"
timeout 30 wine "${LAUNCHER}" \
  --target "${PROXY_ROOT}/MulleMeck.exe" \
  --cwd "${GAME_ROOT}" \
  --observer "${PROXY_ROOT}/native-observer-hook.dll" \
  --real-dinput "${PROXY_ROOT}/dinput-real.dll" \
  --observe-ms 10000 \
  2>&1 | tail -50 || true
echo "=== Launcher exit: $? ==="
# Check for receipt
cat "${PROXY_ROOT}/launch-receipt.json" 2>/dev/null || cat "${GAME_ROOT}/launch-receipt.json" 2>/dev/null || echo "No receipt found"
unset WINEDLLOVERRIDES MIEL_REAL_DINPUT MIEL_OBSERVER_DLL

# Debug: show SHA256 args
echo "=== SHA256 args count: ${#sha256_args[@]} ==="
for arg in "${sha256_args[@]}"; do
  echo "  arg: ${arg}"
done

# Run the suite — call Python directly
echo "=== Running suite (direct Python) ==="
set +e
cd "${REPOSITORY_ROOT}"
python3 tools/miel_vliegt/native_semantic_suite.py \
  --prefix-mode cold-audit \
  --expected-uid "$(id -u)" \
  --backend-id wine \
  --backend-hodll i386 \
  --container-image wine \
  --container-image-sha256 wine \
  --container-id wine \
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
  --wine-prefix "${WINE_PREFIX}" \
  --suite-root "${SUITE_ROOT}" \
  --output-root "${OUTPUT_ROOT}" \
  --observe-ms "${OBSERVE_MS}" \
  --max-records "${MAX_RECORDS}" \
  "${sha256_args[@]}"
suite_status=$?
set -e

if [[ "${suite_status}" -eq 0 ]]; then
  write_receipt PASSED 0
  echo "=== Suite PASSED ==="
else
  write_receipt FAILED "${suite_status}"
  echo "=== Suite FAILED (exit ${suite_status}) ==="
fi
exit "${suite_status}"
