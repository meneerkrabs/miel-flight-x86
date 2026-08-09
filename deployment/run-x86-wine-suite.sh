#!/usr/bin/env bash
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
[[ "${RUN_ROOT}" == /* && "${PRIVATE_ISO}" == /* ]] || { echo "paths must be absolute" >&2; exit 64; }
[[ ! -e "${RUN_ROOT}" ]] || { echo "run root exists: ${RUN_ROOT}" >&2; exit 73; }

for cmd in 7z unshield python3 sha256sum git tee install Xvfb wine wineboot; do
  command -v "${cmd}" >/dev/null || { echo "missing: ${cmd}" >&2; exit 69; }
done

mkdir -m 0700 "${RUN_ROOT}"
exec > >(tee -a "${RUN_ROOT}/orchestration.log") 2>&1

echo "=== x86 Wine suite starting ==="

# Verify ISO hash
expected_iso_sha="$(python3 -c "import json; print(json.load(open('${SOURCE_IDENTITY}'))['iso']['sha256'])")"
actual_iso_sha="$(sha256sum "${PRIVATE_ISO}" | cut -d' ' -f1)"
[[ "${actual_iso_sha}" == "${expected_iso_sha}" ]] || { echo "ISO hash mismatch" >&2; exit 65; }
echo "ISO hash verified"

# Extract game files
INSTALLER_ROOT="${RUN_ROOT}/private-installer"
EXTRACTED_SYSTEM_ROOT="${RUN_ROOT}/private-system"
mkdir -m 0700 "${INSTALLER_ROOT}" "${EXTRACTED_SYSTEM_ROOT}"
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
WINE_PREFIX="${RUN_ROOT}/wine-prefix"
SUITE_ROOT="${RUN_ROOT}/calibrated-suite"
OUTPUT_ROOT="${RUN_ROOT}/output"
CLEAN_STATE_ROOT="${RUN_ROOT}/game-clean"
mkdir -m 0700 "${GAME_ROOT}" "${PROXY_ROOT}" "${FIXTURE_ROOT}"

cp -a "${PRIVATE_GAME_ROOT}/." "${GAME_ROOT}/"
7z e -y "-o${GAME_ROOT}" "${PRIVATE_ISO}" data.up map.up sounds.up Miel.ini

# Resolve observer tools
if [[ -f /opt/miel/native-observer-hook.dll ]]; then
  TOOLS_SRC="/opt/miel"
else
  TOOLS_SRC="${REPOSITORY_ROOT}/tools/miel_vliegt/hangover"
fi
echo "Observer tools from: ${TOOLS_SRC}"

# Copy exe + proxy DLLs to proxy directory
install -m 0600 "${GAME_ROOT}/MulleMeck.exe" "${PROXY_ROOT}/MulleMeck.exe"
install -m 0600 "${TOOLS_SRC}/DINPUT.dll" "${PROXY_ROOT}/DINPUT.dll"
install -m 0600 "${TOOLS_SRC}/native-observer-hook.dll" "${PROXY_ROOT}/native-observer-hook.dll"
install -m 0600 "${TOOLS_SRC}/dinput-real.dll" "${PROXY_ROOT}/dinput-real.dll"

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
mkdir -m 0700 "${CLEAN_STATE_ROOT}"
cp -a "${GAME_ROOT}/." "${CLEAN_STATE_ROOT}/"

# Input identities
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
for label in "${!input_paths[@]}"; do
  input_sha256["${label}"]="$(sha256sum "${input_paths[${label}]}" | cut -d' ' -f1)"
done

identities_tsv="${RUN_ROOT}/input-identities.tsv"
: >"${identities_tsv}"
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  printf '%s\t%s\t%s\n' "${label}" "${input_sha256[${label}]}" "${input_paths[${label}]}" >>"${identities_tsv}"
done

sha256_args=()
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  sha256_args+=("--${label//_/-}-sha256" "${input_sha256[${label}]}")
done

# Start Xvfb
echo "=== Starting Xvfb ==="
Xvfb :99 -screen 0 646x512x16 -nolisten tcp &
sleep 2
export DISPLAY=:99
# NB: do NOT run wine here (e.g. `wine reg add` for a virtual desktop) — it
# implicitly boots and CREATES ${WINE_PREFIX}, which makes the suite abort on
# its `wine_prefix must not already exist` guard. The virtual-desktop
# experiment was reverted (refuted anyway: manager stayed NULL).

# Receipt function
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

# Run suite
echo "=== Running suite ==="
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

# Preserve proxy/observer/orchestration stderr breadcrumbs into the uploaded
# artifact. The proxy DLL (MVP_* lines) and game logs land in game/ proxy/ and
# RUN_ROOT itself, never in output/. Scope the search to those subtrees and
# wine-prefix/drive_c only — NOT the whole prefix, whose dosdevices symlinks
# (z:/boot/efi) make find/upload fail EACCES.
COLLECTED_LOGS="${OUTPUT_ROOT}/collected-logs"
mkdir -p "${COLLECTED_LOGS}"
# OUTPUT_ROOT is included so the observer's own init log survives — it lands
# at output.parent as native-observer-wine.log / observer-*-permanent.log
# under output/.cold-capture-staging and output/failed-attempts, which the
# game/proxy/drive_c subtrees do not cover. Prune collected-logs to avoid
# re-copying our own output recursively.
for _src in "${RUN_ROOT}/orchestration.log" "${GAME_ROOT}" "${PROXY_ROOT}" \
            "${WINE_PREFIX}/drive_c" "${OUTPUT_ROOT}"; do
  [[ -e "${_src}" ]] || continue
  find "${_src}" -xdev -path "${COLLECTED_LOGS}" -prune -o \
       -type f -name '*.log' -print 2>/dev/null | while read -r _log; do
    _safe="$(printf '%s' "${_log#${RUN_ROOT}/}" | tr '/' '_')"
    cp -f "${_log}" "${COLLECTED_LOGS}/${_safe}" 2>/dev/null || true
  done
done
echo "=== Collected $(ls -1 "${COLLECTED_LOGS}" 2>/dev/null | wc -l) log(s) into output/collected-logs ==="

exit "${suite_status}"
