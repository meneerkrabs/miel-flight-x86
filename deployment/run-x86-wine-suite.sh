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

# Check if the game imports dinput.dll
echo "=== Game DLL imports ==="
GAME_EXE="${PRIVATE_GAME_ROOT}/MulleMeck.exe"
if command -v i686-w64-mingw32-objdump >/dev/null 2>&1; then
  i686-w64-mingw32-objdump -p "${GAME_EXE}" 2>/dev/null | grep "DLL Name:" || echo "objdump failed"
elif command -v objdump >/dev/null 2>&1; then
  objdump -p "${GAME_EXE}" 2>/dev/null | grep "DLL Name:" || echo "objdump failed"
else
  # Use Python to parse PE imports
  python3 - <<'PEEOF'
import struct
with open("${GAME_EXE}", "rb") as f:
    data = f.read()
# Find PE header
pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
# Check PE signature
if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
    print("Not a valid PE file")
else:
    # COFF header
    num_sections = struct.unpack_from("<H", data, pe_offset+6)[0]
    opt_header_size = struct.unpack_from("<H", data, pe_offset+20)[0]
    opt_start = pe_offset + 24
    # Data directories start at offset 96 (PE32) or 112 (PE32+)
    magic = struct.unpack_from("<H", data, opt_start)[0]
    if magic == 0x10b:  # PE32
        dd_offset = opt_start + 96
    else:
        dd_offset = opt_start + 112
    # Import table is data directory index 1
    import_rva = struct.unpack_from("<I", data, dd_offset + 8)[0]
    import_size = struct.unpack_from("<I", data, dd_offset + 12)[0]
    # Section table
    section_offset = opt_start + opt_header_size
    sections = []
    for i in range(num_sections):
        s_off = section_offset + i * 40
        name = data[s_off:s_off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        v_addr = struct.unpack_from("<I", data, s_off+12)[0]
        v_size = struct.unpack_from("<I", data, s_off+8)[0]
        raw_offset = struct.unpack_from("<I", data, s_off+20)[0]
        sections.append((name, v_addr, v_size, raw_offset))
    def rva_to_offset(rva):
        for name, va, vs, ro in sections:
            if va <= rva < va + vs:
                return ro + (rva - va)
        return None
    if import_rva:
        offset = rva_to_offset(import_rva)
        if offset:
            print("Imported DLLs:")
            while True:
                ilt_rva = struct.unpack_from("<I", data, offset+12)[0]
                name_rva = struct.unpack_from("<I", data, offset+12)[0]
                name_off = rva_to_offset(name_rva)
                if name_off:
                    end = data.index(b"\x00", name_off)
                    dll_name = data[name_off:end].decode("ascii", errors="replace")
                    print(f"  {dll_name}")
                if data[offset:offset+20] == b"\x00" * 20:
                    break
                offset += 20
    else:
        print("No import table found")
PEEOF
fi
echo "=== End imports ==="

# Check DINPUT proxy DLL format
echo "=== DINPUT proxy check ==="
file /opt/miel/DINPUT.dll 2>/dev/null || echo "file cmd not available"
python3 - <<'DLCHECK'
import struct, sys
dll_path = /opt/miel/DINPUT.dll
try:
    with open(dll_path, "rb") as f:
        data = f.read(1024)
    if data[:2] != b"MZ":
        print("ERROR: Not a valid PE/DOS file")
        sys.exit(1)
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 4 > len(data):
        print("ERROR: PE offset beyond header")
        sys.exit(1)
    if data[pe_off:pe_off+4] != b"PE\x00\x00":
        print("ERROR: Invalid PE signature")
        sys.exit(1)
    magic = struct.unpack_from("<H", data, pe_off+24)[0]
    print(f"PE format: {'PE32 (32-bit)' if magic == 0x10b else 'PE32+ (64-bit)' if magic == 0x20b else f'Unknown (0x{magic:04x})'}")
    machine = struct.unpack_from("<H", data, pe_off+4)[0]
    print(f"Machine: 0x{machine:04x} ({'i386' if machine == 0x14c else 'unknown'})")
    print(f"File size: {len(open(dll_path, 'rb').read())} bytes")
    print("OK: Valid 32-bit PE DLL")
except Exception as e:
    print(f"ERROR: {e}")
DLCHECK
echo "=== End DINPUT check ==="

# Try loading DINPUT.dll via rundll32 to see if Wine can load it
echo "=== Wine DINPUT load test ==="
WINEPREFIX="${RUN_ROOT}/test-prefix" WINEARCH=win32 WINEDEBUG=-all wineboot --init 2>/dev/null || true
WINEPREFIX="${RUN_ROOT}/test-prefix" WINEARCH=win32 WINEDEBUG=+loaddll wine /opt/miel/wine-readiness-canary.exe --rpcss-timeout-ms 5000 2>&1 | grep -i "dinput\|DINPUT\|proxy\|MVP" | head -10 || echo "No dinput in output"
echo "=== End load test ==="

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

# Copy exe, proxy DINPUT, observer hook, and real dinput to proxy directory
install -m 0600 "${GAME_ROOT}/MulleMeck.exe" "${PROXY_ROOT}/MulleMeck.exe"
install -m 0600 /opt/miel/DINPUT.dll "${PROXY_ROOT}/DINPUT.dll"
install -m 0600 "${TOOLS_SRC}/native-observer-hook.dll" "${PROXY_ROOT}/native-observer-hook.dll"
install -m 0600 "${TOOLS_SRC}/dinput-real.dll" "${PROXY_ROOT}/dinput-real.dll"

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
  [smoke_executable]=/opt/miel/wine-readiness-canary.exe
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
