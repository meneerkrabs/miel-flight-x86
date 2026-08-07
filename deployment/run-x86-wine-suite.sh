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

# Critical test: does Wine load DINPUT proxy from C:\game\?
echo "=== CRITICAL: DINPUT proxy load test from C: drive ==="
TESTPREFIX="${RUN_ROOT}/test-prefix"
rm -rf "${TESTPREFIX}" 2>/dev/null || true
mkdir -p "${TESTPREFIX}/drive_c/game"
# Copy game files
cp -a "${PRIVATE_GAME_ROOT}/." "${TESTPREFIX}/drive_c/game/" 2>/dev/null || true
cp "${RUN_ROOT}/private-installer/data.up" "${TESTPREFIX}/drive_c/game/" 2>/dev/null || true
cp "${RUN_ROOT}/private-installer/map.up" "${TESTPREFIX}/drive_c/game/" 2>/dev/null || true
cp "${RUN_ROOT}/private-installer/sounds.up" "${TESTPREFIX}/drive_c/game/" 2>/dev/null || true
cp "${RUN_ROOT}/private-installer/Miel.ini" "${TESTPREFIX}/drive_c/game/" 2>/dev/null || true
# Copy proxy
cp /opt/miel/DINPUT.dll "${TESTPREFIX}/drive_c/game/"
cp /opt/miel/dinput-real.dll "${TESTPREFIX}/drive_c/game/"
cp /opt/miel/native-observer-hook.dll "${TESTPREFIX}/drive_c/game/"
echo "Files in C:\game\:" && ls "${TESTPREFIX}/drive_c/game/" | head -10
# Init prefix
WINEPREFIX="${TESTPREFIX}" WINEARCH=win32 WINEDEBUG=-all wineboot --init 2>/dev/null || true
sleep 2
# Run game with DLL loading trace
echo "=== Running game with +loaddll ==="
cd "${TESTPREFIX}/drive_c/game"
WINEPREFIX="${TESTPREFIX}" WINEARCH=win32 WINEDLLOVERRIDES=dinput=n,b WINEDEBUG=+loaddll,+module timeout 10 wine C:\game\MulleMeck.exe 2>&1 | grep -i "dinput\|DirectInput\|proxy\|MVP\|build_module.*DINPUT" | head -20 || true
echo "=== DLL load test done ==="

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
