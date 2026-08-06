#!/usr/bin/env bash
set -euo pipefail

readonly FEX_ROOTFS_PATH="${FEX_ROOTFS:-/opt/fex/rootfs}"
readonly CANARY_TIMEOUT_SECONDS="${MIEL_FEX_CANARY_TIMEOUT_SECONDS:-120}"
readonly RPCSS_TIMEOUT_MS="${MIEL_FEX_RPCSS_TIMEOUT_MS:-30000}"
readonly CANARY_DISPLAY="${DISPLAY:-:99}"

case "$(uname -m)" in
  aarch64|arm64) ;;
  *)
    echo "FEX runner requires a native ARM64 host" >&2
    exit 64
    ;;
esac

test -x /usr/bin/FEXBash
test -x /opt/miel/fex-wine
test -s /opt/miel/wine-readiness-canary.exe
test -x "${FEX_ROOTFS_PATH}/usr/lib/wine/wine"
test -x "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64"

canary_root="$(mktemp -d /tmp/miel-fex-wine-canary.XXXXXX)"
xvfb_pid=""
wineserver_pid=""

cleanup() {
  if [[ -n "${wineserver_pid}" ]]; then
    timeout --signal=TERM --kill-after=2s 10s \
      FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -k \
      >/dev/null 2>&1 || true
    timeout --signal=TERM --kill-after=2s 10s \
      FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -w \
      >/dev/null 2>&1 || kill "${wineserver_pid}" 2>/dev/null || true
    wait "${wineserver_pid}" 2>/dev/null || true
  fi
  if [[ -n "${xvfb_pid}" ]]; then
    kill "${xvfb_pid}" 2>/dev/null || true
    wait "${xvfb_pid}" 2>/dev/null || true
  fi
  rm -rf "${canary_root}"
}
trap cleanup EXIT INT TERM

export DISPLAY="${CANARY_DISPLAY}"
export FEX_ROOTFS="${FEX_ROOTFS_PATH}"
export WINEARCH=win32
export WINEDEBUG=-all
export WINEDLLOVERRIDES='mscoree,mshtml='
export WINEPREFIX="${canary_root}/prefix"
export XDG_RUNTIME_DIR="${canary_root}/runtime"
mkdir -m 0700 "${WINEPREFIX}" "${XDG_RUNTIME_DIR}"

# Prove the case-sensitive FEX environment contract by observing the IR guard,
# not merely by grepping this wrapper. A miss silently falls back to mtrack and
# lets the 2001 gtSoftware self-modifying rasterizer execute stale code.
smc_output="${canary_root}/fex-smc.log"
FEX_SILENTLOG=0 FEX_OUTPUTLOG=stderr FEX_DUMPIR=stderr FEX_MAXINST=1 \
  FEX_SMCCHECKS=full \
  timeout --signal=TERM --kill-after=5s "${CANARY_TIMEOUT_SECONDS}s" \
  FEX "${FEX_ROOTFS_PATH}/usr/bin/true" >"${smc_output}" 2>&1
if ! grep -Fq 'ValidateCode' "${smc_output}"; then
  cat "${smc_output}" >&2
  echo 'FEX full-SMC validation is not active' >&2
  exit 78
fi

Xvfb "${DISPLAY}" -screen 0 646x512x16 -nolisten tcp >"${canary_root}/xvfb.log" 2>&1 &
xvfb_pid=$!

for _ in $(seq 1 50); do
  if xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${xvfb_pid}" 2>/dev/null; then
    echo "Xvfb terminated before becoming ready" >&2
    exit 70
  fi
  sleep 0.1
done
xdpyinfo -display "${DISPLAY}" >/dev/null

guest_output="${canary_root}/wine.log"

set +e
timeout --signal=TERM --kill-after=5s "${CANARY_TIMEOUT_SECONDS}s" \
  /opt/miel/fex-wine wineboot --init \
  >"${guest_output}" 2>&1
guest_status=$?
set -e
if [[ "${guest_status}" -ne 0 ]]; then
  cat "${guest_output}" >&2
  exit "${guest_status}"
fi

# Flush the fully initialized prefix, then start the capture server with no idle
# timeout. Starting it before wineboot leaves RpcSs only partially initialized.
stop_log="${canary_root}/wineserver-stop.log"
wait_log="${canary_root}/wineserver-wait.log"
set +e
FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -k >"${stop_log}" 2>&1
stop_status=$?
FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -w >"${wait_log}" 2>&1
wait_status=$?
set -e
if ! { [[ "${stop_status}" -eq 0 ]] || {
         [[ "${stop_status}" -eq 1 ]] && [[ ! -s "${stop_log}" ]];
       }; } || ! { [[ "${wait_status}" -eq 0 ]] || {
         [[ "${wait_status}" -eq 1 ]] && [[ ! -s "${wait_log}" ]];
       }; }; then
  cat "${stop_log}" >&2
  cat "${wait_log}" >&2
  exit 71
fi
FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -p0 \
  >"${canary_root}/wineserver.log" 2>&1 &
wineserver_pid=$!
sleep 0.1
if ! kill -0 "${wineserver_pid}" 2>/dev/null; then
  cat "${canary_root}/wineserver.log" >&2
  exit 72
fi

# A zero wineboot exit is insufficient. One guest process starts and polls the
# demand-start RpcSs service, writes and reads the renderer contract, reads both
# required COM registrations, activates both classes, and emits the transport
# sentinel. Keeping this in one process avoids treating repeated emulator
# startup latency as a service failure.
set +e
timeout --signal=TERM --kill-after=5s "${CANARY_TIMEOUT_SECONDS}s" \
  /opt/miel/fex-wine 'Z:\opt\miel\wine-readiness-canary.exe' \
  --rpcss-timeout-ms "${RPCSS_TIMEOUT_MS}" \
  >>"${guest_output}" 2>&1
guest_status=$?
set -e
if [[ "${guest_status}" -ne 0 ]]; then
  cat "${canary_root}/wineserver.log" >&2
  cat "${guest_output}" >&2
  exit "${guest_status}"
fi
grep -Fq 'MIEL_FEX_WINE_CANARY_OK' "${guest_output}"
grep -Fq 'MIEL_RPCSS_STATE=RUNNING' "${guest_output}"
grep -Fq 'MIEL_WINE_RENDERER=GDI' "${guest_output}"
grep -Fq 'MIEL_WINE_DECORATED=N' "${guest_output}"
grep -Fq 'MIEL_FEX_WINE_READINESS_OK' "${guest_output}"

# A Wine prefix is reusable only after its server has exited and flushed all
# registry hives. A live drive_c snapshot is not a prefix readiness proof.
timeout --signal=TERM --kill-after=5s "${CANARY_TIMEOUT_SECONDS}s" \
  FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -k
timeout --signal=TERM --kill-after=5s "${CANARY_TIMEOUT_SECONDS}s" \
  FEX "${FEX_ROOTFS_PATH}/usr/lib/wine/wineserver64" -w
wait "${wineserver_pid}" || true
wineserver_pid=""
test -s "${WINEPREFIX}/system.reg"
test -s "${WINEPREFIX}/user.reg"
test -s "${WINEPREFIX}/userdef.reg"
test -s "${WINEPREFIX}/drive_c/windows/system32/rundll32.exe"
test "$(readlink "${WINEPREFIX}/dosdevices/c:")" = '../drive_c'
test "$(readlink "${WINEPREFIX}/dosdevices/z:")" = '/'

printf '%s\n' 'MIEL_FEX_WINE_XVFB_CANARY_OK'
