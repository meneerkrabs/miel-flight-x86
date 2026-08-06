#!/usr/bin/env bash
set -euo pipefail

readonly rootfs="${FEX_ROOTFS:-/opt/fex/rootfs}"
readonly system32="${WINEPREFIX:?WINEPREFIX is required}/drive_c/windows/system32"
readonly mingw_zlib="${rootfs}/usr/i686-w64-mingw32/lib/zlib1.dll"
readonly mingw_libgcc="${rootfs}/usr/lib/gcc/i686-w64-mingw32/13-win32/libgcc_s_dw2-1.dll"

# Ubuntu's Wine PE modules import these MinGW runtime DLLs, but a newly-created
# prefix cannot discover them after wineboot switches from the installation
# tree to C:\windows\system32. Seed the two pinned runtime files before the
# first Wine process; repeated launches verify and refresh the same bytes.
install -d -m 0755 "${system32}"
install -m 0644 "${mingw_zlib}" "${system32}/zlib1.dll"
install -m 0644 "${mingw_libgcc}" "${system32}/libgcc_s_dw2-1.dll"

export WINELOADER="${MIEL_FEX_WINE_LAUNCHER:-/opt/miel/fex-wine}"
export WINESERVER="${rootfs}/usr/lib/wine/wineserver64"
export WINEDLLPATH="${rootfs}/usr/i686-w64-mingw32/lib:${rootfs}/usr/lib/gcc/i686-w64-mingw32/13-win32:${rootfs}/usr/lib/i386-linux-gnu/wine/i386-windows:${rootfs}/usr/lib/i386-linux-gnu/wine/i386-unix"
# The original gtSoftware renderer patches immediate lookup-table addresses in
# its own executable page. FEX's default page tracker misses this 2001 pattern,
# but full validation also makes unrelated Wine bootstrap and COM processes
# needlessly slow and can destabilize RpcSs across repeated launches. Scope full
# validation to the checked projector launch boundaries; their children inherit
# it. Every other helper uses FEX's normal page-tracked invalidation.
guest_path="${1:-}"
guest_path="${guest_path//\\//}"
guest_name="${guest_path##*/}"
case "${guest_name,,}" in
  mullemeck*.exe|native-observer-launcher.exe|native-scene-debugger.exe)
    export FEX_SMCCHECKS=full
    ;;
  *)
    export FEX_SMCCHECKS=mtrack
    ;;
esac

exec FEX "${rootfs}/usr/lib/wine/wine" "$@"
