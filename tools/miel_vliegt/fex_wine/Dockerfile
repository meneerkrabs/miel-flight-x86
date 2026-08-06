FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS win32-builder
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-mingw-w64-i686 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY tools/miel_vliegt/hangover/native_observer_launcher.c /src/native_observer_launcher.c
COPY tools/miel_vliegt/hangover/native_sha256.h /src/native_sha256.h
COPY tools/miel_vliegt/hangover/native_observer_hook.c /src/native_observer_hook.c
COPY tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h /src/native_dispatch_semantic_hook.h
COPY tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c /src/native_dispatch_semantic_hook.c
COPY tools/miel_vliegt/hangover/native_dispatch_capture_targets.generated.h /src/native_dispatch_capture_targets.generated.h
COPY tools/miel_vliegt/hangover/native_observation_profiles.generated.h /src/native_observation_profiles.generated.h
COPY tools/miel_vliegt/hangover/native_observer_hook.c /repo/tools/miel_vliegt/hangover/native_observer_hook.c
COPY tools/miel_vliegt/hangover/native_sha256.h /repo/tools/miel_vliegt/hangover/native_sha256.h
COPY tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h /repo/tools/miel_vliegt/hangover/native_dispatch_semantic_hook.h
COPY tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c /repo/tools/miel_vliegt/hangover/native_dispatch_semantic_hook.c
COPY tools/miel_vliegt/hangover/native_dispatch_capture_targets.generated.h /repo/tools/miel_vliegt/hangover/native_dispatch_capture_targets.generated.h
COPY tools/miel_vliegt/hangover/native_observation_profiles.generated.h /repo/tools/miel_vliegt/hangover/native_observation_profiles.generated.h
COPY tools/miel_vliegt/hangover/native_scene_debugger.c /src/native_scene_debugger.c
COPY tools/miel_vliegt/x86_wine/native_observer_dinput_proxy.c /src/native_observer_dinput_proxy.c
COPY tools/miel_vliegt/fex_wine/win32_readiness_canary.c /src/win32_readiness_canary.c
COPY tools/miel_vliegt/native_scene_navigator.py /repo/tools/miel_vliegt/native_scene_navigator.py
COPY tools/miel_vliegt/native_trace.py /repo/tools/miel_vliegt/native_trace.py
COPY tools/miel_vliegt/build_native_trace_map.py /repo/tools/miel_vliegt/build_native_trace_map.py
COPY tools/miel_vliegt/native_observer_build.py /repo/tools/miel_vliegt/native_observer_build.py
COPY tools/miel_vliegt/fixtures/native_dispatch_driver/replay.mvo /repo/tools/miel_vliegt/fixtures/native_dispatch_driver/replay.mvo
COPY tools/miel_vliegt/fixtures/native_dispatch_driver/initial-user0.dat.gz.b64 /repo/tools/miel_vliegt/fixtures/native_dispatch_driver/initial-user0.dat.gz.b64
COPY tools/miel_vliegt/native_dispatch_semantic_wire.py /repo/tools/miel_vliegt/native_dispatch_semantic_wire.py
COPY tools/miel_vliegt/native_dispatch_hook_contract.py /repo/tools/miel_vliegt/native_dispatch_hook_contract.py
COPY tools/miel_vliegt/native_dispatch_capture_target_header.py /repo/tools/miel_vliegt/native_dispatch_capture_target_header.py
COPY tools/miel_vliegt/native_dispatch_capture_job.py /repo/tools/miel_vliegt/native_dispatch_capture_job.py
COPY tools/miel_vliegt/native_mygghanget_contract.py /repo/tools/miel_vliegt/native_mygghanget_contract.py
COPY tools/miel_vliegt/native_observation_profile_contract.py /repo/tools/miel_vliegt/native_observation_profile_contract.py
COPY tools/miel_vliegt/fex_wine/Dockerfile /repo/tools/miel_vliegt/fex_wine/Dockerfile
COPY tools/miel_vliegt/x86_wine/Dockerfile /repo/tools/miel_vliegt/x86_wine/Dockerfile
COPY content/miel_vliegt/native_scene_probe.json /repo/content/miel_vliegt/native_scene_probe.json
COPY content/miel_vliegt/native_observation_profiles.json /repo/content/miel_vliegt/native_observation_profiles.json
COPY content/miel_vliegt/scene_semantic_evidence_batches.json /repo/content/miel_vliegt/scene_semantic_evidence_batches.json
COPY content/miel_vliegt/native_scene_transitions.json /repo/content/miel_vliegt/native_scene_transitions.json
COPY content/miel_vliegt/uds_flight_contracts.json /repo/content/miel_vliegt/uds_flight_contracts.json

RUN cd /repo \
    && mkdir -p /out \
    && producer_sha="$(python3 tools/miel_vliegt/native_dispatch_hook_contract.py --producer-build-sha)" \
    && python3 tools/miel_vliegt/native_scene_navigator.py emit-header /src/native_scenes.generated.h \
    && i686-w64-mingw32-gcc -std=c11 -Os -s -static-libgcc -Wall -Wextra -Werror \
        -I/src /src/native_observer_launcher.c \
        -o /out/native-observer-launcher.exe \
    && i686-w64-mingw32-gcc -std=c11 -Os -s -static-libgcc -Wall -Wextra -Werror \
        -shared -I/src -DMVDS_PRODUCER_BUILD_SHA256=\"${producer_sha}\" \
        /src/native_observer_hook.c /src/native_dispatch_semantic_hook.c \
        -o /out/native-observer-hook.dll \
    && i686-w64-mingw32-gcc -std=c11 -Os -s -static-libgcc -Wall -Wextra -Werror \
        -I/src /src/native_scene_debugger.c \
        -o /out/native-scene-debugger.exe \
    && i686-w64-mingw32-gcc -std=c11 -Os -s -static-libgcc -Wall -Wextra -Werror \
        -shared -Wl,--kill-at /src/native_observer_dinput_proxy.c \
        -o /out/DINPUT.dll \
    && i686-w64-mingw32-gcc -std=c11 -Os -s -static-libgcc -Wall -Wextra -Werror \
        /src/win32_readiness_canary.c -ladvapi32 -lole32 -ldsound -luuid \
        -o /out/wine-readiness-canary.exe \
    && i686-w64-mingw32-objdump -p /out/DINPUT.dll > /out/DINPUT.exports \
    && grep -Eq '^[[:space:]]+\[[[:space:]]*[0-9]+\][[:space:]]+DirectInputCreateA$$' \
        /out/DINPUT.exports \
    && ! grep -Eq 'DirectInputCreateA@[0-9]+' /out/DINPUT.exports \
    && sha256sum /out/native-observer-launcher.exe \
        /out/native-observer-hook.dll /out/DINPUT.dll \
        > /out/native-observer-build.sha256 \
    && python3 tools/miel_vliegt/native_observer_build.py \
        --artifact /out/native-observer-hook.dll \
        --compiler-version "$(i686-w64-mingw32-gcc -dumpfullversion -dumpversion)" \
        --output /out/native-observer-build.json

FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG FEX_PACKAGE_URL=https://ppa.launchpadcontent.net/fex-emu/fex/ubuntu/pool/main/f/fex-emu-armv8.0/fex-emu-armv8.0_2607-1~n_arm64.deb
ARG FEX_PACKAGE_SHA256=145247dfbde97bd845d8418c6cafd866a769aaf0906379b546944d6b7f10466b
ARG FEX_PACKAGE_VERSION=2607-1~n
ARG FEX_ROOTFS_URL=https://rootfs.fex-emu.gg/Ubuntu_24_04/2025-12-27/Ubuntu_24_04.sqsh
ARG FEX_ROOTFS_SHA256=12ed41fd13ea4eb2c65c939e920bb6994702c44ae33b68bc7fc8781468b69b04
ARG FEX_ROOTFS_XXH3_64=f1aafb8234af1ac5
ARG UBUNTU_SNAPSHOT=20251227T000000Z
ARG WINE_VERSION=9.0~repack-4build3
ARG MINGW_RUNTIME_VERSION=13.2.0-6ubuntu1+26.1

RUN test "${TARGETARCH}" = arm64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl python3 squashfs-tools xxhash x11-utils xauth xvfb \
    && curl --fail --location --retry 3 "${FEX_PACKAGE_URL}" --output /tmp/fex.deb \
    && echo "${FEX_PACKAGE_SHA256}  /tmp/fex.deb" | sha256sum --check - \
    && apt-get install -y --no-install-recommends /tmp/fex.deb \
    && test "$(dpkg-query -W -f='${Version}' fex-emu-armv8.0)" = "${FEX_PACKAGE_VERSION}" \
    && ! dpkg-query -W fex-emu-binfmt32 >/dev/null 2>&1 \
    && ! dpkg-query -W fex-emu-binfmt64 >/dev/null 2>&1 \
    && rm -f /tmp/fex.deb \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --retry 3 "${FEX_ROOTFS_URL}" --output /tmp/Ubuntu_24_04.sqsh \
    && echo "${FEX_ROOTFS_SHA256}  /tmp/Ubuntu_24_04.sqsh" | sha256sum --check - \
    && test "$(xxhsum -H3 /tmp/Ubuntu_24_04.sqsh | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')" = "${FEX_ROOTFS_XXH3_64}" \
    && mkdir -p /opt/fex/rootfs \
    && unsquashfs -no-progress -d /opt/fex/rootfs /tmp/Ubuntu_24_04.sqsh \
    && rm -f /tmp/Ubuntu_24_04.sqsh \
    && test -x /opt/fex/rootfs/usr/bin/bash

ENV FEX_ROOTFS=/opt/fex/rootfs

COPY tools/miel_vliegt/fex_wine/install_guest_wine.sh /usr/local/libexec/install-miel-fex-guest-wine
RUN chmod 0755 /usr/local/libexec/install-miel-fex-guest-wine \
    && test "$(FEX /usr/bin/uname -m)" = x86_64 \
    && UBUNTU_SNAPSHOT="${UBUNTU_SNAPSHOT}" WINE_VERSION="${WINE_VERSION}" \
        MINGW_RUNTIME_VERSION="${MINGW_RUNTIME_VERSION}" \
        /usr/local/libexec/install-miel-fex-guest-wine \
    && rm -f /usr/local/libexec/install-miel-fex-guest-wine

# FEXBash overlays the ARM64 host filesystem; it is intentionally not a
# chroot. Wine's compiled-in data directory must therefore be visible in the
# container namespace even though the x86 binaries stay in FEX_ROOTFS.
RUN test ! -e /usr/share/wine \
    && ln -s /opt/fex/rootfs/usr/share/wine /usr/share/wine

COPY --from=win32-builder /out/native-observer-launcher.exe /opt/miel/native-observer-launcher.exe
COPY --from=win32-builder /out/native-observer-hook.dll /opt/miel/native-observer-hook.dll
COPY --from=win32-builder /out/native-observer-build.json /opt/miel/native-observer-build.json
COPY --from=win32-builder /out/native-scene-debugger.exe /opt/miel/native-scene-debugger.exe
COPY --from=win32-builder /out/DINPUT.dll /opt/miel/DINPUT.dll
COPY --from=win32-builder /out/wine-readiness-canary.exe /opt/miel/wine-readiness-canary.exe
RUN cp /opt/fex/rootfs/usr/lib/i386-linux-gnu/wine/i386-windows/dinput.dll \
        /opt/miel/dinput-real.dll
COPY tools/miel_vliegt/x86_wine/alsa-null.conf /opt/miel/alsa-null.conf
COPY tools/miel_vliegt/fex_wine/wine.sh /opt/miel/fex-wine
COPY tools/miel_vliegt/fex_wine/canary.sh /opt/miel/fex-wine-canary
COPY tools/miel_vliegt/fex_wine/contract.json /opt/miel/fex-wine-contract.json

# The self-hosted runner bind-mounts its exact /home/ubuntu/... run root into
# this image, then executes Wine as the isolated uid 1001. Ubuntu's base-image
# home is 0750, so that uid cannot traverse to the otherwise correctly owned
# bind mount. Keep the parent non-listable but traversable; the run root itself
# remains mode 0700 and uid-bound by the suite.
RUN chmod 0755 /opt/miel/fex-wine /opt/miel/fex-wine-canary \
    && chmod 0711 /home/ubuntu \
    && test -s /opt/miel/native-observer-launcher.exe \
    && test -s /opt/miel/native-observer-hook.dll \
    && test -s /opt/miel/native-observer-build.json \
    && test -s /opt/miel/native-scene-debugger.exe \
    && test -s /opt/miel/DINPUT.dll \
    && test -s /opt/miel/wine-readiness-canary.exe \
    && test -s /opt/miel/dinput-real.dll \
    && test -s /opt/fex/rootfs/usr/i686-w64-mingw32/lib/zlib1.dll \
    && test -s /opt/fex/rootfs/usr/lib/gcc/i686-w64-mingw32/13-win32/libgcc_s_dw2-1.dll

ENV ALSA_CONFIG_PATH=/opt/miel/alsa-null.conf
WORKDIR /game
ENTRYPOINT ["/opt/miel/fex-wine-canary"]
