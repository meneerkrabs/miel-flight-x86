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


FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update && apt-get install -y \
    wine wine32 wine64 \
    libwine libwine:i386 \
    libgl1-mesa-dri libgl1-mesa-dri:i386 \
    libgl1 libgl1:i386 \
    fonts-liberation \
    xauth xvfb \
    python3 p7zip-full unshield \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/miel /opt/hangover \
    && cp /usr/lib/i386-linux-gnu/wine/i386-windows/dinput.dll \
        /opt/miel/dinput-real.dll

COPY --from=win32-builder /out/native-observer-launcher.exe /opt/miel/native-observer-launcher.exe
COPY --from=win32-builder /out/native-observer-hook.dll /opt/miel/native-observer-hook.dll
COPY --from=win32-builder /out/DINPUT.dll /opt/miel/DINPUT.dll
COPY --from=win32-builder /out/DINPUT.exports /opt/miel/DINPUT.exports
COPY --from=win32-builder /out/native-scene-debugger.exe /opt/miel/native-scene-debugger.exe
COPY --from=win32-builder /out/native-observer-build.sha256 /opt/miel/native-observer-build.sha256
COPY --from=win32-builder /out/native-observer-build.json /opt/miel/native-observer-build.json
COPY --from=win32-builder /out/wine-readiness-canary.exe /opt/miel/wine-readiness-canary.exe
COPY tools/miel_vliegt/x86_wine/alsa-null.conf /opt/miel/alsa-null.conf

RUN test -s /opt/miel/native-observer-hook.dll \
    && test -s /opt/miel/native-observer-build.json

RUN wine --version || echo "WINE_VERSION_FAILED"
RUN WINEDEBUG=-all WINEPREFIX=/tmp/winetest wineboot --init 2>&1 || echo "WINEBOOT_FAILED"
RUN rm -rf /tmp/winetest

WORKDIR /game
