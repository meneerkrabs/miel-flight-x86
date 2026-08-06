#!/usr/bin/env bash
# Stage and run the calibrated seven-scenario FEX oracle on oracle-miel.
set -euo pipefail

readonly REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SOURCE_IDENTITY="${REPOSITORY_ROOT}/content/miel_vliegt/source_identity.json"
readonly IMAGE_CONTRACT="${REPOSITORY_ROOT}/tools/miel_vliegt/fex_wine/contract.json"
readonly OBSERVER_BUILD="${REPOSITORY_ROOT}/tools/miel_vliegt/native_observer_build.py"
readonly INITIAL_USER_FIXTURE="${REPOSITORY_ROOT}/tools/miel_vliegt/fixtures/native_dispatch_driver/initial-user0.dat.gz.b64"
readonly SUITE_LAUNCHER="${REPOSITORY_ROOT}/deployment/run-flight-native-suite.sh"
readonly OBSERVE_MS=3600000
readonly MAX_RECORDS=1000000

RUN_ROOT=""
PRIVATE_ISO="/home/ubuntu/miel-isos/Mielvliegt.iso"
IMAGE_REFERENCE=""
CONTAINER_ID=""
CONTAINER_IMAGE=""
IMAGE_ID=""
IMAGE_SHA256=""
PROBE_CONTAINER=""
PROBE_ROOT=""
VALIDATION_RESULT=""

usage() {
  cat <<'EOF'
usage: deployment/run-oracle-flight-native-suite.sh \
  --run-root /srv/miel-capture/<fresh-run> \
  [--private-iso /home/ubuntu/miel-isos/Mielvliegt.iso] \
  [--image-reference miel-flight-fex-wine:<tag>]

The hash-pinned ISO is the sole private game trust root. It is extracted into
the fresh run root with 7z and unshield before its source files are verified.

Without --image-reference, exactly one locally cached
miel-flight-fex-wine:* image must validate against the checked-out sources.
EOF
}

while (($#)); do
  case "$1" in
    --run-root)
      RUN_ROOT="${2:?--run-root needs an absolute path}"
      shift 2
      ;;
    --private-iso)
      PRIVATE_ISO="${2:?--private-iso needs an absolute path}"
      shift 2
      ;;
    --image-reference)
      IMAGE_REFERENCE="${2:?--image-reference needs a local image reference}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

[[ -n "${RUN_ROOT}" ]] || {
  usage >&2
  exit 64
}
for path in "${RUN_ROOT}" "${PRIVATE_ISO}"; do
  [[ "${path}" == /* ]] || {
    echo "all host paths must be absolute: ${path}" >&2
    exit 64
  }
done
if [[ "${MIEL_NATIVE_BACKEND_ID:-fex}" == "fex" ]]; then
  [[ "$(uname -m)" =~ ^(aarch64|arm64)$ ]] || {
    echo "the native FEX suite requires the ARM64 oracle-miel host" >&2
    exit 69
  }
fi
if [[ "${MIEL_NATIVE_BACKEND_ID:-fex}" == "fex" ]]; then
  REQUIRED_COMMANDS="docker 7z unshield python3 sha256sum cmp git tee install"
else
  REQUIRED_COMMANDS="7z unshield python3 sha256sum cmp git tee install"
fi
for command in ${REQUIRED_COMMANDS}; do
  command -v "${command}" >/dev/null || {
    echo "required command is unavailable: ${command}" >&2
    exit 69
  }
done
[[ -f "${PRIVATE_ISO}" && ! -L "${PRIVATE_ISO}" ]] || {
  echo "private flight ISO is unavailable or is a symlink" >&2
  exit 66
}
[[ ! -e "${RUN_ROOT}" && ! -L "${RUN_ROOT}" ]] || {
  echo "run root must not already exist: ${RUN_ROOT}" >&2
  exit 73
}
case "${RUN_ROOT}/" in
  "${REPOSITORY_ROOT}/"*)
    echo "run root must remain outside the repository" >&2
    exit 73
    ;;
esac
[[ -d "$(dirname "${RUN_ROOT}")" && ! -L "$(dirname "${RUN_ROOT}")" ]] || {
  echo "run-root parent must be a pre-provisioned real directory" >&2
  exit 73
}

mkdir -m 0700 "${RUN_ROOT}"
exec > >(tee -a "${RUN_ROOT}/orchestration.log") 2>&1

cleanup() {
  local status=$?
  if [[ -n "${PROBE_CONTAINER}" ]]; then
    docker rm --force "${PROBE_CONTAINER}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${CONTAINER_ID}" ]]; then
    docker rm --force "${CONTAINER_ID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${PROBE_ROOT}" && -d "${PROBE_ROOT}" ]]; then
    rm -rf "${PROBE_ROOT}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mapfile -t private_identity_rows < <(
  python3 - "${SOURCE_IDENTITY}" <<'PY'
import json
from pathlib import Path
import sys

identity = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(f"iso\t{identity['iso']['sha256']}\t{identity['iso']['filename']}")
for key in ("executable", "launcher", "cc_dll", "udspack_dll", "help_file"):
    record = identity[key]
    print(f"{key}\t{record['sha256']}\t{record['filename']}")
PY
)
[[ "${#private_identity_rows[@]}" -eq 6 ]] || {
  echo "tracked private source identity is incomplete" >&2
  exit 65
}
IFS=$'\t' read -r _ expected_iso_sha256 _ <<<"${private_identity_rows[0]}"
actual_iso_sha256="$(sha256sum "${PRIVATE_ISO}" | cut -d' ' -f1)"
[[ "${actual_iso_sha256}" == "${expected_iso_sha256}" ]] || {
  echo "private ISO hash drifted: expected ${expected_iso_sha256}, got ${actual_iso_sha256}" >&2
  exit 65
}

readonly INSTALLER_ROOT="${RUN_ROOT}/private-installer"
readonly EXTRACTED_SYSTEM_ROOT="${RUN_ROOT}/private-system"
mkdir -m 0700 "${INSTALLER_ROOT}" "${EXTRACTED_SYSTEM_ROOT}"
7z x -y "-o${INSTALLER_ROOT}" "${PRIVATE_ISO}" >/dev/null
[[ -f "${INSTALLER_ROOT}/data1.cab" ]] || {
  echo "hash-pinned ISO lacks the expected data1.cab installer payload" >&2
  exit 66
}
(
  cd "${EXTRACTED_SYSTEM_ROOT}"
  unshield -g "System Files" x "${INSTALLER_ROOT}/data1.cab" >/dev/null
)
readonly PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/System_Files"
[[ -d "${PRIVATE_GAME_ROOT}" && ! -L "${PRIVATE_GAME_ROOT}" ]] || {
  echo "private installed game root is unavailable or is a symlink" >&2
  exit 66
}
for row in "${private_identity_rows[@]:1}"; do
  IFS=$'\t' read -r label expected_sha256 filename <<<"${row}"
  private_path="${PRIVATE_GAME_ROOT}/${filename}"
  [[ -f "${private_path}" && ! -L "${private_path}" ]] || {
    echo "private ${label} input is unavailable: ${private_path}" >&2
    exit 66
  }
  actual_sha256="$(sha256sum "${private_path}" | cut -d' ' -f1)"
  [[ "${actual_sha256}" == "${expected_sha256}" ]] || {
    echo "private ${label} hash drifted: expected ${expected_sha256}, got ${actual_sha256}" >&2
    exit 65
  }
done

# Native Windows backend: no Docker, no Wine, run directly
write_runner_receipt() {
  local status="$1"
  local suite_exit="$2"
  python3 - \
    "${RUN_ROOT}/runner-receipt.json" \
    "${status}" \
    "${suite_exit}" \
    "${IMAGE_ID}" \
    "${CONTAINER_ID}" \
    "${identities_tsv}" \
    "${OUTPUT_ROOT}" \
    "${OBSERVE_MS}" \
    "${MAX_RECORDS}" \
    "$(git -C "${REPOSITORY_ROOT}" rev-parse HEAD)" <<'PY'
import json
from pathlib import Path
import sys

(
    output_path, status, suite_exit, image_id, container_id,
    identities_path, suite_output, observe_ms, max_records, commit,
) = sys.argv[1:]
inputs = {}
for line in Path(identities_path).read_text(encoding="utf-8").splitlines():
    label, sha256, path = line.split("\t")
    inputs[label] = {"path": path, "sha256": sha256}
receipt = {
    "schema": 1,
    "protocol": "miel-vliegt-oracle-native-suite-runner",
    "status": status,
    "suite_exit_code": int(suite_exit),
    "repository_commit": commit,
    "observe_ms": int(observe_ms),
    "max_records": int(max_records),
    "image_id": image_id,
    "container_id": container_id,
    "inputs": inputs,
    "suite_output_root": suite_output,
}
}

echo "DEBUG: MIEL_NATIVE_BACKEND_ID=${MIEL_NATIVE_BACKEND_ID:-UNSET}" 
if [[ "${MIEL_NATIVE_BACKEND_ID:-fex}" == "native" || "${MIEL_NATIVE_BACKEND_ID:-fex}" == "wine" ]]; then
  BACKEND="${MIEL_NATIVE_BACKEND_ID:-fex}"
  echo "=== ${BACKEND} backend: skipping Docker entirely ==="
  
  # Resolve tool paths: prefer /opt/miel (workflow-built), fallback to repo
  if [[ -f /opt/miel/native-observer-hook.dll ]]; then
    TOOLS_SRC="/opt/miel"
  else
    TOOLS_SRC="${REPOSITORY_ROOT}/tools/miel_vliegt/hangover"
  fi
  echo "Using observer tools from: ${TOOLS_SRC}"
  IMAGE_ID="${BACKEND}"
  CONTAINER_ID="${BACKEND}"

  # Backend-specific settings set dynamically below

  # Extract game files from ISO (same as Docker path)
  readonly INSTALLER_ROOT="${RUN_ROOT}/private-installer"
  readonly EXTRACTED_SYSTEM_ROOT="${RUN_ROOT}/private-system"
  mkdir -m 0700 "${INSTALLER_ROOT}" "${EXTRACTED_SYSTEM_ROOT}"
  7z x -y "-o${INSTALLER_ROOT}" "${PRIVATE_ISO}" >/dev/null
  unshield -g "System Files" x "${INSTALLER_ROOT}/data1.cab" >/dev/null 2>&1 || true

  readonly PRIVATE_GAME_ROOT="${EXTRACTED_SYSTEM_ROOT}/System_Files"
  readonly GAME_ROOT="${RUN_ROOT}/game"
  readonly PROXY_ROOT="${RUN_ROOT}/proxy"
  readonly TOOLS_ROOT="${RUN_ROOT}/tools"
  readonly FIXTURE_ROOT="${RUN_ROOT}/fixture"
  readonly WINE_PREFIX="${RUN_ROOT}/wine-prefix"
  readonly SUITE_ROOT="${RUN_ROOT}/calibrated-suite"
  readonly OUTPUT_ROOT="${RUN_ROOT}/output"
  readonly CLEAN_STATE_ROOT="${RUN_ROOT}/game-clean"
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

  # Clean state snapshot
  mkdir -m 0700 "${CLEAN_STATE_ROOT}"
  cp -a "${GAME_ROOT}/." "${CLEAN_STATE_ROOT}/"

  # Input identities
  declare -A input_paths=(
    [source_executable]="${GAME_ROOT}/MulleMeck.exe"
    [disposable_target]="${GAME_ROOT}/MulleMeck.exe"
    [user_profile]="${FIXTURE_ROOT}/user0.dat"
    [observer_dll]="${TOOLS_SRC}/native-observer-hook.dll"
    [observer_launcher]="${TOOLS_SRC}/native-observer-launcher.exe"
    [proxy_dinput]="${TOOLS_SRC}/DINPUT.dll"
    [real_dinput]="${TOOLS_SRC}/dinput-real.dll"
    [smoke_executable]="${TOOLS_SRC}/wine-readiness-canary.exe"
    [data_archive]="${GAME_ROOT}/data.up"
    [map_archive]="${GAME_ROOT}/map.up"
    [sounds_archive]="${GAME_ROOT}/sounds.up"
    [miel_ini]="${GAME_ROOT}/Miel.ini"
  )

  identities_tsv="${RUN_ROOT}/input-identities.tsv"
  : >"${identities_tsv}"
  for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
    sha=$(sha256sum "${input_paths[${label}]}" | cut -d' ' -f1)
    printf '%s\t%s\t%s\n' "${label}" "${sha}" "${input_paths[${label}]}" >>"${identities_tsv}"
  done

  write_runner_receipt RUNNING 0
  set +e
  # For wine backend, start Xvfb before running the suite
  if [[ "${BACKEND}" == "wine" ]]; then
    echo "=== Starting Xvfb for wine backend ===" 
    Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp &
    export DISPLAY=:99
    sleep 2
    # Initialize Wine prefix
    export WINEPREFIX="${WINE_PREFIX}"
    mkdir -p "${WINE_PREFIX}"
    WINEDEBUG=-all wineboot --init 2>/dev/null || true
    sleep 3
    echo "=== Wine prefix ready ===" 
  fi
  MIEL_NATIVE_PREFIX_MODE="${BACKEND}" \
    deployment/run-flight-native-suite.sh \
    --backend-id "${BACKEND}" \
    --backend-hodll "${MIEL_NATIVE_BACKEND_HODLL:-${BACKEND}}" \
    --container-image "${BACKEND}" \
    --container-image-sha256 "${BACKEND}" \
    --container-id "${BACKEND}" \
    --container-mount-root "${RUN_ROOT}" \
    --source-executable "${input_paths[source_executable]}" \
    --disposable-target "${input_paths[disposable_target]}" \
    --game-root "${GAME_ROOT}" \
    --state-root "${GAME_ROOT}" \
    --user-profile "${input_paths[user_profile]}" \
    --observer-dll "${input_paths[observer_dll]}" \
    --observer-launcher "${input_paths[observer_launcher]}" \
    --proxy-dinput "${input_paths[proxy_dinput]}" \
    --real-dinput "${input_paths[real_dinput]}" \
    --smoke-executable "${input_paths[smoke_executable]}" \
    --wine-prefix "${WINE_PREFIX}" \
    --suite-root "${SUITE_ROOT}" \
    --output-root "${OUTPUT_ROOT}" \
    --observe-ms 3600000 \
    --max-records 1000000 \
    --expected-uid "$(id -u)" \
    2>&1 | tee "${RUN_ROOT}/native-suite.log"
  suite_status="${PIPESTATUS[0]}"
  set -e

  if [[ "${suite_status}" -eq 0 ]]; then
    write_runner_receipt PASSED 0
  else
    write_runner_receipt FAILED "${suite_status}"
  fi
  exit "${suite_status}"
fi

# Native/wine backends are fully handled by the shortcut above and must never
# reach the Docker path. Guard against any unexpected fallthrough.
if [[ "${MIEL_NATIVE_BACKEND_ID:-fex}" == "native" || "${MIEL_NATIVE_BACKEND_ID:-fex}" == "wine" ]]; then
  echo "ERROR: ${MIEL_NATIVE_BACKEND_ID} backend should have exited via shortcut" >&2
  exit 70
fi

# For non-FEX backends that need Docker, skip FEX contract validation
# but still extract observer tools from the image.
if [[ "${MIEL_NATIVE_BACKEND_ID:-fex}" != "fex" ]]; then
  IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${IMAGE_REFERENCE}")"
  IMAGE_SHA256="${IMAGE_ID#sha256:}"
  # Extract observer tools from the image (same as validate_image but without contract check)
  PROBE_ROOT="$(mktemp -d "${RUN_ROOT}/.image-validation.XXXXXX")"
  PROBE_CONTAINER="$(docker create --entrypoint /bin/true "${IMAGE_ID}")"
  for image_file in       native-observer-hook.dll       native-observer-launcher.exe       DINPUT.dll       dinput-real.dll       wine-readiness-canary.exe       native-observer-build.json; do
    docker cp "${PROBE_CONTAINER}:/opt/miel/${image_file}" "${PROBE_ROOT}/${image_file}" || {
      echo "failed to extract ${image_file} from image" >&2
      docker rm --force "${PROBE_CONTAINER}" >/dev/null 2>&1 || true
      exit 65
    }
  done
  docker rm --force "${PROBE_CONTAINER}" >/dev/null 2>&1 || true
  PROBE_CONTAINER=""
else
mapfile -t image_candidates < <(
  if [[ -n "${IMAGE_REFERENCE}" ]]; then
    docker image inspect --format '{{.Id}}' "${IMAGE_REFERENCE}"
  else
    docker image ls --quiet --no-trunc \
      --filter 'reference=miel-flight-fex-wine:*'
  fi | sort -u
)
[[ "${#image_candidates[@]}" -gt 0 ]] || {
  echo "no locally cached FEX/Wine flight image was found" >&2
  exit 66
}

validate_image() {
  local candidate="$1"
  local candidate_id
  local candidate_root
  VALIDATION_RESULT=""
  candidate_id="$(docker image inspect --format '{{.Id}}' "${candidate}")"
  if [[ ! "${candidate_id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "rejecting image with invalid immutable identity: ${candidate}" >&2
    return 1
  fi
  candidate_root="$(mktemp -d "${RUN_ROOT}/.image-validation.XXXXXX")"
  PROBE_CONTAINER="$(
    docker create \
      --label "nl.mielmonteur.native-suite.run-id=${GITHUB_RUN_ID:-manual}" \
      --label "nl.mielmonteur.native-suite.run-attempt=${GITHUB_RUN_ATTEMPT:-1}" \
      --entrypoint /bin/true \
      "${candidate_id}"
  )"
  if ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/fex-wine-contract.json" \
      "${candidate_root}/fex-wine-contract.json" \
      || ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/native-observer-build.json" \
      "${candidate_root}/native-observer-build.json" \
      || ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/native-observer-hook.dll" \
      "${candidate_root}/native-observer-hook.dll" \
      || ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/native-observer-launcher.exe" \
      "${candidate_root}/native-observer-launcher.exe" \
      || ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/DINPUT.dll" \
      "${candidate_root}/DINPUT.dll" \
      || ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/dinput-real.dll" \
      "${candidate_root}/dinput-real.dll" \
      || ! docker cp \
      "${PROBE_CONTAINER}:/opt/miel/wine-readiness-canary.exe" \
      "${candidate_root}/wine-readiness-canary.exe"; then
    docker rm --force "${PROBE_CONTAINER}" >/dev/null 2>&1 || true
    PROBE_CONTAINER=""
    rm -rf "${candidate_root}"
    echo "rejecting image whose required native tools are incomplete: ${candidate_id}" >&2
    return 1
  fi
  docker rm --force "${PROBE_CONTAINER}" >/dev/null
  PROBE_CONTAINER=""
  if ! cmp -s "${IMAGE_CONTRACT}" "${candidate_root}/fex-wine-contract.json" \
      || ! python3 "${OBSERVER_BUILD}" \
        --check \
        --output "${candidate_root}/native-observer-build.json" \
        --artifact "${candidate_root}/native-observer-hook.dll" \
        >/dev/null; then
    rm -rf "${candidate_root}"
    echo "rejecting image whose runner or observer build drifted: ${candidate_id}" >&2
    return 1
  fi
  VALIDATION_RESULT="${candidate_id}"$'\t'"${candidate_root}"
}

validated_images=()
for candidate in "${image_candidates[@]}"; do
  if validate_image "${candidate}"; then
    validated_images+=("${VALIDATION_RESULT}")
  fi
done
if [[ "${#validated_images[@]}" -ne 1 ]]; then
  echo "expected exactly one source-valid FEX image, found ${#validated_images[@]}" >&2
  if [[ -z "${IMAGE_REFERENCE}" ]]; then
    echo "supply --image-reference to disambiguate independently valid images" >&2
  fi
  for validation in "${validated_images[@]}"; do
    IFS=$'\t' read -r _ validation_root <<<"${validation}"
    rm -rf "${validation_root}"
  done
  exit 65
fi
IFS=$'\t' read -r IMAGE_ID PROBE_ROOT <<<"${validated_images[0]}"
fi
readonly IMAGE_ID
readonly IMAGE_SHA256="${IMAGE_ID#sha256:}"

readonly GAME_ROOT="${RUN_ROOT}/game"
readonly PROXY_ROOT="${RUN_ROOT}/proxy"
readonly TOOLS_ROOT="${RUN_ROOT}/tools"
readonly FIXTURE_ROOT="${RUN_ROOT}/fixture"
readonly WINE_PREFIX="${RUN_ROOT}/wine-prefix"
readonly SUITE_ROOT="${RUN_ROOT}/calibrated-suite"
readonly OUTPUT_ROOT="${RUN_ROOT}/output"
readonly CLEAN_STATE_ROOT="${RUN_ROOT}/game-clean"
mkdir -m 0700 "${GAME_ROOT}" "${PROXY_ROOT}" "${TOOLS_ROOT}" "${FIXTURE_ROOT}"

cp -a "${PRIVATE_GAME_ROOT}/." "${GAME_ROOT}/"
7z e -y "-o${GAME_ROOT}" "${PRIVATE_ISO}" \
  data.up map.up sounds.up Miel.ini

python3 - "${INITIAL_USER_FIXTURE}" "${FIXTURE_ROOT}/user0.dat" <<'PY'
import base64
import gzip
from pathlib import Path
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
encoded = "".join(source.read_text(encoding="ascii").split())
target.write_bytes(gzip.decompress(base64.b64decode(encoded, validate=True)))
PY
expected_user_sha256="$(
  PYTHONPATH="${REPOSITORY_ROOT}" python3 - <<'PY'
from tools.miel_vliegt.native_observer_build import CAPTURE_DRIVER_FOUNDATION

print(CAPTURE_DRIVER_FOUNDATION["initial_user_sha256"])
PY
)"
actual_user_sha256="$(sha256sum "${FIXTURE_ROOT}/user0.dat" | cut -d' ' -f1)"
[[ "${actual_user_sha256}" == "${expected_user_sha256}" ]] || {
  echo "canonical initial user fixture hash drifted" >&2
  exit 65
}
mkdir -p "${GAME_ROOT}/Data/User"
install -m 0600 "${FIXTURE_ROOT}/user0.dat" \
  "${GAME_ROOT}/Data/User/user0.dat"

install -m 0600 "${GAME_ROOT}/MulleMeck.exe" \
  "${PROXY_ROOT}/MulleMeck.exe"
install -m 0600 "${PROBE_ROOT}/DINPUT.dll" "${PROXY_ROOT}/DINPUT.dll"
for image_file in \
  native-observer-hook.dll \
  native-observer-launcher.exe \
  dinput-real.dll \
  wine-readiness-canary.exe; do
  install -m 0600 "${PROBE_ROOT}/${image_file}" "${TOOLS_ROOT}/${image_file}"
done

# Snapshot the fully-provisioned game root before any capture runs.  The
# native suite mirrors this snapshot back into the live game directory
# before every scenario capture so writes from earlier scenarios (config,
# cache, save side-channels) cannot accumulate and destabilise later boots.
mkdir -m 0700 "${CLEAN_STATE_ROOT}"
cp -a "${GAME_ROOT}/." "${CLEAN_STATE_ROOT}/"

CONTAINER_NAME="miel-native-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-1}-$$"
CONTAINER_ID="$(
  FEX_ENV_ARGS=()
  if [[ -n "${MIEL_FEX_MULTIBLOCK:-}" ]]; then
    FEX_ENV_ARGS+=(--env "FEX_MULTIBLOCK=${MIEL_FEX_MULTIBLOCK}")
  fi
  if [[ -n "${MIEL_FEX_TSOENABLED:-}" ]]; then
    FEX_ENV_ARGS+=(--env "FEX_TSOENABLED=${MIEL_FEX_TSOENABLED}")
  fi
  if [[ -n "${MIEL_FEX_PARANOIDTSO:-}" ]]; then
    FEX_ENV_ARGS+=(--env "FEX_PARANOIDTSO=${MIEL_FEX_PARANOIDTSO}")
  fi
  docker create \
    --name "${CONTAINER_NAME}" \
    --shm-size=256m \
    --label "nl.mielmonteur.native-suite.run-id=${GITHUB_RUN_ID:-manual}" \
    --label "nl.mielmonteur.native-suite.run-attempt=${GITHUB_RUN_ATTEMPT:-1}" \
    --entrypoint /bin/sh \
    --env HOME=/root \
    "${FEX_ENV_ARGS[@]}" \
    --mount "type=bind,source=${RUN_ROOT},target=${RUN_ROOT}" \
    "${IMAGE_ID}" \
    -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done'
)"
docker start "${CONTAINER_ID}" >/dev/null
CONTAINER_ID="$(docker inspect --format '{{.Id}}' "${CONTAINER_ID}")"
readonly CONTAINER_ID
readonly CONTAINER_IMAGE="$(
  docker inspect --format '{{.Config.Image}}' "${CONTAINER_ID}"
)"
[[ "${CONTAINER_IMAGE}" == "${IMAGE_ID}" ]] || {
  echo "run-scoped container did not retain the immutable image reference" >&2
  exit 65
}

declare -A input_paths=(
  [source_executable]="${GAME_ROOT}/MulleMeck.exe"
  [disposable_target]="${PROXY_ROOT}/MulleMeck.exe"
  [user_profile]="${FIXTURE_ROOT}/user0.dat"
  [observer_dll]="${TOOLS_ROOT}/native-observer-hook.dll"
  [observer_launcher]="${TOOLS_ROOT}/native-observer-launcher.exe"
  [proxy_dinput]="${PROXY_ROOT}/DINPUT.dll"
  [real_dinput]="${TOOLS_ROOT}/dinput-real.dll"
  [smoke_executable]="${TOOLS_ROOT}/wine-readiness-canary.exe"
  [data_archive]="${GAME_ROOT}/data.up"
  [map_archive]="${GAME_ROOT}/map.up"
  [sounds_archive]="${GAME_ROOT}/sounds.up"
  [miel_ini]="${GAME_ROOT}/Miel.ini"
)
declare -A input_sha256=()
for label in "${!input_paths[@]}"; do
  input_sha256["${label}"]="$(sha256sum "${input_paths[${label}]}" | cut -d' ' -f1)"
done

identities_tsv="${RUN_ROOT}/input-identities.tsv"
: >"${identities_tsv}"
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  printf '%s\t%s\t%s\n' \
    "${label}" "${input_sha256[${label}]}" "${input_paths[${label}]}" \
    >>"${identities_tsv}"
done

}

NATIVE_BACKEND_ID="${MIEL_NATIVE_BACKEND_ID:-fex}"
NATIVE_BACKEND_HODLL="${MIEL_NATIVE_BACKEND_HODLL:-libwow64fex.dll}"
suite_arguments=(
  --backend-id "${NATIVE_BACKEND_ID}"
  --backend-hodll "${NATIVE_BACKEND_HODLL}"
  --container-image "${CONTAINER_IMAGE}"
  --container-image-sha256 "${IMAGE_SHA256}"
  --container-id "${CONTAINER_ID}"
  --container-mount-root "${RUN_ROOT}"
  --source-executable "${input_paths[source_executable]}"
  --disposable-target "${input_paths[disposable_target]}"
  --game-root "${GAME_ROOT}"
  --state-root "${GAME_ROOT}"
  --clean-state-root "${CLEAN_STATE_ROOT}"
  --user-profile "${input_paths[user_profile]}"
  --observer-dll "${input_paths[observer_dll]}"
  --observer-launcher "${input_paths[observer_launcher]}"
  --proxy-dinput "${input_paths[proxy_dinput]}"
  --real-dinput "${input_paths[real_dinput]}"
  --smoke-executable "${input_paths[smoke_executable]}"
  --wine-prefix "${WINE_PREFIX}"
  --suite-root "${SUITE_ROOT}"
  --output-root "${OUTPUT_ROOT}"
  --observe-ms "${OBSERVE_MS}"
  --max-records "${MAX_RECORDS}"
)
for label in $(printf '%s\n' "${!input_paths[@]}" | sort); do
  suite_arguments+=(
    "--${label//_/-}-sha256" "${input_sha256[${label}]}"
  )
done

write_runner_receipt RUNNING 0

# Start persistent Xvfb for native Wine backend (avoids xvfb-run race condition)
if [[ "${MIEL_NATIVE_BACKEND_ID:-fex}" != "fex" ]]; then
  docker exec -d "${CONTAINER_ID}" Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp
  sleep 2
fi

# Diagnostic: test Wine in the container before running the suite
echo "=== Wine diagnostic ===" >&2
docker exec "${CONTAINER_ID}" which xvfb-run Xvfb >&2 2>&1 || echo "xvfb-run/Xvfb NOT FOUND" >&2
docker exec "${CONTAINER_ID}" xvfb-run -a -s "-screen 0 646x512x16 -nolisten tcp" wine --version >&2 2>&1 || echo "xvfb-run wine FAILED" >&2
echo "=== wineboot test ===" >&2
docker exec "${CONTAINER_ID}" env WINEPREFIX=/tmp/diag-wine2 WINEDEBUG=-all xvfb-run -a -s "-screen 0 646x512x16 -nolisten tcp" wine wineboot --init >&2 2>&1 || echo "WINEBOOT xvfb-run FAILED (exit $?)" >&2
echo "=== wineboot exit: $? ===" >&2
docker exec "${CONTAINER_ID}" wine --version >&2 2>&1 || echo "wine --version FAILED" >&2
docker exec "${CONTAINER_ID}" env WINEPREFIX=/tmp/diag-wine WINEDEBUG=-all wineboot --init >&2 2>&1 || echo "wineboot FAILED" >&2
docker exec "${CONTAINER_ID}" ls -la /tmp/diag-wine/ >&2 2>&1 || echo "prefix not created" >&2
docker exec "${CONTAINER_ID}" env WINEPREFIX=/tmp/diag-wine WINEDEBUG=-all wineserver --version >&2 2>&1 || echo "wineserver FAILED" >&2
echo "=== End Wine diagnostic ===" >&2

set +e
MIEL_NATIVE_PREFIX_MODE=cold-audit \
  "${SUITE_LAUNCHER}" "${suite_arguments[@]}" \
  2>&1 | tee "${RUN_ROOT}/native-suite.log"
suite_status="${PIPESTATUS[0]}"
set -e
if [[ "${suite_status}" -eq 0 ]]; then
  [[ -s "${OUTPUT_ROOT}/calibrated-suite-run.json" ]] || {
    echo "native suite exited zero without calibrated-suite-run.json" >&2
    write_runner_receipt FAILED 70
    exit 70
  }
  write_runner_receipt PASSED 0
else
  write_runner_receipt FAILED "${suite_status}"
fi
exit "${suite_status}"
