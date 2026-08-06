#!/usr/bin/env bash
set -euo pipefail

readonly rootfs="${FEX_ROOTFS:?FEX_ROOTFS is required}"
readonly wine_version="${WINE_VERSION:?WINE_VERSION is required}"
readonly mingw_runtime_version="${MINGW_RUNTIME_VERSION:?MINGW_RUNTIME_VERSION is required}"
readonly ubuntu_snapshot="${UBUNTU_SNAPSHOT:?UBUNTU_SNAPSHOT is required}"
readonly apt_root="$(mktemp -d /tmp/miel-fex-guest-apt.XXXXXX)"

cleanup() {
  rm -rf "${apt_root}"
}
trap cleanup EXIT INT TERM

mkdir -p "${apt_root}/lists/partial" "${apt_root}/archives/partial" /opt/miel
chmod 0755 "${apt_root}" "${apt_root}/lists" "${apt_root}/archives"
chown _apt:root "${apt_root}/lists/partial" "${apt_root}/archives/partial"
cat >"${apt_root}/sources.list" <<EOF
deb [arch=amd64,i386 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/${ubuntu_snapshot} noble main universe
deb [arch=amd64,i386 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/${ubuntu_snapshot} noble-updates main universe
deb [arch=amd64,i386 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/${ubuntu_snapshot} noble-security main universe
EOF

apt_options=(
  -o "Dir::Etc::sourcelist=${apt_root}/sources.list"
  -o Dir::Etc::sourceparts=-
  -o "Dir::State::lists=${apt_root}/lists"
  -o "Dir::State::status=${rootfs}/var/lib/dpkg/status"
  -o "Dir::Cache::archives=${apt_root}/archives"
  -o APT::Architecture=amd64
  -o APT::Architectures::=amd64
  -o APT::Architectures::=i386
)

# Host-native apt verifies the signed snapshot. This deliberately avoids both
# host binfmt and FEX's unsupported gpgv path inside the x86 RootFS.
apt-get "${apt_options[@]}" update
apt-get "${apt_options[@]}" --download-only --no-install-recommends -y install \
  "wine=${wine_version}" \
  "wine64:amd64=${wine_version}" \
  "wine32:i386=${wine_version}" \
  "gcc-mingw-w64-i686-win32-runtime:amd64=${mingw_runtime_version}"

require_package() {
  local expected_package="$1"
  local expected_architecture="$2"
  local expected_version="${3:-${wine_version}}"
  local found=false
  local package_file
  for package_file in "${apt_root}"/archives/*.deb; do
    if [[ "$(dpkg-deb --field "${package_file}" Package)" = "${expected_package}" \
      && "$(dpkg-deb --field "${package_file}" Architecture)" = "${expected_architecture}" \
      && "$(dpkg-deb --field "${package_file}" Version)" = "${expected_version}" ]]; then
      found=true
      break
    fi
  done
  if [[ "${found}" != true ]]; then
    echo "missing exact ${expected_package}:${expected_architecture} ${expected_version}" >&2
    return 1
  fi
}

require_package wine all
require_package wine64 amd64
require_package wine32 i386
require_package libwine amd64
require_package libwine i386
require_package gcc-mingw-w64-i686-win32-runtime amd64 "${mingw_runtime_version}"

(
  cd "${apt_root}/archives"
  sha256sum ./*.deb | sort -k2
) >/opt/miel/guest-wine-packages.sha256

while IFS= read -r -d '' package_file; do
  dpkg-deb --extract "${package_file}" "${rootfs}"
done < <(find "${apt_root}/archives" -maxdepth 1 -name '*.deb' -print0 | sort -z)

FEX /sbin/ldconfig
FEXBash -c 'wine-stable --version' \
  | grep -Fqx "wine-${wine_version%%~*} (Ubuntu ${wine_version})"
