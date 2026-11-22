#!/bin/sh
#
# Build lightbox's .xbps packages, for Void Linux. Run on Void, from anywhere:
#
#   packaging/build-xbps.sh [output directory]        default: dist
#
# It needs gcc, make and ninja to build lightbox, and xbps-create, which is in
# xbps itself. It makes two packages from one build, for this machine's
# architecture with glibc and with musl: lightbox is linked statically and
# without a C library, so the same binary serves both, and only the name of
# the architecture in the package differs.
#
# What a package holds is what `make install PREFIX=/usr` installs, and the
# licence, where Void keeps licences. An xbps package holds no empty
# directory, so lightbox's own under /var/lib are made by packaging/xbps/INSTALL,
# which xbps runs when it has unpacked the package. To install one from the
# directory it is in:
#
#   xbps-rindex -a ./lightbox-*.xbps
#   sudo xbps-install --repository="$PWD" lightbox

set -eu

cd "$(dirname "$0")/.."
out=${1:-dist}

die() { echo "build-xbps: $*" >&2; exit 1; }

for tool in xbps-create make; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done

version=$(sh packaging/version.sh xbps)
revision=${REVISION:-1}
pkgver="lightbox-${version}_${revision}"

case $(uname -m) in
    x86_64)  arch=x86_64 ;;
    aarch64) arch=aarch64 ;;
    *) die "lightbox is built for x86_64 and aarch64, not $(uname -m)" ;;
esac

mkdir -p "$out"
out=$(cd "$out" && pwd)
stage="$out/xbps-stage"
[ ! -e "$stage" ] || die "$stage is there already: remove it first"

make
make -s install PREFIX=/usr DESTDIR="$stage" >/dev/null
install -D -m 644 LICENSE "$stage/usr/share/licenses/lightbox/LICENSE"
install -m 750 packaging/xbps/INSTALL "$stage/INSTALL"

for a in "$arch" "$arch-musl"; do
    (cd "$out" && xbps-create --quiet \
        --architecture "$a" \
        --pkgver "$pkgver" \
        --desc "Minimal, secure container runtime in one static binary" \
        --long-desc "lightbox turns a directory that holds a Linux root filesystem into containers, with a sandbox that is on by default, no daemon and no C library." \
        --homepage "https://github.com/OzkrAC/lightbox" \
        --changelog "https://github.com/OzkrAC/lightbox/blob/main/CHANGELOG.md" \
        --license "MIT" \
        --maintainer "OzkrAC <OzkrAC@users.noreply.github.com>" \
        --dependencies "iptables>=0" \
        --config-files "/etc/lightbox/lightbox.conf" \
        "$stage")
    echo "build-xbps: $out/$pkgver.$a.xbps"
done
