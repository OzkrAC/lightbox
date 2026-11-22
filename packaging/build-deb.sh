#!/bin/sh
#
# Build lightbox's .deb, for Debian and Ubuntu. Run on one of them, from
# anywhere:
#
#   packaging/build-deb.sh [output directory]         default: dist
#
# It needs build-essential, debhelper and ninja-build, with gcc 13 or later,
# and builds for the architecture of the machine it runs on, amd64 or arm64:
#
#   sudo apt install build-essential debhelper ninja-build
#
# Without build-essential dpkg-buildpackage stops with status 3, whatever
# else is installed: every Debian package build takes it for granted.
# To install the result:
#
#   sudo apt install ./dist/lightbox_*.deb
#
# The package is built in a copy of the tree, <output>/deb-build, of the files
# that git tracks, lightc's among them, with packaging/debian as its debian/:
# the tree itself gets no debian directory and nothing of the build. The
# version is lightbox.h's, and debian/changelog is written here from it, so
# that a release is named in one place.

set -eu

cd "$(dirname "$0")/.."
out=${1:-dist}

die() { echo "build-deb: $*" >&2; exit 1; }

for tool in dpkg-buildpackage dh git tar; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
[ -f lightc/configure ] || die "the lightc submodule is not there: git submodule update --init"

version=$(sh packaging/version.sh deb)
revision=${REVISION:-1}

mkdir -p "$out"
out=$(cd "$out" && pwd)
build="$out/deb-build"
[ ! -e "$build" ] || die "$build is there already: remove it first"
src="$build/lightbox-$version"
mkdir -p "$src"

# the files git tracks, as they are in the tree
git ls-files -z --recurse-submodules | tar --no-recursion --null --files-from=- -cf - | tar -xf - -C "$src"
cp -R packaging/debian "$src/debian"

# the date of the commit, so that the same commit gives the same package
date=$(git log -1 --format=%cD)
cat > "$src/debian/changelog" <<EOF
lightbox ($version-$revision) unstable; urgency=medium

  * lightbox $(sh packaging/version.sh). What changed for someone who uses
    it is in /usr/share/doc/lightbox/CHANGELOG.md.gz.

 -- OzkrAC <OzkrAC@users.noreply.github.com>  $date
EOF

(cd "$src" && dpkg-buildpackage --build=binary --no-sign)

for f in "$build"/lightbox_*.deb; do
    [ -f "$f" ] || continue
    mv "$f" "$out/"
    echo "build-deb: $out/$(basename "$f")"
done
ls "$out"/lightbox_*.deb >/dev/null 2>&1 || die "dpkg-buildpackage made no package"
