#!/bin/sh
#
# The release of this tree, as lightbox.h has it and `lightbox --version`
# prints it: the one place a version is written.
#
#   packaging/version.sh           0.9.0-dev
#   packaging/version.sh deb       0.9.0~dev    a Debian version: ~ sorts before the release
#   packaging/version.sh xbps      0.9.0pre     an xbps version: pre sorts before the release
#
# A release, such as 0.9.0, is the same in all three.

set -eu

here=$(dirname "$0")
version=$(sed -n 's/^#define LIGHTBOX_VERSION "\(.*\)"$/\1/p' "$here/../lightbox.h")
[ -n "$version" ] || { echo "version.sh: no LIGHTBOX_VERSION in lightbox.h" >&2; exit 1; }

case ${1:-} in
    '')   printf '%s\n' "$version" ;;
    deb)  printf '%s\n' "$version" | sed 's/-dev$/~dev/' ;;
    xbps) printf '%s\n' "$version" | sed 's/-dev$/pre/' ;;
    *)    echo "usage: version.sh [deb|xbps]" >&2; exit 2 ;;
esac
