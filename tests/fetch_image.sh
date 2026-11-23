#!/bin/sh
#
# Fetch one of the two images the allow-list is fitted to (ROADMAP 8.3) and
# unpack it as a root filesystem for the lifecycle suite:
#
#   sudo tests/fetch_image.sh alpine|debian <directory>
#   sudo make test-lifecycle LIGHTBOX_TEST_ROOTFS=<directory>
#
# for this machine's architecture, x86_64 or aarch64. Each file is pinned by
# its SHA-256 below and checked before anything is unpacked, so that a file
# that changed fails here and not as a case of the suite. A newer image is a
# change of this file, with the new sums.
#
#   alpine  the minirootfs of Alpine Linux 3.24.4, from Alpine's own mirror
#   debian  Debian 13.7, trixie, as Docker's official image debian:trixie-slim
#           of 2026-11-04: its one layer, by its digest, from Docker Hub's
#           registry, which keeps a layer for as long as an image names it.
#           The manifests were sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392
#           for amd64 and sha256:24a01011d10eba3a023bc8585b9650b8b29021240d4217c05b905e09ef4a5232
#           for arm64.
#
# The directory must not exist or be empty. Run as root, so that the files
# keep their owners and modes; needs curl, tar, gzip and sha256sum.
#
#   tests/fetch_image.sh --oci alpine|debian <directory>
#   sudo make test-lifecycle LIGHTBOX_TEST_IMAGE=<directory>
#
# fetches the same release as its registry has it, for the case that makes a
# registry's image a base (ROADMAP I.9): the image of this machine's
# architecture, named by the digest of its manifest, which is pinned below,
# copied by skopeo from Docker Hub into the directory as an OCI image layout.
# The manifest that arrives is held to the pin here, and every other blob to
# the manifest by lightbox, when it reads the image. As any user; needs
# skopeo and sha256sum.
#
#   alpine  alpine:3.24.4 of Docker's official images
#   debian  debian:trixie-slim of 2026-11-04, the manifests named above

set -eu

ALPINE_VERSION=3.24.4

pinned() { # image architecture
    case $1-$2 in
        alpine-x86_64)  echo cdaa38cb8de3537967ee5b6c9b6cd00cc962da2b018e6eea48696bb274923012 ;;
        alpine-aarch64) echo 4b14c18f7e90a063b61462ea1462a5732c154bf6adad594974fe6487cd98a8de ;;
        debian-x86_64)  echo 37fb86c2a767b88d500c6872195f88078f64765fe0d2f9cc375cc2efbd4c0a41 ;;
        debian-aarch64) echo acd43e9bebc37bc4ba7a5f47bd7598913337803e53d468f37d940f11f5d5f1ef ;;
        *) return 1 ;;
    esac
}

# the manifest of the image as Docker Hub has it, for --oci
pinned_manifest() { # image architecture
    case $1-$2 in
        alpine-x86_64)  echo 0f49f331d9212aff11b932863be4eb01cdf962969aa86dab7d1ee21ac6f5f52b ;;
        alpine-aarch64) echo 1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29 ;;
        debian-x86_64)  echo 7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 ;;
        debian-aarch64) echo 24a01011d10eba3a023bc8585b9650b8b29021240d4217c05b905e09ef4a5232 ;;
        *) return 1 ;;
    esac
}

die() { echo "fetch_image: $*" >&2; exit 1; }

oci=
if [ "${1:-}" = --oci ]; then
    oci=1
    shift
fi
[ $# -eq 2 ] || die "usage: fetch_image.sh [--oci] alpine|debian <directory>"
image=$1 dir=$2
arch=$(uname -m)
case $image in
    alpine|debian) ;;
    *) die "the images are alpine and debian, not: $image" ;;
esac
sum=$(pinned "$image" "$arch") || die "no image is pinned for $arch"
if [ -e "$dir" ] && [ -n "$(ls -A "$dir")" ]; then
    die "$dir is not empty"
fi

if [ -n "$oci" ]; then
    manifest=$(pinned_manifest "$image" "$arch") || die "no image is pinned for $arch"
    command -v skopeo >/dev/null 2>&1 || die "--oci needs skopeo, which copies an image from its registry"
    ref="docker://docker.io/library/$image@sha256:$manifest"
    echo "fetch_image: $ref"
    # the manifest as it is, and not one written anew for the directory
    skopeo --insecure-policy copy --preserve-digests "$ref" "oci:$dir" || die "skopeo could not copy $ref"
    got=$(sha256sum "$dir/blobs/sha256/$manifest" 2>/dev/null | cut -d' ' -f1)
    [ "$got" = "$manifest" ] || die "the manifest of the $image image for $arch is not the one that is pinned, $manifest"
    grep -q "\"digest\":\"sha256:$manifest\"" "$dir/index.json" || die "$dir/index.json does not name the manifest that is pinned"
    echo "fetch_image: $image for $arch as an image, manifest sha256:$manifest, in $dir"
    exit 0
fi

case $image in
    alpine)
        url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/$arch/alpine-minirootfs-$ALPINE_VERSION-$arch.tar.gz"
        auth= ;;
    debian)
        url="https://registry-1.docker.io/v2/library/debian/blobs/sha256:$sum"
        # the registry gives anyone a token to pull an official image with
        token=$(curl -fsS --retry 3 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull' |
                sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
        [ -n "$token" ] || die "Docker Hub gave no token"
        auth="Authorization: Bearer $token" ;;
esac

file=$(mktemp "${TMPDIR:-/tmp}/lightbox-image.XXXXXX")
trap 'rm -f -- "$file"' EXIT
echo "fetch_image: $url"
curl -fsSL --retry 3 ${auth:+-H "$auth"} -o "$file" "$url" || die "could not fetch $url"
got=$(sha256sum "$file" | cut -d' ' -f1)
[ "$got" = "$sum" ] || die "the $image image for $arch has SHA-256 $got, and $sum is pinned"

mkdir -p "$dir"
tar -xzf "$file" -C "$dir" --numeric-owner
echo "fetch_image: $image for $arch, SHA-256 $sum, unpacked in $dir"
