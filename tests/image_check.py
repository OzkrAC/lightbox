#!/usr/bin/env python3
"""An OCI image layout, as lightbox export writes one (ROADMAP I.5), held to what it says of itself:
every blob has the size and the SHA-256 its descriptor names it by, the configuration's layers are the
manifest's, and nothing is in the directory that the image does not name. Then what is in it, a line each:

    manifest <digest>
    config <digest>
    architecture <name>
    layers <how many>
    layer <n> <digest> <size>
    annotation <key>=<value>                           by key
    entry <n> <kind> <mode> <uid>:<gid> <size> <name>[ -> <what a link names>]

where <n> is a layer, from 1, and <kind> is file, dir, link, hardlink, char, block or fifo.

    image_check.py <directory>

Its status is 1, with what is wrong said, for a directory that is no such image.
"""
import hashlib
import json
import os
import re
import stat
import sys
import tarfile

MEDIA_INDEX = "application/vnd.oci.image.index.v1+json"
MEDIA_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MEDIA_CONFIG = "application/vnd.oci.image.config.v1+json"
MEDIA_LAYER = "application/vnd.oci.image.layer.v1.tar"


def wrong(what):
    print("image_check: " + what, file=sys.stderr)
    sys.exit(1)


def once(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            wrong("a name is there twice in one object: %r" % k)
        seen[k] = v
    return seen


def read_json(data, what):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=once)
    except (ValueError, UnicodeDecodeError) as e:
        wrong("%s is no JSON: %s" % (what, e))


def blob(root, descriptor, media, what, seen):
    if descriptor.get("mediaType") != media:
        wrong("%s has the media type %r, not %r" % (what, descriptor.get("mediaType"), media))
    digest = descriptor.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        wrong("%s is named by %r, which is no SHA-256" % (what, digest))
    size = descriptor.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        wrong("%s has the size %r" % (what, size))
    path = os.path.join(root, "blobs", "sha256", digest[7:])
    try:
        st = os.lstat(path)
    except OSError:
        wrong("%s is not there: %s" % (what, path))
    if not stat.S_ISREG(st.st_mode):
        wrong("%s is no regular file: %s" % (what, path))
    if st.st_size != size:
        wrong("%s has %d bytes, and its descriptor says %d" % (what, st.st_size, size))
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for piece in iter(lambda: f.read(1 << 20), b""):
            h.update(piece)
    if h.hexdigest() != digest[7:]:
        wrong("%s has the SHA-256 %s, and is named %s" % (what, h.hexdigest(), digest[7:]))
    seen.add(digest[7:])
    return path, digest, size


KINDS = [(tarfile.REGTYPE, "file"), (tarfile.AREGTYPE, "file"), (tarfile.DIRTYPE, "dir"), (tarfile.SYMTYPE, "link"),
         (tarfile.LNKTYPE, "hardlink"), (tarfile.CHRTYPE, "char"), (tarfile.BLKTYPE, "block"), (tarfile.FIFOTYPE, "fifo")]


def main():
    root = sys.argv[1]
    seen = set()

    with open(os.path.join(root, "oci-layout"), "rb") as f:
        if read_json(f.read(), "oci-layout") != {"imageLayoutVersion": "1.0.0"}:
            wrong("oci-layout does not say it is an image layout of version 1.0.0")
    with open(os.path.join(root, "index.json"), "rb") as f:
        index = read_json(f.read(), "index.json")
    if index.get("schemaVersion") != 2 or index.get("mediaType") != MEDIA_INDEX:
        wrong("index.json is no image index of schema 2")
    if not isinstance(index.get("manifests"), list) or len(index["manifests"]) != 1:
        wrong("index.json does not name one manifest")
    named = index["manifests"][0]
    platform = named.get("platform", {})
    if platform.get("os") != "linux" or platform.get("architecture") not in ("amd64", "arm64"):
        wrong("the index names a platform that is none of lightbox's: %r" % platform)

    path, manifest_digest, _ = blob(root, named, MEDIA_MANIFEST, "the manifest", seen)
    with open(path, "rb") as f:
        manifest = read_json(f.read(), "the manifest")
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != MEDIA_MANIFEST:
        wrong("the manifest is no image manifest of schema 2")
    path, config_digest, _ = blob(root, manifest.get("config", {}), MEDIA_CONFIG, "the configuration", seen)
    with open(path, "rb") as f:
        config = read_json(f.read(), "the configuration")
    if config.get("os") != "linux" or config.get("architecture") != platform["architecture"]:
        wrong("the configuration is for %r and %r, and the index says %r" % (
            config.get("os"), config.get("architecture"), platform))
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        wrong("the manifest names no layers")
    found = [blob(root, layer, MEDIA_LAYER, "layer %d" % (n + 1), seen) for n, layer in enumerate(layers)]
    rootfs = config.get("rootfs", {})
    if rootfs.get("type") != "layers" or rootfs.get("diff_ids") != [digest for _, digest, _ in found]:
        wrong("the configuration's layers are not the manifest's: %r" % rootfs)

    # nothing but what the image names
    there = set(os.listdir(os.path.join(root, "blobs", "sha256")))
    if there != seen:
        wrong("blobs/sha256 has what the image does not name, or lacks what it does: %s" % sorted(there ^ seen))
    if sorted(os.listdir(root)) != ["blobs", "index.json", "oci-layout"] or os.listdir(os.path.join(root, "blobs")) != ["sha256"]:
        wrong("the directory has more in it than an image: %s" % sorted(os.listdir(root)))

    print("manifest " + manifest_digest)
    print("config " + config_digest)
    print("architecture " + config["architecture"])
    print("layers %d" % len(found))
    for n, (_, digest, size) in enumerate(found):
        print("layer %d %s %d" % (n + 1, digest, size))
    annotations = manifest.get("annotations", {})
    for key in sorted(annotations):
        if not isinstance(annotations[key], str):
            wrong("the annotation %s is no string" % key)
        print("annotation %s=%s" % (key, annotations[key]))
    for n, (path, _, _) in enumerate(found):
        with tarfile.open(path, "r:") as archive:
            for member in archive:
                kind = dict(KINDS).get(member.type)
                if kind is None:
                    wrong("layer %d has an entry of a kind an image has none of: %r" % (n + 1, member.name))
                target = " -> " + member.linkname if kind in ("link", "hardlink") else ""
                print("entry %d %s %04o %d:%d %d %s%s" % (n + 1, kind, member.mode, member.uid, member.gid,
                                                          member.size, member.name, target))


main()
