#!/usr/bin/env python3
"""Changes an OCI image layout that lightbox export wrote, in its place, into one that import has to take
another way or to refuse (ROADMAP I.6). Unless a change says otherwise, every blob that is changed gets the
name of its new SHA-256 and what names it is written anew, up to index.json: the image is whole, and says
something else.

    image_edit.py <directory> <change> [<argument>]

    annotation KEY=VALUE    the manifest gets this annotation
    gzip                    every layer is compressed, as skopeo compresses one that it copies
    gzip-other              the first layer is compressed, and is another tree than the configuration names
    gzip-cut                the first layer is compressed and its last bytes are gone
    gzip-more               the first layer is compressed and has bytes after its end
    add-layer FILE          a tar archive becomes one more layer, over the others
    architecture NAME       what the configuration says the image is for
    os NAME
    layer-type TYPE         the media type of the first layer
    manifest-type TYPE      the media type the index names the manifest with
    config-type TYPE        the media type the manifest names the configuration with
    schema NUMBER           the manifest's schemaVersion
    layout TEXT             what oci-layout says
    one-layer-more          the configuration names a layer the manifest has not
    other-layer             the configuration names another first layer than the manifest, which is not compressed
    two-manifests           the index names the manifest twice
    no-manifests            the index names none
    index-of-indexes        the index names the manifest as an index
    name-twice              the manifest has "layers" twice
    name-in-capitals        the manifest has "Layers" beside "layers"
    no-json                 the manifest ends before it should

and the changes that leave a blob's name as it was, so that it is no longer what it is named by; WHICH is
manifest, config or layer:

    byte WHICH              one byte of it is another
    longer WHICH            it has a byte more
    gone WHICH              it is not there
    link WHICH              it is a link to a copy of itself
"""
import gzip
import hashlib
import json
import os
import sys

root, change = sys.argv[1], sys.argv[2]
argument = sys.argv[3] if len(sys.argv) > 3 else None
BLOBS = os.path.join(root, "blobs", "sha256")
LAYER = "application/vnd.oci.image.layer.v1.tar"


def blob_path(digest):
    return os.path.join(BLOBS, digest.split(":", 1)[1])


def read(digest):
    with open(blob_path(digest), "rb") as f:
        return f.read()


def put(data):
    """a blob of these bytes: its digest and its size"""
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    with open(blob_path(digest), "wb") as f:
        f.write(data)
    return digest, len(data)


def text(value):
    return json.dumps(value, separators=(",", ":")).encode()


with open(os.path.join(root, "index.json"), "rb") as f:
    index = json.load(f)
named = index["manifests"][0]
manifest_bytes = read(named["digest"])
manifest = json.loads(manifest_bytes)
config = json.loads(read(manifest["config"]["digest"]))
old = {named["digest"], manifest["config"]["digest"]} | {layer["digest"] for layer in manifest["layers"]}


def compressed(data):
    # no time and no name in its header, so that the same layer is the same blob
    return gzip.compress(data, compresslevel=6, mtime=0)


def gzip_layer(n, data=None):
    layer = manifest["layers"][n]
    packed = compressed(read(layer["digest"])) if data is None else data
    layer["digest"], layer["size"] = put(packed)
    layer["mediaType"] = LAYER + "+gzip"


which = {"manifest": named["digest"], "config": manifest["config"]["digest"], "layer": manifest["layers"][0]["digest"]}
if change in ("byte", "longer", "gone", "link"):
    path = blob_path(which[argument])
    data = bytearray(read(which[argument]))
    if change == "byte":
        data[len(data) // 2] ^= 0x01
    elif change == "longer":
        data += b"\n"
    if change == "gone":
        os.unlink(path)
    elif change == "link":
        os.rename(path, path + ".real")
        os.symlink(os.path.basename(path) + ".real", path)
    else:
        with open(path, "wb") as f:
            f.write(bytes(data))
    sys.exit(0)

raw_manifest = None
if change == "annotation":
    key, value = argument.split("=", 1)
    manifest.setdefault("annotations", {})[key] = value
elif change == "gzip":
    for n in range(len(manifest["layers"])):
        gzip_layer(n)
elif change == "gzip-other":
    plain = bytearray(read(manifest["layers"][0]["digest"]))
    # the first entry's time, in its header, and the header's checksum with it: another tree, and an archive still
    plain[136:147] = b"00000000001"
    plain[148:156] = b"        "
    plain[148:156] = ("%06o\0 " % sum(plain[0:512])).encode()
    gzip_layer(0, compressed(bytes(plain)))
elif change == "gzip-cut":
    gzip_layer(0, compressed(read(manifest["layers"][0]["digest"]))[:-12])
elif change == "gzip-more":
    gzip_layer(0, compressed(read(manifest["layers"][0]["digest"])) + b"more")
elif change == "add-layer":
    with open(argument, "rb") as f:
        data = f.read()
    digest, size = put(data)
    manifest["layers"].append({"mediaType": LAYER, "digest": digest, "size": size})
    config["rootfs"]["diff_ids"].append(digest)
elif change == "architecture":
    config["architecture"] = argument
elif change == "os":
    config["os"] = argument
elif change == "layer-type":
    manifest["layers"][0]["mediaType"] = argument
elif change == "manifest-type":
    named["mediaType"] = argument
elif change == "config-type":
    manifest["config"]["mediaType"] = argument
elif change == "schema":
    manifest["schemaVersion"] = int(argument)
elif change == "layout":
    with open(os.path.join(root, "oci-layout"), "w") as f:
        f.write(argument)
    sys.exit(0)
elif change == "one-layer-more":
    config["rootfs"]["diff_ids"].append("sha256:" + "0" * 64)
elif change == "other-layer":
    config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
elif change == "two-manifests":
    index["manifests"].append(dict(named))
elif change == "no-manifests":
    index["manifests"] = []
elif change == "index-of-indexes":
    named["mediaType"] = "application/vnd.oci.image.index.v1+json"
elif change == "name-twice":
    raw_manifest = manifest_bytes[:-1] + b',"layers":[]}'
elif change == "name-in-capitals":
    raw_manifest = manifest_bytes[:-1] + b',"Layers":[]}'
elif change == "no-json":
    raw_manifest = manifest_bytes[:-1]
else:
    sys.exit("image_edit: no such change: " + change)

if raw_manifest is None:
    manifest["config"]["digest"], manifest["config"]["size"] = put(text(config))
    raw_manifest = text(manifest)
if index["manifests"]:
    digest, size = put(raw_manifest)
    for entry in index["manifests"]:
        entry["digest"], entry["size"] = digest, size
with open(os.path.join(root, "index.json"), "wb") as f:
    f.write(text(index))

# what the image does not name any more is no part of it
keep = {manifest["config"]["digest"]} | {layer["digest"] for layer in manifest["layers"]}
keep |= {entry["digest"] for entry in index["manifests"]} if index["manifests"] else old
for digest in old - keep:
    if os.path.exists(blob_path(digest)):
        os.unlink(blob_path(digest))
