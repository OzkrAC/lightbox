#!/usr/bin/env python3
"""An OCI image layout made of tar archives, each a layer over the one before it, not compressed: what a
unit case gives the code that reads an image, without a container to export one from (ROADMAP I.6).

    image_make.py <directory, which is made> <architecture, as an image names one> <archive>...
"""
import hashlib
import json
import os
import sys

root, architecture, archives = sys.argv[1], sys.argv[2], sys.argv[3:]
os.makedirs(os.path.join(root, "blobs", "sha256"))


def put(data):
    digest = hashlib.sha256(data).hexdigest()
    with open(os.path.join(root, "blobs", "sha256", digest), "wb") as f:
        f.write(data)
    return {"digest": "sha256:" + digest, "size": len(data)}


def text(value):
    return json.dumps(value, separators=(",", ":")).encode()


layers = []
for archive in archives:
    with open(archive, "rb") as f:
        layers.append(dict(mediaType="application/vnd.oci.image.layer.v1.tar", **put(f.read())))
config = {"architecture": architecture, "os": "linux",
          "rootfs": {"type": "layers", "diff_ids": [layer["digest"] for layer in layers]}}
manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": dict(mediaType="application/vnd.oci.image.config.v1+json", **put(text(config))),
            "layers": layers}
index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
         "manifests": [dict(mediaType="application/vnd.oci.image.manifest.v1+json", **put(text(manifest)))]}
with open(os.path.join(root, "oci-layout"), "w") as f:
    f.write('{"imageLayoutVersion":"1.0.0"}')
with open(os.path.join(root, "index.json"), "wb") as f:
    f.write(text(index))
