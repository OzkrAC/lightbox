#!/usr/bin/env python3
"""A registry for one test (ROADMAP I.8): as much of the OCI distribution API as skopeo speaks when it
copies an image to a registry and back, over HTTP on the loopback, with no accounts and no TLS. Blobs are
kept by their digest, for every repository, and a manifest under its repository by tag and by digest. A blob
is held to the digest it is uploaded as.

    registry.py <directory, which is made> <file the port is written to> [<file every request is written to>]

It listens on a port the kernel gives it, writes the number, and serves until it is killed. The log has a
line for each request, "<method> <path> <status>", so that a test can see what was sent and what was not.
"""
import hashlib
import json
import os
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT, PORT_FILE = sys.argv[1], sys.argv[2]
LOG = sys.argv[3] if len(sys.argv) > 3 else None
NAME = r"[a-z0-9]+(?:[._/-][a-z0-9]+)*"
DIGEST = r"sha256:[0-9a-f]{64}"
for part in ("blobs", "uploads", "manifests"):
    os.makedirs(os.path.join(ROOT, part), exist_ok=True)


def blob_path(digest):
    return os.path.join(ROOT, "blobs", digest[7:])


def manifest_path(name, reference):
    return os.path.join(ROOT, "manifests", name.replace("/", "%"), reference.replace(":", "="))


class Registry(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def answer(self, status, headers=None, body=b""):
        if LOG:
            with open(LOG, "a") as f:
                f.write("%s %s %d\n" % (self.command, self.path, status))
        self.send_response(status)
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def problem(self, status, code):
        self.answer(status, {"Content-Type": "application/json"},
                    json.dumps({"errors": [{"code": code, "message": code.lower()}]}).encode())

    def body(self):
        """the request's body, whichever way its length is said"""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline().strip():
                        pass
                    return
                left = size
                while left:
                    piece = self.rfile.read(min(left, 1 << 20))
                    if not piece:
                        return
                    left -= len(piece)
                    yield piece
                self.rfile.readline()
        else:
            left = int(self.headers.get("Content-Length") or 0)
            while left:
                piece = self.rfile.read(min(left, 1 << 20))
                if not piece:
                    return
                left -= len(piece)
                yield piece

    def take_body(self, path=None):
        size = 0
        f = open(path, "ab") if path else None
        for piece in self.body():
            size += len(piece)
            if f:
                f.write(piece)
        if f:
            f.close()
        return size

    def route(self):
        path, _, query = self.path.partition("?")
        args = dict(pair.split("=", 1) for pair in query.split("&") if "=" in pair)
        args = {k: v.replace("%3A", ":").replace("%3a", ":").replace("%2F", "/").replace("%2f", "/") for k, v in args.items()}
        method = "GET" if self.command == "HEAD" else self.command

        if path in ("/v2", "/v2/") and method == "GET":
            return self.answer(200, {"Content-Type": "application/json"}, b"{}")

        m = re.fullmatch(r"/v2/(%s)/blobs/(%s)" % (NAME, DIGEST), path)
        if m and method == "GET":
            if not os.path.exists(blob_path(m.group(2))):
                return self.problem(404, "BLOB_UNKNOWN")
            with open(blob_path(m.group(2)), "rb") as f:
                data = f.read()
            return self.answer(200, {"Content-Type": "application/octet-stream", "Docker-Content-Digest": m.group(2)}, data)

        m = re.fullmatch(r"/v2/(%s)/blobs/uploads/?" % NAME, path)
        if m and method == "POST":
            self.take_body()
            mounted = args.get("mount")
            if mounted and re.fullmatch(DIGEST, mounted) and os.path.exists(blob_path(mounted)):
                return self.answer(201, {"Location": "/v2/%s/blobs/%s" % (m.group(1), mounted), "Docker-Content-Digest": mounted})
            upload = uuid.uuid4().hex
            open(os.path.join(ROOT, "uploads", upload), "wb").close()
            return self.answer(202, {"Location": "/v2/%s/blobs/uploads/%s" % (m.group(1), upload), "Range": "0-0",
                                     "Docker-Upload-UUID": upload})

        m = re.fullmatch(r"/v2/(%s)/blobs/uploads/([0-9a-f]{32})" % NAME, path)
        if m and method in ("PATCH", "PUT"):
            partial = os.path.join(ROOT, "uploads", m.group(2))
            if not os.path.exists(partial):
                self.take_body()
                return self.problem(404, "BLOB_UPLOAD_UNKNOWN")
            self.take_body(partial)
            size = os.path.getsize(partial)
            if method == "PATCH":
                return self.answer(202, {"Location": path, "Range": "0-%d" % max(size - 1, 0), "Docker-Upload-UUID": m.group(2)})
            digest = args.get("digest", "")
            h = hashlib.sha256()
            with open(partial, "rb") as f:
                for piece in iter(lambda: f.read(1 << 20), b""):
                    h.update(piece)
            if not re.fullmatch(DIGEST, digest) or "sha256:" + h.hexdigest() != digest:
                os.unlink(partial)
                return self.problem(400, "DIGEST_INVALID")
            os.replace(partial, blob_path(digest))
            return self.answer(201, {"Location": "/v2/%s/blobs/%s" % (m.group(1), digest), "Docker-Content-Digest": digest})

        m = re.fullmatch(r"/v2/(%s)/manifests/([A-Za-z0-9_.:-]+)" % NAME, path)
        if m and method == "PUT":
            data = b"".join(self.body())
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            for reference in {m.group(2), digest}:
                os.makedirs(os.path.dirname(manifest_path(m.group(1), reference)), exist_ok=True)
                with open(manifest_path(m.group(1), reference), "wb") as f:
                    f.write(data)
            return self.answer(201, {"Location": "/v2/%s/manifests/%s" % (m.group(1), digest), "Docker-Content-Digest": digest})
        if m and method == "GET":
            if not os.path.exists(manifest_path(m.group(1), m.group(2))):
                return self.problem(404, "MANIFEST_UNKNOWN")
            with open(manifest_path(m.group(1), m.group(2)), "rb") as f:
                data = f.read()
            kind = json.loads(data).get("mediaType", "application/vnd.oci.image.manifest.v1+json")
            return self.answer(200, {"Content-Type": kind, "Docker-Content-Digest": "sha256:" + hashlib.sha256(data).hexdigest()}, data)

        self.take_body()
        return self.problem(404, "UNSUPPORTED")

    do_GET = do_HEAD = do_POST = do_PATCH = do_PUT = route


server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
with open(PORT_FILE + ".new", "w") as f:
    f.write("%d\n" % server.server_address[1])
os.replace(PORT_FILE + ".new", PORT_FILE)
server.serve_forever()
