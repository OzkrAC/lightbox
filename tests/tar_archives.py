#!/usr/bin/env python3
"""
Archives for the unit cases of the tar reader (ROADMAP I.3).

    tar_archives.py <directory> <a path outside the directory that is unpacked into>

writes <name>.tar into the directory for every archive below. Each is put
together byte by byte, so that it is exactly what its case is about: most of
them are archives no tar program writes, and the reader has to say so. What
the reader has to say of each is in tests/unit_cases.sh, not here.
"""
import sys


def field(value, width):
    """A header's field: text as it is, a number as octal digits and a NUL."""
    if isinstance(value, bytes):
        return value.ljust(width, b"\0")[:width]
    return b"%0*o\0" % (width - 1, value)


def base256(value, width):
    """A number as GNU tar writes one that octal digits cannot hold."""
    if value >= 0:
        return b"\x80" + value.to_bytes(width - 1, "big")
    return (value & ((1 << (8 * width)) - 1)).to_bytes(width, "big")


def header(name, kind=b"0", size=0, link=b"", mode=0o644, uid=0, gid=0, mtime=1000000000,
           magic=b"ustar\x0000", prefix=b"", checksum=None):
    block = bytearray(512)

    def put(at, data):
        block[at:at + len(data)] = data

    put(0, name[:100])
    put(100, field(mode, 8))
    put(108, field(uid, 8))
    put(116, field(gid, 8))
    put(124, field(size, 12))
    put(136, field(mtime, 12))
    put(148, b" " * 8)
    put(156, kind)
    put(157, link[:100])
    put(257, magic)
    put(345, prefix[:155])
    put(148, b"%06o\0 " % (sum(block) if checksum is None else checksum))
    return bytes(block)


def body(data):
    return data + b"\0" * (-len(data) % 512)


def file(name, data=b"", **more):
    return header(name, size=len(data), **more) + body(data)


def directory(name, **more):
    return header(name, kind=b"5", mode=more.pop("mode", 0o755), **more)


def symlink(name, target, **more):
    return header(name, kind=b"2", link=target, mode=0o777, **more)


def second_name(name, first, **more):
    return header(name, kind=b"1", link=first, **more)


def records(pairs):
    """pax records, each "<length> <key>=<value>" and a newline, the length counting itself."""
    out = b""
    for key, value in pairs:
        rest = b" " + key + b"=" + value + b"\n"
        length = len(rest) + 1
        while len(str(length)) + len(rest) != length:
            length = len(str(length)) + len(rest)
        out += str(length).encode() + rest
    return out


def pax(pairs, kind=b"x"):
    data = pairs if isinstance(pairs, bytes) else records(pairs)
    return header(b"././@PaxHeader", kind=kind, size=len(data)) + body(data)


def gnu_long(kind, text):
    return header(b"././@LongLink", kind=kind, size=len(text) + 1, magic=b"ustar  \0") + body(text + b"\0")


END = b"\0" * 1024


def archives(outside):
    long_name = b"/".join([b"n" * 200] * 3) + b"/file"
    made = {
        # ── names that are refused ──
        "dotdot": file(b"../outside", b"x") + END,
        "dotdot-inside": directory(b"a/") + file(b"a/b/../../../outside", b"x") + END,
        "dotdot-pax": pax([(b"path", b"a/../../outside")]) + file(b"short", b"x") + END,
        "dotdot-long": gnu_long(b"L", b"a/../../outside") + file(b"short", b"x") + END,
        "absolute": file(b"/outside", b"x") + END,
        "absolute-outside": file(outside + b"/made", b"x") + END,
        "no-name": file(b"", b"x") + END,
        "unprintable": file(b"a\x1b[2Jb\n\x7f/../c", b"x") + END,
        "pax-name-too-long": pax([(b"path", b"p" * 5000)]) + file(b"short", b"x") + END,
        "long-name-too-long": header(b"././@LongLink", kind=b"L", size=5000, magic=b"ustar  \0") + body(b"q" * 5000)
                              + file(b"short", b"x") + END,

        # ── links: what is at a name is replaced, and nothing is reached through it ──
        "link-out": symlink(b"out", outside) + file(b"out/through", b"x") + END,
        "link-up": symlink(b"up", b"..") + file(b"up/through", b"inside\n") + END,
        "link-replaced": file(b"target", b"original\n") + symlink(b"s", b"target") + file(b"s", b"new\n")
                         + symlink(b"t", outside + b"/secret") + file(b"t", b"new too\n") + END,
        "second-name-dotdot": second_name(b"h", b"../secret") + END,
        "second-name-absolute": second_name(b"h", outside + b"/secret") + END,
        "second-name-through": symlink(b"up", b"..") + second_name(b"h", b"up/secret") + END,
        "second-name-of-directory": directory(b"d/") + second_name(b"h", b"d") + END,
        "second-name-of-link": symlink(b"l", b"nowhere") + second_name(b"h", b"l") + END,

        # ── what is counted and not made ──
        "devices": header(b"null", kind=b"3", mode=0o666) + header(b"disk", kind=b"4", mode=0o660)
                   + file(b"beside", b"x") + END,

        # ── archives that end too soon, or say what is not so ──
        "cut-in-content": (file(b"first", b"1") + file(b"big", b"b" * 2000))[:1024 + 512 + 700],
        "cut-in-header": (file(b"first", b"1") + file(b"second", b"2"))[:1024 + 200],
        "cut-before-end": file(b"only", b"1"),
        "cut-in-end": file(b"only", b"1") + END[:512],
        "cut-in-records": (file(b"first", b"1") + pax([(b"path", b"x" * 900)]))[:1024 + 512 + 100],
        "size-too-large": header(b"liar", size=4096) + body(b"x" * 512) + END,
        "size-too-small": header(b"liar", size=0) + body(b"x" * 512) + END,
        "empty": b"",
        "not-an-archive": b"this is no archive at all\n" * 100,
        "bad-checksum": header(b"file", checksum=1) + END,
        "zeros-then-entry": file(b"first", b"1") + END[:512] + file(b"second", b"2") + END,
        "more-after-end": file(b"only", b"1") + END + b"\0" * 512 + b"more" + b"\0" * 508,
        "bad-number": header(b"file", size=b"12z") + END,
        "blank-number": header(b"file", uid=b" " * 7) + END,
        "negative-size": header(b"file", size=base256(-1, 12)) + END,
        "kind": header(b"strange", kind=b"S") + END,
        "kind-volume": header(b"label", kind=b"V") + END,
        "pax-broken": pax(b"12 path=abc") + file(b"after", b"x") + END,
        "pax-length-lies": pax(b"99 path=abc\n") + file(b"after", b"x") + END,
        "pax-no-equals": pax(b"8 path\n\n") + file(b"after", b"x") + END,
        "pax-number": pax([(b"size", b"12x")]) + file(b"after", b"x") + END,
        "pax-name-with-nul": pax([(b"path", b"a\0b")]) + file(b"after", b"x") + END,
        "pax-sparse": pax([(b"GNU.sparse.major", b"1"), (b"GNU.sparse.minor", b"0")]) + file(b"holes", b"x") + END,
        "pax-too-many-records": header(b"././@PaxHeader", kind=b"x", size=5 << 20) + END,

        # ── ids ──
        "id-outside-range": file(b"in", b"x", uid=65535, gid=65535) + file(b"out", b"x", uid=65536) + END,
        "id-no-id": file(b"file", b"x", uid=base256(0xffffffff, 8)) + END,

        # ── marks of a layer that are none ──
        "mark-of-nothing": file(b".wh.") + END,
        "mark-of-dotdot": directory(b"d/") + file(b"d/.wh...") + END,
        "mark-of-dot": file(b".wh..") + END,
        "mark-aufs": file(b".wh..wh.plnk") + END,
        "mark-on-the-way": file(b"a/.wh.b/c") + END,
        "mark-directory": directory(b".wh.dir/") + END,
        "mark-link": symlink(b"d/.wh..wh..opq", b"x") + END,

        # ── what tar programs write, and this reader takes ──
        "pax-all": directory(b"dir/")
                   + pax([(b"path", long_name), (b"size", b"5"), (b"uid", b"1234"), (b"gid", b"4321"),
                          (b"mtime", b"1234567890.123456789"), (b"atime", b"1.5"), (b"comment", b"left"),
                          (b"SCHILY.xattr.user.note", b"with\0every\nbyte"),
                          (b"SCHILY.xattr.security.selinux", b"left"),
                          (b"SCHILY.xattr.trusted.overlay.opaque", b"y"),
                          (b"LIBARCHIVE.xattr.user.note", b"d2l0aA")])
                   + header(b"short", size=0, uid=1, gid=1) + body(b"12345")
                   + pax([(b"linkpath", b"t" * 300), (b"mtime", b"-1.25")]) + symlink(b"long-link", b"short")
                   + pax([(b"path", b"")]) + file(b"empty-record", b"e") + END,
        "global-records": pax([(b"comment", b"of the whole archive"), (b"path", b"not/this")], kind=b"g")
                          + file(b"file", b"f") + END,
        "gnu": gnu_long(b"L", long_name) + file(b"short", b"gnu\n", magic=b"ustar  \0")
               + gnu_long(b"K", b"t" * 300) + symlink(b"long-link", b"short", magic=b"ustar  \0")
               + header(b"numbers", size=base256(3, 12), uid=base256(1234, 8), gid=base256(4321, 8),
                        mtime=base256(-86400, 12), magic=b"ustar  \0") + body(b"abc") + END,
        "ustar-prefix": file(b"file", b"p", prefix=b"p" * 60 + b"/" + b"q" * 60)
                        + file(b"x" * 100, b"hundred", prefix=b"y" * 155) + END,
        "old": header(b"olddir/", kind=b"\0", mode=0o750, magic=b"")
               + header(b"olddir/file", kind=b"\0", size=3, magic=b"") + body(b"old")
               + header(b"contiguous", kind=b"7", size=1) + body(b"c") + END,
        "names": directory(b"./") + file(b"./a/./b//c", b"1") + directory(b"a/b/d/.") + file(b"a//b/d///e", b"2")
                 + directory(b".") + END,
        "missing-directories": file(b"p/q/r/file", b"deep") + second_name(b"s/t/second", b"p/q/r/file") + END,
        "replaced": directory(b"x/") + file(b"x/inner/file", b"1") + file(b"x", b"a file now\n")
                    + file(b"y", b"1") + directory(b"y/") + file(b"y/in", b"a directory now\n")
                    + directory(b"kept/", mode=0o700) + file(b"kept/first", b"1")
                    + directory(b"kept/", mode=0o750, mtime=1111111111) + END,
        "tape-record": file(b"only", b"1") + END + b"\0" * (10240 - 2048),

        # ── layers: one under, and ones whose marks are about it ──
        "layer-under": directory(b"d/") + file(b"d/low", b"low") + directory(b"d/sub/") + file(b"d/sub/low", b"low")
                       + directory(b"x/") + file(b"x/old", b"old") + file(b"gone", b"g") + directory(b"tree/")
                       + file(b"tree/a/b/c", b"c") + file(b"stays", b"s") + END,
        # the marks first, as most programs write them
        "layer-marks-first": directory(b"d/") + file(b"d/.wh..wh..opq") + file(b"d/own", b"own")
                             + directory(b"d/sub/") + file(b"d/sub/own", b"own")
                             + file(b".wh.x") + directory(b"x/") + file(b"x/new", b"new")
                             + file(b".wh.gone") + file(b".wh.tree") + file(b".wh.never-there")
                             + file(b"nowhere/.wh.at-all") + END,
        # and last: they are still about the layer under this one alone
        "layer-marks-last": directory(b"d/") + file(b"d/own", b"own") + directory(b"d/sub/")
                            + file(b"d/sub/own", b"own") + file(b"d/.wh..wh..opq")
                            + directory(b"x/") + file(b"x/new", b"new") + file(b".wh.x")
                            + file(b".wh.gone") + file(b".wh.tree") + file(b".wh.never-there")
                            + file(b"nowhere/.wh.at-all") + END,
        "layer-all-new": file(b"alone", b"a") + file(b".wh..wh..opq") + END,
    }
    return made


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    for name, data in archives(sys.argv[2].encode()).items():
        with open("%s/%s.tar" % (sys.argv[1], name), "wb") as out:
            out.write(data)


main()
