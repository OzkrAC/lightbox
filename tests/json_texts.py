#!/usr/bin/env python3
"""lightbox's JSON reader (ROADMAP I.4) against Python's, which is held as strictly here: no name twice in
an object, no NaN and no Infinity, no half of a surrogate pair, no U+0000, no more than 32 arrays and
objects inside one another. The texts are JSON written in every way it may be, such texts with bytes taken
out, put in and changed, and pieces put together at random. For each of them the two have to agree on
whether it is read, and for one that is on the value at every path, which "unit json-read" prints.

    json_texts.py <unit harness> <work directory> <how many> [<seed>]
"""
import json
import os
import random
import re
import subprocess
import sys

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

UNIT, WORK, COUNT = sys.argv[1], sys.argv[2], int(sys.argv[3])
rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
TEXT_MAX = 1 << 20
DEPTH_MAX = 32


class Refused(Exception):
    pass


class Obj:
    def __init__(self, pairs):
        self.pairs = pairs


class Num:
    def __init__(self, text):
        self.text = text


def pairs_once(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Refused("twice")
        seen.add(k)
    return Obj(pairs)


def no_constant(c):
    raise Refused("constant")


def held(v, depth=0):
    """what Python takes and this reader is to refuse: half a surrogate pair, U+0000, too deep"""
    if isinstance(v, str):
        if any(0xD800 <= ord(c) <= 0xDFFF or c == "\0" for c in v):
            raise Refused("character")
    elif isinstance(v, list):
        if depth == DEPTH_MAX:
            raise Refused("deep")
        for e in v:
            held(e, depth + 1)
    elif isinstance(v, Obj):
        if depth == DEPTH_MAX:
            raise Refused("deep")
        for k, e in v.pairs:
            held(k)
            held(e, depth + 1)


def reference(data):
    if len(data) > TEXT_MAX:
        return None
    try:
        text = data.decode("utf-8", errors="strict")
        v = json.loads(text, object_pairs_hook=pairs_once, parse_constant=no_constant, parse_int=Num, parse_float=Num)
        held(v)
    except (ValueError, Refused, RecursionError):
        return None
    return (v,)


def fold(s):
    return "".join("s" if c == "ſ" else "k" if c == "K" else c.lower() if c.isascii() else c for c in s)


def kind(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, Num):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    return "object"


def said(v):
    k = kind(v)
    if k == "string":
        b = v.encode("utf-8")
        return b"string " + (b if len(b) < 65536 else b"(cannot be given)") + b"\n"
    if k == "number":
        whole = re.fullmatch(r"0|[1-9][0-9]*", v.text) and int(v.text) < 1 << 64
        return ("number %s%s\n" % (v.text, " whole" if whole else "")).encode()
    if k == "array":
        return ("array %d\n" % len(v)).encode() + b"".join(b"  " + kind(e).encode() + b"\n" for e in v)
    if k == "object":
        out = ("object %d\n" % len(v.pairs)).encode()
        for name, e in v.pairs:
            n = name.encode("utf-8")
            out += b"  " + (n if len(n) < 65536 else b"(cannot be given)") + b": " + kind(e).encode() + b"\n"
        return out
    return k.encode() + b"\n"


def lookup(root, tokens):
    v = root
    for t in tokens:
        if isinstance(v, Obj):
            hit, found = None, False
            for k, e in v.pairs:
                if k == t:
                    hit, found = e, True
                elif fold(k) == fold(t):
                    return b"other case\n"
            if not found:
                return b"none\n"
            v = hit
        elif isinstance(v, list):
            if not re.fullmatch(r"0|[1-9][0-9]{0,18}", t) or int(t) >= len(v):
                return b"none\n"
            v = v[int(t)]
        else:
            return b"none\n"
    return said(v)


def paths(v, at=()):
    yield at
    if isinstance(v, list):
        for i, e in enumerate(v):
            yield from paths(e, at + (str(i),))
    elif isinstance(v, Obj):
        for k, e in v.pairs:
            yield from paths(e, at + (k,))


def pointer(tokens):
    return "".join("/" + t.replace("~", "~0").replace("/", "~1") for t in tokens)


# ── texts ──

NAMES = ["a", "A", "b", "layers", "Layers", "layerſ", "digest", "si/ze", "m~n", "", "0", "1", "k", "K",
         "é", "é", "\U0001f600", "x y", "~1", "a.b", "ſ", "K", "s", "S", "\"", "\\"]
CHARS = ["a", "Z", "0", " ", "\"", "\\", "/", "\b", "\f", "\n", "\r", "\t", "\u007f", "\u0080", "é", "߿",
         "ࠀ", "￿", "\U00010000", "\U0010ffff", " ", "~", "\u0001", "\u001f"]


def a_string():
    if rng.random() < 0.5:
        return rng.choice(NAMES)
    return "".join(rng.choice(CHARS) for _ in range(rng.randrange(0, 6)))


def written_string(s):
    out = ['"']
    for c in s:
        o = ord(c)
        how = rng.random()
        if c in '"\\' or o < 0x20:
            short = {"\"": "\\\"", "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
            if c in short and how < 0.7:
                out.append(short[c])
            else:
                out.append("\\u%04x" % o)
        elif c == "/" and how < 0.5:
            out.append("\\/")
        elif how < 0.15:
            if o >= 0x10000:
                o -= 0x10000
                out.append(("\\u%04x\\u%04X" if how < 0.07 else "\\u%04X\\u%04x") % (0xD800 + (o >> 10), 0xDC00 + (o & 0x3FF)))
            else:
                out.append(("\\u%04x" if how < 0.07 else "\\u%04X") % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def blank():
    return "".join(rng.choice(" \t\n\r") for _ in range(rng.choice([0, 0, 0, 1, 2])))


NUMBERS = ["0", "-0", "1", "7", "10", "123456789", "18446744073709551615", "18446744073709551616", "-1", "1.5",
           "0.0", "1e3", "1E+3", "2e-2", "-12.5e10", "99999999999999999999999"]


def written(depth):
    r = rng.random()
    if depth > 3 or r < 0.3:
        r = rng.random()
        if r < 0.4:
            return written_string(a_string())
        if r < 0.7:
            return rng.choice(NUMBERS)
        return rng.choice(["true", "false", "null"])
    if r < 0.6:
        return "[" + ",".join(blank() + written(depth + 1) + blank() for _ in range(rng.randrange(0, 4))) + blank() + "]"
    members = []
    for _ in range(rng.randrange(0, 5)):
        members.append(blank() + written_string(a_string()) + blank() + ":" + blank() + written(depth + 1) + blank())
    return "{" + ",".join(members) + blank() + "}"


PIECES = [b"{", b"}", b"[", b"]", b",", b":", b'"', b"\\", b"u", b"0", b"1", b"9", b"-", b"+", b".", b"e", b"E", b" ",
          b"\n", b"\t", b"\r", b"true", b"false", b"null", b"a", b"d", b"D", b"8", b"c", b"\xc3\xa9", b"\xc0", b"\x80",
          b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xef\xbb\xbf", b"\x00", b"\x1f", b"\x7f", b"\\ud83d", b"\\ude00",
          b"\\u0000", b"\\u00e9", b'"a"', b'"a":', b"NaN", b"Infinity", b"\x0b", b"\x0c", b"/", b"*", b"'", b"\xe2\x80\xa8"]


def changed(data):
    data = bytearray(data)
    for _ in range(rng.choice([1, 1, 1, 2, 3])):
        how = rng.random()
        at = rng.randrange(0, len(data) + 1)
        if how < 0.35 and data:
            del data[min(at, len(data) - 1)]
        elif how < 0.7:
            data[at:at] = rng.choice(PIECES)
        elif data:
            at = min(at, len(data) - 1)
            data[at:at + 1] = rng.choice(PIECES)
    return bytes(data)


def a_text():
    r = rng.random()
    if r < 0.35:
        return (blank() + written(0) + blank()).encode("utf-8")
    if r < 0.85:
        return changed((blank() + written(0) + blank()).encode("utf-8"))
    return b"".join(rng.choice(PIECES) for _ in range(rng.randrange(0, 12)))


def some_tokens():
    """a path that may or may not be there"""
    tokens = []
    for _ in range(rng.randrange(1, 4)):
        tokens.append(rng.choice(NAMES + ["0", "1", "2", "00", "-", "01", "18446744073709551616"]))
    return tuple(tokens)


def one(data):
    path = os.path.join(WORK, "text.json")
    with open(path, "wb") as f:
        f.write(data)
    want = reference(data)
    if want is None:
        got = subprocess.run([UNIT, "json-read", path], capture_output=True)
        if got.returncode != 1 or not got.stdout.startswith(b"refused: "):
            return "Python refuses it, and the reader said %r (status %d)" % (got.stdout[:200], got.returncode)
        return None
    root = want[0]
    every = [p for p in paths(root)]
    if len(every) > 60:
        every = rng.sample(every, 60)
    every += [some_tokens() for _ in range(6)]
    every = [p for p in every if "\0" not in pointer(p)]
    expected = b"ok\n" + b"".join(lookup(root, p) for p in every)
    got = subprocess.run([UNIT, "json-read", path] + [pointer(p) for p in every], capture_output=True)
    if got.returncode != 0 or got.stdout != expected:
        at = 0
        while at < min(len(expected), len(got.stdout)) and expected[at] == got.stdout[at]:
            at += 1
        return "values differ at byte %d of the output (status %d):\n  wanted %r\n  got    %r\n  paths %r" % (
            at, got.returncode, expected[max(0, at - 60):at + 120], got.stdout[max(0, at - 60):at + 120],
            [pointer(p) for p in every][:12])
    return None


taken = refused = 0
for n in range(COUNT):
    data = a_text()
    wrong = one(data)
    if reference(data) is None:
        refused += 1
    else:
        taken += 1
    if wrong:
        print("text %d: %r\n  %s" % (n, data[:400], wrong))
        keep = os.path.join(WORK, "wrong-%d.json" % n)
        with open(keep, "wb") as f:
            f.write(data)
        sys.exit(1)
print("%d texts: %d taken with every value the same, %d refused by both" % (COUNT, taken, refused))
