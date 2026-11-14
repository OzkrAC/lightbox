#!/usr/bin/env python3
"""Consistency checks for lightbox/ROADMAP.md: links, ledger <-> items, counts, totals, file:line refs."""
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

# tests/seed/check_roadmap.py -> repository root is two directories up.
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
text = open(os.path.join(REPO, "ROADMAP.md"), encoding="utf-8").read()
lines = text.split("\n")
problems = []
DAYS = {"XS": 0.5, "S": 1.5, "M": 5.0, "L": 12.5}
PHASES = ["0", "1", "2", "3", "4", "5", "6", "7", "8"]   # scheduled, in order
TRACKS = ["U", "M", "N"]                                 # the backlog


def anchor(title: str) -> str:
    """GitHub heading anchor: lowercase, drop everything but word chars, spaces and hyphens, spaces -> hyphens."""
    t = title.strip().lower()
    t = re.sub(r"[^\w\- ]", "", t, flags=re.UNICODE)
    return t.replace(" ", "-")


# ---- 1. links -----------------------------------------------------------------
anchors = Counter()
for ln in lines:
    m = re.match(r"^(#{1,6})\s+(.*)$", ln)
    if m:
        anchors[anchor(m.group(2))] += 1
for a, n in anchors.items():
    if n > 1:
        problems.append(f"duplicate heading anchor: #{a}")
links = re.findall(r"\]\(#([^)]+)\)", text)
for target in links:
    if target not in anchors:
        problems.append(f"broken link: #{target}")

# ---- 2. items (### N.M Title + header line) -------------------------------------
items = {}  # id -> dict(title, size, needs, closes=[(id, sev)])
for i, ln in enumerate(lines):
    m = re.match(r"^### ([0-9UMN]\.\d+) (.*)$", ln)
    if not m:
        continue
    iid, title = m.group(1), m.group(2)
    hdr = lines[i + 2] if lines[i + 1] == "" else lines[i + 1]
    hm = re.match(r"^\*\*(XS|S|M|L)\*\* · needs (.*?) · closes (.*)$", hdr)
    if not hm:
        problems.append(f"item {iid}: header line not in the expected form: {hdr!r}")
        continue
    closes = re.findall(r"([A-Z]+-[a-z0-9\-]+) \((high|medium|low|perf)\)", hm.group(3))
    if hm.group(3).strip() != "—" and not closes:
        problems.append(f"item {iid}: could not parse closes: {hm.group(3)!r}")
    items[iid] = dict(title=title, size=hm.group(1), needs=hm.group(2), closes=closes)

# ---- 3. ledger --------------------------------------------------------------------
ledger = {}  # id -> (sev, where, evidence, closed_by)
in_ledger = False
for ln in lines:
    if ln.startswith("## Appendix: finding ledger"):
        in_ledger = True
        continue
    if in_ledger and ln.startswith("## "):
        in_ledger = False
    if not in_ledger or not ln.startswith("| ") or ln.startswith("| Id") or ln.startswith("| ---"):
        continue
    cells = [c.strip() for c in ln.strip().strip("|").split("|")]
    if len(cells) != 6:
        problems.append(f"ledger row has {len(cells)} cells: {ln[:70]}")
        continue
    fid, sev, where, _finding, ev, closed = cells
    cm = re.match(r"^\[([0-9UMN]\.\d+)\]\(#([^)]+)\)$", closed)
    if not cm:
        problems.append(f"ledger {fid}: bad 'Closed by' cell {closed!r}")
        continue
    if fid in ledger:
        problems.append(f"ledger id listed twice: {fid}")
    ledger[fid] = (sev, where, ev, cm.group(1))
    it = items.get(cm.group(1))
    if it and cm.group(2) != anchor(f"{cm.group(1)} {it['title']}"):
        problems.append(f"ledger {fid}: link text {cm.group(1)} does not match its anchor")

closed_by_items = defaultdict(list)
for iid, it in items.items():
    for fid, sev in it["closes"]:
        closed_by_items[fid].append((iid, sev))
for fid, (sev, _w, _e, by) in ledger.items():
    got = closed_by_items.get(fid, [])
    if len(got) != 1:
        problems.append(f"{fid}: closed by {len(got)} items ({[g[0] for g in got]}), expected exactly 1")
        continue
    if got[0][0] != by:
        problems.append(f"{fid}: ledger says {by}, item header says {got[0][0]}")
    if got[0][1] != sev:
        problems.append(f"{fid}: ledger severity {sev}, item header says {got[0][1]}")
for fid in closed_by_items:
    if fid not in ledger:
        problems.append(f"{fid}: closed by an item but missing from the ledger")

sev_count = Counter(v[0] for v in ledger.values())
ev_count = Counter(v[2] for v in ledger.values())

# ---- 4. phase tables vs item headers; sizes and totals -------------------------------
phase_of = lambda iid: iid.split(".")[0]
per_phase_items = defaultdict(list)
for iid in items:
    per_phase_items[phase_of(iid)].append(iid)

table_rows = {}
for ln in lines:
    m = re.match(r"^\| ([0-9UMN]\.\d+) \| \[(.*?)\]\(#(.*?)\) \| (XS|S|M|L) \| (.*?) \| (.*?) \|$", ln)
    if m:
        table_rows[m.group(1)] = dict(title=m.group(2), anchor=m.group(3), size=m.group(4), needs=m.group(5), closes=m.group(6))
for iid, it in items.items():
    row = table_rows.get(iid)
    if not row:
        problems.append(f"item {iid} has no row in its phase table")
        continue
    if row["title"] != it["title"]:
        problems.append(f"item {iid}: table title differs from heading")
    if row["anchor"] != anchor(f"{iid} {it['title']}"):
        problems.append(f"item {iid}: table anchor wrong")
    if row["size"] != it["size"]:
        problems.append(f"item {iid}: table size {row['size']} vs header {it['size']}")
    if row["needs"] != it["needs"]:
        problems.append(f"item {iid}: table needs {row['needs']!r} vs header {it['needs']!r}")
    c = Counter(sev for _f, sev in it["closes"])
    want = ", ".join(f"{c[s]} {s}" for s in ("high", "medium", "low", "perf") if c[s]) or "—"
    if row["closes"] != want:
        problems.append(f"item {iid}: table closes {row['closes']!r}, header implies {want!r}")
for iid in table_rows:
    if iid not in items:
        problems.append(f"table row {iid} has no item section")

summary = {}
for ph, ids in per_phase_items.items():
    days = sum(DAYS[items[i]["size"]] for i in ids)
    c = Counter(sev for i in ids for _f, sev in items[i]["closes"])
    summary[ph] = (len(ids), days, c["high"], c["medium"], c["low"], c["perf"])

# 'needs' must reference items that exist (or lightc items / phase phrases)
for iid, it in items.items():
    for ref in re.findall(r"(?<![\w.])([0-9UMN]\.\d+)(?![\w.])", it["needs"]):
        if ref not in items:
            problems.append(f"item {iid}: needs unknown item {ref}")

# every item id mentioned anywhere in prose must exist
for ref in set(re.findall(r"(?<![\w.`/:\-])(?:\b)([1-8UMN]\.\d{1,2})(?![\w.])(?! d\b)", text)):
    pass  # informational only; version numbers make this too noisy to enforce

# ---- 5. at-a-glance rows vs computed summary ----------------------------------------
for ln in lines:
    m = re.match(r"^\| \[([0-8UMN])\]\(#.*?\) \| .*? \| (\d+) \| ([\d.]+) d \| (.*?) \|", ln)
    if not m:
        continue
    ph, n, d, closes = m.group(1), int(m.group(2)), float(m.group(3)), m.group(4).strip()
    got = summary.get(ph)
    if not got:
        problems.append(f"at a glance: phase {ph} has no items")
        continue
    if (n, d) != (got[0], got[1]):
        problems.append(f"at a glance {ph}: says {n} items / {d} d, computed {got[0]} / {got[1]}")
    if closes != "—":
        nums = tuple(int(x) for x in re.findall(r"\d+", closes))
        if nums != got[2:]:
            problems.append(f"at a glance {ph}: closes {nums}, computed {got[2:]}")
    elif any(got[2:]):
        problems.append(f"at a glance {ph}: says —, computed {got[2:]}")
for ph in PHASES + TRACKS:
    if ph not in summary:
        problems.append(f"phase {ph} has no items")
        summary[ph] = (0, 0.0, 0, 0, 0, 0)

# bold subtotal rows: | **Label** | | **N** | **D d (W weeks)** | **h / m / l / p** | |
tot = lambda ids: tuple(sum(summary[p][k] for p in ids) for k in range(6))
SUBTOTALS = {"Phases 0 to 7": PHASES[:8], "Before the backlog": PHASES, "Backlog": TRACKS}
seen_subtotals = set()
for ln in lines:
    m = re.match(r"^\| \*\*(.+?)\*\* \| \| \*\*(\d+)\*\* \| \*\*([\d.]+) d \(([\d.]+) weeks\)\*\* \| \*\*(.+?)\*\* \|", ln)
    if not m or m.group(1) not in SUBTOTALS:
        continue
    label = m.group(1)
    seen_subtotals.add(label)
    got = tot(SUBTOTALS[label])
    said = (int(m.group(2)), float(m.group(3))) + tuple(int(x) for x in re.findall(r"\d+", m.group(5)))
    if said != got:
        problems.append(f"at a glance subtotal {label!r}: says {said}, computed {got}")
    if abs(float(m.group(4)) - got[1] / 5) > 0.05:
        problems.append(f"at a glance subtotal {label!r}: says {m.group(4)} weeks, computed {got[1] / 5:.1f}")
for label in SUBTOTALS:
    if label not in seen_subtotals:
        problems.append(f"at a glance: no subtotal row {label!r}")

# phase header lines: **Ships:** ... · **Items:** N · **Work:** D d
cur = None
for ln in lines:
    hm = re.match(r"^## (?:Phase|Track) ([0-8UMN]) —", ln)
    if hm:
        cur = hm.group(1)
    m = re.match(r"^(?:\*\*Ships:\*\* .*? · )?\*\*Items:\*\* (\d+) · \*\*Work:\*\* ([\d.]+) d", ln)
    if m and cur:
        got = summary[cur]
        if (int(m.group(1)), float(m.group(2))) != (got[0], got[1]):
            problems.append(f"phase {cur} header: {m.group(1)} items / {m.group(2)} d, computed {got[0]} / {got[1]}")
    sm = re.match(r"^\*\*Size check:\*\* (.*)$", ln)
    if sm and cur:
        parts = re.findall(r"(\d+) (XS|S|M|L) \(([\d.]+) d\)", sm.group(1))
        c = Counter(items[i]["size"] for i in per_phase_items[cur])
        for cnt, size, d in parts:
            if int(cnt) != c[size] or abs(float(d) - c[size] * DAYS[size]) > 1e-9:
                problems.append(f"phase {cur} size check: {cnt} {size} ({d} d) vs computed {c[size]} ({c[size]*DAYS[size]} d)")
        if sum(int(p[0]) for p in parts) != len(per_phase_items[cur]):
            problems.append(f"phase {cur} size check does not cover all items")

# ---- 6. file:line references exist -----------------------------------------------------
# The roadmap's line numbers are to the commit its first lines name ("against `9dfe420`"),
# so they are checked against that commit, not against the files as they are now.
base = re.search(r"against `([0-9a-f]{7,40})`", text)
base = base.group(1) if base else None

def baseline_lines(f):
    """Line count of f at the roadmap's baseline commit, or -1 if it is not there."""
    if base:
        r = subprocess.run(["git", "-C", REPO, "show", f"{base}:{f}"], capture_output=True)
        if r.returncode == 0:
            return r.stdout.count(b"\n")
        if b"exists on disk, but not in" in r.stderr or b"does not exist in" in r.stderr:
            return -1
    p = os.path.join(REPO, f)   # no git, or no such commit: fall back to the working tree
    return sum(1 for _ in open(p, encoding="utf-8")) if os.path.exists(p) else -1

flen = {}
for ref in set(re.findall(r"`((?:lightbox[a-z_]*\.[ch]|Makefile|README\.md)):(\d+)(?:-(\d+))?`", text)):
    f, a, b = ref
    if f not in flen:
        flen[f] = baseline_lines(f)
    if flen[f] < 0:
        problems.append(f"reference to missing file {f}")
    elif int(b or a) > flen[f] or (b and int(b) < int(a)):
        problems.append(f"reference out of range: {f}:{a}{'-' + b if b else ''} (file has {flen[f]} lines)")

# ---- report -----------------------------------------------------------------------------
print("phase  items   days   high/med/low/perf")
for ph in PHASES + TRACKS:
    n, d, h, m_, l, p = summary[ph]
    print(f"  {ph:<4} {n:>5} {d:>6}   {h} / {m_} / {l} / {p}")
for name, ids in (("0-7", PHASES[:8]), ("0-8", PHASES), ("UMN", TRACKS)):
    print(f"  {name:<4}", tot(ids), f"= {tot(ids)[1] / 5:.1f} weeks")
cum = 0
print("cumulative weeks:", end=" ")
for ph in PHASES:
    cum += summary[ph][1]
    print(f"{ph}:{cum}d={cum / 5:.1f}w", end="  ")
print()
print(f"ledger: {len(ledger)} ids  severity={dict(sev_count)}  evidence={dict(ev_count)}")
print(f"items: {len(items)}   links checked: {len(links)}   file:line refs checked: {len(re.findall(chr(96) + r'(?:lightbox[a-z_]*\.[ch]|Makefile|README\.md):\d+', text))}")
print(f"document: {len(lines)} lines")
if problems:
    print(f"\n{len(problems)} PROBLEM(S):")
    for p in problems:
        print("  -", p)
    sys.exit(1)
print("\nOK: no inconsistencies found")
