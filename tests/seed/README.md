# Review seed scripts

These are the scripts the November 2026 review used to produce every finding
marked "ran" in `ROADMAP.md`. They are kept as evidence (ROADMAP Step 0) and as
the starting point for the real suites.

| File | What it did | Superseded by |
| --- | --- | --- |
| `functional.sh` | Twelve unprivileged checks (T1 to T12) of the create, add-vol, ls, inspect and config paths | `tests/validation.sh` (ROADMAP 0.4) |
| `seccomp_compat.c` | Applies lightbox's own `apply_seccomp()` and runs an ordinary program under it | `tests/seccomp_profile.c` (ROADMAP 0.5) |
| `run_static.sh` | Compiles each source file with `-fanalyzer`, a strict warning set and the conversion warnings | `make analyze` (ROADMAP 0.3) |
| `check_roadmap.py` | Re-checks `ROADMAP.md`: links, ledger against items, counts, totals and `file:line` references | still current |

`functional.sh`, `seccomp_compat.c` and `run_static.sh` are verbatim copies.
They refer to the review's temporary directory and will not run as they are;
read them for what each check does. `check_roadmap.py` was changed in three
places: it finds the repository from its own location; it checks the
roadmap's `file:line` references against the commit the roadmap names as its
baseline, not against the files as they are now; and it knows Phase 8 and
checks the subtotal rows of the at-a-glance table. Run it after editing the
roadmap:

```
python3 -I tests/seed/check_roadmap.py
```
