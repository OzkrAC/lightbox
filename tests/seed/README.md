# Review seed scripts

These are the scripts the November 2026 review used to produce every finding
marked "ran" in `ROADMAP.md`. They are kept as evidence (ROADMAP Step 0) and as
the starting point for the real suites.

| File | What it did | Superseded by |
| --- | --- | --- |
| `functional.sh` | Twelve unprivileged checks (T1 to T12) of the create, add-vol, ls, inspect and config paths | `tests/validation.sh` (ROADMAP 0.4) |
| `seccomp_compat.c` | Applies lightbox's own `apply_seccomp()` and runs an ordinary program under it | `tests/seccomp_profile.c` (ROADMAP 0.5) |
| `run_static.sh` | Compiles each source file with `-fanalyzer`, a strict warning set and the conversion warnings | `make analyze` (ROADMAP 0.3) |

`functional.sh`, `seccomp_compat.c` and `run_static.sh` are verbatim copies.
They refer to the review's temporary directory and will not run as they are;
read them for what each check does.
