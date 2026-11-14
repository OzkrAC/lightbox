#!/usr/bin/env bash
#
# Seccomp profile suite (ROADMAP 0.5). Unprivileged.
#
#   tests/seccomp_cases.sh <seccomp_profile harness> [<threaded test program>]
#   V=1 tests/seccomp_cases.sh ...            show the output of every case
#
# The harness is built from lightbox.c and installs lightbox's real profile.
# "probe" calls every syscall of the deny table before and after the profile is
# installed and prints
#
#   deny <nr> <documented errno> <returned before> <returned after>
#   x32 <returned before> <returned after>
#   clone_newuser <returned before> <returned after>
#
# where a return is the raw value (a negative errno on failure) or "killed".
# The case runner (check, xfail, summary) is tests/lib.sh.

set -u

HARNESS=${1:?usage: seccomp_cases.sh <seccomp_profile harness> [<threaded test program>]}
THREADED=${2:-}
if [ ! -x "$HARNESS" ]; then
    echo "seccomp: $HARNESS is not an executable; run make test-seccomp" >&2
    exit 2
fi
HERE=$(cd "$(dirname "$0")" && pwd)

. "$HERE/lib.sh"

EPERM=1 ENOSYS=38

# The profile is written for one architecture. On any other its first rule
# kills every syscall, so nothing below can run.
t_architecture_supported() {
    [ "$(uname -m)" = x86_64 ] && return 0
    echo "the deny table holds x86_64 numbers and the filter kills every other architecture"
    return 1
}
if [ "$(uname -m)" != x86_64 ]; then
    xfail SB-seccomp-arch 'the profile supports this architecture' t_architecture_supported
    summary seccomp
    exit $?
fi

PROBE=$("$HARNESS" probe 2>&1)
probe_status=$?

# name of a syscall number, from the comments of the table in lightbox.c
name_of() {
    sed -n "s/^ *{ *$1, *SC_[A-Z]* *}, *\/\* \([a-z0-9_]*\).*/\1/p" "$HERE/../lightbox.c" | head -1
}

t_probe_ran() {
    [ $probe_status -eq 0 ] && printf '%s\n' "$PROBE" | grep -q '^deny ' && return 0
    echo "the harness exited with $probe_status:"
    printf '%s\n' "$PROBE" | head -5
    return 1
}

t_program_runs() {
    result=$("$HARNESS" run "$(command -v sh)" -c 'echo under-the-profile; ls / >/dev/null') || return 1
    [ "$result" = under-the-profile ]
}

# Every entry of the table returns the errno the table documents.
t_documented_errno() {
    printf '%s\n' "$PROBE" | awk '
        $1 == "deny" { total++
                       if ($5 != -$3) { bad++; printf "syscall %s returned %s, the table says -%s\n", $2, $5, $3 }
                       if ($4 != $5) shown++ }
        END { printf "%d entries; for %d the return changed when the profile was installed\n", total, shown
              exit (bad > 0 || total == 0) }'
}

# glibc 2.34 and later create threads with clone3 and fall back to clone only
# when clone3 answers ENOSYS. Any other errno fails pthread_create.
t_clone3_enosys() {
    line=$(printf '%s\n' "$PROBE" | awk '$1 == "deny" && $2 == 435')
    [ -n "$line" ] || { echo "clone3 (435) is not in the table"; return 1; }
    echo "clone3 returned $(echo "$line" | awk '{print $5}') under the profile, -$ENOSYS is needed"
    [ "$(echo "$line" | awk '{print $5}')" = "-$ENOSYS" ]
}

t_threaded_program_runs() {
    [ -n "$THREADED" ] && [ -x "$THREADED" ] || { echo "no threaded test program was built"; return 77; }
    "$THREADED" >/dev/null 2>&1 || { echo "the threaded program fails even without the profile"; return 77; }
    "$HARNESS" run "$THREADED"
}

# x32 system calls carry bit 30 in the number. A table of plain x86_64 numbers
# does not match them, so the filter has to refuse the whole range.
t_x32_refused() {
    set -- $(printf '%s\n' "$PROBE" | awk '$1 == "x32" { print $2, $3 }')
    [ $# -eq 2 ] || { echo "the harness printed no x32 line"; return 1; }
    if [ "$1" = "-$ENOSYS" ]; then
        echo "this kernel has no x32 ABI, so the filter's answer cannot be observed"
        return 77
    fi
    echo "x32 personality returned $1 before and $2 under the profile"
    [ "$2" = killed ] || [ "$2" -lt 0 ]
}

# unshare and clone3 are denied, so clone must not create namespaces either.
t_clone_namespace_flag_refused() {
    set -- $(printf '%s\n' "$PROBE" | awk '$1 == "clone_newuser" { print $2, $3 }')
    [ $# -eq 2 ] || { echo "the harness printed no clone_newuser line"; return 1; }
    if [ "$1" != 1 ]; then
        echo "this host refuses unprivileged user namespaces ($1), so the filter's answer cannot be observed"
        return 77
    fi
    echo "clone with CLONE_NEWUSER returned $2 under the profile"
    [ "$2" = killed ] || [ "$2" -lt 0 ]
}

check 'the harness installs the profile and probes the table' t_probe_ran
check 'an ordinary program runs under the profile'             t_program_runs
check 'every denied syscall returns the documented errno'      t_documented_errno

check 'clone3 is answered with ENOSYS'                          t_clone3_enosys
check 'a program that starts a thread runs under the profile'  t_threaded_program_runs

xfail SB-seccomp-x32  'x32 syscall numbers are refused'            t_x32_refused
xfail SB-clone-flags  'clone with a namespace flag is refused'     t_clone_namespace_flag_refused

if [ "${V:-0}" = 1 ]; then
    printf '\nprobe output (number, name, documented errno, before, after):\n'
    printf '%s\n' "$PROBE" | while read -r kind nr rest; do
        if [ "$kind" = deny ]; then printf '  %-4s %-20s %s\n' "$nr" "$(name_of "$nr")" "$rest"
        else printf '  %s %s %s\n' "$kind" "$nr" "$rest"; fi
    done
fi

summary seccomp
