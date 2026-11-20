#!/usr/bin/env bash
#
# Seccomp profile suite (ROADMAP 0.5 and 2.4). Unprivileged.
#
#   tests/seccomp_cases.sh <seccomp_profile harness> [<threaded test program>]
#   V=1 tests/seccomp_cases.sh ...            show the output of every case
#
# The harness is built from lightbox.c and installs lightbox's real profile.
# "probe" calls every syscall of the deny table before and after the profile is
# installed and prints
#
#   deny <nr> <documented errno> <returned before> <returned after>
#   x32 <returned before> <returned after>              (x86_64 only)
#   clone_newuser <returned before> <returned after>
#   clone_plain <returned before> <returned after>
#
# where a return is the raw value (a negative errno on failure) or "killed".
# "modes <dir>" makes the calls that set a file's mode, with the setuid or
# setgid bit and without, before and under the profile, and prints
#
#   mode <call> refused|allowed <returned before> <returned after>
#
# Next to the harness, seccomp_filter_x86_64 and seccomp_filter_aarch64 hold the
# program of each architecture and interpret it, so both are checked here
# whatever machine this is.
#
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
MACHINE=$(uname -m)

# The program of one architecture, interpreted: every syscall number, the
# foreign ABIs, the x32 range, clone with and without namespace flags, and
# every bit of the mode of the calls that set one.
t_interpreted() {
    prog="$(dirname "$HARNESS")/seccomp_filter_$1"
    [ -x "$prog" ] || { echo "$prog was not built (no hosted compiler?)"; return 77; }
    "$prog"
}
t_interpreted_x86_64()  { t_interpreted x86_64; }
t_interpreted_aarch64() { t_interpreted aarch64; }

PROBE=$("$HARNESS" probe 2>&1)
probe_status=$?

# name of a syscall number on this machine, from the table in lightbox_seccomp.h
name_of() {
    if [ "$MACHINE" = x86_64 ]; then
        sed -n "s/^ *X(\([a-z0-9_]*\), *$1,.*/\1/p" "$HERE/../lightbox_seccomp.h" | head -1
    else
        sed -n "s/^ *X(\([a-z0-9_]*\), *[0-9]*, *$1, *LB_.*/\1/p" "$HERE/../lightbox_seccomp.h" | head -1
    fi
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
# does not match them, so the filter refuses the whole range with EPERM. The
# filter answers before the kernel looks the number up, so this shows on a
# kernel without the x32 ABI too: there the call returns ENOSYS until the
# profile is installed.
t_x32_refused() {
    [ "$MACHINE" = x86_64 ] || { echo "x32 exists on x86_64 only"; return 77; }
    set -- $(printf '%s\n' "$PROBE" | awk '$1 == "x32" { print $2, $3 }')
    [ $# -eq 2 ] || { echo "the harness printed no x32 line"; return 1; }
    echo "x32 personality returned $1 before and $2 under the profile, -$EPERM is needed"
    [ "$1" != "-$EPERM" ] && [ "$2" = "-$EPERM" ]
}

# unshare and clone3 are denied, so clone must not create namespaces either.
t_clone_namespace_flag_refused() {
    set -- $(printf '%s\n' "$PROBE" | awk '$1 == "clone_newuser" { print $2, $3 }')
    [ $# -eq 2 ] || { echo "the harness printed no clone_newuser line"; return 1; }
    if [ "$1" != 1 ]; then
        echo "this host refuses unprivileged user namespaces ($1), so the filter's answer cannot be observed"
        return 77
    fi
    echo "clone with CLONE_NEWUSER returned $2 under the profile, -$EPERM is needed"
    [ "$2" = "-$EPERM" ]
}

# ... while clone without one keeps working: it is how processes are made.
t_plain_clone_allowed() {
    set -- $(printf '%s\n' "$PROBE" | awk '$1 == "clone_plain" { print $2, $3 }')
    [ $# -eq 2 ] || { echo "the harness printed no clone_plain line"; return 1; }
    echo "plain clone returned $1 before and $2 under the profile"
    [ "$1" = 1 ] && [ "$2" = 1 ]
}

# The calls that set a mode refuse the setuid and setgid bits with EPERM, and
# take a mode without them; an open that makes nothing uses no mode, and the
# kernel takes neither bit from a mkdir's, so both are allowed with either
# (ROADMAP 8.2). Nothing made under the profile has either bit. Before it,
# fchmodat2 may be missing (ENOSYS) and O_TMPFILE unsupported (EOPNOTSUPP);
# the profile answers before the kernel looks, so they are refused all the same.
t_mode_bits_refused() {
    local dir out bad made n
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-seccomp.XXXXXX") || return 1
    mkdir "$dir/before" "$dir/after" || return 1
    out=$("$HARNESS" modes "$dir" 2>&1)
    printf '%s\n' "$out"
    bad=$(printf '%s\n' "$out" | awk '
        $1 != "mode"                       { print "not a line of the probe: " $0; next }
        $4 != 0 && $4 != -38 && $4 != -95  { print $2 " failed before the profile: " $4; next }
        $3 == "refused" && $5 != -1        { print $2 " with a bit returned " $5 " under the profile, -1 is needed" }
        $3 == "allowed" && $5 != $4        { print $2 " returned " $4 " before the profile and " $5 " under it" }')
    made=$(find "$dir/after" -perm /6000)
    n=$(printf '%s\n' "$out" | grep -c '^mode ')
    rm -rf -- "$dir"
    [ -n "$made" ] && echo "made with a setuid or setgid bit under the profile: $made"
    [ -n "$bad" ] && printf '%s\n' "$bad"
    echo "$n calls made"
    [ -z "$bad" ] && [ -z "$made" ] && [ "$n" -ge 16 ]
}

check 'the x86_64 program gives the right verdict for every syscall number'  t_interpreted_x86_64
check 'the aarch64 program gives the right verdict for every syscall number' t_interpreted_aarch64

check 'the harness installs the profile and probes the table' t_probe_ran
check 'an ordinary program runs under the profile'             t_program_runs
check 'every denied syscall returns the documented errno'      t_documented_errno

check 'clone3 is answered with ENOSYS'                          t_clone3_enosys
check 'a program that starts a thread runs under the profile'  t_threaded_program_runs

check 'x32 syscall numbers are refused'                         t_x32_refused
check 'clone with a namespace flag is refused'                  t_clone_namespace_flag_refused
check 'clone without a namespace flag still works'              t_plain_clone_allowed
check 'no call makes a file setuid or setgid, and a plain mode is taken' t_mode_bits_refused

if [ "${V:-0}" = 1 ]; then
    printf '\nprobe output (number, name, documented errno, before, after):\n'
    printf '%s\n' "$PROBE" | while read -r kind nr rest; do
        if [ "$kind" = deny ]; then printf '  %-4s %-20s %s\n' "$nr" "$(name_of "$nr")" "$rest"
        else printf '  %s %s %s\n' "$kind" "$nr" "$rest"; fi
    done
fi

summary seccomp
