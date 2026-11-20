#!/usr/bin/env bash
#
# Seccomp profile suite (ROADMAP 0.5, 2.4, 8.2 and 8.3). Unprivileged.
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
# With --allow after the command, the harness installs the allow-list, and
# "probe --allow" also prints what a call the list does not name, a number
# past every table and socket and socketpair of some families returned:
#
#   unlisted <returned before> <returned after>
#   past <returned before> <returned after>
#   socket <family> <returned before> <returned after>
#   socketpair <family> <returned before> <returned after>
#
# The workload of tests/workload, what agents run, runs under both profiles.
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
# absolute: the workload runs in directories of its own
HARNESS="$(cd "$(dirname "$HARNESS")" && pwd)/$(basename "$HARNESS")"

. "$HERE/lib.sh"

EPERM=1 ENOSYS=38

# A program run under a profile that lacks what it needs may wait for ever,
# for a child it cannot reap: 120 seconds, and the case fails.
limited() {
    if command -v timeout >/dev/null 2>&1; then timeout -k 5 120 "$@"; else "$@"; fi
}
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
PROBE_ALLOW=$("$HARNESS" probe --allow 2>&1)
probe_allow_status=$?

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
    result=$(limited "$HARNESS" run "$(command -v sh)" -c 'echo under-the-profile; ls / >/dev/null') || return 1
    [ "$result" = under-the-profile ]
}

# Every entry of the table returns the errno the table documents.
t_documented_errno() { documented_errno "$PROBE"; }
documented_errno() {
    printf '%s\n' "$1" | awk '
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
    limited "$HARNESS" run "$THREADED"
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

# ─── The allow-list (ROADMAP 8.3) ──────────────────────────────────────────

t_allow_probe_ran() {
    [ $probe_allow_status -eq 0 ] && printf '%s\n' "$PROBE_ALLOW" | grep -q '^unlisted ' && return 0
    echo "the harness exited with $probe_allow_status:"
    printf '%s\n' "$PROBE_ALLOW" | head -5
    return 1
}

t_allow_program_runs() {
    result=$(limited "$HARNESS" run --allow "$(command -v sh)" -c 'echo under-the-allow-list; ls / >/dev/null') || return 1
    [ "$result" = under-the-allow-list ]
}

# The rows of the deny table answer what they do in the deny-list.
t_allow_documented_errno() { documented_errno "$PROBE_ALLOW"; }

# A call the list does not name answers ENOSYS, which it did not without the
# profile (vhangup: EPERM without CAP_SYS_TTY_CONFIG), and so does a number
# past every table.
t_allow_unlisted_enosys() {
    set -- $(printf '%s\n' "$PROBE_ALLOW" | awk '$1 == "unlisted" || $1 == "past" { print $2, $3 }')
    [ $# -eq 4 ] || { echo "the harness printed no unlisted or past line"; return 1; }
    echo "vhangup returned $1 before and $2 under the allow-list; number 1000 $3 and $4; -$ENOSYS is needed"
    [ "$1" != "-$ENOSYS" ] && [ "$2" = "-$ENOSYS" ] && [ "$4" = "-$ENOSYS" ]
}

# Under both profiles socket takes AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK,
# and socketpair AF_UNIX, as without a profile; any other family is
# EAFNOSUPPORT, as the kernel says of one it does not have: AF_PACKET, AF_ALG
# and AF_VSOCK here.
socket_families() { # the probe's output, the profile's name
    printf '%s\n' "$1" | awk -v eafnosupport=97 -v profile="$2" '
        $1 == "socket" || $1 == "socketpair" {
            n++
            taken = $1 == "socket" ? ($2 == 1 || $2 == 2 || $2 == 10 || $2 == 16) : ($2 == 1)
            printf "%s of family %s: %s before, %s under the %s\n", $1, $2, $3, $4, profile
            if (taken && $4 != $3) bad++
            if (!taken && $4 != -eafnosupport) bad++
        }
        END { exit (bad > 0 || n < 9) }'
}
t_socket_families()       { socket_families "$PROBE" deny-list; }
t_allow_socket_families() { socket_families "$PROBE_ALLOW" allow-list; }

# x32, clone with a namespace flag and a plain clone answer as in the deny-list.
t_allow_same_rules() {
    a=$(printf '%s\n' "$PROBE" | awk '$1 == "x32" || $1 ~ /^clone_/ { print $1, $3 }')
    b=$(printf '%s\n' "$PROBE_ALLOW" | awk '$1 == "x32" || $1 ~ /^clone_/ { print $1, $3 }')
    printf 'deny-list:  %s\nallow-list: %s\n' "$(printf '%s' "$a" | paste -sd' ')" "$(printf '%s' "$b" | paste -sd' ')"
    [ -n "$a" ] && [ "$a" = "$b" ]
}

# The calls that set a mode get the same answers under it as under the
# deny-list (ROADMAP 8.2).
t_allow_modes_same() {
    local dir a b
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-seccomp.XXXXXX") || return 1
    mkdir -p "$dir/deny/before" "$dir/deny/after" "$dir/allow/before" "$dir/allow/after" || return 1
    a=$("$HARNESS" modes "$dir/deny" 2>&1 | awk '{ print $2, $3, $5 }')
    b=$("$HARNESS" modes --allow "$dir/allow" 2>&1 | awk '{ print $2, $3, $5 }')
    rm -rf -- "$dir"
    printf '%s\n' "$b"
    [ -n "$a" ] && [ "$a" = "$b" ] || { echo "the deny-list answered:"; printf '%s\n' "$a"; return 1; }
}

t_allow_threaded_program_runs() {
    [ -n "$THREADED" ] && [ -x "$THREADED" ] || { echo "no threaded test program was built"; return 77; }
    "$THREADED" >/dev/null 2>&1 || { echo "the threaded program fails even without the profile"; return 77; }
    limited "$HARNESS" run --allow "$THREADED"
}

# The workload, in a directory of its own each time: without a profile, which
# has to work for the case to mean anything, then under the allow-list and
# under the deny-list.
WORKLOAD="$HERE/workload"
workload() { # tool, the shell command that runs it
    local tool=$1 script=$2 dir out profile rc=0
    command -v "$tool" >/dev/null 2>&1 || { echo "this host has no $tool"; return 77; }
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-workload.XXXXXX") || return 1
    mkdir "$dir/none" "$dir/allow" "$dir/deny" || return 1
    if ! out=$(cd "$dir/none" && limited sh -c "$script" 2>&1); then
        echo "it fails without a profile too:"
        printf '%s\n' "$out"
        rm -rf -- "$dir"
        return 77
    fi
    for profile in allow deny; do
        set -- run
        [ "$profile" = allow ] && set -- run --allow
        if out=$(cd "$dir/$profile" && limited "$HARNESS" "$@" "$(command -v sh)" -c "$script" 2>&1); then
            echo "under the $profile-list: $(printf '%s\n' "$out" | tail -n 1)"
        else
            echo "under the $profile-list it fails:"
            printf '%s\n' "$out"
            rc=1
        fi
    done
    rm -rf -- "$dir"
    return $rc
}
t_workload_git()    { workload git     "sh '$WORKLOAD/git.sh'"; }
t_workload_python() { workload python3 "python3 '$WORKLOAD/threads.py'"; }
t_workload_node()   { workload node    "node '$WORKLOAD/threads.js'"; }
t_workload_cc()     { workload cc      "cc -O2 -pthread -o hello '$WORKLOAD/hello.c' && ./hello"; }

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
check 'a socket is of a family agents use'                       t_socket_families

check 'the harness installs the allow-list and probes it'       t_allow_probe_ran
check 'an ordinary program runs under the allow-list'           t_allow_program_runs
check 'under the allow-list every denied syscall returns its errno' t_allow_documented_errno
check 'under the allow-list a call it does not name answers ENOSYS' t_allow_unlisted_enosys
check 'under the allow-list a socket is of a family agents use' t_allow_socket_families
check 'under the allow-list x32 and clone are as in the deny-list' t_allow_same_rules
check 'under the allow-list the calls that set a mode answer as in the deny-list' t_allow_modes_same
check 'a program that starts a thread runs under the allow-list' t_allow_threaded_program_runs
check 'git makes and clones a repository under both profiles'   t_workload_git
check 'Python starts threads and a child and uses sockets under both profiles' t_workload_python
check 'Node.js starts a worker and a child and uses a socket under both profiles' t_workload_node
check 'a C program is compiled, linked and run under both profiles' t_workload_cc

if [ "${V:-0}" = 1 ]; then
    printf '\nprobe output (number, name, documented errno, before, after):\n'
    printf '%s\n' "$PROBE" | while read -r kind nr rest; do
        if [ "$kind" = deny ]; then printf '  %-4s %-20s %s\n' "$nr" "$(name_of "$nr")" "$rest"
        else printf '  %s %s %s\n' "$kind" "$nr" "$rest"; fi
    done
fi

summary seccomp
