#!/usr/bin/env bash
#
# Unit suite (ROADMAP 3.1 and 1.2). Unprivileged. The mount cases work in a
# temporary directory, inside a user and mount namespace of their own.
#
#   tests/unit_cases.sh <unit harness>
#   V=1 tests/unit_cases.sh ...            show the output of every case
#
# The harness is built from lightbox.c and calls lightbox's own helpers. For
# the one that runs a program, which every tool invocation goes through, it
# prints "result <n>": the program's exit status, or 256 when no child could be
# made, 257 when the program could not be executed, 258 when a signal ended it
# and 259 when it could not be waited for. For the ones that mount, make
# directories and bring up loopback, "result 0" or "result -1". The sandbox's
# helpers end the process when they fail, as they do in a container.
#
# The case runner (check, xfail, summary) is tests/lib.sh.

set -u

UNIT=${1:?usage: unit_cases.sh <unit harness>}
if [ ! -x "$UNIT" ]; then
    echo "unit: $UNIT is not an executable; run make test-unit" >&2
    exit 2
fi
UNIT=$(cd "$(dirname "$UNIT")" && pwd)/$(basename "$UNIT")
HERE=$(cd "$(dirname "$0")" && pwd)

. "$HERE/lib.sh"

# the files, not the shell's builtins of the same name
SH=$(type -P sh)
TRUE=$(type -P true)
ENV=$(type -P env)

RUN_FORK_FAILED=256 RUN_EXEC_FAILED=257 RUN_SIGNALED=258

# the helper's verdict, from the harness's output
result_of() { printf '%s\n' "$1" | sed -n 's/^result //p'; }

# Run the harness and split what it wrote: sets $out (stdout) and $err (stderr).
# The programs used here do the same thing every time, so running twice is fine.
both() {
    out=$("$UNIT" "$@" 2>/dev/null)
    err=$("$UNIT" "$@" 2>&1 >/dev/null)
    echo "stdout: $out"
    echo "stderr: $err"
}

t_success() {
    both run "$TRUE"
    [ "$(result_of "$out")" = 0 ] && [ -z "$err" ]
}

t_exit_status() {
    both run "$SH" -c 'exit 7'
    [ "$(result_of "$out")" = 7 ] && [ -z "$err" ]
}

# The defect this replaces: only the exit byte was read, so a tool that a
# signal killed counted as a success.
t_killed_by_signal() {
    both run "$SH" -c 'kill -KILL $$'
    [ "$(result_of "$out")" = "$RUN_SIGNALED" ] &&
        printf '%s' "$err" | grep -q "^Error: $SH was killed (signal 9)\$"
}

t_missing_program() {
    both run /nonexistent/lightbox-unit-tool
    [ "$(result_of "$out")" = "$RUN_EXEC_FAILED" ] &&
        printf '%s' "$err" | grep -q '^Error: cannot execute /nonexistent/lightbox-unit-tool (errno 2)$'
}

t_not_executable() {
    both run /etc/passwd
    [ "$(result_of "$out")" = "$RUN_EXEC_FAILED" ] &&
        printf '%s' "$err" | grep -q '^Error: cannot execute /etc/passwd (errno 13)$'
}

# A process limit of 1 makes the helper's fork fail. Root is exempt from it.
t_fork_failure() {
    [ "$(id -u)" != 0 ] || { echo "root is exempt from the process limit"; return 77; }
    out=$( (ulimit -u 1 && exec "$UNIT" run "$TRUE") 2>/dev/null )
    err=$( (ulimit -u 1 && exec "$UNIT" run "$TRUE") 2>&1 >/dev/null )
    echo "stdout: $out"
    echo "stderr: $err"
    [ "$(result_of "$out")" = "$RUN_FORK_FAILED" ] &&
        printf '%s' "$err" | grep -q "^Error: cannot start $TRUE (fork failed, errno 11)\$"
}

t_output_passes_through() {
    both run "$SH" -c 'echo to-stdout; echo to-stderr >&2; exit 3'
    [ "$out" = "to-stdout
result 3" ] && [ "$err" = to-stderr ]
}

t_quiet_silences_both() {
    both quiet "$SH" -c 'echo to-stdout; echo to-stderr >&2; exit 3'
    [ "$out" = "result 3" ] && [ -z "$err" ]
}

# Quiet callers ask "does this exist?" and read a non-zero exit as "no". A
# tool that crashed or is missing is not a "no", and still has to be heard.
t_quiet_reports_abnormal_ends() {
    both quiet "$SH" -c 'echo noise; kill -TERM $$'
    [ "$out" = "result $RUN_SIGNALED" ] && [ "$err" = "Error: $SH was killed (signal 15)" ] || return 1
    both quiet /nonexistent/lightbox-unit-tool
    [ "$out" = "result $RUN_EXEC_FAILED" ] &&
        [ "$err" = "Error: cannot execute /nonexistent/lightbox-unit-tool (errno 2)" ]
}

t_capture() {
    both capture 64 "$SH" -c 'echo default via 10.1.2.3 dev eth7; echo unseen >&2'
    [ "$out" = "result 0
captured default via 10.1.2.3 dev eth7" ] && [ "$err" = unseen ]
}

# More output than the buffer holds: the helper keeps what fits and reads the
# rest away, so the program finishes and is not left blocked on a full pipe.
t_capture_overflow() {
    command -v timeout >/dev/null || { echo "no timeout(1) to guard against a hang"; return 77; }
    out=$(timeout 30 "$UNIT" capture 16 "$SH" -c 'i=0; while [ $i -lt 30000 ]; do echo 0123456789; i=$((i + 1)); done; exit 4')
    rc=$?
    echo "harness exit $rc, stdout: $out"
    [ $rc -eq 0 ] && [ "$out" = "result 4
captured 0123456789
0123" ]
}

t_capture_of_missing_program() {
    both capture 64 /nonexistent/lightbox-unit-tool
    [ "$out" = "result $RUN_EXEC_FAILED
captured " ]
}

# Tools get a fixed PATH and nothing of the caller's environment.
t_environment() {
    out=$(LIGHTBOX_UNIT_LEAK=1 "$UNIT" run "$ENV")
    echo "$out"
    [ "$out" = "PATH=/usr/bin:/bin:/usr/sbin:/sbin
result 0" ]
}

# A blocked signal in the caller is not blocked in the tool: the helper clears
# the mask. With SIGTERM blocked, the tool below would never end by its own
# signal and would exit 0.
t_signal_mask_cleared() {
    command -v python3 >/dev/null || { echo "no python3 to block a signal with"; return 77; }
    out=$(python3 -I -c '
import os, signal, sys
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
os.execv(sys.argv[1], sys.argv[1:])' "$UNIT" run "$SH" -c 'kill -TERM $$; exit 0' 2>/dev/null)
    echo "$out"
    [ "$(result_of "$out")" = "$RUN_SIGNALED" ]
}

t_status_decoding() {
    a=$(result_of "$("$UNIT" status 0)")       # exited 0
    b=$(result_of "$("$UNIT" status 1792)")    # exited 7
    c=$(result_of "$("$UNIT" status 9)")       # killed by signal 9
    d=$(result_of "$("$UNIT" status 139)")     # killed by signal 11, core dumped
    echo "0 -> $a, 7<<8 -> $b, 9 -> $c, 139 -> $d"
    [ "$a" = 0 ] && [ "$b" = 7 ] && [ "$c" = 137 ] && [ "$d" = 139 ]
}

# ─── do_mount ───────────────────────────────────────────────────────────────

# Run a script as root of a user namespace with a mount namespace of its own.
# The script gets the harness as $1 and an empty directory as $2, and these:
#   opts <mount point>         the mount's options, as /proc/self/mountinfo has them
#   has  <mount point> <flag>  whether they include the flag
#   m    <unit mount's arguments>   do_mount, which must succeed
in_mount_namespace() { # script
    unshare -r --mount true 2>/dev/null || { echo "user namespaces are not available to this user"; return 77; }
    local dir rc
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    unshare -r --mount -- bash -c '
        opts() { awk -v m="$1" '"'"'$5 == m { o = $6 } END { print o }'"'"' /proc/self/mountinfo; }
        has()  { case ",$(opts "$1")," in *",$2,"*) return 0 ;; esac; return 1; }
        m()    { r=$("$UNIT" mount "$@" 2>&1); [ "$r" = "result 0" ] || { echo "mount $*: $r"; exit 1; }; }
        UNIT=$1; D=$2
        '"$1" _ "$UNIT" "$dir"
    rc=$?
    rm -rf -- "$dir"
    return $rc
}

t_mount_with_flags_and_data() {
    in_mount_namespace '
        mkdir "$D/t"
        m tmpfs "$D/t" tmpfs nosuid,noexec mode=750
        echo "options: $(opts "$D/t"), mode $(stat -c %a "$D/t")"
        has "$D/t" nosuid && has "$D/t" noexec && ! has "$D/t" nodev && ! has "$D/t" ro &&
        [ "$(stat -c %a "$D/t")" = 750 ]'
}

# Changing the flags of a mount replaces them all. lightbox only ever adds a
# restriction, so the ones the mount has must still be there afterwards.
t_mount_change_keeps_restrictions() {
    in_mount_namespace '
        mkdir "$D/src" "$D/dst"
        m tmpfs "$D/src" tmpfs nodev,noexec -
        m "$D/src" "$D/dst" - bind -
        echo "a bind of a nodev,noexec mount: $(opts "$D/dst")"
        m - "$D/dst" - remount,bind,nosuid,ro -
        echo "after asking for nosuid and ro:  $(opts "$D/dst")"
        has "$D/dst" ro && has "$D/dst" nosuid && has "$D/dst" nodev && has "$D/dst" noexec'
}

t_mount_file_over_file() {
    in_mount_namespace '
        : > "$D/file"
        m /dev/null "$D/file" - bind -
        m - "$D/file" - remount,bind,nosuid,noexec,ro -
        echo "options: $(opts "$D/file")"
        [ -c "$D/file" ] && has "$D/file" ro && has "$D/file" nosuid && has "$D/file" noexec'
}

t_mount_makes_private() {
    in_mount_namespace '
        mkdir "$D/t"
        m tmpfs "$D/t" tmpfs - -
        mount --make-shared "$D/t" || exit 77
        grep " $D/t " /proc/self/mountinfo | grep -q " shared:" || { echo "could not make a shared mount to begin with"; exit 77; }
        m - "$D/t" - rec,private -
        ! grep " $D/t " /proc/self/mountinfo | grep -q " shared:"'
}

# Needs no namespace: the target is looked up before the kernel asks who is calling.
t_mount_failure_is_reported() {
    both mount tmpfs /nonexistent/lightbox-unit-dir tmpfs - -
    [ "$out" = "result -1" ] && [ "$err" = "Error: mount failed: /nonexistent/lightbox-unit-dir (errno 2)" ]
}

# ─── make_dirs and loopback_up ──────────────────────────────────────────────

t_make_dirs() {
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    (
        umask 022
        both mkdirs "$dir/a/b/c"
        [ "$out" = "result 0" ] && [ -z "$err" ] && [ -d "$dir/a/b/c" ] || exit 1
        echo "modes: $(stat -c %a "$dir/a" "$dir/a/b" "$dir/a/b/c" | tr '\n' ' ')"
        [ "$(stat -c %a "$dir/a/b/c")" = 755 ] && [ "$(stat -c %a "$dir/a")" = 755 ] || exit 1
        # again, and with slashes to spare: what is there already is fine
        both mkdirs "$dir/a//b/c/"
        [ "$out" = "result 0" ] && [ -z "$err" ] || exit 1
        # a directory someone else made keeps its mode
        mkdir -m 700 "$dir/closed"
        both mkdirs "$dir/closed/inside"
        [ "$out" = "result 0" ] && [ "$(stat -c %a "$dir/closed")" = 700 ] && [ -d "$dir/closed/inside" ]
    )
    rc=$?
    rm -rf -- "$dir"
    return $rc
}

t_make_dirs_stops_at_a_file() {
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    (
        : > "$dir/file"
        both mkdirs "$dir/file/below"
        [ "$out" = "result -1" ] && [ "$err" = "Error: cannot make directory: $dir/file/below (errno 20)" ] || exit 1
        both mkdirs "$dir/file"
        [ "$out" = "result -1" ] && [ "$err" = "Error: not a directory: $dir/file" ]
    )
    rc=$?
    rm -rf -- "$dir"
    return $rc
}

# A network namespace starts with its loopback interface down.
t_loopback_up() {
    command -v ip >/dev/null 2>&1 || { echo "no ip to look at the interface with"; return 77; }
    unshare -r --net true 2>/dev/null || { echo "user namespaces are not available to this user"; return 77; }
    unshare -r --net -- bash -c '
        before=$(ip -o link show lo)
        result=$("$1" loopback 2>&1)
        after=$(ip -o link show lo)
        echo "before: ${before%%>*}>"
        echo "$result"
        echo "after:  ${after%%>*}>"
        case $before in *"<LOOPBACK>"*) ;; *) echo "loopback was not down to begin with"; exit 77 ;; esac
        [ "$result" = "result 0" ] || exit 1
        case $after in *[\<,]UP[,\>]*) ;; *) exit 1 ;; esac
        # and once more: an interface that is up already stays up
        [ "$("$1" loopback 2>&1)" = "result 0" ]' _ "$UNIT"
}

# ─── The sandbox: capabilities, no_new_privs, seccomp, masked paths ─────────

ALLOWED_CAPS=00000000a00405fb       # ALLOWED_CAPS of lightbox.c, as /proc/<pid>/status prints a set

field() { printf '%s\n' "$out" | awk -v k="$1:" '$1 == k { print $2 }'; }

# As root of a user namespace, which holds every capability there. Some hosts
# let an ordinary user make the namespace and give no capability in it; making
# a mount namespace inside tells the two apart.
t_capabilities_reduced() {
    unshare -r --mount true 2>/dev/null || { echo "user namespaces with capabilities are not available to this user"; return 77; }
    # with something in the two sets that are passed on, where this host's setpriv can put it there
    with=""
    if unshare -r setpriv --inh-caps +chown --ambient-caps +chown true 2>/dev/null; then
        with="setpriv --inh-caps +chown --ambient-caps +chown"
    fi
    before=$(unshare -r $with grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb):' /proc/self/status | tr -s '\t\n' ' ')
    out=$(unshare -r $with "$UNIT" caps 2>&1)
    echo "before: $before"
    echo "after:  $(printf '%s\n' "$out" | tr -s '\t\n' ' ')"
    [ "$(field CapEff)" = "$ALLOWED_CAPS" ] && [ "$(field CapPrm)" = "$ALLOWED_CAPS" ] &&
    [ "$(field CapBnd)" = "$ALLOWED_CAPS" ] &&
    [ "$(field CapInh)" = 0000000000000000 ] && [ "$(field CapAmb)" = 0000000000000000 ]
}

# The whole sandbox, and a program run inside it: what it holds after the
# execve is the bounding set and no more, and it cannot gain privileges.
t_sandbox_covers_a_program() {
    unshare -r --mount true 2>/dev/null || { echo "user namespaces with capabilities are not available to this user"; return 77; }
    out=$(unshare -r "$UNIT" sandbox "$SH" -c 'grep -E "^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):" /proc/self/status' 2>&1)
    printf '%s\n' "$out" | tr -s '\t\n' ' '; echo
    [ "$(field Seccomp)" = 2 ] && [ "$(field NoNewPrivs)" = 1 ] &&
    [ "$(field CapEff)" = "$ALLOWED_CAPS" ] && [ "$(field CapPrm)" = "$ALLOWED_CAPS" ] &&
    [ "$(field CapBnd)" = "$ALLOWED_CAPS" ] &&
    [ "$(field CapInh)" = 0000000000000000 ] && [ "$(field CapAmb)" = 0000000000000000 ]
}

# An ordinary user may not shrink the bounding set. The sandbox must then end
# the process: a container never runs with a step of it left out.
t_sandbox_fails_closed() {
    [ "$(id -u)" != 0 ] || { echo "root can apply the sandbox"; return 77; }
    out=$("$UNIT" sandbox "$SH" -c 'echo the program ran' 2>&1)
    rc=$?
    echo "exit $rc: $out"
    [ $rc -ne 0 ] && case $out in *'the program ran'*) false ;; *'Error: failed to drop a capability'*) true ;; *) false ;; esac
}

t_paths_are_masked() {
    unshare -r --mount --pid --fork --mount-proc true 2>/dev/null ||
        { echo "user namespaces are not available to this user"; return 77; }
    unshare -r --mount --pid --fork --mount-proc -- bash -c '
        is_mount() { awk -v m="$1" '"'"'$5 == m { found = 1 } END { exit !found }'"'"' /proc/self/mountinfo; }
        opts()     { awk -v m="$1" '"'"'$5 == m { o = $6 } END { print o }'"'"' /proc/self/mountinfo; }
        said=$("$1" maskproc 2>&1) || { echo "mask_proc_paths ended the process: $said"; exit 1; }
        bad=0 seen=""
        for p in /proc/acpi /proc/asound /proc/interrupts /proc/kcore /proc/keys /proc/latency_stats \
                 /proc/sched_debug /proc/scsi /proc/sysrq-trigger /proc/timer_list /proc/timer_stats \
                 /sys/devices/virtual/powercap /sys/firmware; do
            [ -e "$p" ] || continue
            seen="$seen ${p##*/}"
            is_mount "$p" || { echo "$p is not covered"; bad=1; continue; }
            if [ -d "$p" ]; then
                [ -z "$(ls -A "$p")" ] || { echo "$p is not empty"; bad=1; }
            else
                [ -z "$(head -c 1 "$p" 2>/dev/null)" ] || { echo "$p can be read"; bad=1; }
            fi
        done
        for p in /proc/bus /proc/fs /proc/irq /proc/sys; do
            [ -d "$p" ] || continue
            seen="$seen ${p##*/}"
            case ",$(opts "$p")," in *,ro,*) ;; *) echo "$p is not read-only: $(opts "$p")"; bad=1 ;; esac
        done
        echo "covered here:$seen"
        exit $bad' _ "$UNIT"
}

# ─── netns_disable_ipv6 ─────────────────────────────────────────────────────

# Another network namespace, held by a process. Afterwards it has no IPv6
# address and gives none to an interface it gets, and this one is as it was.
t_ipv6_switched_off() {
    [ -e /proc/sys/net/ipv6/conf ] || { echo "this kernel runs without IPv6"; return 77; }
    command -v ip >/dev/null 2>&1 && command -v nsenter >/dev/null 2>&1 || { echo "no ip and nsenter to look with"; return 77; }
    unshare -r --net true 2>/dev/null || { echo "user namespaces are not available to this user"; return 77; }
    unshare -r --net -- bash -c '
        unshare --net -- sleep 60 >/dev/null 2>&1 </dev/null &
        holder=$!
        i=0
        until [ -n "$(readlink /proc/$holder/ns/net 2>/dev/null)" ] &&
              [ "$(readlink /proc/$holder/ns/net)" != "$(readlink /proc/self/ns/net)" ]; do
            i=$((i + 1)); [ $i -lt 50 ] || exit 1; sleep 0.1
        done
        there() { nsenter -t "$holder" -n "$@"; }
        there ip link set lo up
        before=$(there cat /proc/net/if_inet6)
        mine=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
        result=$("$1" noipv6 "$holder" 2>&1)
        after=$(there cat /proc/net/if_inet6)
        all=$(there cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
        default=$(there cat /proc/sys/net/ipv6/conf/default/disable_ipv6)
        still=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
        kill "$holder"
        echo "addresses there before: $(printf "%s\n" "$before" | grep -c .); $result; after: $(printf "%s\n" "$after" | grep -c .)"
        echo "there: all=$all default=$default; here: $mine before, $still after"
        [ -n "$before" ] && [ "$result" = "result 0" ] && [ -z "$after" ] &&
        [ "$all" = 1 ] && [ "$default" = 1 ] && [ "$still" = "$mine" ]' _ "$UNIT"
}

# No process has this number, so there is no namespace to join. start must
# hear of it: a container is not to run with IPv6 left as it was.
t_ipv6_failure_is_an_error() {
    both noipv6 2147483600
    [ "$out" = "result -1" ]
}

check 'a program that succeeds gives 0'                          t_success
check 'a non-zero exit status is returned as it is'              t_exit_status
check 'a program killed by a signal is a failure, and reported'  t_killed_by_signal
check 'a missing program is a failure, and reported'             t_missing_program
check 'a file that cannot be executed is a failure, and reported' t_not_executable
check 'a failed fork is a failure, and reported'                 t_fork_failure

check 'output passes through by default'                         t_output_passes_through
check 'quiet mode silences stdout and stderr'                    t_quiet_silences_both
check 'quiet mode still reports a crash or a missing program'    t_quiet_reports_abnormal_ends

check 'captured output is returned as a string'                  t_capture
check 'output beyond the buffer is cut, not waited on'           t_capture_overflow
check 'capturing a missing program gives an empty string'        t_capture_of_missing_program

check 'tools run with a fixed PATH and nothing else'             t_environment
check 'a signal the caller blocks is not blocked in the tool'    t_signal_mask_cleared
check 'wait statuses decode as a shell reports them'             t_status_decoding

check 'a mount gets the flags and the data it was given'         t_mount_with_flags_and_data
check 'changing a mount keeps the restrictions it has'           t_mount_change_keeps_restrictions
check 'a file is bound over a file, then restricted'             t_mount_file_over_file
check 'a mount is made private'                                  t_mount_makes_private
check 'a mount that fails is reported with its errno'            t_mount_failure_is_reported

check 'directories are made with the ones above them'            t_make_dirs
check 'a file in the way of a directory is an error'             t_make_dirs_stops_at_a_file
check 'the loopback interface is brought up'                     t_loopback_up

check 'every capability set is reduced to the allowed ones'      t_capabilities_reduced
check 'a program run in the sandbox is confined by it'           t_sandbox_covers_a_program
check 'a sandbox that cannot be applied ends the process'        t_sandbox_fails_closed
check 'paths of /proc and /sys are masked or made read-only'     t_paths_are_masked

check 'IPv6 is switched off in another network namespace'        t_ipv6_switched_off
check 'a namespace that cannot be joined is an error'            t_ipv6_failure_is_an_error

summary unit
