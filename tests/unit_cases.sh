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
# "unit init" runs both sides of a start: a real init in a PID namespace of
# its own, and the code of the command that starts it. tests/unit.c says what
# it prints.
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
CAT=$(type -P cat)

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

# ─── The start handshake ────────────────────────────────────────────────────

# Both sides of a start, without a container: "unit init" clones the init of
# lightbox.c into a PID namespace and plays the command that starts it. That
# takes the root of a user namespace. Each case gets an empty directory, $D,
# for its hook and for what the hook leaves; a hook runs with init's fixed
# environment, so its script names $D in full.
in_handshake_dir() { # function
    unshare -r --pid --fork true 2>/dev/null ||
        { echo "this user cannot make a PID namespace in a user namespace"; return 77; }
    local rc
    D=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    ( "$1" )
    rc=$?
    rm -rf -- "$D"
    return $rc
}

# The command's side in the foreground, under a time limit: sets $out.
handshake() { # how, confined|open, seconds, hook | -, log | -
    out=$(timeout -k 2 30 unshare -r "$UNIT" init "$@" 2>&1)
    printf '%s\n' "$out"
}

# The same in the background, for a case that does something meanwhile. unshare
# runs the harness in its own place, so $command is the harness.
handshake_begins() { # how, confined|open, seconds, hook | -, log | -
    unshare -r "$UNIT" init "$@" > "$D/out" 2>&1 &
    command=$!
}
handshake_ends() { # sets $out
    local i=0
    while kill -0 "$command" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$command" 2>/dev/null; then
        echo "the command was still there after 10 seconds"
        kill -KILL "$command"
    fi
    wait "$command" 2>/dev/null
    out=$(cat "$D/out")
    printf '%s\n' "$out"
}

# What the command saw, on one line, without the PID of init.
story() { printf '%s\n' "$out" | sed 1d | paste -sd' ' -; }

wait_for() { # seconds, command...
    local limit=$(($1 * 10)) i=0
    shift
    until "$@"; do
        [ "$i" -lt "$limit" ] || return 1
        sleep 0.1
        i=$((i + 1))
    done
}

# Is "sleep <seconds>" running? The odd number of seconds is what tells a
# case's own sleep from every other process, so the whole command line has to
# be that and nothing else: a shell or an editor that merely names the number
# does not count. The number has this suite's process ID in it, so that two
# suites running on one machine do not take each other's sleep for their own.
NAP=31.$$
sleeping() {
    local f
    for f in /proc/[0-9]*/cmdline; do
        [ "$(tr '\0' ' ' < "$f" 2>/dev/null)" = "sleep $NAP " ] && return 0
    done
    return 1
}

t_init_reports_its_end() { in_handshake_dir h_init_reports_its_end; }

h_without_hook() {
    handshake whole confined 5 - -
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] || return 1
    # and without the sandbox, as in a privileged container
    handshake whole open 5 - -
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ]
}

# The first byte is what tells init that its cgroup and its network are in
# place. Until it comes init does nothing: here the command takes a second.
h_init_waits_for_its_first_byte() {
    printf ': > %s/ran\n' "$D" > "$D/hook"
    handshake late-first-byte confined 5 "$D/hook" -
    [ "$(story)" = "init waits ready hook 0 sent SIGTERM init-exit 0" ] && [ -e "$D/ran" ]
}

h_hook_runs_and_reports() {
    printf 'echo ran > %s/mark\n' "$D" > "$D/hook"
    handshake whole confined 5 "$D/hook" -
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] && [ "$(cat "$D/mark")" = ran ]
}

h_hook_failure() {
    printf 'exit 3\n' > "$D/hook"
    handshake whole confined 5 "$D/hook" -
    [ "$(story)" = "ready hook 3 init-exit 1" ] || return 1
    # a hook that a signal ends has failed as well
    printf 'kill -KILL $$\n' > "$D/hook"
    handshake whole confined 5 "$D/hook" -
    [ "$(story)" = "ready hook 137 init-exit 1" ]
}

# The report of a hook is the hook's own end, not the end of what it started.
h_hook_with_a_service() {
    printf 'sleep %s &\necho started > %s/mark\n' "$NAP" "$D" > "$D/hook"
    began=$SECONDS
    handshake whole confined 20 "$D/hook" -
    echo "took $((SECONDS - began)) s"
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] && [ -e "$D/mark" ] &&
    [ $((SECONDS - began)) -lt 10 ] || return 1
    # init took its PID namespace with it
    ! sleeping || { echo "the service is still running"; return 1; }
}

# The hook is still running when the command stops waiting, and init still
# hears SIGTERM: before, init sat in a wait for the hook and nothing reached it.
h_slow_hook() {
    printf ': > %s/started\nsleep %s\n: > %s/finished\n' "$D" "$NAP" "$D" > "$D/hook"
    began=$SECONDS
    handshake whole confined 1 "$D/hook" -
    echo "took $((SECONDS - began)) s"
    [ "$(story)" = "ready hook-timeout sent SIGTERM init-exit 0" ] && [ -e "$D/started" ] &&
    [ ! -e "$D/finished" ] && [ $((SECONDS - began)) -lt 10 ] || return 1
    ! sleeping || { echo "the hook is still running"; return 1; }
}

# SIGTERM for init while the command waits for the hook: init goes, and the
# command sees its pipe close.
h_init_stops_during_hook() {
    printf ': > %s/started\nsleep %s\n' "$D" "$NAP" > "$D/hook"
    handshake_begins whole confined 20 "$D/hook" -
    wait_for 5 test -e "$D/started" || { echo "the hook did not start"; handshake_ends; return 1; }
    init=$(sed -n 's/^init //p' "$D/out")
    kill -TERM "$init"
    handshake_ends
    [ "$(story)" = "ready closed init-exit 0" ] && ! sleeping
}

# SIGTERM for the command while it waits: it kills init and what init started.
h_interrupted_command() {
    printf ': > %s/started\nsleep %s\n' "$D" "$NAP" > "$D/hook"
    handshake_begins whole confined 20 "$D/hook" -
    wait_for 5 test -e "$D/started" || { echo "the hook did not start"; handshake_ends; return 1; }
    kill -TERM "$command"
    handshake_ends
    [ "$(story)" = "ready signal 15 abandoned" ] && ! sleeping
}

# A command that is gone, at each point where init looks: init exits, and the
# hook has not run.
h_command_gone() {
    printf ': > %s/ran\n' "$D" > "$D/hook"
    handshake no-first-byte confined 5 "$D/hook" -
    [ "$(story)" = "init-exit 1" ] || return 1
    handshake deaf confined 5 "$D/hook" -
    [ "$(story)" = "init-exit 1" ] || return 1
    handshake no-second-byte confined 5 "$D/hook" -
    [ "$(story)" = "ready init-exit 1" ] || return 1
    [ ! -e "$D/ran" ] || { echo "the hook ran"; return 1; }
}

# The hook gets three standard streams and nothing else: not init's pipes to
# the command, not its signalfd, not the record of how init ends, no blocked
# signal, and nothing that was open in the command, which here has a file on
# descriptor 9.
h_hook_inherits_nothing() {
    printf 'grep SigBlk: /proc/self/status > %s/blocked\nexec ls /proc/self/fd > %s/fds\n' "$D" "$D" > "$D/hook"
    : > "$D/open-in-the-command"
    UNIT_EXIT="$D/exit" handshake whole confined 5 "$D/hook" - 9< "$D/open-in-the-command"
    # ls itself has the directory it lists on 3
    echo "descriptors in the hook: $(tr '\n' ' ' < "$D/fds")"
    echo "blocked in the hook: $(cat "$D/blocked")"
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] &&
    [ "$(tr '\n' ' ' < "$D/fds")" = "0 1 2 3 " ] && [ "$(awk '{ print $2 }' "$D/blocked")" = 0000000000000000 ]
}

# With a log, init reads nothing and writes to the log, and so does the hook.
# Nothing the hook prints reaches the command's own output.
h_output_goes_to_the_log() {
    printf 'echo printed by the hook\necho complained by the hook >&2\nreadlink /proc/self/fd/0 > %s/stdin\n' "$D" > "$D/hook"
    handshake whole confined 5 "$D/hook" "$D/log"
    echo "the log:"; sed 's/^/  /' "$D/log"
    echo "the hook reads from: $(cat "$D/stdin")"
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] || return 1
    case $out in *'by the hook'*) echo "the hook's output reached the command"; return 1 ;; esac
    [ "$(cat "$D/log")" = "printed by the hook
complained by the hook" ] && [ "$(cat "$D/stdin")" -ef /dev/null ] || return 1
    [ "$(stat -c %a "$D/log")" = 600 ] || { echo "the log has mode $(stat -c %a "$D/log")"; return 1; }
    # a second start appends
    handshake whole confined 5 "$D/hook" "$D/log" >/dev/null
    [ "$(grep -c 'printed by the hook' "$D/log")" = 2 ]
}

# A start that worked ends and leaves init running. A shell that captures the
# command's output must get it then: init holds nothing of the command, is in
# a session and a process group of its own, and has only its three streams,
# its signalfd and the record of how it ends open, as after a real start.
#
# The command writes to a pipe here, as it does under $( ). What reads the
# pipe ends when nothing has it open any more, and is given ten seconds: an
# init that held on to the pipe must fail this case, not stall it.
h_command_returns_and_init_stays() {
    : > "$D/open-in-the-command"
    ( UNIT_EXIT="$D/exit" unshare -r "$UNIT" init leave confined 5 - "$D/log" 2>&1 9< "$D/open-in-the-command" | cat > "$D/out" ) &
    reader=$!
    i=0
    while kill -0 "$reader" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
    out=$(cat "$D/out")
    printf '%s\n' "$out"
    init=$(sed -n 's/^init //p' "$D/out")
    bad=0
    if kill -0 "$reader" 2>/dev/null; then
        echo "the pipe the command wrote to is still open ten seconds later: init holds it"
        bad=1
    fi
    if [ -z "$init" ] || ! kill -0 "$init" 2>/dev/null; then
        echo "init is not running"
        kill "$reader" 2>/dev/null
        return 1
    fi
    [ "$(story)" = "ready hook 0 left" ] || bad=1
    read -r _ _ _ _ group session _ < "/proc/$init/stat"
    echo "init $init is in process group $group and session $session; this shell is $$"
    [ "$session" = "$init" ] && [ "$group" = "$init" ] || { echo "init does not lead a session of its own"; bad=1; }
    records=0
    for fd in "/proc/$init/fd"/*; do
        n=${fd##*/}
        to=$(readlink "$fd")
        echo "  descriptor $n: $to"
        # the same file, however its path is spelled
        if [ "$n" = 0 ] && [ "$fd" -ef /dev/null ]; then continue; fi
        if { [ "$n" = 1 ] || [ "$n" = 2 ]; } && [ "$fd" -ef "$D/log" ]; then continue; fi
        if [ "$n" -gt 2 ] && [ "$to" = 'anon_inode:[signalfd]' ]; then continue; fi
        if [ "$n" -gt 2 ] && [ "$fd" -ef "$D/exit" ]; then records=$((records + 1)); continue; fi
        echo "  init should not have that"
        bad=1
    done
    [ -e "/proc/$init/fd/0" ] && [ -e "/proc/$init/fd/1" ] && [ -e "/proc/$init/fd/2" ] || { echo "  init lacks a standard stream"; bad=1; }
    [ "$records" = 1 ] || { echo "  init has the record of how it ends open $records times, not once"; bad=1; }
    kill -KILL "$init"
    wait "$reader" 2>/dev/null
    return $bad
}

# ─── Stopping: init ends what runs in the container, and stop waits ─────────

# An init that goes on running after the command has left, as after a start
# that worked: sets $init. Its processes get $2 seconds when a SIGTERM comes
# without a number of its own.
init_with() { # hook | -, grace
    out=$(timeout -k 2 10 unshare -r "$UNIT" init leave confined 5 "$1" "$D/log" "$2" 2>&1)
    printf '%s\n' "$out"
    init=$(printf '%s\n' "$out" | sed -n 's/^init //p')
    [ "$(story)" = "ready hook 0 left" ] && [ -n "$init" ] && kill -0 "$init" 2>/dev/null
}

# What stop does to init, timed: sets $said and $ms.
stop_init() { # seconds
    local t0=${EPOCHREALTIME/[.,]/}
    said=$("$UNIT" stop "$init" "$1" 2>&1 | paste -sd' ' -)
    ms=$(((${EPOCHREALTIME/[.,]/} - t0) / 1000))
    echo "stop $1: $said, after $ms ms"
}

init_is_gone() {
    wait_for 5 eval '! kill -0 "$init" 2>/dev/null' || { echo "init $init is still there"; kill -KILL "$init"; return 1; }
}

# A service that does what a service should on SIGTERM, and one that will not.
service() { # polite | stubborn | stopped
    case $1 in
        polite)   printf 'trap "echo asked to stop > %s/stopped; exit 0" TERM\n: > %s/started\nwhile :; do sleep 1 & wait $!; done\n' "$D" "$D" ;;
        stubborn) printf 'trap "" TERM\n: > %s/started\nwhile :; do sleep %s; done\n' "$D" "$NAP" ;;
        stopped)  printf ': > %s/started\nkill -STOP $$\nsleep %s\n' "$D" "$NAP" ;;
    esac > "$D/service"
    printf '/bin/sh %s/service &\n' "$D" > "$D/hook"
}

h_stop_idle() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    init_with - 10 || return 1
    stop_init 5
    [ "$said" = "asked ended" ] && [ "$ms" -lt 1000 ] && init_is_gone
}

h_stop_lets_a_service_end() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    service polite
    init_with "$D/hook" 10 || return 1
    wait_for 5 test -e "$D/started" || { echo "the service did not start"; kill -KILL "$init"; return 1; }
    stop_init 5
    # the service had its say by the time stop returned, and nobody waited out the five seconds
    [ "$said" = "asked ended" ] && [ "$(cat "$D/stopped" 2>/dev/null)" = "asked to stop" ] && [ "$ms" -lt 3000 ] && init_is_gone
}

# stop -t 1 against an init whose own limit is 30 seconds: the number travels
# with the signal. The service is killed when the second is over, not before.
h_stop_kills_after_the_limit() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    service stubborn
    init_with "$D/hook" 30 || return 1
    wait_for 5 test -e "$D/started" || { echo "the service did not start"; kill -KILL "$init"; return 1; }
    stop_init 1
    echo "the log: $(cat "$D/log")"
    [ "$said" = "asked ended" ] && [ "$ms" -ge 1000 ] && [ "$ms" -lt 2900 ] && init_is_gone || return 1
    grep -q 'within 1 s of SIGTERM' "$D/log" || { echo "init does not say that it had to kill"; return 1; }
    ! sleeping || { echo "the service is still running"; return 1; }
}

# A SIGTERM that brings no number, as from kill: init's own limit holds.
h_plain_sigterm_uses_inits_limit() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    service stubborn
    init_with "$D/hook" 1 || return 1
    wait_for 5 test -e "$D/started" || { echo "the service did not start"; kill -KILL "$init"; return 1; }
    t0=${EPOCHREALTIME/[.,]/}
    kill -TERM "$init"
    init_is_gone || return 1
    ms=$(((${EPOCHREALTIME/[.,]/} - t0) / 1000))
    echo "init went $ms ms after a plain SIGTERM; the log: $(cat "$D/log")"
    [ "$ms" -ge 1000 ] && [ "$ms" -lt 4000 ] && ! sleeping
}

# A process that is stopped cannot act on SIGTERM until it is continued.
h_stop_wakes_a_stopped_process() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    service stopped
    init_with "$D/hook" 30 || return 1
    wait_for 5 test -e "$D/started" || { echo "the service did not start"; kill -KILL "$init"; return 1; }
    sleep 0.3
    stop_init 20
    [ "$said" = "asked ended" ] && [ "$ms" -lt 3000 ] && init_is_gone
}

# What exec puts into a container is in its PID namespace and is nobody's
# child there. Init sends it the SIGTERM with the rest and waits for it too:
# this one takes a moment over ending, and has ended when stop returns.
h_stop_ends_what_is_not_inits_child() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    command -v nsenter >/dev/null 2>&1 || { echo "no nsenter to put a process into the namespace with"; return 77; }
    init_with - 30 || return 1
    printf 'trap "sleep 0.4; echo ended in its own time > %s/guest.stopped; exit 0" TERM\n: > %s/guest.started\nwhile :; do sleep 1 & wait $!; done\n' "$D" "$D" > "$D/guest"
    nsenter --user --pid --preserve-credentials -t "$init" /bin/sh "$D/guest" >"$D/guest.out" 2>&1 &
    guest=$!
    wait_for 3 test -e "$D/guest.started" || { echo "nsenter could not put a process there: $(cat "$D/guest.out")"; kill -KILL "$init"; return 77; }
    stop_init 5
    [ "$said" = "asked ended" ] && [ "$ms" -ge 400 ] && [ "$ms" -lt 3000 ] && init_is_gone || return 1
    wait "$guest" 2>/dev/null
    [ "$(cat "$D/guest.stopped" 2>/dev/null)" = "ended in its own time" ] || { echo "init did not wait for the process that was put there"; return 1; }
}

# The list of a cgroup's processes is read whole, and a number is never cut
# where one read ends and the next begins: 3000 numbers are 18 891 bytes,
# which is more than four reads.
t_pid_list_is_read_whole() {
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    (
        seq 100001 103000 > "$dir/procs"
        out=$("$UNIT" pids "$dir/procs")
        echo "bytes in the list: $(wc -c < "$dir/procs"); numbers read: $(result_of "$out")"
        [ "$(result_of "$out")" = 3000 ] && [ "$(printf '%s\n' "$out" | sed '$d')" = "$(cat "$dir/procs")" ] || exit 1
        # a last line without its newline, an empty list, and a list that is not there
        printf '41\n42' > "$dir/short"
        [ "$("$UNIT" pids "$dir/short" | paste -sd' ' -)" = "41 42 result 2" ] || exit 1
        : > "$dir/empty"
        [ "$("$UNIT" pids "$dir/empty")" = "result 0" ] && [ "$("$UNIT" pids "$dir/missing")" = "result -1" ]
    )
    rc=$?
    rm -rf -- "$dir"
    return $rc
}

t_stop_idle()                   { in_handshake_dir h_stop_idle; }
t_stop_graceful()               { in_handshake_dir h_stop_lets_a_service_end; }
t_stop_limit()                  { in_handshake_dir h_stop_kills_after_the_limit; }
t_stop_plain_sigterm()          { in_handshake_dir h_plain_sigterm_uses_inits_limit; }
t_stop_stopped_process()        { in_handshake_dir h_stop_wakes_a_stopped_process; }
t_stop_guest()                  { in_handshake_dir h_stop_ends_what_is_not_inits_child; }

t_handshake_without_hook()      { in_handshake_dir h_without_hook; }
t_handshake_first_byte()        { in_handshake_dir h_init_waits_for_its_first_byte; }
t_handshake_hook()              { in_handshake_dir h_hook_runs_and_reports; }
t_handshake_hook_failure()      { in_handshake_dir h_hook_failure; }
t_handshake_service()           { in_handshake_dir h_hook_with_a_service; }
t_handshake_slow_hook()         { in_handshake_dir h_slow_hook; }
t_handshake_stop_during_hook()  { in_handshake_dir h_init_stops_during_hook; }
t_handshake_interrupted()       { in_handshake_dir h_interrupted_command; }
t_handshake_command_gone()      { in_handshake_dir h_command_gone; }
t_handshake_hook_inherits()     { in_handshake_dir h_hook_inherits_nothing; }
t_handshake_log()               { in_handshake_dir h_output_goes_to_the_log; }
t_handshake_detached()          { in_handshake_dir h_command_returns_and_init_stays; }

# ─── Volumes ────────────────────────────────────────────────────────────────

t_volume_spec() {
    bad=0
    expect() { # spec, what parse_volume_spec makes of it
        got=$("$UNIT" volspec "$1")
        case $2 in
            invalid) case $got in invalid:*) ;; *) echo "'$1' -> $got, expected it to be refused"; bad=1 ;; esac ;;
            *) [ "$got" = "$2" ] || { echo "'$1' -> $got, expected $2"; bad=1; } ;;
        esac
    }
    expect /a:/b '/a -> /b rw'
    expect /a:/b:ro '/a -> /b ro'
    # one spelling for a path, however it was typed
    expect /a/./b//c/:/data//x/:ro '/a/b/c -> /data/x ro'
    expect //srv:/procfs '/srv -> /procfs rw'
    # a path with .. means what the directories before it make it mean
    for spec in /a:/b/../c /a/../b:/c /a:/.. /a:/b/..; do expect "$spec" invalid; done
    # the reserved places, however they are spelled
    for spec in /a:/proc /a:/proc/x /a://proc/x /a:/./sys /a:/dev/ /a:/sys/fs/cgroup /a:/ /a:// /a:/. \
                /proc/1/root:/data //proc//self:/data /sys:/data /dev/sda:/data /a:/.old_root /a:/.old_root/x; do
        expect "$spec" invalid
    done
    # and what is not a volume at all
    for spec in /a a:/b /a:b /a: :/b /a:/b:rw /a:/b:ro:x /a:/b:; do expect "$spec" invalid; done
    return $bad
}

# The volumes of a container, as init takes and attaches them, in a root
# filesystem made here. The harness gets a mount namespace of its own inside
# the script's, because the pivot moves the root of everything in a namespace.
t_volumes_are_attached_inside() {
    in_mount_namespace '
        m tmpfs "$D" tmpfs - -
        mkdir -p "$D/src/sub" "$D/fixed" "$D/root/etc" "$D/root/inside" "$D/root/tmp" "$D/named-on-the-host"
        mkdir -p "$D/root$D/named-on-the-host"          # the new root has a directory of that name too
        echo from the source > "$D/src/file"
        echo fixed > "$D/fixed/file"
        echo one file > "$D/single"
        ln -s /inside "$D/root/link"                    # as an image has it: absolute, and meant inside
        mkdir "$D/root/inside/last-target"
        ln -s /inside/last-target "$D/root/last"        # the destination itself is a link
        ln -s "$D/named-on-the-host" "$D/root/away"     # names a directory that the host has too
        out=$(unshare --mount "$UNIT" volumes "$D/root" \
                  "$D/src:/data" "$D/fixed:/link/fixed:ro" "$D/single:/etc/app/single" "$D/src:/away/vol" "$D/src:/tmp/below" "$D/fixed:/last:ro" -- \
                  cat:/data/file cat:/inside/fixed/file write:/inside/fixed/new write:/data/new \
                  cat:/etc/app/single cat:/inside/last-target/file ls:/tmp/below ls:/ 2>&1)
        rc=$?
        printf "%s\n" "$out"
        [ $rc -eq 0 ] || exit 1
        said() { printf "%s\n" "$out" | grep -qxF -- "$1" || { echo "missing: $1"; exit 1; }; }
        said "attached"
        said "cat:/data/file = from the source"
        # through the link, to where the link leads in the new root
        said "cat:/inside/fixed/file = fixed"
        said "write:/inside/fixed/new = refused"
        said "write:/data/new = written"
        said "cat:/etc/app/single = one file"
        said "cat:/inside/last-target/file = fixed"
        said "  file"
        # the host is out of sight: nothing of it is in the new root
        printf "%s\n" "$out" | sed -n "/^ls:\/ =/,\$p" | grep -q "old_root" && { echo "the old root is still there"; exit 1; }
        # what was written through the volume is in its source
        [ -e "$D/src/new" ] || { echo "the volume is not its source"; exit 1; }
        [ ! -e "$D/fixed/new" ] || exit 1
        # a link that names a directory the host has too led to the one in the new root, and the
        # host one was not touched
        [ -z "$(ls -A "$D/named-on-the-host")" ] || { echo "something was made in the directory on the host: $(ls -A "$D/named-on-the-host")"; exit 1; }
        [ -d "$D/root$D/named-on-the-host/vol" ] || { echo "the destination was not made inside the new root"; exit 1; }'
}

# A link that leads nowhere in the new root leads nowhere: the start ends
# there, and the place of that name on the host is as it was.
t_volume_through_a_dangling_link() {
    in_mount_namespace '
        m tmpfs "$D" tmpfs - -
        mkdir -p "$D/src" "$D/root" "$D/named-on-the-host"
        ln -s "$D/named-on-the-host" "$D/root/away"
        out=$(unshare --mount "$UNIT" volumes "$D/root" "$D/src:/away/vol" 2>&1) && { echo "the volume was attached: $out"; exit 1; }
        echo "$out"
        [ -z "$(ls -A "$D/named-on-the-host")" ] || { echo "something was made on the host: $(ls -A "$D/named-on-the-host")"; exit 1; }
        [ "$(ls -A "$D/root")" = away ] || { echo "something was made in the new root: $(ls -A "$D/root")"; exit 1; }'
}

t_volume_that_cannot_be_had() {
    in_mount_namespace '
        m tmpfs "$D" tmpfs - -
        mkdir -p "$D/src" "$D/root"
        out=$(unshare --mount "$UNIT" volumes "$D/root" "$D/missing:/data" 2>&1) && { echo "a missing source was accepted"; exit 1; }
        echo "$out"
        [ "$out" = "Error: volume source does not exist: $D/missing" ] || exit 1
        # a directory cannot go where the image has a file
        : > "$D/root/file"
        out=$(unshare --mount "$UNIT" volumes "$D/root" "$D/src:/file" 2>&1) && { echo "a directory was mounted on a file"; exit 1; }
        echo "$out"
        [ -z "$(ls -A "$D/src")" ]'
}

# ─── Name servers ───────────────────────────────────────────────────────────

# What a container can ask of the name servers a host asks: the IPv4 ones that
# are not the host's own loopback, the first three.
t_name_servers_of_the_host() {
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    (
        {
            echo '# made for a test'
            echo 'nameserver 127.0.0.53'
            echo 'nameserver ::1'
            echo 'nameserver 2001:db8::53'
            echo 'search example.org'
            printf '  nameserver \t 192.0.2.1  \n'
            echo 'nameserverx 192.0.2.9'
            echo 'nameserver 192.0.2.2 # the second'
            echo 'nameserver 0.0.0.0'
            echo 'nameserver 192.0.2.300'
            printf 'nameserver 192.0.2.3\r\n'
            echo 'nameserver 192.0.2.4'
        } > "$dir/resolv.conf"
        got=$("$UNIT" nameservers "$dir/resolv.conf" | paste -sd' ' -)
        echo "$got"
        [ "$got" = "192.0.2.1 192.0.2.2 192.0.2.3 result 3" ] || exit 1
        printf 'nameserver 127.0.0.1\n' > "$dir/stub"
        [ "$("$UNIT" nameservers "$dir/stub")" = "result 0" ] && [ "$("$UNIT" nameservers "$dir/missing")" = "result 0" ] || exit 1
        # the dns setting: a list, and nothing but a list
        [ "$("$UNIT" dnslist '9.9.9.9, 149.112.112.112' | paste -sd' ' -)" = "9.9.9.9 149.112.112.112 result 2" ] || exit 1
        [ "$("$UNIT" dnslist '9.9.9.9 1.1.1.1,8.8.8.8' | paste -sd' ' -)" = "9.9.9.9 1.1.1.1 8.8.8.8 result 3" ] || exit 1
        for list in 'nine' '9.9.9.9, ::1' '127.0.0.1' '1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4' '9.9.9.9;8.8.8.8'; do
            [ "$("$UNIT" dnslist "$list" | tail -n 1)" = "result -1" ] || { echo "'$list' was taken for a list of name servers"; exit 1; }
        done
    )
    rc=$?
    rm -rf -- "$dir"
    return $rc
}

# ─── exec: the command's standard streams ───────────────────────────────────

# "unit relay" does about a command's streams what exec does once it is in a
# container, with the host's /dev/ptmx for the container's. A terminal for it
# to be run on comes from script(1), which runs a command on a pseudo-terminal
# of its own.

SH_PATH=$(type -P sh)

in_scratch_dir() { # function
    local rc
    D=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    ( "$1" )
    rc=$?
    rm -rf -- "$D"
    return $rc
}

# Run a command line on a terminal: its output, without the carriage returns
# a terminal adds. script passes the end of its own input on as an end of
# input on the terminal, so its input is held open until it is done, by
# whatever the case gives as the feeder, or by nothing being typed at all.
on_a_terminal() { # command line [feeder function]
    command -v script >/dev/null 2>&1 || { echo "no script(1) to make a terminal with"; return 77; }
    rm -f "$D/script.done"
    {
        [ -z "${2:-}" ] || "$2"
        while [ ! -e "$D/script.done" ]; do sleep 0.1; done
    } | {
        timeout -k 2 30 script -qec "$1" /dev/null
        : > "$D/script.done"
    } | tr -d '\r'
}

await_file() { # path : up to five seconds
    local i=0
    while [ ! -e "$1" ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    [ -e "$1" ]
}

h_streams_without_a_terminal() {
    : > "$D/open-in-the-caller"
    out=$(echo typed | "$UNIT" relay /dev/ptmx -- "$SH_PATH" -c '
        cat
        test -t 0 && echo "stdin is a terminal"
        read -r pid _ _ _ _ session _ < /proc/self/stat
        [ "$pid" = "$session" ] && echo "leads its session"
        echo "descriptors: $(ls /proc/self/fd | tr "\n" " ")"
        exit 7' 9< "$D/open-in-the-caller")
    rc=$?
    printf '%s\n' "$out"
    echo "status $rc"
    # ls has the directory it lists on 3; the caller had a file on 9
    [ $rc -eq 7 ] && [ "$out" = "typed
leads its session
descriptors: 0 1 2 3 " ]
}

h_a_terminal_of_its_own() {
    out=$(on_a_terminal "tty; stty rows 31 cols 97; stty -g > $D/before
        '$UNIT' relay /dev/ptmx -- $SH_PATH -c 'tty; stty size; test -t 2 && echo stderr-is-a-terminal; ls /proc/self/fd | tr \"\\n\" \" \"; echo; exit 5'
        echo status \$?; stty -g > $D/after") || return $?
    printf '%s\n' "$out"
    outer=$(printf '%s\n' "$out" | sed -n 1p)
    inner=$(printf '%s\n' "$out" | sed -n 2p)
    case $outer:$inner in /dev/*:/dev/*) ;; *) echo "no two terminals"; return 1 ;; esac
    [ "$outer" != "$inner" ] || { echo "the command has the caller's terminal"; return 1; }
    printf '%s\n' "$out" | grep -qx '31 97' || { echo "the command's terminal does not have the caller's size"; return 1; }
    printf '%s\n' "$out" | grep -qx 'stderr-is-a-terminal' && printf '%s\n' "$out" | grep -qx '0 1 2 3 ' &&
    printf '%s\n' "$out" | grep -qx 'status 5' || return 1
    cmp -s "$D/before" "$D/after" || { echo "the caller's terminal did not get its modes back"; return 1; }

    # The terminal is the command's controlling terminal, and the command is in its foreground:
    # fields 5, 7 and 8 of its stat. A program that does nothing about terminals is asked,
    # because some shells take a controlling terminal by themselves when they have none.
    out=$(on_a_terminal "'$UNIT' relay /dev/ptmx -- $(type -P cat) /proc/self/stat") || return $?
    # shellcheck disable=SC2086
    set -- ${out##*) }
    echo "the command's process group $3, terminal $5, foreground group of that terminal $6"
    [ "$5" != 0 ] && [ "$3" = "$6" ] || { echo "the terminal is not the command's controlling terminal"; return 1; }
}

# The worker is in the container's cgroup, and ends without a word when the
# container is stopped. The process that ran exec puts the terminal's modes
# back then: here the command kills the worker, which is its parent.
h_terminal_modes_survive_the_worker() {
    out=$(on_a_terminal "stty -g > $D/before
        '$UNIT' relay /dev/ptmx -- $SH_PATH -c 'kill -KILL \$PPID; sleep 5'
        echo status \$?; stty -g > $D/after") || return $?
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -qx 'status 137' || { echo "the first process did not report its worker's end"; return 1; }
    cmp -s "$D/before" "$D/after" || { echo "the terminal was left as the worker had it: $(cat "$D/after") instead of $(cat "$D/before")"; return 1; }
}

# What is typed reaches the command, and the key that interrupts is the
# command's to get: as SIGINT, from its own terminal.
h_terminal_input_and_keys() {
    feeder() {
        await_file "$D/reading" && printf 'hello\n'
        await_file "$D/waiting" && printf '\003'
    }
    out=$(on_a_terminal "'$UNIT' relay /dev/ptmx -- $SH_PATH -c 'trap \"echo got-SIGINT; exit 3\" INT; : > $D/reading; read -r line; echo \"read: \$line\"; : > $D/waiting; sleep 20 & wait'
        echo status \$?" feeder) || return $?
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -qx 'read: hello' && printf '%s\n' "$out" | grep -q 'got-SIGINT' &&
    printf '%s\n' "$out" | grep -qx 'status 3'
}

# When the caller's terminal changes its size, so does the command's.
h_terminal_follows_the_window() {
    out=$(on_a_terminal "stty rows 20 cols 80
        ( while [ ! -e $D/first ]; do sleep 0.1; done; stty rows 44 cols 120 < /dev/tty; : > $D/resized ) &
        '$UNIT' relay /dev/ptmx -- $SH_PATH -c 'stty size; : > $D/first
            i=0; while [ ! -e $D/resized ] && [ \$i -lt 50 ]; do sleep 0.1; i=\$((i + 1)); done
            i=0; while [ \"\$(stty size)\" = \"20 80\" ] && [ \$i -lt 30 ]; do sleep 0.1; i=\$((i + 1)); done
            stty size'") || return $?
    printf '%s\n' "$out"
    [ "$(printf '%s\n' "$out" | grep -E '^[0-9]+ [0-9]+$' | paste -sd' ' -)" = "20 80 44 120" ]
}

# With a terminal on one side only, the command gets a pipe in its place:
# nothing of the caller's terminal, and bytes that arrive as they were sent.
h_pipes_for_half_a_terminal() {
    out=$(on_a_terminal "echo piped | '$UNIT' relay /dev/ptmx -- $SH_PATH -c 'cat; test -t 1 && echo stdout-is-a-terminal; test -t 2 && echo stderr-is-a-terminal; echo to-stderr >&2'") || return $?
    printf '%s\n' "$out"
    [ "$out" = "piped
to-stderr" ] || return 1
    # the end of what is typed is the end of the command's input: it must end, and say so
    feeder() { await_file "$D/reading" && printf 'one\ntwo\n\004'; }
    on_a_terminal "'$UNIT' relay /dev/ptmx -- $SH_PATH -c 'test -t 0 && echo stdin-is-a-terminal >&2; : > $D/reading; cat' > $D/typed; echo \$? > $D/status" feeder >/dev/null || return $?
    echo "what the command read from the keyboard: $(od -An -c "$D/typed" | tr -s ' \n' ' '); status $(cat "$D/status" 2>&1)"
    [ "$(cat "$D/status" 2>/dev/null)" = 0 ] || { echo "the command did not come to the end of its input"; return 1; }
    [ "$(cat "$D/typed")" = "one
two" ] && ! grep -q "$(printf '\r')" "$D/typed"
}

# A signal that asks exec to end is passed on, to the worker and by it to the
# command, which leads a session of its own and would not hear of it.
h_signals_are_passed_on() {
    "$UNIT" relay /dev/ptmx -- "$SH_PATH" -c "trap 'echo asked > $D/asked; exit 9' TERM; : > $D/started; sleep 20 & wait" </dev/null >/dev/null 2>&1 &
    front=$!
    await_file "$D/started" || { echo "the command did not start"; kill -KILL "$front"; return 1; }
    kill -TERM "$front"
    wait "$front"
    rc=$?
    echo "status $rc; the command: $(cat "$D/asked" 2>&1)"
    [ $rc -eq 9 ] && [ "$(cat "$D/asked")" = asked ] || return 1
    # and a command that does nothing about it ends of it, which is the status that comes back.
    # (SIGHUP and not SIGINT: a shell starts what it runs with & ignoring SIGINT, and what
    # is ignored stays ignored in everything that is started from there.)
    "$UNIT" relay /dev/ptmx -- "$SH_PATH" -c ": > $D/started2; exec sleep 20" </dev/null >/dev/null 2>&1 &
    front=$!
    await_file "$D/started2" || { kill -KILL "$front"; return 1; }
    kill -HUP "$front"
    wait "$front"
    rc=$?
    echo "status of a command that SIGHUP ended: $rc"
    [ $rc -eq 129 ]
}

# More than a pipe or a terminal holds at once, in both directions.
h_plenty_goes_through() {
    seq 1 30000 > "$D/numbers"
    "$UNIT" relay /dev/ptmx -- "$SH_PATH" -c 'cat' < "$D/numbers" > "$D/through" || return 1
    cmp -s "$D/numbers" "$D/through" || { echo "what went through pipes of the caller's is not what was sent"; return 1; }
    out=$(on_a_terminal "'$UNIT' relay /dev/ptmx -- $SH_PATH -c 'cat $D/numbers | wc -l; cat $D/numbers | tail -n 1; cat $D/numbers' | tail -n 3") || return $?
    printf '%s\n' "$out" | tail -n 3
    [ "$(printf '%s\n' "$out" | tail -n 1)" = 30000 ] || return 1

    # What a command wrote just before it ended is still delivered: 170 KB through a pipe that
    # stands in for the terminal, of which a pipe's worth is still on its way when the command ends.
    out=$(on_a_terminal "echo x | '$UNIT' relay /dev/ptmx -- $(type -P cat) $D/numbers") || return $?
    echo "lines that arrived of 30000: $(printf '%s\n' "$out" | grep -c .), the last: $(printf '%s\n' "$out" | tail -n 1)"
    [ "$(printf '%s\n' "$out" | tail -n 1)" = 30000 ] && [ "$(printf '%s\n' "$out" | grep -c .)" = 30000 ] || return 1

    # What is typed faster than the command reads waits for it, and none of it is lost: 3000
    # lines before the command reads its first, into a terminal of its own and into a pipe.
    lines() { await_file "$D/ready" && seq -f 'line %.0f' 1 3000 && printf 'END\n'; }
    out=$(on_a_terminal "'$UNIT' relay /dev/ptmx -- $SH_PATH -c 'stty -echo; : > $D/ready; sleep 1; n=0; while read -r l; do [ \"\$l\" = END ] && break; n=\$((n + 1)); done; echo read \$n lines'" lines) || return $?
    printf '%s\n' "$out" | tail -n 1
    printf '%s\n' "$out" | grep -qx 'read 3000 lines' || return 1
    rm -f "$D/ready"
    lines() { await_file "$D/ready" && seq -f 'line %.0f' 1 3000 && printf '\004'; }
    on_a_terminal "'$UNIT' relay /dev/ptmx -- $SH_PATH -c ': > $D/ready; sleep 1; wc -l' > $D/count" lines >/dev/null || return $?
    echo "lines counted through a pipe: $(cat "$D/count")"
    [ "$(tr -d ' ' < "$D/count")" = 3000 ]
}

t_streams_without_a_terminal()  { in_scratch_dir h_streams_without_a_terminal; }
t_streams_terminal()            { in_scratch_dir h_a_terminal_of_its_own; }
t_streams_modes_survive()       { in_scratch_dir h_terminal_modes_survive_the_worker; }
t_streams_input_and_keys()      { in_scratch_dir h_terminal_input_and_keys; }
t_streams_window()              { in_scratch_dir h_terminal_follows_the_window; }
t_streams_half_a_terminal()     { in_scratch_dir h_pipes_for_half_a_terminal; }
t_streams_signals()             { in_scratch_dir h_signals_are_passed_on; }
t_streams_plenty()              { in_scratch_dir h_plenty_goes_through; }

# ─── exec: the binary it runs from ──────────────────────────────────────────

# exec begins by executing itself again from a sealed copy in memory. What
# comes back is the same command with the same words and environment, running
# from a file that cannot be opened for writing.
t_exec_runs_from_a_sealed_copy() {
    [ "$(cat /proc/sys/vm/memfd_noexec 2>/dev/null)" != 2 ] || { echo "executable memfds are refused on this host"; return 77; }
    out=$(KEPT=yes "$UNIT" sealed one 'two words' 2>&1)
    printf '%s\n' "$out"
    said() { printf '%s\n' "$out" | grep -qxF -- "$1" || { echo "missing: $1"; return 1; }; }
    # 15: no more seals, no shrinking, no growing, no writing
    said 'exe /memfd:lightbox (deleted)' && said 'seals 15' && said 'sealed yes' && said 'name lightbox' &&
    said 'words [one] [two words]' && said 'kept yes' || return 1
    case $out in *'write DONE'*) echo "the running binary was written to"; return 1 ;; esac
    # a process that has executed itself once and still is not sealed stops, and does not try for ever
    out=$(LIGHTBOX_EXEC_SEALED=1 timeout 10 "$UNIT" sealed 2>&1)
    rc=$?
    echo "with the mark already set: status $rc, $out"
    [ $rc -eq 1 ]
}

# Where executable memfds are refused, exec takes the binary through a mount
# of its own that is read-only. That takes the right to mount.
t_exec_sealing_by_a_read_only_mount() {
    unshare -r --mount true 2>/dev/null || { echo "user namespaces with capabilities are not available to this user"; return 77; }
    out=$(KEPT=yes unshare -r --mount "$UNIT" sealed-readonly one 'two words' 2>&1)
    printf '%s\n' "$out"
    said() { printf '%s\n' "$out" | grep -qxF -- "$1" || { echo "missing: $1"; return 1; }; }
    said 'mount read-only' && said 'sealed yes' && said 'words [one] [two words]' && said 'kept yes' || return 1
    # the binary itself, not a copy of it: a file like any other has at most the seal that says it takes none
    case $out in *'exe /memfd:'*|*'seals 15'*) echo "that is a memfd"; return 1 ;; esac
    case $out in *'write DONE'*) echo "the running binary was written to"; return 1 ;; esac
}

# ─── exec: who a command runs as ────────────────────────────────────────────

t_user_spec() {
    bad=0
    expect() { # text, what parse_user_spec makes of it
        got=$("$UNIT" userspec "$1")
        [ "$got" = "$2" ] || { echo "--user '$1' -> $got, expected $2"; bad=1; }
    }
    expect 0 'uid 0'
    expect 1000 'uid 1000'
    expect 1000:50 'uid 1000 gid 50'
    expect 2147483647 'uid 2147483647'
    expect lbuser 'name lbuser'
    expect _svc-1.x 'name _svc-1.x'
    expect "$(printf 'n%.0s' $(seq 1 255))" "name $(printf 'n%.0s' $(seq 1 255))"
    # numbers that are not numbers, parts that are missing, names that cannot be
    for spec in 0x10 1000: :5 1000:x 12abc 1000:50:7 99999999999 2147483648 1000:99999999999 \
                a:b a/b 'a b' "$(printf 'n%.0s' $(seq 1 256))"; do
        expect "$spec" invalid
    done
    expect '' invalid
    return $bad
}

# Account files for a case: sets $P and $G, in a directory of its own.
accounts() {
    A=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    P=$A/passwd G=$A/group
    {
        echo 'root:x:0:0:root:/root:/bin/sh'
        echo 'a line that is not an account'
        echo 'short:x:5'
        echo 'fourfields:x:4804:4804'
        # a name and a home directory that are too long to be anyone's
        printf '%s:x:4802:4802::/home/longname:/bin/sh\n' "$(printf 'n%.0s' $(seq 1 300))"
        printf 'longhome:x:4803:4803::/%s:/bin/sh\n' "$(printf 'h%.0s' $(seq 1 600))"
        echo 'badnumber:x:12abc:12:bad:/home/bad:/bin/sh'
        echo 'lbuser:x:4711:4711:lightbox test:/home/lbuser:/bin/sh'
        # a comment field far longer than any buffer, then the account after it
        printf 'wordy:x:4800:4800:%s:/home/wordy:/bin/sh\n' "$(head -c 10000 /dev/zero | tr '\0' c)"
        echo 'afterwordy:x:4801:4801::/home/afterwordy:/bin/sh'
        # accounts enough to put the next ones beyond the first reads of the file
        for i in $(seq 1 300); do echo "filler$i:x:$((10000 + i)):$((10000 + i)):filler account:/home/filler$i:/bin/sh"; done
        echo 'a-user-whose-name-is-longer-than-twelve:x:4900:4900::/home/long:/bin/sh'
        echo 'second4711:x:4711:1::/home/second:/bin/sh'
        printf 'last:x:4999:4999::/home/last'        # no shell, and no newline
    } > "$P"
    {
        echo 'root:x:0:'
        echo 'lbuser:x:4711:lbuser'
        echo 'lbgroup:x:4712:lbuser'
        echo 'others:x:4713:lbuserx,xlbuser,lbuse,root'
        echo 'again:x:4712:someone,lbuser'
        printf 'crowd:x:4714:%s,lbuser\n' "$(seq -f 'member%.0f' -s , 1 3000)"
        echo 'badgid:x:47x:lbuser'
        printf 'tail:x:4715:root,lbuser'                # no newline
    } > "$G"
}

t_accounts_are_found() {
    accounts || return 1
    (
        bad=0
        expect() { # exec's options, what resolve_identity makes of them
            local want=$1
            shift
            got=$("$UNIT" identity "$P" "$G" "$@" 2>&1)
            [ "$got" = "$want" ] || { echo "$*: $got"; echo "   expected: $want"; bad=1; }
        }
        echo "passwd is $(wc -c < "$P") bytes, group $(wc -c < "$G")"
        # without --user: root, with what the container says about root
        expect 'uid 0 gid 0 name root home /root groups 4713 4715'
        expect 'uid 4711 gid 4711 name lbuser home /home/lbuser groups 4712 4714 4715' --user lbuser
        expect 'uid 4711 gid 4711 name lbuser home /home/lbuser groups 4712 4714 4715' --user 4711
        # with another primary group, the user's own group is one of the others it is listed in
        expect 'uid 4711 gid 9 name lbuser home /home/lbuser groups 4711 4712 4714 4715' --user 4711:9
        # beyond a line of 10 000 characters, beyond the first reads, and at the very end
        expect 'uid 4801 gid 4801 name afterwordy home /home/afterwordy groups' --user afterwordy
        expect 'uid 4900 gid 4900 name a-user-whose-name-is-longer-than-twelve home /home/long groups' --user 4900
        expect 'uid 4900 gid 4900 name a-user-whose-name-is-longer-than-twelve home /home/long groups' --user a-user-whose-name-is-longer-than-twelve
        expect 'uid 4999 gid 4999 name last home /home/last groups' --user last
        # a uid the container has no account for: itself as its group, and no other group
        expect 'uid 1234 gid 1234 name - home - groups' --user 1234
        expect 'uid 1234 gid 7 name - home - groups' --user 1234:7
        # lines that are not accounts are not accounts
        expect 'uid 12 gid 12 name - home - groups' --user 12
        expect 'uid 5 gid 5 name - home - groups' --user 5
        expect 'uid 4804 gid 4804 name - home - groups' --user 4804
        # nor is a line whose name or home was too long to keep whole
        expect 'uid 4802 gid 4802 name - home - groups' --user 4802
        expect 'uid 4803 gid 4803 name - home - groups' --user 4803
        expect 'Error: user not found in container: longhome' --user longhome
        expect 'Error: user not found in container: badnumber' --user badnumber
        expect 'Error: user not found in container: nosuch' --user nosuch
        exit $bad
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

# A name that is the beginning of another, or its end, is another name.
t_group_members_match_whole() {
    accounts || return 1
    (
        printf 'lbuser:x:4711:4711::/h:/s\nlbuse:x:4720:4720::/h:/s\n' > "$P"
        got=$("$UNIT" identity "$P" "$G" --user lbuse)
        echo "$got"
        [ "$got" = 'uid 4720 gid 4720 name lbuse home /h groups 4713' ] || exit 1
        # more groups than a command can be given is said, not cut
        for i in $(seq 1 70); do echo "g$i:x:$((5000 + i)):lbuser"; done > "$G"
        got=$("$UNIT" identity "$P" "$G" --user lbuser 2>&1)
        echo "$got"
        case $got in 'Error: the container lists more than 64 groups for user lbuser') ;; *) exit 1 ;; esac
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

# What the container puts at /etc/passwd is the container's choice. Only a
# regular file is read: a pipe would never end, a device would never stop.
t_account_file_must_be_a_file() {
    accounts || return 1
    (
        rm -f "$P" && mkfifo "$P" || exit 77
        got=$(timeout 5 "$UNIT" identity "$P" "$G" --user 1234 2>&1) || { echo "a pipe for passwd: status $?, $got"; exit 1; }
        echo "passwd is a pipe: $got"
        [ "$got" = 'uid 1234 gid 1234 name - home - groups' ] || exit 1
        # and a pipe that has an account waiting in it is not asked either
        exec 7<> "$P"
        printf 'planted:x:1234:0::/:/bin/sh\n' >&7
        got=$(timeout 5 "$UNIT" identity "$P" "$G" --user 1234 2>&1) || { echo "a pipe with a line in it: status $?, $got"; exit 1; }
        exec 7>&-
        echo "passwd is a pipe with an account in it: $got"
        [ "$got" = 'uid 1234 gid 1234 name - home - groups' ] || exit 1
        rm -f "$P" && ln -s /dev/zero "$P"
        got=$(timeout 5 "$UNIT" identity "$P" "$G" 2>&1) || { echo "a link to /dev/zero for passwd: status $?, $got"; exit 1; }
        echo "passwd is a link to /dev/zero: $got"
        [ "$got" = 'uid 0 gid 0 name - home - groups' ] || exit 1
        rm -f "$P"
        got=$("$UNIT" identity "$P" "$G" --user 7 2>&1)
        echo "no passwd at all: $got"
        [ "$got" = 'uid 7 gid 7 name - home - groups' ]
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

# ─── exec: the command, its arguments and its environment ───────────────────

t_command_environment() {
    accounts || return 1
    (
        run() { env -i "$@"; }          # the harness with exactly this environment
        got=$(run TERM=vt220 "$UNIT" command "$P" "$G" --user lbuser /usr/bin/env | sort | paste -sd' ' -)
        echo "as lbuser: $got"
        [ "$got" = "HOME=/home/lbuser LOGNAME=lbuser PATH=/usr/bin:/bin:/usr/sbin:/sbin TERM=vt220 USER=lbuser" ] || exit 1
        # a uid without an account has no name to give, and a TERM that is not a plain name is not passed on
        got=$(run 'TERM=x$(reboot)' "$UNIT" command "$P" "$G" --user 1234 /usr/bin/env | sort | paste -sd' ' -)
        echo "as 1234: $got"
        [ "$got" = "HOME=/ PATH=/usr/bin:/bin:/usr/sbin:/sbin TERM=xterm" ] || exit 1
        got=$(run "$UNIT" command "$P" "$G" /usr/bin/env | sort | paste -sd' ' -)
        echo "as root: $got"
        [ "$got" = "HOME=/root LOGNAME=root PATH=/usr/bin:/bin:/usr/sbin:/sbin TERM=xterm USER=root" ] || exit 1
        # --env adds, replaces what is there, and the later of two wins; nothing else of the caller's gets in
        got=$(run SECRET=1 "$UNIT" command "$P" "$G" --env A=1 --env HOME=/elsewhere -e A=2 --env B= /usr/bin/env | sort | paste -sd' ' -)
        echo "with --env: $got"
        [ "$got" = "A=2 B= HOME=/elsewhere LOGNAME=root PATH=/usr/bin:/bin:/usr/sbin:/sbin TERM=xterm USER=root" ]
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

t_command_is_found_on_path() {
    accounts || return 1
    (
        cd /
        # by name, as the README shows it
        [ "$("$UNIT" command "$P" "$G" echo found)" = found ] || { echo "echo was not found on PATH"; exit 1; }
        mkdir "$A/bin" "$A/other"
        printf '#!/bin/sh\necho mine\n' > "$A/bin/tool"
        chmod 755 "$A/bin/tool"
        : > "$A/other/tool"                 # there, and not a program
        [ "$("$UNIT" command "$P" "$G" --env "PATH=/nonexistent:$A/other:$A/bin" tool)" = mine ] || { echo "a later directory of PATH was not tried"; exit 1; }
        "$UNIT" command "$P" "$G" --env "PATH=$A/other" tool 2>"$A/err"
        rc=$?
        echo "not a program: status $rc, $(cat "$A/err")"
        [ $rc -eq 126 ] || exit 1
        "$UNIT" command "$P" "$G" no-such-command-anywhere 2>"$A/err"
        rc=$?
        echo "not there: status $rc, $(cat "$A/err")"
        [ $rc -eq 127 ] && grep -q 'command not found: no-such-command-anywhere' "$A/err" || exit 1
        "$UNIT" command "$P" "$G" /no/such/program 2>"$A/err"
        rc=$?
        echo "a path that is not there: status $rc, $(cat "$A/err")"
        [ $rc -eq 127 ] || exit 1
        # a name with a slash is a path and is not looked for; an empty entry of PATH is not this directory
        cd "$A/bin" || exit 1
        "$UNIT" command "$P" "$G" --env "PATH=:/usr/bin:/bin" tool 2>/dev/null && { echo "the current directory was searched"; exit 1; }
        [ "$("$UNIT" command "$P" "$G" ./tool)" = mine ]
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

t_command_gets_every_argument() {
    accounts || return 1
    (
        # shellcheck disable=SC2046
        got=$("$UNIT" command "$P" "$G" /bin/sh -c 'echo "$# $1 ${537} ${1000}"' sh $(seq 1 1000))
        echo "1000 arguments in; their number, the first, the 537th and the last: $got"
        [ "$got" = "1000 1 537 1000" ] || exit 1
        # after --, a word that looks like an option is the command's
        got=$("$UNIT" command "$P" "$G" --env X=1 -- echo --user -e)
        [ "$got" = "--user -e" ] || { echo "after --: $got"; exit 1; }
        got=$("$UNIT" command "$P" "$G" --workdir /usr /bin/sh -c pwd)
        [ "$got" = /usr ] || { echo "--workdir /usr: $got"; exit 1; }
        "$UNIT" command "$P" "$G" --workdir /no/such/directory /bin/true 2>"$A/err"
        rc=$?
        echo "a directory that is not there: status $rc, $(cat "$A/err")"
        [ $rc -eq 126 ]
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

t_command_options_are_checked() {
    accounts || return 1
    (
        bad=0
        refuse() { # what the message must say, exec's options...
            local want=$1
            shift
            got=$("$UNIT" command "$P" "$G" "$@" 2>&1) && { echo "$* ran: $got"; bad=1; return; }
            case $got in *"$want"*) echo "$*: $got" ;; *) echo "$*: $got"; echo "   expected to read: $want"; bad=1 ;; esac
        }
        refuse 'option --user requires a value' --user
        refuse 'option --env requires a value' --env X=1 --env
        refuse 'option -w requires a value' -w
        refuse 'unknown option: --bogus' --bogus echo
        refuse 'goes after --' -n echo
        refuse '--env takes KEY=VALUE' --env novalue echo
        refuse '--env takes KEY=VALUE' --env =value echo
        refuse '--workdir takes an absolute path' --workdir relative echo
        refuse 'this is none of them: 0x10' --user 0x10 echo
        refuse 'this is none of them: 1000:' --user 1000: echo
        exit $bad
    )
    rc=$?
    rm -rf -- "$A"
    return $rc
}

# ─── parse_seconds, and the shape of cmd_start ──────────────────────────────

t_seconds() {
    bad=0
    for pair in 0:0 7:7 30:30 86400:86400 86401:-1 -1:-1 5s:-1 s5:-1 1.5:-1 ' 5':-1 99999999999999999999:-1; do
        got=$(result_of "$("$UNIT" seconds "${pair%:*}")")
        [ "$got" = "${pair##*:}" ] || { echo "'${pair%:*}' -> $got, expected ${pair##*:}"; bad=1; }
    done
    got=$(result_of "$("$UNIT" seconds '')")
    [ "$got" = -1 ] || { echo "an empty value -> $got"; bad=1; }
    return $bad
}

# Whatever of its three standard streams a caller leaves closed, the first
# file lightbox opens is not given that number: a message meant for the
# terminal would be written into the file.
t_standard_streams_are_reserved() {
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    (
        "$UNIT" streams "$dir/all" <&- >&- 2>&-
        "$UNIT" streams "$dir/out" >&-
        "$UNIT" streams "$dir/none"
        echo "next descriptor with all three closed: $(cat "$dir/all"); with stdout closed: $(cat "$dir/out"); with none closed: $(cat "$dir/none")"
        [ "$(cat "$dir/all")" = 3 ] && [ "$(cat "$dir/out")" = 3 ] && [ "$(cat "$dir/none")" = 3 ]
    )
    rc=$?
    rm -rf -- "$dir"
    return $rc
}

# From its first change to the host on, cmd_start has one way out, which undoes
# what was done. A call that ends the process where it stands would leave an
# interface, a cgroup or an init behind.
t_start_has_one_way_out() {
    src=$HERE/../lightbox.c
    region=$(awk '/^static void cmd_start\(/ { inside = 1 }
                  inside && /const char \*start_err = NULL;/ { on = 1 }
                  on { print }
                  inside && /^}/ { exit }' "$src")
    [ -n "$region" ] || { echo "cmd_start, or the start of its guarded part, was not found in $src"; return 1; }
    echo "lines looked at: $(printf '%s\n' "$region" | wc -l)"
    bad=0
    if printf '%s\n' "$region" | grep -nE '\b(die|die2|[a-z_]+_or_die|require_[a-z_]+|set_container_state|usage)\(' ; then
        echo "these end the process where it stands"; bad=1
    fi
    exits=$(printf '%s\n' "$region" | grep -c 'lc_kernel_exit(')
    [ "$exits" = 1 ] || { echo "lc_kernel_exit is called $exits times; the one in fail_start is the only one there may be"; bad=1; }
    printf '%s\n' "$region" | grep -q 'goto fail_start' || { echo "nothing goes to fail_start"; bad=1; }
    return $bad
}

# ─── Text and numbers ───────────────────────────────────────────────────────

# The three helpers that put text into a buffer never put part of it there.
t_text_is_whole_or_refused() {
    bad=0
    expect() { # expected output, then the harness's arguments
        want=$1; shift
        got=$("$UNIT" text "$@")
        [ "$got" = "$want" ] || { echo "text $*: '$got', expected '$want'"; bad=1; }
    }
    # five characters need six bytes
    expect 'whole hello'  copy 6 hello
    expect 'cut '         copy 5 hello
    expect 'cut '         copy 1 hello
    expect 'whole '       copy 1 ''
    # what does not fit is not appended, and what was there stays whole
    expect 'whole abcdef' append 7 abc def
    expect 'cut abc'      append 6 abc def
    expect 'cut abc'      append 4 abc def
    # one slash between the two, whatever they bring
    expect 'whole /a/b'   join 5 /a b
    expect 'whole /a/b'   join 5 /a/ b
    expect 'whole /a/b'   join 5 /a /b
    expect 'whole /a/b'   join 5 /a/ /b
    expect 'cut '         join 4 /a b
    expect 'cut '         join 3 /a b
    expect 'whole /b'     join 3 / b
    return $bad
}

t_numbers_are_strict() {
    bad=0
    expect() { # text, min, max, expected
        got=$("$UNIT" number "$1" "$2" "$3")
        [ "$got" = "$4" ] || { echo "'$1' in [$2, $3]: $got, expected $4"; bad=1; }
    }
    expect 0 0 10 0
    expect 10 0 10 10
    expect 11 0 10 refused
    expect -1 0 10 refused
    expect -5 -10 10 -5
    expect 007 0 10 7
    # nothing but a sign and digits
    for text in '' '-' '+5' ' 5' '5 ' 5s s5 1.5 0x10 1e3 '5
' -0 --5; do
        expect "$text" -100 100 refused
    done
    # the ends of what a number can be, and one past each
    expect 9223372036854775807 0 9223372036854775807 9223372036854775807
    expect 9223372036854775808 0 9223372036854775807 refused
    expect -9223372036854775808 -9223372036854775808 0 -9223372036854775808
    expect -9223372036854775809 -9223372036854775808 0 refused
    # a number that would come round to a small one
    expect 18446744073709551621 0 100 refused
    expect 99999999999999999999999999 0 9223372036854775807 refused
    return $bad
}

# What --mem, --pids, --cpu and --oom-score take; the settings default_* and
# the lines of a .conf are held to the same.
# An address is four numbers of 0 to 255 and three dots, and nothing else:
# no shorter form, and no zero in front of a number, which some programs
# read as octal.
t_addresses_are_strict() {
    bad=0
    expect() { # text, expected
        got=$("$UNIT" address "$1")
        [ "$got" = "$2" ] || { echo "'$1': $got, expected $2"; bad=1; }
    }
    expect 10.0.0.2 10.0.0.2
    expect 0.0.0.0 0.0.0.0
    expect 255.255.255.255 255.255.255.255
    expect 192.168.100.10 192.168.100.10
    expect 10.0.0.0 10.0.0.0
    for text in '' 10 10.0 10.0.0 10.0.0.0.0 10.0.0. .10.0.0 10..0.0 10.0.0.256 10.0.0.1000 256.0.0.1 \
                '10.0.0.2 ' ' 10.0.0.2' '10.0.0.2
' 10.0.0.2/24 10.0.0.-2 10.0.0.+2 10.0.0.0x2 1e1.0.0.2 10.0.0.a 10,0,0,2 ::1 \
                010.0.0.2 10.0.0.02 10.00.0.2 10.0.0.007 00.0.0.0; do
        expect "$text" refused
    done
    return $bad
}

# subnet and gw are one network, read and checked together: any address of
# the subnet names it, its prefix is 8 to 30 bits, and the gateway is one of
# its addresses that an interface can have. On it, a container can have any
# address but the first, the last and the gateway's, with the subnet's prefix.
t_network_settings() {
    bad=0
    expect() { # subnet, gw, expected
        got=$("$UNIT" network "$1" "$2")
        [ "$got" = "$3" ] || { echo "subnet '$1', gw '$2': $got, expected $3"; bad=1; }
    }
    expect 10.0.0.0/24 10.0.0.1 'subnet 10.0.0.0/24 broadcast 10.0.0.255 gateway 10.0.0.1'
    expect 10.9.0.0/16 10.9.0.1 'subnet 10.9.0.0/16 broadcast 10.9.255.255 gateway 10.9.0.1'
    expect 10.9.5.7/16 10.9.200.1 'subnet 10.9.0.0/16 broadcast 10.9.255.255 gateway 10.9.200.1'
    expect 10.0.0.0/8 10.255.255.254 'subnet 10.0.0.0/8 broadcast 10.255.255.255 gateway 10.255.255.254'
    expect 192.168.7.0/30 192.168.7.2 'subnet 192.168.7.0/30 broadcast 192.168.7.3 gateway 192.168.7.2'
    for subnet in 10.0.0.0 10.0.0.0/ 10.0.0.0/7 10.0.0.0/31 10.0.0.0/32 10.0.0.0/024 10.0.0.0/24x 10.0.0/24 \
                  /24 10.0.0.0/-24 '10.0.0.0/24 ' 010.0.0.0/24 10.0.0.0//24 ''; do
        got=$("$UNIT" network "$subnet" 10.0.0.1)
        case $got in 'subnet is not <address>/<bits>'|'subnet takes 8 to 30 bits after the /') ;;
            *) echo "subnet '$subnet' was taken: $got"; bad=1 ;; esac
    done
    expect 10.0.0.0/24 10.0.1.1 'gw is not in the subnet'
    expect 10.9.0.0/16 10.8.0.1 'gw is not in the subnet'
    expect 10.0.0.0/24 10.0.0.0 'gw is the first or the last address of the subnet, which no interface can have'
    expect 10.0.0.0/24 10.0.0.255 'gw is the first or the last address of the subnet, which no interface can have'
    expect 10.0.0.0/24 10.0.0.01 'gw is not an IPv4 address'
    expect 10.0.0.0/24 '' 'gw is not an IPv4 address'

    got=$("$UNIT" network 10.9.0.0/16 10.9.0.1 10.9.5.2 10.9.0.1 10.9.0.0 10.9.255.255 10.10.0.2 10.8.255.255 \
                  10.9.255.254 10.9.0.2 10.9.0.02 | tail -n +2)
    want='10.9.5.2: 10.9.5.2/16
10.9.0.1: it is the gateway'"'"'s, the address of the bridge
10.9.0.0: it is the address of the subnet itself
10.9.255.255: it is the broadcast address of the subnet
10.10.0.2: it is outside the subnet of lightbox.conf
10.8.255.255: it is outside the subnet of lightbox.conf
10.9.255.254: 10.9.255.254/16
10.9.0.2: 10.9.0.2/16
10.9.0.02: not an address'
    [ "$got" = "$want" ] || { echo "on 10.9.0.0/16:"; printf '%s\n' "$got"; bad=1; }
    # a gateway that is not the first address leaves the first to a container
    got=$("$UNIT" network 10.0.0.0/24 10.0.0.254 10.0.0.1 10.0.0.254 | tail -n +2 | paste -sd'|' -)
    [ "$got" = "10.0.0.1: 10.0.0.1/24|10.0.0.254: it is the gateway's, the address of the bridge" ] ||
        { echo "with the gateway at .254: $got"; bad=1; }
    return $bad
}

# The prefix of every address an interface is given comes from subnet: no
# source names one of its own.
t_no_prefix_of_its_own() {
    src=$HERE/..
    if grep -nE '"/[0-9]+"' "$src"/lightbox*.c; then
        echo "a prefix is written into the source"
        return 1
    fi
}

# A program gets its input whole, whether it reads it or not, and an input
# that is too long is refused before anything runs.
t_program_input() {
    out=$("$UNIT" input 'two
lines
' "$CAT")
    [ "$out" = 'two
lines
result 0
left open 0' ] || { echo "cat said: $out"; return 1; }
    # one that ends without reading: no wait, and no signal for lightbox
    long=$(head -c 30000 /dev/zero | tr '\0' x)
    out=$(timeout 10 "$UNIT" input "$long" "$TRUE") || { echo "status $? with a program that does not read"; return 1; }
    [ "$out" = 'result 0
left open 0' ] || { echo "true said: $out"; return 1; }
    out=$(timeout 10 "$UNIT" input "$long" "$CAT" | tail -c 21)
    [ "$out" = 'result 0
left open 0' ] || { echo "the end of what cat said: $out"; return 1; }
    [ "$(timeout 10 "$UNIT" input "$long" "$CAT" | head -n 1 | tr -d x)" = 'result 0' ] || { echo "cat did not get all of it"; return 1; }
    [ "$(timeout 10 "$UNIT" input "$long" "$CAT" | head -n 1 | tr -cd x | wc -c)" = 30000 ] || { echo "cat did not get all 30000 bytes"; return 1; }
    out=$("$UNIT" input "$(head -c 40000 /dev/zero | tr '\0' x)" "$CAT" 2>&1)
    printf '%s\n' "$out"
    [ "$(printf '%s\n' "$out" | tail -n 2)" = 'result 256
left open 0' ] || return 1
    case $out in *'the input is too long for '*) ;; *) return 1 ;; esac
}

# What a container is called on the host: vb- and LB- with the same twelve
# hex digits of its name's FNV-1a hash, whatever the name's length, the same
# for a name every time and another for another name.
t_host_names() {
    bad=0
    expect() { # name, interface, chain
        got=$("$UNIT" names "$1" | paste -sd' ' -)
        [ "$got" = "$2 $3" ] || { echo "'$1': $got, expected $2 $3"; bad=1; }
    }
    expect web vb-5ea0e1194872 LB-5ea0e1194872
    expect db vb-08914e07b53b LB-08914e07b53b
    expect a vb-af63dc4c8601 LB-af63dc4c8601
    expect abcdefghijklmnopqrstuvwxyz0123 vb-b99d11b887d2 LB-b99d11b887d2
    [ "$("$UNIT" names web2 | head -n 1)" != vb-5ea0e1194872 ] || { echo "web2 has web's interface"; bad=1; }
    return $bad
}

# Whose an interface is, from what "ip link show" prints: lightbox's for this
# container only with the alias lightbox:<name>, exactly; without an alias,
# or with another, not lightbox's to touch.
t_interface_owner() {
    bad=0
    expect() { # name, listing, expected
        got=$("$UNIT" owner "$1" "$2")
        [ "$got" = "$3" ] || { echo "$1 with: $2"; echo "  $got, expected $3"; bad=1; }
    }
    head='7: vb-5ea0e1194872@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br0 state UP mode DEFAULT group default qlen 1000
    link/ether 2a:51:0c:7e:1b:93 brd ff:ff:ff:ff:ff:ff link-netnsid 1'
    expect web "$head
    alias lightbox:web" ours
    expect web "$head
    alias lightbox:web2" foreign
    expect web "$head
    alias lightbox:we" foreign
    expect web "$head
    alias lightbox:web " foreign
    expect web "$head
    alias something:web" foreign
    expect web "$head" foreign
    expect web "$head
    altname enp0s31f6" foreign
    expect web "$head
    altname lightbox:web
    alias lightbox:web" ours
    return $bad
}

# A record of link rules names a chain of lightbox's, or nothing is done with it.
t_link_chain_names() {
    bad=0
    for chain in LB-5ea0e1194872 LB-web LB-a LB-abcdefghijklmnopqrstuvwxy; do
        [ "$("$UNIT" chain "$chain")" = ok ] || { echo "$chain was refused"; bad=1; }
    done
    for chain in '' LB- LB LIGHTBOX-LINKS FORWARD 'LB-a b' 'LB-a;b' LB-abcdefghijklmnopqrstuvwxyz '-j ACCEPT' 'LB-x
-A FORWARD'; do
        [ "$("$UNIT" chain "$chain")" = refused ] || { echo "'$chain' was taken"; bad=1; }
    done
    return $bad
}

# What iptables-restore is given for a container's links: a chain of its own,
# a rule for each way of each link that names the two ports and no address,
# and the jump to it.
t_firewall_links_text() {
    got=$("$UNIT" firewall links web db cache)
    want='*filter
:LB-5ea0e1194872 - [0:0]
-A LB-5ea0e1194872 -m physdev --physdev-in vb-5ea0e1194872 --physdev-out vb-08914e07b53b -j ACCEPT
-A LB-5ea0e1194872 -m physdev --physdev-in vb-08914e07b53b --physdev-out vb-5ea0e1194872 -j ACCEPT
-A LB-5ea0e1194872 -m physdev --physdev-in vb-5ea0e1194872 --physdev-out vb-1c33d13ab5ec -j ACCEPT
-A LB-5ea0e1194872 -m physdev --physdev-in vb-1c33d13ab5ec --physdev-out vb-5ea0e1194872 -j ACCEPT
-A LIGHTBOX-LINKS -j LB-5ea0e1194872
COMMIT'
    [ "$got" = "$want" ] || { printf '%s\n' "$got"; return 1; }
    # eight links of the longest names fit
    long=abcdefghijklmnopqrstuvwxyz0123
    got=$("$UNIT" firewall links "$long" "${long%?}1" "${long%?}2" "${long%?}3" "${long%?}4" \
          "${long%?}5" "${long%?}6" "${long%?}7" "${long%?}8" | grep -c -- '--physdev-in')
    [ "$got" = 16 ] || { echo "rules for eight links: $got"; return 1; }
    # and a text that does not fit is no text
    got=$("$UNIT" firewall links-into-64 web db)
    [ "$got" = 'too long' ] || { echo "into 64 bytes: $got"; return 1; }
}

# firewall_backend = nftables: setup's two tables in one transaction. The
# chains are flushed and filled again and the set of links is not, as its
# elements are the running containers'. Between two ports of the bridge, the
# pairs in links and nothing else; out of the bridge anything, and back what
# belongs to it; the subnet masqueraded when ip_masq is true.
t_nft_setup_text() {
    got=$("$UNIT" firewall nft-setup 10.9.5.0/16 10.9.0.1 br7 true)
    tab=$(printf '\t')
    want="table ip lightbox {
${tab}chain forward {
${tab}${tab}type filter hook forward priority filter; policy accept;
${tab}}
${tab}chain postrouting {
${tab}${tab}type nat hook postrouting priority srcnat; policy accept;
${tab}}
}
flush chain ip lightbox forward
flush chain ip lightbox postrouting
add rule ip lightbox forward oifname \"br7\" ct state established,related accept
add rule ip lightbox forward oifname \"br7\" iifname != \"br7\" drop
add rule ip lightbox postrouting ip saddr 10.9.0.0/16 oifname != \"br7\" masquerade
table bridge lightbox {
${tab}set links {
${tab}${tab}type ifname . ifname
${tab}}
${tab}chain forward {
${tab}${tab}type filter hook forward priority filter; policy accept;
${tab}}
}
flush chain bridge lightbox forward
add rule bridge lightbox forward meta ibrname \"br7\" iifname . oifname @links accept
add rule bridge lightbox forward meta ibrname \"br7\" drop"
    [ "$got" = "$want" ] || { printf '%s\n' "$got"; return 1; }
    got=$("$UNIT" firewall nft-setup 10.0.0.0/24 10.0.0.1 br0 false | grep -c masquerade)
    [ "$got" = 0 ] || { echo "with ip_masq = false, masquerade rules: $got"; return 1; }
    # bridge_accept_fwmark: accepted before anything is dropped, in both tables
    got=$("$UNIT" firewall nft-setup 10.0.0.0/24 10.0.0.1 br0 true 0x10/0xf0 | grep -n 'mark')
    [ "$got" = '11:add rule ip lightbox forward meta mark & 0xf0 == 0x10 accept
24:add rule bridge lightbox forward meta mark & 0xf0 == 0x10 accept' ] || { printf '%s\n' "$got"; return 1; }
    got=$("$UNIT" firewall nft-setup 10.0.0.0/24 10.0.0.1 br0 true 0x10 | grep 'mark' | head -n 1)
    [ "$got" = 'add rule ip lightbox forward meta mark 0x10 accept' ] || { echo "a mark without a mask: $got"; return 1; }
    # a bridge whose name would not stay between the quotes gets no rules
    for br in 'br"0' 'br 0' 'br;0' 'abcdefghijklmnop' ''; do
        got=$("$UNIT" firewall nft-setup 10.0.0.0/24 10.0.0.1 "$br" true)
        [ "$got" = 'too long' ] || { echo "bridge '$br': $got"; return 1; }
    done
}

# A container's links under nftables: a record of the pairs of ports, each
# once, and from it the elements of the set, both ways of each pair. Removal
# puts them in and takes them out again, so that what a peer took out already
# does not stop it.
t_nft_link_elements() {
    got=$("$UNIT" firewall nft-record web db cache db web)
    want='nftables
vb-5ea0e1194872 vb-08914e07b53b
vb-5ea0e1194872 vb-1c33d13ab5ec'
    [ "$got" = "$want" ] || { echo "the record, with a link given twice and one to itself:"; printf '%s\n' "$got"; return 1; }
    nl='
'
    got=$("$UNIT" nftlinks add "$want$nl")
    elements='{ "vb-5ea0e1194872" . "vb-08914e07b53b", "vb-08914e07b53b" . "vb-5ea0e1194872", "vb-5ea0e1194872" . "vb-1c33d13ab5ec", "vb-1c33d13ab5ec" . "vb-5ea0e1194872" }'
    [ "$got" = "add element bridge lightbox links $elements" ] || { printf '%s\n' "$got"; return 1; }
    got=$("$UNIT" nftlinks remove "$want$nl")
    [ "$got" = "add element bridge lightbox links $elements
delete element bridge lightbox links $elements" ] || { printf '%s\n' "$got"; return 1; }
    # a record of no link is nothing to do
    got=$("$UNIT" nftlinks remove "nftables$nl")
    [ -z "$got" ] || { echo "for a record of no link: $got"; return 1; }
    # eight links of the longest names fit
    long=abcdefghijklmnopqrstuvwxyz0123
    record=$("$UNIT" firewall nft-record "$long" "${long%??}a1" "${long%??}a2" "${long%??}a3" "${long%??}a4" \
             "${long%??}a5" "${long%??}a6" "${long%??}a7" "${long%??}a8")
    got=$("$UNIT" nftlinks remove "$record$nl" | grep -o '" \. "' | wc -l)
    [ "$got" = 32 ] || { echo "elements for eight links, put in and taken out: $got"; return 1; }
}

# A record that is not one lightbox writes is not given to nft: each line two
# ports, as host_port_name names them, and a newline.
t_nft_records_refused() {
    nl='
'
    a=vb-5ea0e1194872 b=vb-08914e07b53b
    bad=0
    for record in "$a $b$nl" "nftables $a $b$nl" "nftables$nl$a $b" "nftables$nl$a  $b$nl" \
                  "nftables$nl$a $b $b$nl" "nftables$nl$a$nl" "nftables$nl$a $a$nl" \
                  "nftables$nl${a%?}A $b$nl" "nftables$nl${a%?} $b$nl" "nftables$nl$a ${b}0$nl" \
                  "nftables$nl\"$a\" $b$nl" "nftables$nl$a $b$nl$nl" "nftables$nl$a $b$nl;$nl" \
                  "nftables$nl$a vb-08914e07b5\" ;$nl" "NFTABLES$nl$a $b$nl" "LB-5ea0e1194872$nl"; do
        got=$("$UNIT" nftlinks remove "$record")
        [ "$got" = refused ] || { printf 'not refused: %s\n  gave: %s\n' "$record" "$got"; bad=1; }
    done
    for name in vb-5ea0e1194872 vb-000000000000; do
        [ "$("$UNIT" portname "$name")" = ok ] || { echo "$name refused"; bad=1; }
    done
    for name in vb-5ea0e119487 vb-5ea0e11948720 vb-5EA0E1194872 ve-5ea0e1194872 'vb-5ea0e119487"' vb-web ''; do
        [ "$("$UNIT" portname "$name")" = refused ] || { echo "$name taken for a port"; bad=1; }
    done
    return $bad
}

# bridge_accept_fwmark: a mark, or a mark and its mask, in decimal or hex,
# that a packet can carry and nft reads as written.
t_fwmarks() {
    bad=0
    expect() { # text, what parse_fwmark makes of it
        got=$("$UNIT" fwmark "$1" | paste -sd' ' -)
        [ "$got" = "$2" ] || { echo "'$1': $got, expected $2"; bad=1; }
    }
    expect 0x10 'mark 0x10 mask 0xffffffff as 0x10'
    expect 16/0xf0 'mark 0x10 mask 0xf0 as 0x10/0xf0'
    expect 0x1/0x3 'mark 0x1 mask 0x3 as 0x1/0x3'
    expect 0xFFFFFFFF 'mark 0xffffffff mask 0xffffffff as 0xffffffff'
    expect 4294967295 'mark 0xffffffff mask 0xffffffff as 0xffffffff'
    # 0 is every unmarked packet's; a bit outside the mask, no packet's; a
    # leading 0 is octal to nft
    for text in 0 0x0 0/0xff 1/0 0x10/0x1 016 08 0x 0x123456789 4294967296 1/ /1 1/2/3 ' 1' '1 ' -1 +1 1x 0x1g ''; do
        expect "$text" refused
    done
    return $bad
}

# What doctor and setup name as dropping what lightbox's nftables rules
# accept: forward base chains whose policy is drop, in ip, inet and bridge.
t_forward_drop_chains() {
    listing='table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
	}
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
	}
}
table inet firewall {
	chain fwd {
		type filter hook forward priority 0; policy drop;
	}
	chain mine {
	}
}
table inet open {
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
table ip6 filter {
	chain FORWARD {
		type filter hook forward priority filter; policy drop;
	}
}
table bridge lightbox {
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
table bridge other {
	chain forward {
		type filter hook forward priority filter; policy drop;
	}
}'
    got=$("$UNIT" dropping "$listing")
    [ "$got" = 'chains 3
ip filter FORWARD, inet firewall fwd, bridge other forward' ] || { printf '%s\n' "$got"; return 1; }
    got=$("$UNIT" dropping 'table inet open {
	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}')
    [ "$got" = 'chains 0' ] || { printf '%s\n' "$got"; return 1; }
}

# What setup puts in its chains: between two ports of the bridge what a link
# allows and nothing else; out by any interface but the bridge, and back what
# belongs to that; masquerading of the subnet, as the network spells it, when
# ip_masq is true.
t_firewall_setup_text() {
    got=$("$UNIT" firewall setup 10.9.5.0/16 10.9.0.1 br7 true)
    want='*filter
-F LIGHTBOX-FORWARD
-A LIGHTBOX-FORWARD -i br7 -o br7 -j LIGHTBOX-LINKS
-A LIGHTBOX-FORWARD -i br7 -o br7 -j DROP
-A LIGHTBOX-FORWARD -i br7 ! -o br7 -j ACCEPT
-A LIGHTBOX-FORWARD -o br7 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
*nat
-F LIGHTBOX-POSTROUTING
-A LIGHTBOX-POSTROUTING -s 10.9.0.0/16 ! -o br7 -j MASQUERADE
COMMIT'
    [ "$got" = "$want" ] || { printf '%s\n' "$got"; return 1; }
    got=$("$UNIT" firewall setup 10.0.0.0/24 10.0.0.1 br0 false | sed -n '/^\*nat/,$p')
    [ "$got" = '*nat
-F LIGHTBOX-POSTROUTING
COMMIT' ] || { echo "with ip_masq = false:"; printf '%s\n' "$got"; return 1; }
}

t_limits() {
    bad=0
    expect() { # kind, text, expected
        got=$("$UNIT" limit "$1" "$2")
        [ "$got" = "$3" ] || { echo "$1 '$2': $got, expected $3"; bad=1; }
    }
    for text in 1 4096 268435456 64K 64k 256M 256m 1G 2g 1T 2t max 9223372036854775807 8589934591G 8388607T; do
        expect mem "$text" ok
    done
    # the kernel would read a leading 0 as octal: 0100M is 64M to it
    for text in '' 0 0100M 00 M 1P 1GB 1.5G -1 +1 ' 1G' '1G ' 'not-a-size' MAX 9223372036854775808 8589934592G 8388608T 99999999999999999999 '1G
privileged=1'; do
        expect mem "$text" refused
    done
    for text in 1 128 4194304 max; do expect pids "$text" ok; done
    for text in '' 0 010 -1 4194305 123456789 12a 1.5 MAX '5
'; do
        expect pids "$text" refused
    done
    expect cpu 1 'quota 100000'
    expect cpu 2 'quota 200000'
    expect cpu 0.5 'quota 50000'
    expect cpu 0.25 'quota 25000'
    expect cpu 1.5 'quota 150000'
    expect cpu 0.01 'quota 1000'
    expect cpu 512 'quota 51200000'
    expect cpu 02 'quota 200000'
    for text in '' 0 0.0 0.00 0.001 0.125 .5 1. 1.x -1 +1 512.01 513 1024 1e3 abc '1 ' 1,5; do
        expect cpu "$text" refused
    done
    expect oom 0 'score 0'
    expect oom -1000 'score -1000'
    expect oom 1000 'score 1000'
    for text in '' abc 12abc 1001 -1001 1.5 ' 5'; do expect oom "$text" refused; done
    # swap: what mem takes, or none
    for text in 0 1 64M 1g max 8388607T; do expect swap "$text" ok; done
    for text in '' 00 0100M -1 lots MAX '0 ' '64M
mem=1G'; do expect swap "$text" refused; done
    # a line of io.max for one disk, with numbers the kernel cannot read in another base
    for text in '8:0 rbps=1048576' '8:0 wbps=max' '259:0 rbps=1 wbps=2 riops=3 wiops=4' '8:16 wiops=max riops=10' \
                '4095:1048575 rbps=9223372036854775807'; do
        expect io "$text" ok
    done
    for text in '' 8:0 '8:0 ' '8:0 rbps' '8:0 rbps=' '8:0 rbps=0' '8:0 rbps=01' '8:0 rbps=0x10' '8:0 xbps=1' \
                '8:0 rbps=1 rbps=2' '8:0  rbps=1' '8:0 rbps=1 ' ' 8:0 rbps=1' '08:0 rbps=1' '8:00 rbps=1' \
                '0:0 rbps=1' '4096:0 rbps=1' '8:1048576 rbps=1' '8 rbps=1' '8:0,rbps=1' '8:0 rbps=maximum' \
                '8:0 rbps=9223372036854775808' '8:0 rbps=1
privileged=1' 'a:b rbps=1'; do
        expect io "$text" refused
    done
    return $bad
}

# The controllers a container's cgroup has: one that a limit needs is there
# or the start is refused; one that is missing and not needed is said once.
t_controllers() {
    bad=0
    expect() { # listed, mem, pids, swap, io, expected (with what was said before it)
        got=$("$UNIT" controllers "$1" "$2" "$3" "$4" "$5" 2>&1 | paste -sd'|' -)
        [ "$got" = "$6" ] || { echo "'$1' for mem $2 pids $3 swap $4 io '$5': $got"; echo "  expected $6"; bad=1; }
    }
    all='cpuset cpu io memory hugetlb pids rdma misc'
    expect "$all" 256M 128 - - 'have memory pids cpu io'
    expect "$all" 256M 128 64M '8:0 rbps=1' 'have memory pids cpu io'
    # without io: a container without an I/O limit is told once, one with one is refused
    expect 'cpuset cpu memory pids' 256M 128 - - "Warning: the container's cgroup has no io controller; the container has no I/O limit that needs it|have memory pids cpu"
    expect 'cpuset cpu memory pids' 256M 128 - '8:0 rbps=1' "refused: the container's cgroup has no io controller, and the container has an I/O limit"
    # cpuset is not cpu, nor is a name with more to it
    expect 'cpuset memory pids io' 256M 128 - - "refused: the container's cgroup has no cpu controller, and every container has a CPU limit"
    expect 'cpuacct memory pids io' 256M 128 - - "refused: the container's cgroup has no cpu controller, and every container has a CPU limit"
    # memory, for a memory limit or a swap limit that was given; not for the 0 of no --swap
    expect 'cpu io pids' 256M 128 - - "refused: the container's cgroup has no memory controller, and the container has a memory or a swap limit"
    expect 'cpu io pids' max 128 1G - "refused: the container's cgroup has no memory controller, and the container has a memory or a swap limit"
    expect 'cpu io pids' max 128 0 - "refused: the container's cgroup has no memory controller, and the container has a memory or a swap limit"
    expect 'cpu io pids' max 128 - - "Warning: the container's cgroup has no memory controller: nothing keeps the container from swapping|have pids cpu io"
    expect 'cpu io pids' max 128 max - "Warning: the container's cgroup has no memory controller: nothing keeps the container from swapping|have pids cpu io"
    # pids, for a process limit
    expect 'cpu io memory' 256M 128 - - "refused: the container's cgroup has no pids controller, and the container has a process limit"
    expect 'cpu io memory' 256M max - - "Warning: the container's cgroup has no pids controller; the container has no process limit that needs it|have memory cpu io"
    # a refusal says nothing of what else is missing, not before it either
    expect 'cpu memory' 256M max - '8:0 rbps=1' "refused: the container's cgroup has no io controller, and the container has an I/O limit"
    # two missing, two warnings, and a list with a newline at its end as the kernel writes it
    expect 'cpu memory
' max max - - "Warning: the container's cgroup has no pids controller; the container has no process limit that needs it|Warning: the container's cgroup has no io controller; the container has no I/O limit that needs it|have memory cpu"
    return $bad
}

# ─── A container's configuration ────────────────────────────────────────────

# Runs a function with $D as a directory of containers that holds one, "web".
in_config_dir() { # function
    D=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    mkdir "$D/web"
    ( "$1" )
    rc=$?
    rm -rf -- "$D"
    return $rc
}
config()  { "$UNIT" config "$D" web "$@"; }
written() { "$UNIT" config-write "$D" web "$@"; }

config_as_written() {
    {
        echo 'version=1'
        echo 'mem=512M'
        echo 'pids=64'
        echo 'cpu=0.5'
        echo 'oom_score=-300'
        echo 'privileged=1'
        echo 'readonly=1'
        echo 'io=8:0 rbps=1048576'
        echo 'swap=1G'
        echo 'vol=/srv/data:/data'
        echo 'vol=/etc/app.conf:/etc/app.conf:ro'
        echo 'link=db'
        echo 'link=cache'
    } > "$D/web/.conf"
    got=$(config)
    want='version 1
mem 512M
pids 64
cpu 0.5
oom_score -300
privileged 1
readonly 1
userns 0
uid_start 0
io 8:0 rbps=1048576
swap 1G
vol /srv/data -> /data rw
vol /etc/app.conf -> /etc/app.conf ro
link db
link cache'
    printf '%s\n' "$got"
    [ "$got" = "$want" ]
}
t_config_is_read_whole() { in_config_dir config_as_written; }

# What a file does not say is what lightbox.conf says, and a file may say
# nothing at all.
config_defaults() {
    : > "$D/web/.conf"
    got=$(config)
    printf '%s\n' "$got"
    [ "$got" = 'version 0
mem 256M
pids 128
cpu 1
oom_score 500
privileged 0
readonly 0
userns 0
uid_start 0
io -
swap -' ] || return 1
    # a default that cannot be used is no default: the file must have the limit
    got=$(config nodefaults)
    printf '%s\n' "$got"
    case $got in 'refused: '*"$D/web/.conf"*'default_mem') ;; *) return 1 ;; esac
    printf 'version=1\nmem=1G\npids=max\ncpu=2\noom_score=0\n' > "$D/web/.conf"
    got=$(config nodefaults)
    printf '%s\n' "$got"
    case $got in 'version 1
mem 1G
pids max
cpu 2
oom_score 0
'*) ;; *) return 1 ;; esac
    # each limit by itself: the file lacks it, and its default is the one named
    for missing in mem pids cpu oom_score; do
        printf 'version=1\nmem=1G\npids=max\ncpu=2\noom_score=0\n' | grep -v "^$missing=" > "$D/web/.conf"
        got=$(config nodefaults)
        setting=default_${missing%_score}
        case $got in 'refused: '*": $setting") ;; *) echo "without $missing: $got"; return 1 ;; esac
        got=$(config)
        case $got in 'version 1'*) ;; *) echo "without $missing, and a default: $got"; return 1 ;; esac
    done
    # and no file is not an empty file
    rm "$D/web/.conf"
    got=$(config)
    printf '%s\n' "$got"
    case $got in 'refused: '*'cannot be read') ;; *) return 1 ;; esac
}
t_config_defaults() { in_config_dir config_defaults; }

# A file with the version line is lightbox's own writing: whatever in it is
# not what lightbox writes means the file is damaged, and is said with the
# line it is on.
config_strict() {
    bad=0
    refuses() { # what the message must say, then the file's lines
        want=$1; shift
        printf '%s\n' "$@" > "$D/web/.conf"
        got=$(config)
        # shellcheck disable=SC2254     # $want is a pattern, and is meant as one
        case $got in "refused: $D/web/.conf: "$want) ;; *) echo "expected '$want', got: $got"; bad=1 ;; esac
    }
    refuses 'line 2: a key lightbox does not know'      version=1 colour=blue
    refuses 'line 3: is not key=value'                  version=1 mem=1G junk
    refuses 'line 3: a key the file already has'        version=1 mem=1G mem=2G
    refuses 'line 2: mem is not *'                      version=1 mem=lots
    refuses 'line 2: mem is not *'                      version=1 mem=0100M
    refuses 'line 2: pids is not *'                     version=1 pids=123456789
    refuses 'line 2: cpu is not *'                      version=1 cpu=1024
    refuses 'line 2: oom_score is not *'                version=1 oom_score=12abc
    refuses 'line 2: swap is not *'                     version=1 swap=lots
    refuses 'line 2: swap is not *'                     version=1 swap=064M
    refuses 'line 3: a key the file already has'        version=1 swap=1G swap=2G
    refuses 'line 2: io is not *'                       version=1 io=8:0
    refuses 'line 2: io is not *'                       version=1 'io=8:0 rbps=010'
    refuses 'line 2: io is not *'                       version=1 'io=8:0 rbps=1 rbps=2'
    refuses 'line 2: privileged is not 0 or 1'          version=1 privileged=yes
    refuses 'line 2: readonly is not 0 or 1'            version=1 readonly=2
    refuses 'line 2: the link is not the name of a container' version=1 'link=a b'
    refuses 'line 2: the link is not the name of a container' version=1 link=a-name-of-thirty-one-characters
    refuses 'line 2: *absolute path without ..'         version=1 vol=/srv:/a/../b
    refuses 'line 2: a volume is written src:dst*'      version=1 vol=/srv
    refuses 'line 2: *only :ro may follow'              version=1 vol=/srv:/data:rw
    refuses 'line 2: *may not be under /proc*'          version=1 vol=/srv:/proc/sys
    refuses 'line 2: the version is not the first line' mem=1G version=1
    refuses 'line 1: the version is not a number'       version=one
    refuses 'line 1: the version is not a number'       version=0
    refuses 'line 1: was written by a newer lightbox*'  version=2 mem=1G
    # a carriage return is a control character like any other
    printf 'version=1\r\nmem=1G\r\n' > "$D/web/.conf"
    got=$(config)
    case $got in "refused: $D/web/.conf: line 1: has a control character") ;; *) echo "CRLF: $got"; bad=1 ;; esac
    # what follows a NUL byte would never be read
    printf 'version=1\nmem=1G\n\0privileged=1\n' > "$D/web/.conf"
    got=$(config)
    case $got in "refused: $D/web/.conf: has a NUL byte") ;; *) echo "NUL: $got"; bad=1 ;; esac
    # more volumes and links than a container has
    { echo version=1; for i in $(seq 1 17); do echo "vol=/srv:/v$i"; done; } > "$D/web/.conf"
    got=$(config)
    case $got in "refused: $D/web/.conf: line 18: more than 16 volumes") ;; *) echo "17 volumes: $got"; bad=1 ;; esac
    { echo version=1; for i in $(seq 1 9); do echo "link=c$i"; done; } > "$D/web/.conf"
    got=$(config)
    case $got in "refused: $D/web/.conf: line 10: more than 8 links") ;; *) echo "9 links: $got"; bad=1 ;; esac
    # a file too large to be a configuration
    { echo version=1; head -c 30000 /dev/zero | tr '\0' '\n'; } > "$D/web/.conf"
    got=$(config)
    case $got in "refused: $D/web/.conf: is larger than lightbox supports") ;; *) echo "large: $got"; bad=1 ;; esac
    # the line that is named is the line an editor shows, empty ones counted
    refuses 'line 5: a key lightbox does not know'      version=1 '' mem=1G '' colour=blue
    # empty lines are no lines
    printf '\nversion=1\n\nmem=1G\n\n' > "$D/web/.conf"
    got=$(config)
    case $got in 'version 1
mem 1G
'*) ;; *) echo "empty lines: $got"; bad=1 ;; esac
    return $bad
}
t_config_is_read_strictly() { in_config_dir config_strict; }

# A file from before the version line is read as it was read then: the first
# of two values counts, and what lightbox does not know is passed over. What
# it does know still has to be a value.
config_from_before() {
    {
        echo 'mem=512M'
        echo 'pids=64'
        echo 'cpu=2'
        echo 'a line that is no setting'
        echo 'colour=blue'
        echo 'mem=1G'
        echo 'privileged=1'
        echo 'oom_score=100'
        echo 'vol=/srv/data//:/data/'
        echo 'vol=/srv/other:/data'
        echo 'link=db'
    } > "$D/web/.conf"
    got=$(config)
    printf '%s\n' "$got"
    [ "$got" = 'version 0
mem 512M
pids 64
cpu 2
oom_score 100
privileged 1
readonly 0
userns 0
uid_start 0
io -
swap -
vol /srv/data -> /data rw
vol /srv/other -> /data rw
link db' ] || return 1
    printf 'mem=lots\n' > "$D/web/.conf"
    got=$(config)
    printf '%s\n' "$got"
    case $got in "refused: $D/web/.conf: line 1: mem is not "*) ;; *) return 1 ;; esac
    printf 'cpu=1\nversion=1\n' > "$D/web/.conf"
    got=$(config)
    printf '%s\n' "$got"
    case $got in "refused: $D/web/.conf: line 2: the version is not the first line") ;; *) return 1 ;; esac
}
t_config_from_before_the_version_line() { in_config_dir config_from_before; }

# What is written is what is read back, and a value that would be read back
# as anything else is not written at all. No command lets such a value in;
# this is the writer's own refusal, for the day one does.
config_written() {
    bad=0
    got=$(written mem=1G swap=64M pids=max cpu=0.25 'io=8:0 wbps=1024' src=/srv/data dst=/data link=db)
    [ "$got" = written ] || { echo "a good configuration: $got"; bad=1; }
    cat "$D/web/.conf"
    [ "$(cat "$D/web/.conf")" = 'version=1
mem=1G
swap=64M
pids=max
cpu=0.25
oom_score=500
io=8:0 wbps=1024
vol=/srv/data:/data
link=db' ] || { echo "the file is not what was put in"; bad=1; }
    [ "$(stat -c %a "$D/web/.conf")" = 600 ] || { echo "the file's mode is $(stat -c %a "$D/web/.conf")"; bad=1; }
    got=$(config | tr '\n' ' ')
    case $got in 'version 1 mem 1G pids max cpu 0.25 oom_score 500 '*'io 8:0 wbps=1024 swap 64M vol /srv/data -> /data rw link db ') ;;
        *) echo "read back: $got"; bad=1 ;; esac

    before=$(cat "$D/web/.conf")
    nl='
'
    for value in "mem=1G${nl}privileged=1" "pids=5${nl}cpu=9" "cpu=1${nl}mem=1G" \
                 "io=8:0 rbps=1${nl}privileged=1" "link=db${nl}cpu=9" \
                 "src=/srv${nl}privileged=1" "src=/srv:/etc"; do
        case $value in src=*) got=$(written "$value" dst=/data) ;; *) got=$(written "$value") ;; esac
        case $got in 'refused: '*) ;; *) echo "written with ${value%%=*} of two lines or two paths: $got"; bad=1 ;; esac
    done
    got=$(written src=/srv "dst=/data${nl}privileged=1")
    case $got in 'refused: '*) ;; *) echo "written with a destination of two lines: $got"; bad=1 ;; esac
    got=$(written src=/srv dst=/data:ro)
    case $got in 'refused: '*) ;; *) echo "written with a colon in a destination: $got"; bad=1 ;; esac
    # a value that the reader takes back shorter, which only the comparison sees
    got=$(written "swap=64M${nl}")
    case $got in 'refused: '*) ;; *) echo "written with a swap that ends in a newline: $got"; bad=1 ;; esac
    got=$(written "mem=1G$(printf '\r')")
    case $got in 'refused: '*) ;; *) echo "written with a carriage return: $got"; bad=1 ;; esac
    # values that are one line and still not what a reader takes, or takes as they are
    for value in mem=lots mem=0100M mem= pids=0 pids= cpu=1024 cpu= 'link=a b' link= swap=lots swap=00 \
                 io=8:0 'io=8:0 rbps=01' 'io=8:0 xbps=1' \
                 src=/srv/ src=/srv/../etc src=srv src=/proc/1; do
        case $value in src=*) got=$(written "$value" dst=/data) ;; *) got=$(written "$value") ;; esac
        case $got in 'refused: '*) ;; *) echo "written with $value: $got"; bad=1 ;; esac
    done
    for value in dst=/data/ dst=/ dst=/proc/x dst=/a/../b dst=data; do
        got=$(written src=/srv "$value")
        case $got in 'refused: '*) ;; *) echo "written with $value: $got"; bad=1 ;; esac
    done
    # two volumes at one place are refused where one is added, not here: a
    # container from before can have them, and its file is written all the same
    got=$(written src=/srv dst=/data src=/other dst=/data)
    [ "$got" = written ] || { echo "two volumes at one place: $got"; bad=1; }
    got=$(written mem=1G swap=64M pids=max cpu=0.25 'io=8:0 wbps=1024' src=/srv/data dst=/data link=db)
    [ "$got" = written ] || { echo "the good configuration again: $got"; bad=1; }
    [ "$(cat "$D/web/.conf")" = "$before" ] || { echo "a refused configuration changed the file"; bad=1; }
    for left in "$D/web"/.[!.]* "$D/web"/*; do
        [ -e "$left" ] || continue
        [ "$left" = "$D/web/.conf" ] || { echo "left beside the file: $left"; bad=1; }
    done
    return $bad
}
t_config_is_written_as_it_will_be_read() { in_config_dir config_written; }

# One reader and one writer: nothing else opens a .conf, and nothing else
# knows what is in one.
t_conf_has_one_reader() {
    src=$HERE/..
    bad=0
    users=$(grep -l 'container_conf_path(' "$src"/lightbox*.c | xargs -n1 basename | sort | tr '\n' ' ')
    echo "container_conf_path is called in: $users"
    [ "$users" = 'lightbox_container.c lightbox_meta.c lightbox_state.c ' ] || { echo "expected the reader and writer, inspect (which prints the path) and the definition"; bad=1; }
    # inspect names the file and does not read it
    grep -n 'conf_path' "$src/lightbox_meta.c" | grep -v 'container_conf_path(conf_path, name)\|print_kv("config_path", conf_path)\|char cdir' && { echo "lightbox_meta.c does more with the path than print it"; bad=1; }
    for file in "$src"/lightbox.c "$src"/lightbox_meta.c "$src"/lightbox_state.c "$src"/lightbox_net.c \
                "$src"/lightbox_config.c "$src"/lightbox_util.c; do
        if grep -nE '"(vol|link|mem|pids|cpu|oom_score|privileged|readonly|userns|uid_start|version)="|conf_get|container_conf_read' "$file" /dev/null; then
            echo "$(basename "$file") looks into a .conf's text"; bad=1
        fi
    done
    # and the helpers that cut are gone
    grep -n 'str_append_whole\|[^a-z_]parse_int(' "$src"/lightbox*.c "$src"/lightbox.h && { echo "a helper that cuts text or reads half a number is still there"; bad=1; }
    return $bad
}

# ─── A container that ended without a stop ──────────────────────────────────

# Init says how it ends, where the command that comes next finds it: 0 when
# it was asked to stop, something else when its hook failed, and nothing at
# all when it was killed. While it lives no process it starts can look into
# it, which keeps the files it holds open on the host its own.
h_init_reports_its_end() {
    UNIT_EXIT="$D/exit" handshake whole confined 5 - -
    echo "asked to stop, init wrote: $(cat "$D/exit")"
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] && [ "$(cat "$D/exit")" = 0 ] || return 1

    printf 'exit 3\n' > "$D/hook"
    UNIT_EXIT="$D/exit" handshake whole confined 5 "$D/hook" -
    echo "after a hook that failed, init wrote: $(cat "$D/exit")"
    [ "$(story)" = "ready hook 3 init-exit 1" ] && [ "$(cat "$D/exit")" = 1 ] || return 1

    # What init starts cannot get at the files init has open, which are files
    # of the host: not by asking where one of init's descriptors leads, and
    # not by opening it. The hook is such a process. /proc is the host's
    # here, so the hook finds init there as its parent. That init has such
    # descriptors can be seen, which is no more than their numbers.
    {
        # read by the shell itself: a program run for it would name the shell as its parent
        echo 'while read -r key value; do [ "$key" = PPid: ] && init=$value; done < /proc/self/status'
        echo 'echo "the hook sees init as process $init"'
        echo "{"
        echo "    if readlink /proc/\$init/fd/1 >/dev/null 2>&1; then echo 'read where it leads'; else echo 'not told where it leads'; fi"
        echo "    if ( : < /proc/\$init/fd/1 ) 2>/dev/null; then echo 'opened it'; else echo 'not let open it'; fi"
        echo "    if ( : < /proc/\$init/environ ) 2>/dev/null; then echo 'opened its environment'; else echo 'not let see its environment'; fi"
        echo "} > $D/look"
    } > "$D/hook"
    UNIT_EXIT="$D/exit" handshake whole confined 5 "$D/hook" -
    echo "the hook, at init's first descriptor: $(paste -sd, "$D/look")"
    seen=$(printf '%s\n' "$out" | sed -n 's/^the hook sees init as process //p')
    [ -n "$seen" ] && [ "$seen" = "$(printf '%s\n' "$out" | sed -n 's/^init //p')" ] ||
        { echo "the hook looked at process '$seen', which is not init"; return 1; }
    out=$(printf '%s\n' "$out" | grep -v '^the hook sees init')
    [ "$(story)" = "ready hook 0 sent SIGTERM init-exit 0" ] &&
    [ "$(paste -sd, "$D/look")" = 'not told where it leads,not let open it,not let see its environment' ] || return 1

    # The next start empties the record before init can write it. Init stays
    # here, and with it whatever it writes to: so its output goes to a file,
    # as no pipe would end before init does.
    UNIT_EXIT="$D/exit" handshake_begins leave confined 5 - -
    handshake_ends
    pid=$(printf '%s\n' "$out" | sed -n 's/^init //p')
    [ -n "$pid" ] || { echo "the command did not say which process init is"; return 1; }
    kill -0 "$pid" 2>/dev/null || { echo "init is not there to be looked at"; return 1; }
    bad=0
    [ ! -s "$D/exit" ] || { echo "a start kept the record of the run before: $(cat "$D/exit")"; bad=1; }
    kill -KILL "$pid"
    wait_for 5 gone "$pid" || { echo "init $pid survived SIGKILL"; return 1; }
    echo "killed, init wrote: '$(cat "$D/exit")'"
    [ ! -s "$D/exit" ] || { echo "an init that was killed left a report"; bad=1; }
    return $bad
}
gone() { ! kill -0 "$1" 2>/dev/null; }

# The records of a container that runs are in run_dir, which a reboot empties:
# the first record after one makes the directory again, for root alone. The
# container's own directory there has to be a directory, and no link to one.
run_dir_cases() {
    recorded() { result_of "$("$UNIT" record "$@" 2>"$D/err")"; }
    # run_dir is not there, and neither is what it is in
    [ "$(recorded "$D/a/b/run" web starting)" = 0 ] || { cat "$D/err"; return 1; }
    echo "run_dir $(stat -c %a "$D/a/b/run"), the container's directory $(stat -c %a "$D/a/b/run/web"), the record $(stat -c %a "$D/a/b/run/web/state")"
    [ "$(stat -c %a "$D/a/b/run")" = 700 ] && [ "$(stat -c %a "$D/a/b/run/web")" = 700 ] &&
    [ "$(stat -c %a "$D/a/b/run/web/state")" = 600 ] && [ "$(cat "$D/a/b/run/web/state")" = starting ] || return 1
    # a second record replaces the first, and leaves nothing beside it
    [ "$(recorded "$D/a/b/run" web running)" = 0 ] && [ "$(cat "$D/a/b/run/web/state")" = running ] &&
    [ "$(ls -A "$D/a/b/run/web")" = state ] || { echo "left: $(ls -A "$D/a/b/run/web")"; return 1; }
    # a run_dir that is there is left as it is
    mkdir -m 755 "$D/open"
    [ "$(recorded "$D/open" web starting)" = 0 ] && [ "$(stat -c %a "$D/open")" = 755 ] && [ "$(stat -c %a "$D/open/web")" = 700 ] || return 1
    # where the container's directory should be there is a link, or a file
    mkdir "$D/run" "$D/elsewhere"
    ln -s "$D/elsewhere" "$D/run/linked"
    : > "$D/run/file"
    [ "$(recorded "$D/run" linked starting)" = -1 ] && [ -z "$(ls -A "$D/elsewhere")" ] || { echo "a record was written through a link"; return 1; }
    cat "$D/err"
    [ "$(recorded "$D/run" file starting)" = -1 ] || { echo "a file was taken for the container's directory"; return 1; }
}
t_run_dir_is_made_when_missing() { in_config_dir run_dir_cases; }

# The mark of a half-made container is removed to stay removed. A file that
# is gone already is removed; one that cannot be removed is said to be there.
remove_cases() {
    removed() { result_of "$("$UNIT" remove "$1")"; }
    : > "$D/mark"
    [ "$(removed "$D/mark")" = 0 ] && [ ! -e "$D/mark" ] || { echo "a file was not removed"; return 1; }
    [ "$(removed "$D/mark")" = 0 ] || { echo "a file that is gone is an error"; return 1; }
    mkdir "$D/dir"
    [ "$(removed "$D/dir")" = -1 ] && [ -d "$D/dir" ] || { echo "a directory was taken for a file"; return 1; }
    [ "$(removed "$D/nowhere/mark")" = -1 ] || { echo "a file in no directory was reported as removed for good"; return 1; }
}
t_remove_durably() { in_config_dir remove_cases; }

# What start, stop and rm do first about a container that ended without a
# stop. The container here has no cgroup, no interface and no links, so what
# is seen is what goes on record. Its name is one no real container has: the
# interface that is looked for is called after it.
REC=zz-unit-rec
in_records_dir() { # function
    D=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-unit.XXXXXX") || return 1
    mkdir -p "$D/c/$REC" "$D/run"
    printf 'version=1\nmem=1G\npids=max\ncpu=1\noom_score=0\n' > "$D/c/$REC/.conf"
    ( "$1" )
    rc=$?
    rm -rf -- "$D"
    return $rc
}
reconciled() { "$UNIT" reconcile "$D/c" "$D/run" "$REC" 2>"$D/err"; }
a_pid_that_is_gone() { sleep 0 & wait $!; echo $!; }
records() { # pid | -, state | -, what init said | -
    rm -rf -- "$D/run/$REC"
    mkdir -p "$D/run/$REC"
    [ "$1" = - ] || { printf '%s' "$1" > "$D/run/$REC/pid"; printf '1' > "$D/run/$REC/pid_start"; }
    [ "$2" = - ] || printf '%s\n' "$2" > "$D/run/$REC/state"
    [ "$3" = - ] || printf '%s\n' "$3" > "$D/run/$REC/exit"
}
expect_reconciled() { # what it says, the state after
    got=$(reconciled)
    [ "$got" = "$1
state $2" ] || { echo "expected '$1' and state $2, got: $got"; cat "$D/err"; return 1; }
}
reconcile_cases() {
    RD="$D/run/$REC"
    # nothing on record: nothing to do, and nothing is made
    expect_reconciled nothing stopped && [ ! -e "$RD" ] || return 1

    # an init that is gone and said that it ended with 0
    records "$(a_pid_that_is_gone)" running 0
    expect_reconciled cleared exited || return 1
    cat "$D/err"
    grep -q "had stopped by itself" "$D/err" || { echo "it does not say what it found"; return 1; }
    [ ! -e "$RD/pid" ] && [ ! -e "$RD/pid_start" ] && [ ! -e "$RD/exit" ] || { echo "records are left: $(ls -A "$RD")"; return 1; }
    # and a second time there is nothing more to do: the state stays
    expect_reconciled nothing exited || return 1

    # one that said anything else, or nothing, or was never able to say
    for said in 1 137 - '' 0x 256 -0 '0 0' zero; do
        records "$(a_pid_that_is_gone)" running "$said"
        expect_reconciled cleared failed || { echo "  after init said '$said'"; return 1; }
        grep -q "had ended without a stop" "$D/err" || { echo "it does not say what it found, for '$said'"; return 1; }
    done

    # a command that died in the middle: the record says it was at work, and
    # with the lock held nothing is
    for state in starting stopping running; do
        records - "$state" -
        expect_reconciled cleared failed || { echo "  for a record that says $state"; return 1; }
    done
    # a record that says it is at rest is left alone
    for state in failed exited; do
        records - "$state" -
        expect_reconciled nothing "$state" || return 1
    done
    rm -rf -- "$RD"
    : > "$D/c/$REC/.creating"
    expect_reconciled nothing creating || return 1
    rm "$D/c/$REC/.creating"

    # A container that a lightbox before 0.5 started has its records in its
    # own directory. They are read from there, and go when it is cleared away.
    rm -rf -- "$RD"
    printf '%s' "$(a_pid_that_is_gone)" > "$D/c/$REC/.pid"
    printf '1' > "$D/c/$REC/.pid_start"
    printf 'running\n' > "$D/c/$REC/.state"
    expect_reconciled cleared failed || { echo "  for records in the place they had before"; return 1; }
    [ "$(ls -A "$D/c/$REC")" = .conf ] || { echo "old records are left: $(ls -A "$D/c/$REC" | tr '\n' ' ')"; return 1; }
    [ "$(cat "$RD/state")" = failed ] || return 1
    # with records in both places, the old ones are not looked at
    printf 'running\n' > "$D/c/$REC/.state"
    expect_reconciled nothing failed || return 1
    rm "$D/c/$REC/.state"

    # an init that is there is not touched, whatever the record says. Only an
    # ordinary user can stand in for one here: root sees that this shell is
    # in no PID namespace of its own.
    if [ "$(id -u)" -ne 0 ]; then
        records $$ stopping 0
        awk '{ printf "%s", $22 }' /proc/$$/stat > "$RD/pid_start"
        expect_reconciled nothing stopping && [ "$(cat "$RD/pid")" = $$ ] && [ "$(cat "$RD/exit")" = 0 ] || return 1
    fi
}
t_reconcile() { in_records_dir reconcile_cases; }

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

check 'init reports ready, then the end of a hook it does not have' t_handshake_without_hook
check 'init does nothing until the command sends its first byte' t_handshake_first_byte
check 'the hook runs once init is on record, and is reported'    t_handshake_hook
check 'a hook that fails or is killed ends init'                 t_handshake_hook_failure
check 'a service the hook leaves does not hold up the report'    t_handshake_service
check 'init hears SIGTERM while a slow hook runs'                t_handshake_slow_hook
check 'the command sees init go while it waits for the hook'     t_handshake_stop_during_hook
check 'a signal for the command undoes the start'                t_handshake_interrupted
check 'init exits when the command is gone, and runs no hook'    t_handshake_command_gone
check 'the hook inherits three streams and no blocked signal'    t_handshake_hook_inherits
check 'init and the hook write to the log, and read nothing'     t_handshake_log
check 'the command returns to a capture, and init is detached'   t_handshake_detached

check 'init with nothing to end goes at once'                    t_stop_idle
check 'a service gets SIGTERM and time to act on it'             t_stop_graceful
check 'a service that ignores SIGTERM is killed after the limit' t_stop_limit
check 'a SIGTERM without a number uses init'"'"'s own limit'          t_stop_plain_sigterm
check 'a stopped process is continued so that it can end'        t_stop_stopped_process
check 'a process that is not init'"'"'s child is ended and waited for' t_stop_guest
check 'a list of PIDs is read whole, across reads'               t_pid_list_is_read_whole

check 'a volume is src:dst[:ro], with paths that mean what they say' t_volume_spec
check 'volumes are attached after the pivot, inside the new root' t_volumes_are_attached_inside
check 'a volume through a link that leads nowhere ends the start' t_volume_through_a_dangling_link
check 'a volume that cannot be had ends the start'               t_volume_that_cannot_be_had

check 'the name servers of a host are the ones a container can ask' t_name_servers_of_the_host

check 'without a terminal a command gets the streams as they are, and a session' t_streams_without_a_terminal
check 'on a terminal a command gets a terminal of its own'       t_streams_terminal
check 'the caller'"'"'s terminal gets its modes back when the worker is killed' t_streams_modes_survive
check 'what is typed, and the key that interrupts, reach the command' t_streams_input_and_keys
check 'the command'"'"'s terminal follows the size of the caller'"'"'s'    t_streams_window
check 'a pipe stands in where only one side is a terminal'       t_streams_half_a_terminal
check 'a signal that asks exec to end reaches the command'       t_streams_signals
check 'plenty of data goes through, both ways'                   t_streams_plenty

check 'exec executes itself again from a sealed copy in memory'  t_exec_runs_from_a_sealed_copy
check 'a read-only mount of the binary does where memfds may not' t_exec_sealing_by_a_read_only_mount

check '--user is a name, a uid or uid:gid, and nothing else'     t_user_spec
check 'accounts are found wherever they are in the file'         t_accounts_are_found
check 'a group member is a whole name, and too many groups is an error' t_group_members_match_whole
check 'an account file that is not a regular file is not read'   t_account_file_must_be_a_file
check 'a command gets a fixed environment, and what --env adds'  t_command_environment
check 'a command without a slash is looked for on PATH'          t_command_is_found_on_path
check 'a command gets every argument, its directory, and what follows --' t_command_gets_every_argument
check 'exec'"'"'s options are checked, and a missing value names its option' t_command_options_are_checked

check 'a number of seconds is digits within the limit'           t_seconds
check 'a file never gets the number of a closed standard stream' t_standard_streams_are_reserved
check 'cmd_start has one way out once it has changed the host'   t_start_has_one_way_out

check 'text is put into a buffer whole or not at all'            t_text_is_whole_or_refused
check 'a number is digits in its range, and never wraps'         t_numbers_are_strict
check 'memory, process, CPU and OOM limits are what they say'    t_limits
check 'a cgroup without a controller: refused when a limit needs it, said when not' t_controllers
check 'a program gets its input whole, read or not, and too much is refused' t_program_input
check 'a container is vb- and LB- with twelve digits of its name'"'"'s hash on the host' t_host_names
check 'an interface is lightbox'"'"'s for a container only with its alias' t_interface_owner
check 'a record of link rules names a chain of lightbox'"'"'s or is refused' t_link_chain_names
check 'a container'"'"'s link rules are a chain of its own, by port and not address' t_firewall_links_text
check 'setup'"'"'s rules: links between ports, out by any interface, masquerade if set' t_firewall_setup_text
check 'nftables: setup'"'"'s two tables, flushed chains, a set of links that is kept' t_nft_setup_text
check 'nftables: a container'"'"'s links are elements of the set, each once, taken out safely' t_nft_link_elements
check 'nftables: a record that is not lightbox'"'"'s is not given to nft'  t_nft_records_refused
check 'bridge_accept_fwmark: a mark nft reads as written, and none that matches all' t_fwmarks
check 'the forward chains that drop what nothing accepts are named'      t_forward_drop_chains
check 'an address is four numbers and three dots, and no zero in front' t_addresses_are_strict
check 'subnet and gw are one network, and an address on it is one a container can have' t_network_settings
check 'no prefix is written into the source: subnet gives it'      t_no_prefix_of_its_own
check 'a .conf is read into one structure, whole'                t_config_is_read_whole
check 'what a .conf leaves out is the default, if that is usable' t_config_defaults
check 'a .conf with a version is read strictly, by line'         t_config_is_read_strictly
check 'a .conf from before the version line is still read'       t_config_from_before_the_version_line
check 'a .conf is written as it will be read, or not written'    t_config_is_written_as_it_will_be_read
check 'one file reads and writes a .conf, and none looks into it' t_conf_has_one_reader
check 'a runtime record makes its directory when a reboot took it'  t_run_dir_is_made_when_missing
check 'a file is removed for good, or said not to be'             t_remove_durably
check 'init says how it ends, and nothing it starts can look into it' t_init_reports_its_end
check 'a container that ended without a stop is cleared away, and how it ended recorded' t_reconcile

summary unit
