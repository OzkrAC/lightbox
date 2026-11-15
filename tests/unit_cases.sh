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
# does not count.
NAP=31.4159
sleeping() {
    local f
    for f in /proc/[0-9]*/cmdline; do
        [ "$(tr '\0' ' ' < "$f" 2>/dev/null)" = "sleep $NAP " ] && return 0
    done
    return 1
}

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
# the command, not its signalfd, no blocked signal, and nothing that was open
# in the command, which here has a file on descriptor 9.
h_hook_inherits_nothing() {
    printf 'grep SigBlk: /proc/self/status > %s/blocked\nexec ls /proc/self/fd > %s/fds\n' "$D" "$D" > "$D/hook"
    : > "$D/open-in-the-command"
    handshake whole confined 5 "$D/hook" - 9< "$D/open-in-the-command"
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
# a session and a process group of its own, and has only its three streams and
# its signalfd open.
#
# The command writes to a pipe here, as it does under $( ). What reads the
# pipe ends when nothing has it open any more, and is given ten seconds: an
# init that held on to the pipe must fail this case, not stall it.
h_command_returns_and_init_stays() {
    : > "$D/open-in-the-command"
    ( unshare -r "$UNIT" init leave confined 5 - "$D/log" 2>&1 9< "$D/open-in-the-command" | cat > "$D/out" ) &
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
    for fd in "/proc/$init/fd"/*; do
        n=${fd##*/}
        to=$(readlink "$fd")
        echo "  descriptor $n: $to"
        # the same file, however its path is spelled
        if [ "$n" = 0 ] && [ "$fd" -ef /dev/null ]; then continue; fi
        if { [ "$n" = 1 ] || [ "$n" = 2 ]; } && [ "$fd" -ef "$D/log" ]; then continue; fi
        if [ "$n" -gt 2 ] && [ "$to" = 'anon_inode:[signalfd]' ]; then continue; fi
        echo "  init should not have that"
        bad=1
    done
    [ -e "/proc/$init/fd/0" ] && [ -e "/proc/$init/fd/1" ] && [ -e "/proc/$init/fd/2" ] || { echo "  init lacks a standard stream"; bad=1; }
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
    if printf '%s\n' "$region" | grep -nE '\b(die|die2|require_[a-z_]+|set_container_state|usage)\(' ; then
        echo "these end the process where it stands"; bad=1
    fi
    exits=$(printf '%s\n' "$region" | grep -c 'lc_kernel_exit(')
    [ "$exits" = 1 ] || { echo "lc_kernel_exit is called $exits times; the one in fail_start is the only one there may be"; bad=1; }
    printf '%s\n' "$region" | grep -q 'goto fail_start' || { echo "nothing goes to fail_start"; bad=1; }
    return $bad
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

summary unit
