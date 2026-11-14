#!/usr/bin/env bash
#
# Unit suite (ROADMAP 3.1). Unprivileged; creates no file.
#
#   tests/unit_cases.sh <unit harness>
#   V=1 tests/unit_cases.sh ...            show the output of every case
#
# The harness is built from lightbox.c and calls lightbox's own helper for
# running a program, the one every tool invocation goes through. It prints
# "result <n>": the program's exit status, or 256 when no child could be made,
# 257 when the program could not be executed, 258 when a signal ended it and
# 259 when it could not be waited for.
#
# The case runner (check, xfail, summary) is tests/lib.sh.

set -u

UNIT=${1:?usage: unit_cases.sh <unit harness>}
if [ ! -x "$UNIT" ]; then
    echo "unit: $UNIT is not an executable; run make test-unit" >&2
    exit 2
fi
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

summary unit
