#!/usr/bin/env bash
#
# Timing of the basic commands (ROADMAP 0.8).
#
#   sudo make bench
#   sudo bench/bench.sh [path/to/lightbox]          default: ./lightbox
#
# Measures the wall time of create, start, exec /bin/true, stop and rm, each on
# a fresh container, and counts the processes that one start makes.
#
# It needs what tests/lifecycle.sh needs, and it runs inside that suite's
# private namespaces and fixture, so it uses nothing of the host's and leaves
# nothing there.
#
#   BENCH_RUNS=10       how often each command is measured
#
# bench/baseline.txt holds the numbers of the tree as it stood before Phase 1
# of ROADMAP.md. Later numbers are compared with it on the same kind of machine.

if [ -z "${LIFECYCLE_T:-}" ]; then
    # On the host. The lifecycle suite makes the namespaces and the fixture and
    # then reads this file again inside them.
    here=$(cd "$(dirname "$0")" && pwd)
    exec bash "$here/../tests/lifecycle.sh" --program "$here/bench.sh" "$@"
fi

# ─── From here on: sourced by tests/lifecycle.sh, with its helpers ──────────

BENCH_RUNS=${BENCH_RUNS:-10}
BENCH_DIR="$T/bench"

# Run a command and note how long it took, in microseconds, under a label.
# The clock is read without making a process.
timed() { # label command...
    local label=$1 t0 t1 rc
    shift
    t0=${EPOCHREALTIME/[.,]/}
    "$@" >/dev/null 2>"$BENCH_DIR/stderr" </dev/null
    rc=$?
    t1=${EPOCHREALTIME/[.,]/}
    echo $((t1 - t0)) >> "$BENCH_DIR/$label"
    if [ $rc -ne 0 ]; then
        echo "bench: '$*' failed with status $rc:" >&2
        cat "$BENCH_DIR/stderr" >&2
    fi
    return $rc
}

# Median, lowest and highest of a label's times, in milliseconds.
bench_stats() { # label format
    sort -n "$BENCH_DIR/$1" | awk -v f="$2" '
        { v[NR] = $1 }
        END {
            if (NR == 0) exit 1
            median = (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
            printf f, median / 1000, v[1] / 1000, v[NR] / 1000
        }'
}

# The processes one start makes: the lightbox command itself, every tool it
# runs, the container's init and every tool that runs. In a PID namespace of
# its own nothing else makes processes, so the count is the distance the
# namespace's last process id moves. Reading it makes no process, and neither
# does the wait for init to finish.
bench_spawns() { # -> sets spawned
    local ip before after
    spawned=n/a
    [ -r /proc/sys/kernel/ns_last_pid ] || return 0
    ip=$(next_ip) || return 1
    "$LB" create spawns "$ip" >/dev/null 2>&1 || return 1
    mkfifo "$BENCH_DIR/idle" || return 1
    read -r before < /proc/sys/kernel/ns_last_pid
    "$LB" start spawns >/dev/null 2>&1 </dev/null || return 1
    read -r -t 2 _ <> "$BENCH_DIR/idle"
    read -r after < /proc/sys/kernel/ns_last_pid
    spawned=$((after - before))
}

bench_main() {
    local i ip label name line
    [ -n "${EPOCHREALTIME:-}" ] || { echo "bench: this needs bash 5 or later, for its clock" >&2; return 2; }
    mkdir -p "$BENCH_DIR" || return 1

    lb setup >"$BENCH_DIR/setup" 2>&1 || { cat "$BENCH_DIR/setup" >&2; echo "bench: setup failed" >&2; return 1; }

    for i in $(seq 1 "$BENCH_RUNS"); do
        ip=$(next_ip) || return 1
        timed create "$LB" create bench "$ip" &&
        timed start  "$LB" start bench &&
        settled bench &&
        timed exec   "$LB" exec bench /bin/true &&
        timed stop   "$LB" stop bench &&
        timed rm     "$LB" rm bench || { echo "bench: run $i did not complete" >&2; teardown; return 1; }
    done

    bench_spawns || { echo "bench: the processes of one start could not be counted" >&2; teardown; return 1; }
    teardown

    printf 'lightbox timing: %s runs of each command, wall time in milliseconds\n' "$BENCH_RUNS"
    printf '%s on %s, %s processors\n\n' "$(uname -sr)" "$(uname -m)" "$(nproc)"
    printf '%-16s %9s %9s %9s\n' command median lowest highest
    line=""
    for label in create start exec stop rm; do
        name=$label
        [ "$label" = exec ] && name='exec /bin/true'
        printf '%-16s %s\n' "$name" "$(bench_stats "$label" '%9.1f %9.1f %9.1f')"
        line="$line$label $(bench_stats "$label" '%.1f (%.1f to %.1f)'), "
    done
    printf '\nprocesses made by one start: %s\n' "$spawned"

    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        printf '::notice title=timing::%sin ms as median (lowest to highest) of %s; %s processes per start; %s %s with %s processors\n' \
            "$line" "$BENCH_RUNS" "$spawned" "$(uname -r)" "$(uname -m)" "$(nproc)"
    fi
}

bench_main
return $?
