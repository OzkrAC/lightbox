#!/usr/bin/env bash
#
# Root lifecycle suite (ROADMAP 0.6): the one suite that starts containers.
#
#   sudo make test-lifecycle
#   sudo tests/lifecycle.sh [path/to/lightbox]          default: ./lightbox
#
# Needs root, a kernel with bridge, veth and cgroup v2, the host tools lightbox
# itself needs (iproute2, iptables, util-linux) and a statically linked busybox
# to build the containers' root filesystem from.
#
# The host is not used and nothing is left on it. The suite runs itself again
# in private network, mount and PID namespaces with a throwaway configuration:
# its bridge, firewall rules, interfaces and mounts exist only there, and every
# process it starts dies with the PID namespace. cgroups cannot be private in
# that way, so its containers live in one directory of the real hierarchy,
# /sys/fs/cgroup/lightbox-test-<pid>, which is removed at the end. The host's
# virtual interfaces, firewall rules and cgroups are compared before and after,
# and a difference fails the run. A network card that the machine gains or
# loses meanwhile is reported and does not count.
#
#   LIGHTBOX_TEST_ROOTFS=/path  use a copy of this root filesystem (Alpine, Debian ...)
#   BUSYBOX=/path               the static busybox to build the root filesystem from
#   LIGHTBOX_TEST_MODPROBE=1    load br_netfilter when it is not loaded (CI sets this;
#                               on a workstation it changes how every bridge is filtered)
#   CASE_TIMEOUT=90             seconds one case may take
#   KEEP=1                      keep the work directory
#   V=1                         show the output of every case
#
# sudo drops the environment, so give these on make's command line:
#   sudo make test-lifecycle V=1
#
# The case runner (check, xfail, summary) is tests/lib.sh. Here every case is a
# process of its own with a time limit and its output in a file, so a command
# that hangs, or a container that holds a pipe open, fails its case and not
# the run.
#
#   tests/lifecycle.sh --program <script> [path/to/lightbox]
#
# runs another script in place of the cases: it is sourced inside the private
# namespaces once the fixture stands, with the helpers of this file, and its
# status is the run's. bench/bench.sh measures that way.
#
# Findings whose test would be a walk through the weakness itself have no case
# here (SB-vol-host-resolve, SB-create-host-write, SB-exec-self). Their fixes
# bring cases that state the safe behaviour.

set -u

SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
HERE=$(dirname "$SELF")

MODE=outer
case ${1:-} in
    --inside) MODE=inside; shift ;;
    --case)   MODE=case;   shift ;;
    --program)
        [ -r "${2:-}" ] || { echo "lifecycle: --program needs a script it can read" >&2; exit 2; }
        LIFECYCLE_PROGRAM=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
        export LIFECYCLE_PROGRAM
        shift 2 ;;
esac

# ─── Names used by every stage ──────────────────────────────────────────────

BR=lbt0                     # the bridge; not br0, in case a namespace ever fails to be private
SUBNET=10.199.0.0/24
NETP=10.199.0
GW=10.199.0.1
WAN=lbt-wan                 # the interface the default route leaves by
OUTSIDE=192.0.2.1           # an address beyond it, in a namespace that stands for the internet
ALLOWED_CAPS=00000000a00405fb   # ALLOWED_CAPS of lightbox.c as /proc/<pid>/status prints a set
BRNF=/proc/sys/net/bridge/bridge-nf-call-iptables

settings() { # after LIFECYCLE_T is known
    T=$LIFECYCLE_T
    LB=$LIFECYCLE_LB
    BB=${LIFECYCLE_BB:-}
    [ -n "$T" ] && [ -d "$T" ] || { echo "lifecycle: no work directory" >&2; exit 2; }
    C="$T/lb/containers"
    BASE="$T/base"
    OUT="$T/out"
    CG=$(cat "$T/cgroup_base")
    export HOME="$T/home"
}

# ─── Helpers for cases ──────────────────────────────────────────────────────

# lightbox with a time limit: a command that hangs fails instead of stalling.
lb() { timeout -k 5 "${LB_TIMEOUT:-60}" "$LB" "$@"; }

# Succeeds when the command fails.
refused() { ! "$@"; }

wait_until() { # seconds command... : poll until the command succeeds
    local limit=$(($1 * 10)) i=0
    shift
    until "$@"; do
        [ "$i" -lt "$limit" ] || return 1
        sleep 0.1
        i=$((i + 1))
    done
}

status_field() { # pid field : a value from /proc/<pid>/status
    awk -v k="$2:" '$1 == k { print $2; exit }' "/proc/$1/status" 2>/dev/null
}
alive()   { kill -0 "$1" 2>/dev/null && [ "$(status_field "$1" State)" != Z ]; }
gone()    { ! kill -0 "$1" 2>/dev/null; }          # exited and reaped
no_link() { ! ip link show "$1" >/dev/null 2>&1; }

pid_of()   { cat "$C/$1/.pid"; }
state_of() { cat "$C/$1/.state"; }
addr_of()  { cat "$C/$1/.ip"; }

next_ip() {
    local last
    last=$(($(cat "$T/next_ip") + 1))
    [ "$last" -le 254 ] || { echo "lifecycle: out of addresses" >&2; return 1; }
    echo "$last" > "$T/next_ip"
    echo "$NETP.$last"
}

box() { # name [create options] : create a container on the next free address
    local name=$1 ip
    shift
    ip=$(next_ip) || return 1
    lb create "$name" "$ip" "$@" >"$OUT/$name.create" 2>&1 || { cat "$OUT/$name.create"; return 1; }
}

mounted_in()   { awk -v m="$2" '$5 == m { found = 1 } END { exit !found }' "/proc/$1/mountinfo" 2>/dev/null; }
root_changed() { [ "$(stat -L -c %d:%i "/proc/$1/root" 2>/dev/null)" != "$(stat -c %d:%i /)" ]; }
sandboxed()    { [ "$(status_field "$1" Seccomp)" = 2 ]; }
in_own_root()  { root_changed "$1" && mounted_in "$1" /run; }

# start returns when init has built the container, so everything init does
# before its hook is there to see at once, without waiting: its own root, its
# mounts, its sandbox. A start that returned earlier would let a case look at,
# or run a command in, a container that is still being built.
settled() { # name
    local pid
    pid=$(pid_of "$1") || return 1
    in_own_root "$pid" || { echo "start returned before init $pid had its own root and /run"; return 1; }
    if grep -qx 'readonly=1' "$C/$1/.conf"; then
        mounted_in "$pid" /var/tmp || { echo "start returned before init $pid had mounted /var/tmp"; return 1; }
    fi
    if ! grep -qx 'privileged=1' "$C/$1/.conf"; then
        sandboxed "$pid" || { echo "start returned before init $pid had applied its sandbox"; return 1; }
    fi
}

# start's output goes to a file and is printed from there. A pipe would do
# since init stopped holding on to the command's streams, but if that ever
# came back, every case would wait at its pipe until its time ran out. The
# cases that are about capturing start's output use a pipe, under a limit.
start() { # name
    lb start "$1" >"$OUT/$1.start" 2>&1 </dev/null
    local rc=$?
    cat "$OUT/$1.start"
    [ $rc -eq 0 ] || return $rc
    settled "$1"
}

up() { box "$@" && start "$1"; }

sh_in()     { lb exec "$1" /bin/sh -c "$2" </dev/null; }   # name script
script_in() { lb exec "$1" /bin/sh; }                      # name, the script on standard input
hook()      { cat > "$C/$1/rootfs/init.sh"; }              # name, the init hook on standard input

children_of() { # pid program : the children of a process that run this program
    awk -v p="$1" -v c="($2)" '$4 == p && $2 == c { print $1 }' /proc/[0-9]*/stat 2>/dev/null
}

# What must not remain of a container that is not running.
nothing_left() { # name
    local bad=0
    if [ -e "$C/$1/.pid" ] || [ -e "$C/$1/.pid_start" ]; then
        echo "runtime files are left: $(ls -A "$C/$1" | tr '\n' ' ')"; bad=1
    fi
    no_link "vb-$1" || { echo "the interface vb-$1 is left"; bad=1; }
    [ ! -d "$CG/$1" ] || { echo "the cgroup $CG/$1 is left"; bad=1; }
    echo "state: $(state_of "$1")"
    return $bad
}

need_nc() { [ -e "$T/have_nc" ] || { echo "this image has no nc to open connections with"; return 77; }; }

# Does a TCP connection from the container get an answer from that address?
# Nothing listens on the port, so the answer is a refusal. Traffic that is
# filtered or not routed gets none, and the attempt times out.
reaches() { # name address
    local answer
    answer=$(sh_in "$1" "nc -w 3 $2 9 </dev/null" 2>&1)
    printf '%s -> %s: %s\n' "$1" "$2" "${answer:-no answer}"
    case $answer in *[Rr]efused*) return 0 ;; *) return 1 ;; esac
}

# Whether bridged traffic passes through iptables in this network namespace.
# Fails when the kernel cannot do it (br_netfilter is not loaded).
brnf() { # 0 | 1
    [ -w "$BRNF" ] || return 1
    echo "$1" > "$BRNF"
}

first_existing() { local p; for p in "$@"; do [ -e "$p" ] && { echo "$p"; return; }; done; echo "$1"; }

# In this mount namespace only, put a script in the place of a host tool.
# "$REAL" in the script is the tool itself.
shim() { # path script
    local name=${1##*/}
    cp -L "$1" "$T/real/$name" || return 1
    printf '#!/bin/sh\nREAL=%s\n%s\n' "$T/real/$name" "$2" > "$T/shim/$name"
    chmod 755 "$T/shim/$name"
    mount --bind "$T/shim/$name" "$1" || return 1
    echo "$1" >> "$T/shims"
}

# ─── Cases: host setup ──────────────────────────────────────────────────────

t_setup() {
    lb setup || return 1
    ip -o -4 addr show dev "$BR" | grep -q " $GW/24 " || { echo "the bridge has no address:"; ip addr show dev "$BR"; return 1; }
    ip link show dev "$BR" | head -n 1 | grep -q '[<,]UP[,>]' || { echo "the bridge is not up"; return 1; }
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "forwarding is off"; return 1; }
    iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE &&
    iptables -C FORWARD -i "$BR" -o "$WAN" -j ACCEPT &&
    iptables -C FORWARD -i "$WAN" -o "$BR" -m state --state RELATED,ESTABLISHED -j ACCEPT &&
    iptables -C FORWARD -i "$BR" -o "$BR" -j DROP || { echo "a rule is missing:"; iptables-save; return 1; }
    # the fixture made these 0755, as installations before 0.2 did
    echo "storage modes after setup: $(stat -c %a "$T/lb") $(stat -c %a "$C")"
    [ "$(stat -c %a "$T/lb")" = 700 ] && [ "$(stat -c %a "$C")" = 700 ]
}

firewall_rules() { iptables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//'; }

t_setup_again() {
    mounts=$(cat /proc/self/mountinfo)
    rules=$(firewall_rules)
    said=$(lb setup 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    [ "$mounts" = "$(cat /proc/self/mountinfo)" ] || { echo "the mount table changed"; return 1; }
    [ "$rules" = "$(firewall_rules)" ] || { echo "the firewall rules changed:"; firewall_rules; return 1; }
    # setup's own lines only: no listing from "ip link show" comes through
    ! printf '%s\n' "$said" | grep -Eq '^[0-9]+: '
}

t_setup_refuses_other_cgroup_root() {
    mkdir -p "$T/alt/home/.config/lightbox" "$T/alt/cgroup"
    : > "$T/alt/cgroup/not-empty"
    sed -e "s#^cgroup_root = .*#cgroup_root = $T/alt/cgroup#" -e '/^cgroup_base = /d' \
        -e 's#^bridge = .*#bridge = lbt9#' "$HOME/.config/lightbox/lightbox.conf" \
        > "$T/alt/home/.config/lightbox/lightbox.conf"
    mounts=$(cat /proc/self/mountinfo)
    said=$(HOME="$T/alt/home" timeout -k 5 60 "$LB" setup 2>&1) && { echo "setup succeeded"; return 1; }
    printf '%s\n' "$said"
    [ "$mounts" = "$(cat /proc/self/mountinfo)" ] || { echo "the mount table changed"; return 1; }
    no_link lbt9 || { echo "a bridge was made before the refusal"; return 1; }
    case $said in *'not a cgroup v2 hierarchy'*) ;; *) return 1 ;; esac
}

t_doctor() {
    said=$(lb doctor)
    rc=$?
    printf '%s\n' "$said"
    [ $rc -eq 0 ] && printf '%s\n' "$said" | grep -qx 'overall: ok'
}

# ─── Cases: the life of a container ─────────────────────────────────────────

t_lifecycle() {
    box web --mem 64M || return 1
    [ "$(state_of web)" = stopped ] || { echo "state after create: $(state_of web)"; return 1; }

    said=$(start web) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    pid=$(pid_of web) && alive "$pid" || { echo "no init process"; return 1; }
    printf '%s\n' "$said" | grep -qx "Container 'web' started (pid=$pid, ip=$(addr_of web))" || return 1
    [ "$(state_of web)" = running ] || { echo "state after start: $(state_of web)"; return 1; }

    [ "$(sh_in web 'echo hello from $(hostname)')" = 'hello from web' ] || return 1

    said=$(lb stop web 2>"$OUT/web.stop.err") || { printf '%s\n' "$said"; cat "$OUT/web.stop.err"; return 1; }
    printf '%s\n' "$said"
    cat "$OUT/web.stop.err"
    # stop's own two lines, and no listing from "ip link show" on either stream
    [ "$said" = "Stopping container 'web'...
Container 'web' stopped" ] || return 1
    ! grep -Eq '^[0-9]+: ' "$OUT/web.stop.err" || return 1

    [ "$(state_of web)" = stopped ] || { echo "state after stop: $(state_of web)"; return 1; }
    wait_until 5 gone "$pid" || { echo "init $pid is still there after stop"; return 1; }
    wait_until 5 no_link vb-web || { echo "vb-web is still there after stop"; return 1; }
    nothing_left web || return 1

    lb rm web || return 1
    [ ! -e "$C/web" ]
}

t_queries_show_running() {
    up shown || return 1
    pid=$(pid_of shown)
    ip=$(addr_of shown)
    lb ls; lb ls --json; lb inspect shown
    lb ls | grep -Eq "^shown +$ip +running +$pid\$" &&
    lb ls --json | grep -qF "{\"name\":\"shown\",\"ip\":\"$ip\",\"status\":\"running\",\"pid\":$pid}" &&
    lb inspect shown | grep -qx 'running: yes' &&
    lb inspect shown | grep -qx 'state: running' &&
    lb inspect shown | grep -qx "pid: $pid"
}

t_exec_status() {
    up status || return 1
    sh_in status 'exit 0';         a=$?
    sh_in status 'exit 7';         b=$?
    sh_in status 'kill -TERM $$';  c=$?
    lb exec status /no/such/program </dev/null; d=$?
    echo "exit 0 -> $a, exit 7 -> $b, killed by SIGTERM -> $c, a missing program -> $d"
    [ $a -eq 0 ] && [ $b -eq 7 ] && [ $c -eq 143 ] && [ $d -ne 0 ]
}

t_exec_default_shell() {
    up shell || return 1
    said=$(echo 'echo read from standard input' | lb exec shell)
    printf '%s\n' "$said"
    [ "$said" = 'read from standard input' ]
}

t_own_world() {
    up world || return 1
    script_in world <<EOF
echo "hostname \$(hostname), this shell is pid \$\$, pid 1 is \$(cat /proc/1/comm), \$(ls /proc | grep -c '^[0-9]') processes, uid \$(id -u)"
[ "\$(hostname)" = world ] || exit 1
[ "\$(cat /proc/1/comm)" = "$(basename "$LB" | cut -c1-15)" ] || exit 1
[ "\$(ls /proc | grep -c '^[0-9]')" -le 6 ] || exit 1
[ "\$(id -u)" = 0 ] || exit 1
[ ! -e /.old_root ] || { echo "the host's root is still at /.old_root"; exit 1; }
[ ! -e "$T" ] || { echo "the host's $T is visible"; exit 1; }
EOF
}

t_running_container_is_protected() {
    up busy || return 1
    pid=$(pid_of busy)
    refused start busy || { echo "a second start succeeded"; return 1; }
    refused lb rm busy || { echo "rm removed a running container"; return 1; }
    alive "$pid" && [ -d "$C/busy/rootfs" ] && [ "$(state_of busy)" = running ]
}

t_restart_keeps_files() {
    up again || return 1
    sh_in again 'echo kept > /root/note' || return 1
    lb stop again || return 1
    start again || return 1
    [ "$(sh_in again 'cat /root/note')" = kept ]
}

t_start_after_init_died() {
    up crash || return 1
    pid=$(pid_of crash)
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || { echo "init $pid survived SIGKILL"; return 1; }
    lb ls
    lb ls | grep -Eq '^crash +[0-9.]+ +exited' || { echo "ls does not show it as exited"; return 1; }
    # the kernel removes the dead container's interface a moment later
    wait_until 5 no_link vb-crash || { echo "vb-crash did not go away"; return 1; }
    start crash || return 1
    [ "$(sh_in crash 'echo back')" = back ]
}

t_failed_start_leaves_nothing() {
    box broken --vol "$T/vol/does-not-exist:/data" || return 1
    if said=$(start broken); then
        printf '%s\n' "$said"
        echo "the start succeeded"
        return 1
    fi
    printf '%s\n' "$said"
    # init's reason comes out of the command, though init's output goes to a log
    printf '%s\n' "$said" | grep -q 'volume source does not exist' || { echo "start does not say why"; return 1; }
    nothing_left broken
}

# ─── Cases: exec as another user ────────────────────────────────────────────

t_exec_user() {
    up users || return 1
    for who in lbuser 4711; do
        said=$(lb exec users --user "$who" /bin/sh -c 'id -u; id -g; id -G; echo "$HOME"; echo "$USER"' </dev/null)
        printf -- '--user %s:\n%s\n' "$who" "$said"
        [ "$said" = "4711
4711
4711 4712
/home/lbuser
lbuser" ] || return 1
    done
}

# The groups of a command are what the container's files give its user, and
# none for a uid the container has no account for. The groups of whoever runs
# lightbox are not among them, with --user or without.
t_exec_unknown_uid_drops_groups() {
    command -v setpriv >/dev/null 2>&1 || { echo "no setpriv to put the caller in a group with"; return 77; }
    up nogroups || return 1
    said=$(setpriv --groups 4242 timeout -k 5 60 "$LB" exec nogroups --user 1234 /bin/sh -c 'id -G' </dev/null) || return 1
    echo "groups of uid 1234 in the container: $said (the caller was in group 4242)"
    [ "$said" = 1234 ] || return 1
    said=$(setpriv --groups 4242 timeout -k 5 60 "$LB" exec nogroups /bin/sh -c 'id -u; id -G' </dev/null | tr '\n' ' ') || return 1
    echo "uid and groups without --user: $said"
    [ "$said" = "0 0 " ]
}

t_exec_user_is_strict() {
    up strict || return 1
    bad=0
    for spec in 0x10 1000: 12abc 99999999999 :5; do
        if said=$(lb exec strict --user "$spec" /bin/sh -c 'echo "$(id -u):$(id -g)"' </dev/null 2>&1); then
            echo "--user $spec was accepted and ran as $said"
            bad=1
        fi
    done
    said=$(lb exec strict --user 2>&1 </dev/null) && { echo "--user without a value was accepted"; bad=1; }
    printf '%s\n' "$said"
    case $said in *'option --user requires a value'*) ;; *) echo "a missing value is not named"; bad=1 ;; esac
    [ $bad -eq 0 ]
}

# An account is found wherever it is in the container's passwd, and is the
# container's: the file is read inside it, to its end.
t_exec_finds_a_late_account() {
    up late || return 1
    {
        for i in $(seq 1 200); do echo "filler$i:x:$((20000 + i)):$((20000 + i)):an account to fill the file:/home/filler$i:/bin/sh"; done
        echo 'a-late-user-with-a-long-name:x:4800:4800::/home/late:/bin/sh'
    } >> "$C/late/rootfs/etc/passwd"
    echo 'lategroup:x:4801:a-late-user-with-a-long-name' >> "$C/late/rootfs/etc/group"
    echo "the container's passwd is $(wc -c < "$C/late/rootfs/etc/passwd") bytes"
    said=$(lb exec late --user a-late-user-with-a-long-name /bin/sh -c 'id -u; id -G; echo "$USER $HOME"' </dev/null | tr '\n' ' ')
    echo "by name: $said"
    [ "$said" = "4800 4800 4801 a-late-user-with-a-long-name /home/late " ] || return 1
    said=$(lb exec late --user 4800 /bin/sh -c 'echo "$USER"' </dev/null)
    [ "$said" = a-late-user-with-a-long-name ]
}

t_exec_searches_path() {
    up path || return 1
    said=$(lb exec path echo found </dev/null)
    [ "$said" = found ] || return 1
    # with an argument, as the README shows it
    echo from a file > "$C/path/rootfs/etc/a-file"
    [ "$(lb exec path cat /etc/a-file </dev/null)" = "from a file" ] || return 1
    lb exec path no-such-command </dev/null 2>"$OUT/path.err"
    rc=$?
    echo "a command that is not there: status $rc, $(cat "$OUT/path.err")"
    [ $rc -eq 127 ] && grep -q 'command not found: no-such-command' "$OUT/path.err"
}

t_exec_passes_every_argument() {
    up argv || return 1
    words=$(seq 1 100 | tr '\n' ' ')
    # shellcheck disable=SC2086
    said=$(lb exec argv /bin/echo $words </dev/null)
    echo "100 arguments in, $(printf '%s' "$said" | wc -w) out"
    [ "$said" = "${words% }" ]
}

# While a command runs, the lightbox processes that put it there are not the
# installed binary: they run from a sealed copy in memory.
t_exec_runs_from_a_sealed_copy() {
    up sealed || return 1
    "$LB" exec sealed /bin/sh -c ': > /e.started; exec sleep 30' >"$OUT/sealed.exec" 2>&1 </dev/null &
    front=$!
    wait_until 5 test -e "$C/sealed/rootfs/e.started" || { echo "the command did not start:"; cat "$OUT/sealed.exec"; return 1; }
    bad=0
    for p in "$front" $(children_of "$front" lightbox); do
        exe=$(readlink "/proc/$p/exe")
        echo "lightbox process $p runs from: $exe"
        case $exe in '/memfd:lightbox'*) ;; *) echo "  that is not the sealed copy"; bad=1 ;; esac
    done
    [ -n "$(children_of "$front" lightbox)" ] || { echo "exec has no worker to look at"; bad=1; }
    lb doctor | grep -x 'exec_sealing: yes (a sealed copy in memory)' || { echo "doctor does not say how exec is sealed"; bad=1; }
    lb stop sealed >/dev/null
    wait "$front" 2>/dev/null
    return $bad
}

# --env, --workdir, the caller's TERM, and -- before a command of any shape.
t_exec_environment() {
    up envs || return 1
    said=$(TERM=vt220 timeout -k 5 60 "$LB" exec envs --env GREETING=hello --env GREETING=hi --workdir /tmp -- \
               /bin/sh -c 'echo "$GREETING $TERM $(pwd) $PATH"' </dev/null)
    echo "$said"
    [ "$said" = "hi vt220 /tmp /usr/bin:/bin:/usr/sbin:/sbin" ] || return 1
    # nothing else of the caller's environment goes in
    said=$(NOT_FOR_THE_CONTAINER=1 timeout -k 5 60 "$LB" exec envs /bin/sh -c 'env | sort' </dev/null | tr '\n' ' ')
    echo "the environment of a command: $said"
    case $said in *NOT_FOR_THE_CONTAINER*) return 1 ;; esac
    case $said in *'HOME=/root '*'LOGNAME=root '*'USER=root '*) ;; *) return 1 ;; esac
    refused lb exec envs --bogus /bin/true </dev/null
}

# ─── Cases: volumes and the root filesystem ─────────────────────────────────

t_volume_directory() {
    mkdir -p "$T/vol/shared"
    echo from-the-host > "$T/vol/shared/in"
    up vdir --vol "$T/vol/shared:/data" || return 1
    [ "$(sh_in vdir 'cat /data/in')" = from-the-host ] || return 1
    sh_in vdir 'echo from-the-container > /data/out' || return 1
    [ "$(cat "$T/vol/shared/out")" = from-the-container ]
}

t_volume_file() {
    echo 'setting = 1' > "$T/vol/app.conf"
    up vfile --vol "$T/vol/app.conf:/etc/app/app.conf" || return 1
    [ "$(sh_in vfile 'cat /etc/app/app.conf')" = 'setting = 1' ]
}

t_volume_read_only() {
    mkdir -p "$T/vol/fixed"
    echo fixed > "$T/vol/fixed/in"
    up vro --vol "$T/vol/fixed:/data:ro" || return 1
    [ "$(sh_in vro 'cat /data/in')" = fixed ] || return 1
    refused sh_in vro 'echo x > /data/new' || { echo "a read-only volume was written"; return 1; }
    [ ! -e "$T/vol/fixed/new" ]
}

t_addvol_applies_at_next_start() {
    mkdir -p "$T/vol/late"
    echo late > "$T/vol/late/in"
    up addvol || return 1
    lb add-vol addvol "$T/vol/late:/late" || return 1
    refused sh_in addvol 'cat /late/in' || { echo "the volume appeared without a restart"; return 1; }
    lb stop addvol && start addvol || return 1
    [ "$(sh_in addvol 'cat /late/in')" = late ]
}

t_volume_under_run() {
    mkdir -p "$T/vol/secrets"
    echo token > "$T/vol/secrets/token"
    up vrun --vol "$T/vol/secrets:/run/secrets:ro" || return 1
    said=$(sh_in vrun 'cat /run/secrets/token' 2>&1)
    echo "/run/secrets/token in the container: $said"
    [ "$said" = token ]
}

# A destination is looked up in the container. A link in the image leads
# where the container sees it lead, also when it names a path that the host
# has as well; nothing is made on the host.
#
# The directory that stands for the host's is on a tmpfs over /mnt, in this
# suite's own mount namespace. It cannot be in the work directory: that is
# below /tmp, and a container mounts a tmpfs of its own over /tmp, which would
# hide the container's directory of the same name.
t_volume_destination_is_inside() {
    [ -d /mnt ] || { echo "no /mnt to put a directory of the host's on"; return 77; }
    mount -t tmpfs tmpfs /mnt || return 1
    echo /mnt >> "$T/shims"
    host=/mnt/named-on-the-host
    mkdir -p "$T/vol/linked" "$host"
    echo through-a-link > "$T/vol/linked/in"
    box vlink --vol "$T/vol/linked:/link/data" --vol "$T/vol/linked:/away/data:ro" || return 1
    # a link as an image has it, and one that names a directory the host has too
    mkdir -p "$C/vlink/rootfs/srv" "$C/vlink/rootfs$host"
    ln -s /srv "$C/vlink/rootfs/link"
    ln -s "$host" "$C/vlink/rootfs/away"
    start vlink || return 1
    [ "$(sh_in vlink 'cat /srv/data/in')" = through-a-link ] || { echo "the volume is not where the link leads in the container"; return 1; }
    [ "$(sh_in vlink 'cat /away/data/in')" = through-a-link ] || { echo "the second volume is not reachable through its link"; return 1; }
    [ -z "$(ls -A "$host")" ] || { echo "something was made on the host: $(ls -A "$host")"; return 1; }
    [ -d "$C/vlink/rootfs$host/data" ] || { echo "the destination was not made in the container's root filesystem"; return 1; }
    lb stop vlink >/dev/null || return 1

    # the same link when the container has no such directory: it leads nowhere, and the start says so
    box vnowhere --vol "$T/vol/linked:/away/data" || return 1
    ln -s "$host" "$C/vnowhere/rootfs/away"
    if said=$(start vnowhere); then
        printf '%s\n' "$said"
        echo "a volume was mounted through a link that leads nowhere in the container"
        return 1
    fi
    printf '%s\n' "$said"
    [ -z "$(ls -A "$host")" ] || { echo "something was made on the host: $(ls -A "$host")"; return 1; }
    nothing_left vnowhere
}

# Volumes go on top of what init mounts itself, and keep their restrictions.
t_volume_under_tmp() {
    mkdir -p "$T/vol/cache"
    echo cached > "$T/vol/cache/in"
    echo 'one = 1' > "$T/vol/one.conf"
    up vtmp --read-only --vol "$T/vol/cache:/tmp/cache" --vol "$T/vol/one.conf:/run/app/one.conf:ro" --vol "$T/vol/cache:/not/in/the/image" || return 1
    [ "$(sh_in vtmp 'cat /tmp/cache/in')" = cached ] || { echo "a volume under /tmp is not visible"; return 1; }
    [ "$(sh_in vtmp 'cat /run/app/one.conf')" = 'one = 1' ] || { echo "a file volume under /run is not visible"; return 1; }
    [ "$(sh_in vtmp 'cat /not/in/the/image/in')" = cached ] || { echo "a volume at a path the image lacks is not there, with a read-only root"; return 1; }
    refused sh_in vtmp 'echo x > /run/app/one.conf' || { echo "a read-only file volume was written"; return 1; }
    sh_in vtmp 'echo written > /tmp/cache/out' && [ "$(cat "$T/vol/cache/out")" = written ]
}

# vm.memfd_noexec says whether a memfd may be executed. With 1, exec's copy is
# still allowed, because exec asks for it by name; with 2 it is not, and exec
# takes the binary through a read-only mount instead. The setting belongs to
# this suite's PID namespace and cannot always be taken back, which is why
# this case is the last one.
t_exec_where_memfds_may_not_be_executed() {
    knob=/proc/sys/vm/memfd_noexec
    [ -w "$knob" ] || { echo "this kernel has no vm.memfd_noexec"; return 77; }
    was=$(cat "$knob")
    up noexec || return 1
    bad=0
    echo 1 > "$knob" || { echo "vm.memfd_noexec cannot be set here"; return 77; }
    said=$(sh_in noexec 'echo ran') || true
    echo "with vm.memfd_noexec = 1: $said; $(lb doctor | grep '^exec_sealing')"
    [ "$said" = ran ] && lb doctor | grep -qx 'exec_sealing: yes (a sealed copy in memory)' || bad=1

    echo 2 > "$knob" || { echo "vm.memfd_noexec cannot be set to 2 here"; return 77; }
    said=$(sh_in noexec 'echo ran') || true
    echo "with vm.memfd_noexec = 2: $said; $(lb doctor | grep '^exec_sealing')"
    [ "$said" = ran ] && lb doctor | grep -q '^exec_sealing: yes (a read-only mount of the binary' || bad=1
    "$LB" exec noexec /bin/sh -c ': > /e.started; exec sleep 30' >"$OUT/noexec.exec" 2>&1 </dev/null &
    front=$!
    wait_until 5 test -e "$C/noexec/rootfs/e.started" || { echo "the command did not start:"; cat "$OUT/noexec.exec"; bad=1; }
    exe=$(readlink "/proc/$front/exe")
    echo "lightbox process $front runs from: $exe"
    case $exe in /memfd:*) echo "  a memfd was executed though the setting forbids it"; bad=1 ;; esac
    lb stop noexec >/dev/null
    wait "$front" 2>/dev/null
    echo "$was" > "$knob" 2>/dev/null || echo "(vm.memfd_noexec stays at $(cat "$knob") in this suite's PID namespace)"
    return $bad
}

t_read_only_root() {
    up readonly --read-only || return 1
    refused sh_in readonly 'echo x > /root/new' || { echo "the root filesystem was written"; return 1; }
    sh_in readonly 'echo x > /tmp/a && echo x > /run/a && echo x > /var/tmp/a && echo x > /dev/shm/a'
}

t_run_mode() {
    up runmode || return 1
    said=$(sh_in runmode 'ls -ld /run')
    echo "$said"
    case $said in drwxr-xr-x*) ;; *) return 1 ;; esac
}

t_rootfs_mount_flags() {
    up flags || return 1
    script_in flags <<'EOF'
opts=$(awk '$5 == "/" { print $6 }' /proc/self/mountinfo | tail -n 1)
echo "mount options of / in the container: $opts"
case ",$opts," in *,nodev,*) ;; *) exit 1 ;; esac
case ",$opts," in *,nosuid,*) ;; *) exit 1 ;; esac
echo x > /dev/null      # devices still come from the /dev that start mounts
EOF
}

# What init mounts, and with which restrictions. /proc/sys is the row to watch:
# it gets read-only added to a mount that is nosuid, nodev and noexec, and a
# change of flags that did not keep those three would lose them.
t_mount_table() {
    mkdir -p "$T/vol/table"
    up table --vol "$T/vol/table:/data:ro" || return 1
    script_in table <<'EOF'
bad=0
want() { # mount point, filesystem type or "-" for any, the flags it must have
    point=$1 type=$2
    shift 2
    line=$(awk -v m="$point" '$5 == m { for (i = 7; i <= NF; i++) if ($i == "-") break; l = $6 " " $(i + 1) } END { print l }' /proc/self/mountinfo)
    [ -n "$line" ] || { echo "$point is not a mount"; bad=1; return; }
    opts=${line% *}
    [ "$type" = - ] || [ "${line##* }" = "$type" ] || { echo "$point is ${line##* }, not $type"; bad=1; }
    for flag in "$@"; do
        case ",$opts," in *",$flag,"*) ;; *) echo "$point lacks $flag: it has $opts"; bad=1 ;; esac
    done
}
want /            -      nodev nosuid
want /proc        proc   nosuid nodev noexec
want /proc/sys    proc   ro nosuid nodev noexec
for d in bus fs irq; do
    [ ! -d "/proc/$d" ] || want "/proc/$d" proc ro nosuid nodev noexec     # not every kernel has all three
done
want /sys         sysfs  ro
want /dev         tmpfs  nosuid noexec
want /dev/pts     devpts nosuid noexec
want /dev/shm     tmpfs  nosuid nodev noexec
want /dev/null    -      nosuid noexec
want /dev/urandom -      ro nosuid noexec
want /tmp         tmpfs  nosuid nodev
want /run         tmpfs  nosuid nodev
want /data        -      ro nosuid nodev
exit $bad
EOF
}

# lightbox mounts by itself. With the host's mount turned into something that
# only records being run, and none in the image, a container starts and stops.
t_start_needs_no_mount_tool() {
    box nomount || return 1
    rm -f "$C/nomount/rootfs/bin/mount" "$C/nomount/rootfs/usr/bin/mount"
    tool=$(type -P mount) || { echo "this host has no mount to stand in for"; return 77; }
    shim "$tool" "echo \"\$*\" >> '$T/mount.ran'; exit 97" || return 1
    start nomount || return 1
    sh_in nomount 'echo x > /tmp/a && cat /proc/1/comm > /dev/null' || return 1
    lb stop nomount || return 1
    if [ -e "$T/mount.ran" ]; then
        echo "the host's mount was run:"
        cat "$T/mount.ran"
        return 1
    fi
}

t_image_without_mount_points() {
    box bare || return 1
    for d in dev proc sys tmp run var; do rm -rf -- "$C/bare/rootfs/$d"; done
    start bare || return 1
    [ "$(sh_in bare 'echo x > /dev/null && cat /proc/1/comm > /dev/null && ls /sys > /dev/null && echo x > /tmp/a && echo fine')" = fine ]
}

t_image_with_one_binary() {
    [ -n "$BB" ] || { echo "no static busybox to make the image from"; return 77; }
    mkdir -p "$T/base-one"
    cp "$BB" "$T/base-one/busybox"
    lb create one "$(next_ip)" --rootfs "$T/base-one" || return 1
    start one || { echo "an image without mount, ip and sh did not start"; return 1; }
    [ "$(lb exec one /busybox echo runs </dev/null)" = runs ] && lb stop one
}

t_start_runs_nothing_from_the_image() {
    [ -n "$BB" ] || { echo "the recording stand-ins are made for the busybox image"; return 77; }
    box record || return 1
    for tool in mount ip; do
        rm -f "$C/record/rootfs/bin/$tool"
        printf '#!/bin/sh\necho %s >> /run-from-the-image\nexec /bin/busybox %s "$@"\n' "$tool" "$tool" \
            > "$C/record/rootfs/bin/$tool"
        chmod 755 "$C/record/rootfs/bin/$tool"
    done
    start record || return 1
    log="$C/record/rootfs/run-from-the-image"
    if [ -s "$log" ]; then
        echo "run from the image during start: $(sort "$log" | uniq -c | tr -s ' \n' ' ')"
        return 1
    fi
}

# ─── Cases: limits ──────────────────────────────────────────────────────────

t_limits() {
    up limits --mem 64M --pids 50 --cpu 2 --oom-score 300 || return 1
    pid=$(pid_of limits)
    echo "memory.max $(cat "$CG/limits/memory.max"), pids.max $(cat "$CG/limits/pids.max"), cpu.max $(cat "$CG/limits/cpu.max"), oom_score_adj $(cat "/proc/$pid/oom_score_adj")"
    [ "$(cat "$CG/limits/memory.max")" = 67108864 ] && [ "$(cat "$CG/limits/pids.max")" = 50 ] &&
    [ "$(cat "$CG/limits/cpu.max")" = '200000 100000' ] && [ "$(cat "/proc/$pid/oom_score_adj")" = 300 ]
}

t_cgroup_membership() {
    up member || return 1
    grep -qx "$(pid_of member)" "$CG/member/cgroup.procs" || { echo "init is not in the container's cgroup"; return 1; }
    where=$(sh_in member 'cat /proc/self/cgroup')
    echo "a command run by exec is in: $where"
    case $where in *"/${CG##*/}/member") ;; *) return 1 ;; esac
}

# ─── Cases: the init hook, starting and stopping ────────────────────────────

t_hook_runs() {
    box hooked || return 1
    hook hooked <<'EOF'
grep -q ' /run tmpfs ' /proc/mounts && grep -q ' /tmp tmpfs ' /proc/mounts && echo ready > /hook.ran
EOF
    start hooked || return 1
    wait_until 5 test -e "$C/hooked/rootfs/hook.ran" || { echo "the hook left no mark"; return 1; }
    [ "$(cat "$C/hooked/rootfs/hook.ran")" = ready ]
}

t_service_outlives_start() {
    box service || return 1
    hook service <<'EOF'
(while :; do echo beat >> /beats; sleep 1; done) &
EOF
    start service || return 1
    beats() { wc -l < "$C/service/rootfs/beats" 2>/dev/null || echo 0; }
    sleep 1.2; first=$(beats)
    sleep 2.2; later=$(beats)
    echo "beats written by the service: $first, then $later"
    [ "$later" -gt "$first" ]
}

t_hook_is_sandboxed() {
    box hooksbx || return 1
    hook hooksbx <<'EOF'
grep -E '^(NoNewPrivs|Seccomp|CapEff|CapPrm|CapBnd):' /proc/self/status > /hook.status
EOF
    start hooksbx || return 1
    seen="$C/hooksbx/rootfs/hook.status"
    wait_until 5 test -s "$seen" || { echo "the hook left no mark"; return 1; }
    field() { awk -v k="$1:" '$1 == k { print $2 }' "$seen"; }
    echo "the hook ran with Seccomp $(field Seccomp), NoNewPrivs $(field NoNewPrivs), CapEff $(field CapEff), CapBnd $(field CapBnd)"
    [ "$(field Seccomp)" = 2 ] && [ "$(field NoNewPrivs)" = 1 ] && [ "$(field CapBnd)" = "$ALLOWED_CAPS" ] &&
    [ "$(field CapEff)" = "$ALLOWED_CAPS" ] && [ "$(field CapPrm)" = "$ALLOWED_CAPS" ]
}

t_privileged_hook_is_not_sandboxed() {
    box hookpriv --privileged || return 1
    hook hookpriv <<'EOF'
grep -E '^(NoNewPrivs|Seccomp|CapEff|CapBnd):' /proc/self/status > /hook.status
EOF
    start hookpriv || return 1
    seen="$C/hookpriv/rootfs/hook.status"
    wait_until 5 test -s "$seen" || { echo "the hook left no mark"; return 1; }
    field() { awk -v k="$1:" '$1 == k { print $2 }' "$seen"; }
    echo "the hook ran with Seccomp $(field Seccomp), NoNewPrivs $(field NoNewPrivs), CapEff $(field CapEff), CapBnd $(field CapBnd)"
    # as unconfined as this shell is
    [ "$(field Seccomp)" = "$(status_field $$ Seccomp)" ] && [ "$(field NoNewPrivs)" = "$(status_field $$ NoNewPrivs)" ] &&
    [ "$(field CapEff)" = "$(status_field $$ CapEff)" ] && [ "$(field CapBnd)" = "$(status_field $$ CapBnd)" ]
}

# start returns when the hook has ended, not before.
t_start_waits_for_the_hook() {
    box waited || return 1
    hook waited <<'EOF'
sleep 1
echo done > /hook.done
EOF
    start waited || return 1
    [ -e "$C/waited/rootfs/hook.done" ] || { echo "start returned before the hook had ended"; return 1; }
}

# A hook that fails two seconds in. start used to look after half a second,
# and report success.
t_failing_hook_fails_start() {
    box hookfail || return 1
    hook hookfail <<'EOF'
sleep 2
echo the reason the hook gives
exit 3
EOF
    if said=$(start hookfail); then
        printf '%s\n' "$said"
        echo "start reported success for a hook that goes on to fail"
        return 1
    fi
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -q 'failed with exit status 3' || { echo "start does not say how the hook ended"; return 1; }
    printf '%s\n' "$said" | grep -q 'lightbox logs hookfail' || { echo "start does not say where the hook's output is"; return 1; }
    lb logs hookfail | grep -qx 'the reason the hook gives' || { echo "the hook's output is not in the log"; return 1; }
    nothing_left hookfail
}

# With -t, start gives up waiting, says so, and leaves the container running.
t_start_stops_waiting() {
    box patient || return 1
    hook patient <<'EOF'
: > /hook.started
sleep 6
: > /hook.finished
EOF
    lb start patient -t 1 >"$OUT/patient.start" 2>&1 </dev/null
    rc=$?
    cat "$OUT/patient.start"
    [ $rc -eq 0 ] || return 1
    grep -q 'still running after 1 s' "$OUT/patient.start" || { echo "nothing says that the hook is still running"; return 1; }
    [ ! -e "$C/patient/rootfs/hook.finished" ] || { echo "the hook had ended already: this showed nothing"; return 1; }
    [ "$(state_of patient)" = running ] || { echo "state: $(state_of patient)"; return 1; }
    settled patient || return 1
    # the hook goes on, and the container is still there when it has ended
    wait_until 10 test -e "$C/patient/rootfs/hook.finished" || { echo "the hook did not go on"; return 1; }
    sleep 0.3
    alive "$(pid_of patient)" || { echo "the container ended with its hook"; return 1; }
}

# start used to sleep half a second before it looked whether init was alive.
# The quickest of three, because one start on a shared machine can be slow.
t_start_does_not_wait_a_fixed_time() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    box quick || return 1
    best=999999
    for i in 1 2 3; do
        t0=${EPOCHREALTIME/[.,]/}
        "$LB" start quick >"$OUT/quick.start" 2>&1 </dev/null || { cat "$OUT/quick.start"; return 1; }
        t1=${EPOCHREALTIME/[.,]/}
        ms=$(((t1 - t0) / 1000))
        echo "start $i took $ms ms"
        [ "$ms" -lt "$best" ] && best=$ms
        settled quick || return 1
        lb stop quick >/dev/null || return 1
    done
    [ "$best" -lt 300 ] || { echo "the quickest of three starts took $best ms"; return 1; }
}

t_stop_during_hook() {
    box hookslow || return 1
    hook hookslow <<'EOF'
: > /hook.started
sleep 30
EOF
    "$LB" start hookslow >"$OUT/hookslow.start" 2>&1 </dev/null &
    starter=$!
    echo "$starter" >> "$T/background"
    wait_until 10 test -e "$C/hookslow/rootfs/hook.started" || { echo "the hook did not start:"; cat "$OUT/hookslow.start"; return 1; }
    init=$(sort -n "$CG/hookslow/cgroup.procs" | head -n 1)
    [ -n "$init" ] || { echo "no process in the container's cgroup"; return 1; }
    kill -TERM "$init"
    wait_until 5 gone "$init" || { echo "init $init ignored SIGTERM while its hook was running"; return 1; }
}

t_start_returns_to_a_capture() {
    box capture || return 1
    timeout -k 2 8 bash -c 'said=$("$1" start capture 2>&1); printf "%s\n" "$said"' _ "$LB" </dev/null
    rc=$?
    if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then
        echo 'said=$(lightbox start capture) was still waiting after 8 seconds: init holds the pipe open'
        return 1
    fi
    [ $rc -eq 0 ] && settled capture
}

t_start_returns_to_a_pipe() {
    box piped || return 1
    timeout -k 2 8 bash -c 'set -o pipefail; "$1" start piped 2>&1 | cat' _ "$LB" </dev/null
    rc=$?
    if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then
        echo 'lightbox start piped | cat was still waiting after 8 seconds: init holds the pipe open'
        return 1
    fi
    [ $rc -eq 0 ] && settled piped
}

# The starter leads a session of its own here, so that its number is one this
# PID namespace can see: a session led from outside it reads as 0.
t_init_has_its_own_session() {
    box session || return 1
    setsid --wait bash -c 'echo $$ > "$3"; exec "$1" start session >"$2" 2>&1 </dev/null' \
        _ "$LB" "$OUT/session.start" "$T/starter.session" || { cat "$OUT/session.start"; return 1; }
    settled session || return 1
    starter=$(cat "$T/starter.session")
    pid=$(pid_of session)
    read -r _ _ _ _ group its _ < "/proc/$pid/stat"
    echo "session of the command that started it: $starter; of the container's init $pid: session $its, process group $group"
    [ "$its" != "$starter" ] && [ "$its" = "$pid" ] && [ "$group" = "$pid" ]
}

# What Ctrl-C does: SIGINT to the process group of the command that was typed.
# The starter leads its group here, so the group's number is the starter's.
t_sigint_spares_the_container() {
    box sigint || return 1
    setsid --wait bash -c 'echo $$ > "$3"; exec "$1" start sigint >"$2" 2>&1 </dev/null' \
        _ "$LB" "$OUT/sigint.start" "$T/starter.group" || { cat "$OUT/sigint.start"; return 1; }
    settled sigint || return 1
    pid=$(pid_of sigint)
    starter=$(cat "$T/starter.group")
    its=$(awk '{ print $5 }' "/proc/$pid/stat")
    echo "process group of the command that started it: $starter; of the container's init $pid: $its"
    kill -INT -- "-$starter" 2>/dev/null      # nobody is left in it once init is out of it
    sleep 1
    alive "$pid" || { echo "SIGINT to the starter's process group ended the container"; return 1; }
    [ "$its" != "$starter" ]
}

# What the container prints goes to its log and not to the command that
# started it; logs shows it, and logs -f goes on until the container ends.
t_logs() {
    box logged || return 1
    hook logged <<'EOF'
echo printed by the hook
echo complained by the hook >&2
(sleep 2; echo printed by the service) &
EOF
    said=$(start logged) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    case $said in *'by the hook'*) echo "the hook's output reached the command that started the container"; return 1 ;; esac
    first=$(lb logs logged) || return 1
    echo "the log when start returned:"; printf '%s\n' "$first" | sed 's/^/  /'
    [ "$first" = "printed by the hook
complained by the hook" ] || return 1
    [ "$(stat -c %a "$C/logged/console.log")" = 600 ] || { echo "the log has mode $(stat -c %a "$C/logged/console.log")"; return 1; }

    "$LB" logs logged -f > "$OUT/logged.followed" 2>&1 </dev/null &
    follower=$!
    wait_until 5 grep -qx 'printed by the service' "$OUT/logged.followed" || { echo "logs -f did not show what the service printed later"; kill "$follower"; return 1; }
    alive "$follower" || { echo "logs -f ended while the container was running"; return 1; }
    lb stop logged >/dev/null || return 1
    wait_until 5 gone "$follower" || { echo "logs -f did not end with the container"; kill "$follower"; return 1; }
    [ "$(cat "$OUT/logged.followed")" = "printed by the hook
complained by the hook
printed by the service" ] || { echo "logs -f showed:"; cat "$OUT/logged.followed"; return 1; }

    # the log is kept from one start to the next
    start logged >/dev/null || return 1
    [ "$(lb logs logged | grep -c 'printed by the hook')" = 2 ]
}

# Nothing that was open in the command stays open in the container: init has
# /dev/null, the log twice, and its signalfd. The command here has a file on
# descriptor 9, and no standard streams of its own the second time.
t_init_keeps_nothing_of_the_command() {
    box clean || return 1
    look() { # name
        local pid fd n to log bad=0
        pid=$(pid_of "$1") || return 1
        log=$C/$1/console.log
        for fd in "/proc/$pid/fd"/*; do
            n=${fd##*/}
            to=$(readlink "$fd")
            echo "  init $pid, descriptor $n: $to"
            # the same file, however its path is spelled
            if [ "$n" = 0 ] && [ "$fd" -ef /dev/null ]; then continue; fi
            if { [ "$n" = 1 ] || [ "$n" = 2 ]; } && [ "$fd" -ef "$log" ]; then continue; fi
            if [ "$n" -gt 2 ] && [ "$to" = 'anon_inode:[signalfd]' ]; then continue; fi
            echo "  init should not have that"
            bad=1
        done
        [ -e "/proc/$pid/fd/0" ] && [ -e "/proc/$pid/fd/1" ] && [ -e "/proc/$pid/fd/2" ] || { echo "  init lacks a standard stream"; bad=1; }
        return $bad
    }
    : > "$T/open-in-the-command"
    lb start clean >"$OUT/clean.start" 2>&1 </dev/null 9< "$T/open-in-the-command" || { cat "$OUT/clean.start"; return 1; }
    settled clean && look clean || return 1
    lb stop clean >/dev/null || return 1

    "$LB" start clean <&- >&- 2>&- || { echo "a start with its standard streams closed failed with status $?"; return 1; }
    settled clean && look clean
}

t_stop_is_graceful() {
    box graceful || return 1
    hook graceful <<'EOF'
cat > /service.sh <<'SERVICE'
trap 'echo got SIGTERM > /service.stopped; exit 0' TERM
: > /service.started
while :; do sleep 1 & wait $!; done
SERVICE
/bin/sh /service.sh &
EOF
    start graceful || return 1
    wait_until 5 test -e "$C/graceful/rootfs/service.started" || { echo "the service did not start"; return 1; }
    pid=$(pid_of graceful)
    began=$SECONDS
    lb stop graceful || return 1
    echo "stop took about $((SECONDS - began)) s"
    [ -e "$C/graceful/rootfs/service.stopped" ] || { echo "the service was killed without being asked to stop"; return 1; }
    # a service that ends when asked is not waited for any longer
    [ $((SECONDS - began)) -lt 5 ] || { echo "stop waited though the service had ended"; return 1; }
    wait_until 5 gone "$pid" || { echo "init $pid is still there after stop"; return 1; }
    nothing_left graceful
}

# A service that will not end is killed, when the time stop gives it is over
# and not before.
t_stop_kills_after_the_limit() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    box stubborn || return 1
    hook stubborn <<'EOF'
cat > /service.sh <<'SERVICE'
trap '' TERM
: > /service.started
while :; do sleep 1; done
SERVICE
/bin/sh /service.sh &
EOF
    start stubborn || return 1
    wait_until 5 test -e "$C/stubborn/rootfs/service.started" || { echo "the service did not start"; return 1; }
    pid=$(pid_of stubborn)
    t0=${EPOCHREALTIME/[.,]/}
    lb stop stubborn -t 2 >"$OUT/stubborn.stop" 2>&1
    rc=$?
    ms=$(((${EPOCHREALTIME/[.,]/} - t0) / 1000))
    cat "$OUT/stubborn.stop"
    echo "stop -t 2 returned $rc after $ms ms"
    [ $rc -eq 0 ] || return 1
    [ "$ms" -ge 2000 ] || { echo "the service did not get its two seconds"; return 1; }
    [ "$ms" -lt 6000 ] || { echo "stop took far longer than the limit it was given"; return 1; }
    lb logs stubborn | grep -q 'within 2 s of SIGTERM' || { echo "the log does not say that the service had to be killed"; return 1; }
    wait_until 5 gone "$pid" || { echo "init $pid is still there after stop"; return 1; }
    nothing_left stubborn
}

# stop looked every 200 ms whether init was gone. The quickest of three.
t_stop_of_an_idle_container_is_quick() {
    [ -n "${EPOCHREALTIME:-}" ] || { echo "this needs bash 5 or later, for its clock"; return 77; }
    box idle || return 1
    best=999999
    for i in 1 2 3; do
        start idle >/dev/null || return 1
        t0=${EPOCHREALTIME/[.,]/}
        "$LB" stop idle >"$OUT/idle.stop" 2>&1 </dev/null || { cat "$OUT/idle.stop"; return 1; }
        ms=$(((${EPOCHREALTIME/[.,]/} - t0) / 1000))
        echo "stop $i took $ms ms"
        [ "$ms" -lt "$best" ] && best=$ms
        nothing_left idle >/dev/null || { nothing_left idle; return 1; }
    done
    [ "$best" -lt 150 ] || { echo "the quickest of three stops took $best ms"; return 1; }
}

# A command that exec runs is in the container too: stop ends it, and the
# exec that started it returns.
t_stop_ends_an_exec() {
    up guest || return 1
    lb exec guest /bin/sh -c ': > /guest.started; exec sleep 300' >"$OUT/guest.exec" 2>&1 </dev/null &
    execer=$!
    wait_until 5 test -e "$C/guest/rootfs/guest.started" || { echo "the command did not start:"; cat "$OUT/guest.exec"; return 1; }
    pid=$(pid_of guest)
    began=$SECONDS
    lb stop guest || return 1
    echo "stop took about $((SECONDS - began)) s"
    [ $((SECONDS - began)) -lt 5 ] || { echo "stop waited though the command ends on SIGTERM"; return 1; }
    wait_until 5 gone "$execer" || { echo "the exec is still waiting for its command"; kill "$execer"; return 1; }
    wait "$execer"
    echo "exec returned $?"
    wait_until 5 gone "$pid" || { echo "init $pid is still there after stop"; return 1; }
    nothing_left guest
}

# What Ctrl-C or a kill does to a start that waits for the hook: the command
# undoes what it did and says which signal it was.
t_interrupted_start_is_undone() {
    box interrupt || return 1
    hook interrupt <<'EOF'
: > /hook.started
sleep 30
EOF
    "$LB" start interrupt >"$OUT/interrupt.start" 2>&1 </dev/null &
    starter=$!
    echo "$starter" >> "$T/background"
    wait_until 10 test -e "$C/interrupt/rootfs/hook.started" || { echo "the hook did not start:"; cat "$OUT/interrupt.start"; return 1; }
    init=$(pid_of interrupt) || { echo "init is not on record while its hook runs"; return 1; }
    kill -TERM "$starter"
    wait "$starter"
    rc=$?
    cat "$OUT/interrupt.start"
    echo "start exited with status $rc"
    [ $rc -eq 143 ] || return 1
    grep -q 'interrupted by signal 15' "$OUT/interrupt.start" || { echo "start does not say what interrupted it"; return 1; }
    gone "$init" || { echo "init $init is still there"; return 1; }
    nothing_left interrupt && [ "$(state_of interrupt)" = failed ]
}

# A start that is killed outright can undo nothing. While the hook runs, what
# it leaves is a container on record: ls shows it and stop clears it up.
t_killed_start_leaves_a_container() {
    box survivor || return 1
    hook survivor <<'EOF'
: > /hook.started
sleep 30
EOF
    "$LB" start survivor >"$OUT/survivor.start" 2>&1 </dev/null &
    starter=$!
    echo "$starter" >> "$T/background"
    wait_until 10 test -e "$C/survivor/rootfs/hook.started" || { echo "the hook did not start:"; cat "$OUT/survivor.start"; return 1; }
    kill -KILL "$starter"
    wait "$starter" 2>/dev/null
    pid=$(pid_of survivor) || { echo "no init is on record"; return 1; }
    sleep 0.5
    alive "$pid" || { echo "init $pid went with the command that started it"; return 1; }
    lb ls
    lb ls | grep -Eq "^survivor +[0-9.]+ +running +$pid\$" || { echo "ls does not show it as running"; return 1; }
    lb stop survivor || return 1
    wait_until 5 gone "$pid" || { echo "init $pid is still there after stop"; return 1; }
    nothing_left survivor
}

# start stands still in nsenter, between the clone and the byte that releases
# init. Killed there, it must not leave init behind.
t_killed_start_leaves_no_container() {
    box orphan || return 1
    nsenter_path=$(first_existing /usr/bin/nsenter /bin/nsenter /usr/sbin/nsenter /sbin/nsenter)
    shim "$nsenter_path" ": > '$T/nsenter.reached'; sleep 5; exec \"\$REAL\" \"\$@\"" || return 1
    "$LB" start orphan >"$OUT/orphan.start" 2>&1 </dev/null &
    starter=$!
    echo "$starter" >> "$T/background"
    wait_until 10 test -e "$T/nsenter.reached" || { echo "start did not reach nsenter:"; cat "$OUT/orphan.start"; return 1; }
    init=$(children_of "$starter" "$(basename "$LB" | cut -c1-15)")
    [ -n "$init" ] || { echo "the starter has no cloned child"; return 1; }
    kill -KILL "$starter"
    wait "$starter" 2>/dev/null
    sleep 2
    for p in $init; do
        if alive "$p"; then
            echo "pid $p, the child of the killed start, is still running"
            return 1
        fi
    done
}

t_stale_pid_start() {
    box stale || return 1
    printf '12345' > "$C/stale/.pid_start"
    start stale
}

# ─── Cases: the sandbox ─────────────────────────────────────────────────────

t_sandbox_on_init() {
    up sandbox || return 1
    pid=$(pid_of sandbox)
    grep -E '^(NoNewPrivs|Seccomp|CapBnd):' "/proc/$pid/status"
    [ "$(status_field "$pid" Seccomp)" = 2 ] && [ "$(status_field "$pid" NoNewPrivs)" = 1 ] &&
    [ "$(status_field "$pid" CapBnd)" = "$ALLOWED_CAPS" ]
}

t_sandbox_on_exec() {
    up sandboxed || return 1
    said=$(sh_in sandboxed 'grep -E "^(NoNewPrivs|Seccomp|Cap(Inh|Prm|Eff|Bnd|Amb)):" /proc/self/status')
    printf '%s\n' "$said"
    value() { printf '%s\n' "$said" | awk -v k="$1:" '$1 == k { print $2 }'; }
    [ "$(value Seccomp)" = 2 ] && [ "$(value NoNewPrivs)" = 1 ] && [ "$(value CapBnd)" = "$ALLOWED_CAPS" ] &&
    [ "$(value CapEff)" = "$ALLOWED_CAPS" ] && [ "$(value CapPrm)" = "$ALLOWED_CAPS" ] &&
    [ "$(value CapInh)" = 0000000000000000 ] && [ "$(value CapAmb)" = 0000000000000000 ]
}

t_init_holds_only_allowed_capabilities() {
    up initcaps || return 1
    pid=$(pid_of initcaps)
    echo "init holds CapEff $(status_field "$pid" CapEff), CapPrm $(status_field "$pid" CapPrm), CapInh $(status_field "$pid" CapInh), CapAmb $(status_field "$pid" CapAmb); allowed is $ALLOWED_CAPS"
    [ "$(status_field "$pid" CapEff)" = "$ALLOWED_CAPS" ] && [ "$(status_field "$pid" CapPrm)" = "$ALLOWED_CAPS" ] &&
    [ "$(status_field "$pid" CapInh)" = 0000000000000000 ] && [ "$(status_field "$pid" CapAmb)" = 0000000000000000 ]
}

t_privileged_is_not_sandboxed() {
    up priv --privileged || return 1
    pid=$(pid_of priv)
    sleep 0.3      # nothing marks the end of a privileged init's setup; it has none left to do
    grep -E '^(NoNewPrivs|Seccomp|CapBnd):' "/proc/$pid/status"
    # as unconfined as this shell is
    [ "$(status_field "$pid" Seccomp)" = "$(status_field $$ Seccomp)" ] &&
    [ "$(status_field "$pid" NoNewPrivs)" = "$(status_field $$ NoNewPrivs)" ] &&
    [ "$(status_field "$pid" CapBnd)" = "$(status_field $$ CapBnd)" ] || return 1
    # and it sees /proc and /sys as they are
    script_in priv <<'EOF'
for p in /proc/kcore /proc/interrupts /proc/sys /sys/firmware; do
    [ -e "$p" ] || continue
    if awk -v m="$p" '$5 == m { found = 1 } END { exit !found }' /proc/self/mountinfo; then
        echo "$p is covered in a privileged container"
        exit 1
    fi
done
EOF
}

t_proc_is_masked() {
    up masked || return 1
    script_in masked <<'EOF'
bad=0
for f in kcore sysrq-trigger timer_list keys sched_debug; do
    [ -e "/proc/$f" ] || continue
    [ -c "/proc/$f" ] || { echo "/proc/$f is not masked"; bad=1; }
done
for d in bus fs irq sys; do
    [ -d "/proc/$d" ] || continue
    awk -v m="/proc/$d" '$5 == m { found = 1; if ($6 !~ /(^|,)ro(,|$)/) open = 1 } END { exit !found || open }' /proc/self/mountinfo ||
        { echo "/proc/$d is not a read-only mount"; bad=1; }
done
exit $bad
EOF
}

t_docker_masks() {
    up dmasked || return 1
    script_in dmasked <<'EOF'
bad=0 seen=""
for p in /proc/acpi /proc/asound /proc/interrupts /proc/latency_stats /proc/timer_stats /proc/scsi \
         /sys/firmware /sys/devices/virtual/powercap; do
    [ -e "$p" ] || continue
    seen="$seen $p"
    awk -v m="$p" '$5 == m { found = 1 } END { exit !found }' /proc/self/mountinfo ||
        { echo "$p is not masked"; bad=1; continue; }
    if [ -d "$p" ]; then
        [ -z "$(ls -A "$p")" ] || { echo "$p is not empty"; bad=1; }
    else
        [ -z "$(head -c 1 "$p" 2>/dev/null)" ] || { echo "$p can be read"; bad=1; }
    fi
done
echo "masked here:$seen"
exit $bad
EOF
}

t_storage_closed_to_others() {
    command -v setpriv >/dev/null 2>&1 || { echo "no setpriv to become another user with"; return 77; }
    as_nobody() { setpriv --reuid 65534 --regid 65534 --clear-groups "$@"; }
    as_nobody true || { echo "cannot become an unprivileged user here"; return 77; }
    as_nobody ls "$T" >/dev/null || { echo "the work directory itself is closed to others; nothing to observe"; return 77; }
    up closed || return 1
    refused as_nobody ls "$C" && refused as_nobody cat "$C/closed/.conf" &&
    refused as_nobody cat "$C/closed/rootfs/etc/passwd"
}

# ─── Cases: the network ─────────────────────────────────────────────────────

t_network_inside() {
    up net || return 1
    said=$(sh_in net 'ip addr; ip route')
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -q 'inet 127\.0\.0\.1/8' &&
    printf '%s\n' "$said" | grep -q "inet $(addr_of net)/24" &&
    printf '%s\n' "$said" | grep -q "^default via $GW "
}

t_reaches_gateway() {
    need_nc || return 77
    up togw || return 1
    reaches togw "$GW"
}

# The outside namespace has no route back to the containers' subnet, so an
# answer from it shows forwarding and address translation both working.
t_reaches_outside() {
    need_nc || return 77
    up tonat || return 1
    reaches tonat "$OUTSIDE"
}

t_isolated_when_filtered() {
    need_nc || return 77
    brnf 1 || { echo "br_netfilter is not loaded, so bridged traffic cannot be filtered here"; return 77; }
    up iso1 && up iso2 || return 1
    reaches iso1 "$(addr_of iso2)" && { echo "iso1 reached iso2"; return 1; }
    reaches iso2 "$(addr_of iso1)" && { echo "iso2 reached iso1"; return 1; }
    reaches iso1 "$GW"      # it is the firewall that stops them, not a network that does not work
}

# A host without br_netfilter: bridged traffic does not pass through iptables.
# Containers without links are kept apart at the bridge itself.
t_isolated_when_not_filtered() {
    need_nc || return 77
    if [ -e "$BRNF" ]; then brnf 0 || return 1; fi
    up iso3 && up iso4 || return 1
    reaches iso3 "$(addr_of iso4)" && { echo "iso3 reached iso4"; return 1; }
    reaches iso4 "$(addr_of iso3)" && { echo "iso4 reached iso3"; return 1; }
    reaches iso3 "$GW"      # and the bridge address is still within reach
}

# A container with links shares the bridge with the others, and only the
# firewall keeps it to its links. Where the firewall does not see bridged
# traffic, such a container is not started, and is told why.
t_link_needs_filtering() {
    if [ -e "$BRNF" ]; then brnf 0 || return 1; fi
    box linkpeer && box wantslink --link linkpeer || return 1
    if said=$(start wantslink); then
        printf '%s\n' "$said"
        echo "a container with a link started where nothing filters bridged traffic"
        return 1
    fi
    printf '%s\n' "$said"
    case $said in *br_netfilter*) ;; *) echo "the refusal does not name br_netfilter"; return 1 ;; esac
    nothing_left wantslink && [ "$(state_of wantslink)" = stopped ]
}

t_linked_containers() {
    need_nc || return 77
    brnf 1 || { echo "br_netfilter is not loaded, and a container with a link does not start without it"; return 77; }
    box peer && box linked --link peer || return 1
    start peer && start linked || return 1
    reaches linked "$(addr_of peer)" && reaches peer "$(addr_of linked)" || return 1
    up third || return 1
    reaches third "$(addr_of peer)" && { echo "a container without the link reached peer"; return 1; }
    return 0
}

t_link_to_later_container() {
    need_nc || return 77
    brnf 1 || { echo "br_netfilter is not loaded, so nothing is filtered and a link changes nothing"; return 77; }
    box early --link late || return 1
    start early || return 1
    up late || return 1
    reaches early "$(addr_of late)"
}

t_rm_leaves_no_rule() {
    brnf 1 || { echo "br_netfilter is not loaded, and a container with a link does not start without it"; return 77; }
    box lpeer && box lmain --link lpeer || return 1
    start lpeer && start lmain || return 1
    ip=$(addr_of lmain)
    pid=$(pid_of lmain)
    iptables -S FORWARD | grep -qF -- "$ip/32" || { echo "the link added no rule to begin with"; return 77; }
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || return 1
    lb rm lmain || return 1
    left=$(iptables -S FORWARD | grep -cF -- "$ip/32")
    echo "FORWARD rules that still name $ip after rm: $left"
    [ "$left" -eq 0 ]
}

t_start_spares_foreign_interface() {
    box clobber || return 1
    ip link add vb-clobber type veth peer name lbt-foreign || return 1
    start clobber       # it may refuse, or use another name
    no_link lbt-foreign && { echo "start deleted an interface it had not created"; return 1; }
    return 0
}

t_interface_is_eth0() {
    up ifname || return 1
    said=$(sh_in ifname 'cat /proc/net/dev')
    printf '%s\n' "$said" | sed '1,2d' | awk -F: '{ gsub(/ /, "", $1); printf "%s ", $1 } END { print "" }'
    printf '%s\n' "$said" | grep -q '^ *eth0:'
}

t_no_ipv6_in_container() {
    [ -e /proc/net/if_inet6 ] || { echo "this kernel runs without IPv6"; return 77; }
    up six || return 1
    said=$(sh_in six 'cat /proc/net/if_inet6 2>/dev/null')
    printf 'IPv6 addresses in the container:\n%s\n' "${said:-none}"
    [ -z "$said" ]
}

# ─── Fixture ────────────────────────────────────────────────────────────────

add_account() { # file key line
    grep -q "^$2:" "$1" 2>/dev/null || printf '%s\n' "$3" >> "$1"
}

build_rootfs() {
    mkdir -p "$BASE"
    if [ -n "${LIGHTBOX_TEST_ROOTFS:-}" ]; then
        cp -a "$LIGHTBOX_TEST_ROOTFS/." "$BASE/" || return 1
    else
        mkdir -p "$BASE/bin" "$BASE/etc" "$BASE/root" "$BASE/dev" "$BASE/proc" "$BASE/sys" \
                 "$BASE/tmp" "$BASE/run" "$BASE/var"
        cp "$BB" "$BASE/bin/busybox" && chmod 755 "$BASE/bin/busybox" || return 1
        for applet in $("$BB" --list); do
            [ "$applet" = busybox ] || ln -sf busybox "$BASE/bin/$applet"
        done
    fi
    mkdir -p "$BASE/etc" "$BASE/home/lbuser"
    add_account "$BASE/etc/passwd" root    'root:x:0:0:root:/root:/bin/sh'
    add_account "$BASE/etc/passwd" lbuser  'lbuser:x:4711:4711:lightbox test:/home/lbuser:/bin/sh'
    add_account "$BASE/etc/group"  root    'root:x:0:'
    add_account "$BASE/etc/group"  lbuser  'lbuser:x:4711:'
    add_account "$BASE/etc/group"  lbgroup 'lbgroup:x:4712:lbuser'
    chown 4711:4711 "$BASE/home/lbuser"

    if ! chroot "$BASE" /bin/sh -c 'exit 0'; then
        echo "lifecycle: /bin/sh of the test root filesystem does not run." >&2
        echo "  It must be statically linked or come with its libraries, and ${TMPDIR:-/tmp} must not be mounted noexec." >&2
        return 1
    fi
    if chroot "$BASE" /bin/sh -c 'command -v nc' >/dev/null 2>&1; then : > "$T/have_nc"; fi
}

network() {
    ip link set lo up || return 1
    # A second namespace stands for the internet: setup wants a default route,
    # and address translation needs somewhere to go.
    unshare --net -- sleep 86400 >/dev/null 2>&1 </dev/null &
    local outside=$!
    different_net() { [ "$(readlink "/proc/$outside/ns/net" 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ] &&
                      [ -n "$(readlink "/proc/$outside/ns/net" 2>/dev/null)" ]; }
    wait_until 5 different_net || return 1
    ip link add "$WAN" type veth peer name lbt-out &&
    ip link set lbt-out netns "$outside" &&
    ip addr add 192.0.2.2/24 dev "$WAN" &&
    ip link set "$WAN" up &&
    nsenter -t "$outside" -n ip link set lo up &&
    nsenter -t "$outside" -n ip addr add "$OUTSIDE/24" dev lbt-out &&
    nsenter -t "$outside" -n ip link set lbt-out up &&
    ip route add default via "$OUTSIDE" dev "$WAN"
}

fixture() {
    mkdir -p "$HOME/.config/lightbox" "$C" "$OUT" "$T/vol" "$T/real" "$T/shim" "$T/run" || return 1
    chmod 755 "$T/lb" "$C"          # as installations before 0.2 left them; setup tightens them
    cat > "$HOME/.config/lightbox/lightbox.conf" <<EOF
lightbox_dir = $T/lb
rootfs = $BASE
container_dir = $C
run_dir = $T/run
cgroup_root = /sys/fs/cgroup
cgroup_base = $CG
bridge = $BR
subnet = $SUBNET
gw = $GW
EOF
    echo 1 > "$T/next_ip"
    : > "$T/shims"
    : > "$T/background"
    build_rootfs && network
}

kill_cgroup() { # directory
    [ -d "$1" ] || return 0
    if [ -e "$1/cgroup.kill" ]; then
        echo 1 > "$1/cgroup.kill"
    else
        local p
        for p in $(cat "$1/cgroup.procs"); do kill -KILL "$p"; done
    fi 2>/dev/null
    local i=0
    until rmdir "$1" 2>/dev/null; do
        [ $i -lt 50 ] || return 1
        sleep 0.1
        i=$((i + 1))
    done
}

# After every case, whatever it did: no container, no interface of one, the
# firewall as setup made it, no stand-in for a host tool.
teardown() {
    local p d
    while read -r p; do [ -n "$p" ] && umount -l "$p"; done < "$T/shims"
    : > "$T/shims"
    # a start a case left in the background; the number may belong to something else by now
    while read -r p; do
        [ -n "$p" ] && [ "$(readlink "/proc/$p/exe")" = "$LB" ] && kill -KILL "$p"
    done < "$T/background"
    : > "$T/background"
    for d in "$CG"/*/; do
        [ -d "$d" ] && kill_cgroup "${d%/}"
    done
    for p in $(ip -o link show | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }' | grep -E '^(vb-|ve-|lbt-foreign$)'); do
        ip link delete "$p"
    done
    [ -s "$T/firewall" ] && iptables-restore < "$T/firewall"
    [ -w "$BRNF" ] && echo 1 > "$BRNF"
    find "$C" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    rm -f "$T/nsenter.reached" "$T/mount.ran"
} 2>/dev/null

# ─── Stage: one case ────────────────────────────────────────────────────────

if [ "$MODE" = case ]; then
    settings
    declare -F "$1" >/dev/null || { echo "lifecycle: no such case: $1" >&2; exit 2; }
    "$@"
    exit $?
fi

# ─── Stage: inside the private namespaces ───────────────────────────────────

if [ "$MODE" = inside ]; then
    settings
    # this shell is PID 1 of its namespace, which gets only the signals it handles
    trap 'exit 130' INT TERM

    fixture || { echo "lifecycle: the fixture could not be built" >&2; exit 2; }

    if [ -e "$BRNF" ]; then filtering="br_netfilter is loaded"; else filtering="br_netfilter is not loaded"; fi
    echo "lifecycle: $(uname -sr) on $(uname -m); $(iptables --version 2>&1 | head -n 1); $filtering"
    if [ -n "$BB" ]; then
        echo "lifecycle: root filesystem from $BB ($("$BB" 2>&1 | head -n 1))"
    else
        echo "lifecycle: root filesystem copied from $LIGHTBOX_TEST_ROOTFS"
    fi
    echo

    if [ -n "${LIFECYCLE_PROGRAM:-}" ]; then
        . "$LIFECYCLE_PROGRAM"
        exit $?
    fi

    CASE_TIMEOUT=${CASE_TIMEOUT:-90}
    SHOW_LINES=60
    SHOW_FILTER="s#$T#<T>#g"
    . "$HERE/lib.sh"

    run_case() { # function -> sets rc and out
        n=$((n + 1))
        timeout -k 5 "$CASE_TIMEOUT" bash "$SELF" --case "$1" >"$T/case.out" 2>&1 </dev/null
        rc=$?
        out=$(cat "$T/case.out")
        if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then
            out="$out
(the case was stopped: it had not finished after $CASE_TIMEOUT seconds)"
            rc=1
        fi
        teardown
    }

    check 'setup makes the bridge, the forwarding and the firewall rules, and closes storage' t_setup
    if [ "$failed" -ne 0 ]; then
        echo
        echo "lifecycle: setup failed, and every other case needs it"
        summary lifecycle
        exit 1
    fi
    iptables-save > "$T/firewall"

    check 'setup again changes no mount and adds no rule'                 t_setup_again
    check 'setup refuses a cgroup_root that is not cgroup v2'             t_setup_refuses_other_cgroup_root
    check 'doctor finds nothing missing'                                  t_doctor

    check 'create, start, exec, stop and rm'                              t_lifecycle
    check 'ls and inspect show a running container'                       t_queries_show_running
    check 'exec returns the exit status of the command'                   t_exec_status
    check 'exec without a command runs a shell on standard input'         t_exec_default_shell
    check 'a container has its own hostname, processes and root'          t_own_world
    check 'a running container cannot be started again or removed'        t_running_container_is_protected
    check 'a stopped container starts again and keeps its files'          t_restart_keeps_files
    check 'a container whose init died starts again'                      t_start_after_init_died
    check 'a start that fails leaves no interface, cgroup or runtime file' t_failed_start_leaves_nothing

    check 'exec --user takes a name or a number and sets groups and HOME' t_exec_user
    check 'exec keeps none of the caller'"'"'s groups, with --user or without' t_exec_unknown_uid_drops_groups
    check 'exec --user refuses a malformed value, and names a missing one' t_exec_user_is_strict
    check 'exec finds an account late in the container'"'"'s passwd'           t_exec_finds_a_late_account
    check 'exec finds a command on PATH'                                  t_exec_searches_path
    check 'exec passes every argument'                                    t_exec_passes_every_argument
    check 'exec sets --env and --workdir, and passes TERM and nothing else' t_exec_environment
    check 'exec runs from a sealed copy of the binary'                    t_exec_runs_from_a_sealed_copy

    check 'a directory volume is shared in both directions'               t_volume_directory
    check 'a file volume is mounted'                                      t_volume_file
    check 'a read-only volume cannot be written'                          t_volume_read_only
    check 'add-vol takes effect at the next start'                        t_addvol_applies_at_next_start
    check 'a volume under /run is visible'                                t_volume_under_run
    check 'volumes under /tmp and /run, and with a read-only root'        t_volume_under_tmp
    check 'a volume'"'"'s destination is looked up inside the container'      t_volume_destination_is_inside
    check '--read-only closes the root and leaves /tmp, /run and /var/tmp writable' t_read_only_root
    check '/run is mode 0755'                                             t_run_mode
    check 'init mounts everything with the restrictions it should have'   t_mount_table
    check 'a container starts and stops without any mount tool'           t_start_needs_no_mount_tool
    check 'the root filesystem is mounted nodev and nosuid'               t_rootfs_mount_flags
    check 'an image without /dev, /proc, /sys, /tmp and /run starts'      t_image_without_mount_points
    check 'an image of one static binary starts'                          t_image_with_one_binary
    check 'start runs nothing from the image'                             t_start_runs_nothing_from_the_image

    check 'limits reach the cgroup and the oom score reaches init'        t_limits
    check 'init and commands run by exec are in the container cgroup'     t_cgroup_membership

    check 'the init hook runs with /tmp and /run mounted'                 t_hook_runs
    check 'a service the hook starts outlives the start command'          t_service_outlives_start
    check 'the init hook runs inside the sandbox'                         t_hook_is_sandboxed
    check 'in a privileged container the hook is not sandboxed'           t_privileged_hook_is_not_sandboxed
    check 'start returns when the hook has ended'                         t_start_waits_for_the_hook
    check 'a hook that fails later fails the start, with its exit status' t_failing_hook_fails_start
    check 'start -t stops waiting for a slow hook, and says so'           t_start_stops_waiting
    check 'start does not wait a fixed time'                              t_start_does_not_wait_a_fixed_time
    check 'init answers SIGTERM while its hook runs'                      t_stop_during_hook
    check 'a start that is interrupted undoes itself'                     t_interrupted_start_is_undone
    check 'a start that is killed leaves no init behind'                  t_killed_start_leaves_no_container
    check 'a start killed while the hook runs leaves a container stop finds' t_killed_start_leaves_a_container
    check 'a leftover .pid_start does not fail the next start'            t_stale_pid_start
    check 'said=$(lightbox start x) returns'                              t_start_returns_to_a_capture
    check 'lightbox start x | cat returns'                                t_start_returns_to_a_pipe
    check 'init leads a session and a process group of its own'           t_init_has_its_own_session
    check 'SIGINT to the starter'"'"'s process group spares the container'    t_sigint_spares_the_container
    check 'the container'"'"'s output is in its log, which logs shows and follows' t_logs
    check 'init keeps nothing that was open in the command'               t_init_keeps_nothing_of_the_command
    check 'stop lets a service handle SIGTERM, and waits for it'          t_stop_is_graceful
    check 'stop -t kills a service that will not end, when the time is over' t_stop_kills_after_the_limit
    check 'stop of an idle container does not wait a fixed time'          t_stop_of_an_idle_container_is_quick
    check 'stop ends a command that exec runs in the container'           t_stop_ends_an_exec

    check 'init has the seccomp filter, no_new_privs and the bounding set' t_sandbox_on_init
    check 'a command run by exec has them too, and only the allowed capabilities' t_sandbox_on_exec
    check 'init holds only the allowed capabilities and passes none on'   t_init_holds_only_allowed_capabilities
    check 'a privileged container is not sandboxed and sees /proc as it is' t_privileged_is_not_sandboxed
    check '/proc is masked and its system trees are read-only'            t_proc_is_masked
    check 'the paths Docker masks are masked and show nothing'            t_docker_masks
    check 'another user cannot reach container files'                     t_storage_closed_to_others

    check 'a container has loopback, its address and a default route'     t_network_inside
    check 'a container reaches the bridge address'                        t_reaches_gateway
    check 'a container reaches an outside address through address translation' t_reaches_outside
    check 'containers cannot reach each other when bridged traffic is filtered' t_isolated_when_filtered
    check 'containers cannot reach each other without br_netfilter'      t_isolated_when_not_filtered
    check 'a container with a link is refused where nothing filters bridged traffic' t_link_needs_filtering
    check 'linked containers reach each other, and a third reaches neither' t_linked_containers
    xfail NET-link-leak        'a link to a container created later applies'           t_link_to_later_container
    xfail NET-link-leak        'rm of a dead container leaves no firewall rule'        t_rm_leaves_no_rule
    xfail NET-veth-clobber     'start leaves alone an interface it did not create'     t_start_spares_foreign_interface
    xfail NET-ifname           'the interface in the container is eth0'                t_interface_is_eth0
    check 'a container has no IPv6 address'                               t_no_ipv6_in_container

    # last: it may leave a kernel setting changed for the rest of this suite's life
    check 'exec works where a memfd may not be executed'                  t_exec_where_memfds_may_not_be_executed

    summary lifecycle
    exit $?
fi

# ─── Stage: on the host ─────────────────────────────────────────────────────

stop_early() {
    echo "lifecycle: $1" >&2
    exit 2
}

# A busybox that runs with nothing else in the filesystem.
static_busybox() { # path
    local dir ok=1
    dir=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-busybox.XXXXXX") || return 1
    cp "$1" "$dir/busybox" && chroot "$dir" /busybox true 2>/dev/null && ok=0
    rm -rf -- "$dir"
    return $ok
}

find_busybox() {
    local name path
    if [ -n "${BUSYBOX:-}" ]; then
        static_busybox "$BUSYBOX" && { echo "$BUSYBOX"; return 0; }
        return 1
    fi
    for name in busybox.static busybox-static busybox; do
        path=$(type -P "$name" 2>/dev/null) || continue
        static_busybox "$path" && { echo "$path"; return 0; }
    done
    return 1
}

preflight() {
    local tool missing=""
    for tool in unshare nsenter ip iptables iptables-save iptables-restore mount umount mkdir cp rm \
                chroot timeout setsid findmnt awk sed stat find; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    [ -z "$missing" ] || stop_early "these tools are missing:$missing"

    [ "$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ] ||
        stop_early "/sys/fs/cgroup is not a cgroup v2 hierarchy"
    for tool in memory pids cpu io; do
        grep -qw "$tool" /sys/fs/cgroup/cgroup.controllers ||
            stop_early "the cgroup controller '$tool' is not available at /sys/fs/cgroup"
    done

    unshare --net -- sh -c 'ip link add lbt-p0 type bridge && ip link add lbt-p1 type veth peer name lbt-p2' 2>/dev/null ||
        stop_early "this kernel cannot make bridge and veth interfaces"

    if [ -n "${LIGHTBOX_TEST_ROOTFS:-}" ]; then
        [ -e "$LIGHTBOX_TEST_ROOTFS/bin/sh" ] || [ -L "$LIGHTBOX_TEST_ROOTFS/bin/sh" ] ||
            stop_early "LIGHTBOX_TEST_ROOTFS=$LIGHTBOX_TEST_ROOTFS has no /bin/sh"
        LIFECYCLE_BB=
    else
        LIFECYCLE_BB=$(find_busybox) || stop_early "no statically linked busybox was found${BUSYBOX:+ at $BUSYBOX}.
  Install busybox-static, or give one with BUSYBOX=/path, or a root filesystem with LIGHTBOX_TEST_ROOTFS=/path.
  (${TMPDIR:-/tmp} must not be mounted noexec either.)"
    fi

    if [ "${LIGHTBOX_TEST_MODPROBE:-0}" = 1 ] && [ ! -e "$BRNF" ]; then
        modprobe br_netfilter 2>/dev/null ||
            echo "lifecycle: br_netfilter could not be loaded; the cases that need it will be skipped"
    fi
}

# The host's interfaces of one kind: virtual or hardware. What lightbox and the
# suite can make is virtual, a bridge and veth pairs, and that must not be left
# behind. A network card is the machine's: a cloud VM is given one, or loses
# one, whenever its own host decides, and one arrived during a run on GitHub.
interfaces() { # kind
    local path name kind
    for path in /sys/class/net/*; do
        [ -d "$path" ] || continue
        name=${path##*/}
        kind=hardware
        [ -e "/sys/devices/virtual/net/$name" ] && kind=virtual
        [ "$kind" = "$1" ] && printf '%s ' "$name"
    done
    echo
}

# Network cards that came or went are reported and do not count.
cards_note() { # before, after
    [ "$1" = "$2" ] && return 0
    echo "lifecycle: the machine's network cards changed during the run, which is not the suite's doing: '${1% }' before, '${2% }' after"
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::notice title=lifecycle%3A the machine's network cards changed::Before the run '${1% }', after it '${2% }'. Not counted as a change the suite made."
    fi
}

# What the suite must leave as it found it.
host_state() {
    echo "virtual interfaces: $(interfaces virtual)"
    echo "forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "bridged traffic through iptables: $(cat "$BRNF" 2>/dev/null || echo 'br_netfilter not loaded')"
    echo "lightbox cgroups: $(find /sys/fs/cgroup -maxdepth 1 -name 'lightbox*' | sort | tr '\n' ' ')"
    echo "controllers enabled at the cgroup root: $(cat /sys/fs/cgroup/cgroup.subtree_control)"
    echo "mounts under the work directory: $(grep -c " $LIFECYCLE_T" /proc/self/mountinfo)"
    echo "firewall:"
    iptables-save 2>/dev/null | grep -v '^#' | sed -e 's/ *\[[0-9]*:[0-9]*\]//' -e 's/^/  /'
}

# The suite's own cgroups. Its processes died with the PID namespace.
remove_cgroups() {
    local i=0
    while [ -d "$CG" ] && [ $i -lt 30 ]; do
        find "$CG" -depth -type d -exec rmdir {} \; 2>/dev/null
        [ -d "$CG" ] || break
        sleep 0.1
        i=$((i + 1))
    done
}

# lightbox enables controllers at the cgroup root and leaves them enabled
# (RT-cgroup-controllers). Switch off the ones that were off before.
restore_controllers() {
    local c
    for c in $(cat /sys/fs/cgroup/cgroup.subtree_control); do
        case " $CONTROLLERS_BEFORE " in
            *" $c "*) ;;
            *) if echo "-$c" 2>/dev/null > /sys/fs/cgroup/cgroup.subtree_control; then
                   echo "lifecycle: switched the cgroup controller '$c' off again at the root; lightbox had enabled it"
               fi ;;
        esac
    done
}

remove_work_dir() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "lifecycle: work directory kept at $LIFECYCLE_T"
    else
        rm -rf -- "$LIFECYCLE_T"
    fi
}

interrupted() { remove_cgroups; restore_controllers; remove_work_dir; }

LIFECYCLE_LB=${1:-./lightbox}
[ -x "$LIFECYCLE_LB" ] || stop_early "$LIFECYCLE_LB is not an executable; run make first"
LIFECYCLE_LB=$(cd "$(dirname "$LIFECYCLE_LB")" && pwd)/$(basename "$LIFECYCLE_LB")
[ "$(id -u)" -eq 0 ] || stop_early "this starts containers and needs root: run it with sudo, as in sudo make test-lifecycle"

preflight

LIFECYCLE_T=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-lifecycle.XXXXXX") || exit 2
chmod 755 "$LIFECYCLE_T"        # open to others, so that the suite can see lightbox close what is inside
CG=/sys/fs/cgroup/lightbox-test-$$
echo "$CG" > "$LIFECYCLE_T/cgroup_base"
CONTROLLERS_BEFORE=$(cat /sys/fs/cgroup/cgroup.subtree_control)
export LIFECYCLE_LB LIFECYCLE_T LIFECYCLE_BB
trap interrupted EXIT

host_state > "$LIFECYCLE_T/host.before"
CARDS_BEFORE=$(interfaces hardware)

unshare --net --mount --pid --fork --kill-child --mount-proc -- bash "$SELF" --inside
rc=$?

# cgroups and controllers first, so that the comparison sees the host as the suite leaves it
trap remove_work_dir EXIT
remove_cgroups
restore_controllers
host_state > "$LIFECYCLE_T/host.after"
cards_note "$CARDS_BEFORE" "$(interfaces hardware)"

if cmp -s "$LIFECYCLE_T/host.before" "$LIFECYCLE_T/host.after"; then
    echo "lifecycle: the host's virtual interfaces, firewall rules, cgroups and mounts are as they were"
else
    echo "lifecycle: THE HOST CHANGED (-: before, +: after)"
    diff -u "$LIFECYCLE_T/host.before" "$LIFECYCLE_T/host.after" | sed '1,2d'
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::error title=lifecycle%3A the host changed::The suite left something on the host; the log has the difference."
    fi
    rc=1
fi
exit $rc
