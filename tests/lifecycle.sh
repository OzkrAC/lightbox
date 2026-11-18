#!/usr/bin/env bash
#
# Root lifecycle suite (ROADMAP 0.6): the one suite that starts containers.
#
#   sudo make test-lifecycle
#   sudo tests/lifecycle.sh [path/to/lightbox]          default: ./lightbox
#
# Needs root, a kernel with bridge, veth and cgroup v2, the host tools lightbox
# needs (iptables, coreutils), those the suite looks with (iproute2,
# util-linux) and a statically linked busybox to build the containers' root
# filesystem from. lightbox runs neither ip nor nsenter: every case runs with
# both masked, and the last but one looks that nothing ran them.
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
#   LIGHTBOX_TEST_USERNS=overlay
#                               make every container with --userns: every case is
#                               then one of a container whose root is an
#                               unprivileged uid of the host's (ROADMAP 8.1)
#   LIGHTBOX_TEST_USERNS=copy   the same, and with --copy but in the cases about
#                               overlays
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
WIDE_BR=lbt16               # the bridge of the case with a /16
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
    USERNS_MODE=${LIGHTBOX_TEST_USERNS:-}
    RUN="$T/run"                # run_dir: the records of a container that runs are in $RUN/<name>/
    BASE="$T/base"
    OUT="$T/out"
    CG=$(cat "$T/cgroup_base")
    export HOME="$T/home"
    # named, so that neither /etc/lightbox nor $HOME is looked at
    export LIGHTBOX_CONFIG="$HOME/.config/lightbox/lightbox.conf"
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
# the interfaces of this network namespace, by name
links_now() { ip -o link show | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }' | sort; }

pid_of()   { cat "$RUN/$1/pid"; }
# what is on record; a container without a record of its state is stopped
state_of() { if [ -e "$RUN/$1/state" ]; then cat "$RUN/$1/state"; else echo stopped; fi; }
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
    # shellcheck disable=SC2046  # options of one word each
    lb create "$name" "$ip" "$@" $(mode_options "$@") >"$OUT/$name.create" 2>&1 || { cat "$OUT/$name.create"; return 1; }
    port_of "$name" >/dev/null
}

# What LIGHTBOX_TEST_USERNS adds to a create: --userns, and with copy --copy
# too, where the case did not give them. A case about overlays sets OVERLAY=1,
# which keeps --copy out; a container that is to have no range is made with
# PLAIN=1 box ..., which adds nothing.
mode_options() { # the options the case gives
    local given=" $* "
    [ -n "$USERNS_MODE" ] && [ -z "${PLAIN:-}" ] || return 0
    case $given in *' --userns '*) ;; *) echo --userns ;; esac
    if [ "$USERNS_MODE" = copy ] && [ -z "${OVERLAY:-}" ]; then
        case $given in *' --copy '*) ;; *) echo --copy ;; esac
    fi
}

conf_value() { sed -n "s/^$2=//p" "$C/$1/.conf"; }  # name key

# What the suite puts in a container's rootfs/ from the host, made its root's,
# as if the container had made it. In the upper layer of an overlay with
# --userns that is the first uid and gid of its range. A --copy with --userns
# is idmapped as it is, and there host root's files are its root's already.
made_for() { # name path...
    local name=$1
    shift
    [ "$(conf_value "$name" userns)" = 1 ] && [ -n "$(conf_value "$name" base)" ] || return 0
    chown -hR "$(conf_value "$name" uid_start):$(conf_value "$name" gid_start)" "$@"
}

# A volume that a container writes in, made its root's on the host. With
# --userns that is the first uid and gid of its range: host root's files are
# not its root's.
volume_for() { # name path...
    local name=$1
    shift
    [ "$(conf_value "$name" userns)" = 1 ] || return 0
    chown -R "$(conf_value "$name" uid_start):$(conf_value "$name" gid_start)" "$@"
}

# The end of a container's interface on the host, as inspect names it: kept,
# so that it can be asked for after the container is removed.
port_of() { # name
    [ -s "$T/port.$1" ] || lb inspect "$1" 2>/dev/null | sed -n 's/^host_interface: //p' > "$T/port.$1"
    cat "$T/port.$1"
}
# The chain of a container's links: LB- and the same digits as its port.
chain_of() { # name
    local port
    port=$(port_of "$1") && [ -n "$port" ] && echo "LB-${port#vb-}"
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
    if [ -e "$RUN/$1/pid" ] || [ -e "$RUN/$1/pid_start" ] || [ -e "$RUN/$1/exit" ]; then
        echo "runtime records are left: $(ls -A "$RUN/$1" | tr '\n' ' ')"; bad=1
    fi
    local port
    port=$(port_of "$1")
    if [ -z "$port" ]; then
        echo "what the interface of $1 is called on the host cannot be told"; bad=1
    elif ! no_link "$port"; then
        echo "the interface $port is left"; bad=1
    fi
    [ ! -d "$CG/$1" ] || { echo "the cgroup $CG/$1 is left"; bad=1; }
    if [ -n "$port" ] && { [ -e "$RUN/$1/firewall" ] || iptables -n -L "LB-${port#vb-}" >/dev/null 2>&1; }; then
        echo "the firewall chain LB-${port#vb-} of its links, or the record of it, is left"; bad=1
    fi
    if [ -n "$port" ] && nft list set bridge lightbox links 2>/dev/null | grep -q "\"$port\""; then
        echo "an element of the nftables set of links names $port"; bad=1
    fi
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

# setup makes lightbox's chains and jumps to them from the top of FORWARD and
# POSTROUTING. Forwarding was off (the fixture turned it off), so, as Docker
# does, setup turns it on with the FORWARD policy at DROP: from then on every
# case runs with a host firewall that drops what lightbox does not accept.
t_setup() {
    lb setup >"$OUT/setup" 2>&1 || { cat "$OUT/setup"; return 1; }
    cat "$OUT/setup"
    ip -o -4 addr show dev "$BR" | grep -q " $GW/24 " || { echo "the bridge has no address:"; ip addr show dev "$BR"; return 1; }
    ip link show dev "$BR" | head -n 1 | grep -q '[<,]UP[,>]' || { echo "the bridge is not up"; return 1; }
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "forwarding is off"; return 1; }
    iptables -S FORWARD
    [ "$(iptables -S FORWARD | head -n 1)" = '-P FORWARD DROP' ] || { echo "the FORWARD policy is not DROP"; return 1; }
    [ "$(iptables -S FORWARD | sed -n '2,3p' | paste -sd'|' -)" = '-A FORWARD -j LIGHTBOX-USER|-A FORWARD -j LIGHTBOX-FORWARD' ] ||
        { echo "FORWARD does not begin with the jumps to LIGHTBOX-USER and LIGHTBOX-FORWARD"; return 1; }
    [ "$(iptables -t nat -S POSTROUTING | sed -n 2p)" = '-A POSTROUTING -j LIGHTBOX-POSTROUTING' ] ||
        { echo "POSTROUTING does not begin with the jump to LIGHTBOX-POSTROUTING"; iptables -t nat -S POSTROUTING; return 1; }
    iptables -S LIGHTBOX-FORWARD; iptables -t nat -S LIGHTBOX-POSTROUTING
    iptables -C LIGHTBOX-FORWARD -i "$BR" -o "$BR" -j LIGHTBOX-LINKS &&
    iptables -C LIGHTBOX-FORWARD -i "$BR" -o "$BR" -j DROP &&
    iptables -C LIGHTBOX-FORWARD -i "$BR" ! -o "$BR" -j ACCEPT &&
    iptables -C LIGHTBOX-FORWARD -o "$BR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &&
    iptables -t nat -C LIGHTBOX-POSTROUTING -s "$SUBNET" ! -o "$BR" -j MASQUERADE &&
    iptables -n -L LIGHTBOX-USER >/dev/null && iptables -n -L LIGHTBOX-LINKS >/dev/null ||
        { echo "a rule or a chain is missing:"; iptables-save; return 1; }
    # nothing names the interface the default route leaves by
    ! iptables-save | grep -qw -- "$WAN" || { echo "a rule names $WAN"; return 1; }
    # the fixture made these 0755, as installations before 0.2 did
    echo "storage modes after setup: $(stat -c %a "$T/lb") $(stat -c %a "$C"), and of run_dir: $(stat -c %a "$RUN")"
    [ "$(stat -c %a "$T/lb")" = 700 ] && [ "$(stat -c %a "$C")" = 700 ] && [ "$(stat -c %a "$RUN")" = 700 ]
}

firewall_rules() { iptables-save | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//'; }

# A lightbox.conf of the suite's with more settings, for a case: sets $ALT.
alt_conf() { # directory name, settings...
    ALT=$T/$1/home
    ALT_CONF=$ALT/.config/lightbox/lightbox.conf
    shift
    mkdir -p "$ALT/.config/lightbox" || return 1
    { cat "$HOME/.config/lightbox/lightbox.conf"; printf '%s\n' "$@"; } > "$ALT/.config/lightbox/lightbox.conf"
}
alt_lb() { LIGHTBOX_CONFIG="$ALT_CONF" timeout -k 5 60 "$LB" "$@"; }

# What lightbox 0.4 put straight into FORWARD and POSTROUTING, taken out by
# setup; a rule of the host's that looks like one stays.
t_setup_takes_out_old_rules() {
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE &&
    iptables -A FORWARD -i "$BR" -o "$WAN" -j ACCEPT &&
    iptables -A FORWARD -i "$WAN" -o "$BR" -m state --state RELATED,ESTABLISHED -j ACCEPT &&
    iptables -A FORWARD -i "$BR" -o "$BR" -j DROP &&
    iptables -A FORWARD -s "$NETP.40/32" -d "$NETP.41/32" -i "$BR" -o "$BR" -j ACCEPT &&
    iptables -A FORWARD -s 192.0.2.7/32 -d 192.0.2.8/32 -j ACCEPT || return 1
    said=$(lb setup 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    case $said in *'Removed 5 firewall rules'*) ;; *) echo "setup did not say that it removed five rules"; return 1 ;; esac
    old=$( { iptables -S FORWARD; iptables -t nat -S POSTROUTING; } | grep -E -- "$WAN|$NETP\.4[01]/32|-A FORWARD -i $BR -o $BR -j DROP")
    [ -z "$old" ] || { echo "left: $old"; return 1; }
    iptables -C FORWARD -s 192.0.2.7/32 -d 192.0.2.8/32 -j ACCEPT || { echo "the host's own rule was taken out"; return 1; }
    iptables -C FORWARD -j LIGHTBOX-FORWARD && iptables -C LIGHTBOX-FORWARD -i "$BR" ! -o "$BR" -j ACCEPT
}

# The host's own rules go in LIGHTBOX-USER, which decides before lightbox's
# rules, and setup leaves them there.
t_user_chain() {
    need_nc || return 77
    up user1 || return 1
    reaches user1 "$OUTSIDE" || return 1
    ip=$(addr_of user1)
    iptables -A LIGHTBOX-USER -s "$ip" -d "$OUTSIDE" -j DROP || return 1
    lb setup >/dev/null || return 1
    iptables -C LIGHTBOX-USER -s "$ip" -d "$OUTSIDE" -j DROP || { echo "setup took the host's rule out"; return 1; }
    reaches user1 "$OUTSIDE" && { echo "the host's rule in LIGHTBOX-USER did not decide"; return 1; }
    iptables -F LIGHTBOX-USER
    reaches user1 "$OUTSIDE"
}

# A host firewall that drops all that is forwarded after lightbox's jumps, as
# a DROP policy and a last rule of ufw's do: the bridge's traffic still passes.
t_host_firewall_drops_the_rest() {
    need_nc || return 77
    iptables -A FORWARD -j DROP || return 1
    up behind || return 1
    reaches behind "$OUTSIDE"
}

# ip_forward_no_drop = true: setup turns forwarding on and leaves the policy.
t_ip_forward_no_drop() {
    alt_conf nodrop 'ip_forward_no_drop = true' || return 1
    echo 0 > /proc/sys/net/ipv4/ip_forward && iptables -P FORWARD ACCEPT || return 1
    alt_lb setup >"$OUT/nodrop.setup" 2>&1 || { cat "$OUT/nodrop.setup"; return 1; }
    cat "$OUT/nodrop.setup"
    echo "forwarding $(cat /proc/sys/net/ipv4/ip_forward), $(iptables -S FORWARD | head -n 1)"
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] && [ "$(iptables -S FORWARD | head -n 1)" = '-P FORWARD ACCEPT' ]
}

# ip_masq = false: nothing is masqueraded, and a container gets no answer
# from the outside, which has no route back to it.
t_ip_masq_false() {
    need_nc || return 77
    alt_conf nomasq 'ip_masq = false' || return 1
    alt_lb setup >"$OUT/nomasq.setup" 2>&1 || { cat "$OUT/nomasq.setup"; return 1; }
    left=$(iptables -t nat -S LIGHTBOX-POSTROUTING | tail -n +2)
    [ -z "$left" ] || { echo "LIGHTBOX-POSTROUTING has: $left"; return 1; }
    up nomasq || return 1
    reaches nomasq "$OUTSIDE" && { echo "the outside answered a container that was not masqueraded"; return 1; }
    return 0
}

# firewall = false: setup makes no rule, and a container with links is not
# started, since only lightbox's rules keep it to them.
t_firewall_false() {
    alt_conf nofw 'firewall = false' || return 1
    rules=$(firewall_rules)
    said=$(alt_lb setup 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    [ "$rules" = "$(firewall_rules)" ] || { echo "setup with firewall = false changed the firewall:"; firewall_rules; return 1; }
    case $said in *'no firewall rules were made'*) ;; *) return 1 ;; esac
    box fwpeer && box fwlinked --link fwpeer || return 1
    said=$(alt_lb start fwlinked 2>&1 </dev/null) && { echo "a container with links started with firewall = false"; return 1; }
    printf '%s\n' "$said"
    case $said in *'firewall = false'*) ;; *) return 1 ;; esac
    nothing_left fwlinked
}

# setup reads subnet and gw as one network before it changes anything: a
# gateway outside the subnet ends it, with no bridge made and no rule added.
t_setup_refuses_a_gateway_outside() {
    mkdir -p "$T/gwout/home/.config/lightbox"
    sed -e 's#^bridge = .*#bridge = lbt9#' -e 's#^gw = .*#gw = 10.198.0.1#' "$HOME/.config/lightbox/lightbox.conf" \
        > "$T/gwout/home/.config/lightbox/lightbox.conf"
    rules=$(firewall_rules)
    said=$(LIGHTBOX_CONFIG="$T/gwout/home/.config/lightbox/lightbox.conf" timeout -k 5 60 "$LB" setup 2>&1) && { echo "setup succeeded"; return 1; }
    printf '%s\n' "$said"
    no_link lbt9 || { echo "a bridge was made before the refusal"; return 1; }
    [ "$rules" = "$(firewall_rules)" ] || { echo "the firewall rules changed:"; firewall_rules; return 1; }
    case $said in *'gw in lightbox.conf is not in the subnet'*) ;; *) return 1 ;; esac
}

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
    said=$(LIGHTBOX_CONFIG="$T/alt/home/.config/lightbox/lightbox.conf" timeout -k 5 60 "$LB" setup 2>&1) && { echo "setup succeeded"; return 1; }
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
    wait_until 5 no_link "$(port_of web)" || { echo "$(port_of web) is still there after stop"; return 1; }
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
    wait_until 5 no_link "$(port_of crash)" || { echo "$(port_of crash) did not go away"; return 1; }
    start crash || return 1
    [ "$(sh_in crash 'echo back')" = back ]
}

# stop is a command that changes a container, so it is where the record of a
# dead init gets cleaned up, as start is.
t_stop_of_a_dead_container_cleans_up() {
    up dead || return 1
    pid=$(pid_of dead)
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || { echo "init $pid survived SIGKILL"; return 1; }
    [ -d "$CG/dead" ] || { echo "the dead container's cgroup is gone before any command looked"; return 1; }
    said=$(lb stop dead 2>&1) && { echo "stop of a container whose init is gone succeeded"; return 1; }
    printf '%s\n' "$said"
    case $said in *"had ended without a stop"*"not running"*) ;; *) echo "stop does not say what it found"; return 1 ;; esac
    echo "state after stop: $(state_of dead)"
    # killed, init said nothing about its end: that is a failure
    nothing_left dead && [ "$(state_of dead)" = failed ]
}

# A container that is told to stop from inside, or by a signal from anywhere,
# ends as it does for lightbox stop. No command is there to clear up after
# it: the next one that changes it does, and records that it ended well.
t_stopped_from_inside_is_exited() {
    up inside || return 1
    pid=$(pid_of inside)
    sh_in inside 'kill -TERM 1' >/dev/null 2>&1     # the shell that says it ends with the container
    wait_until 15 gone "$pid" || { echo "init $pid did not end when a process in the container sent it SIGTERM"; return 1; }
    # ls says what it sees and changes nothing
    before=$(ls -A "$RUN/inside" | tr '\n' ' ')
    lb ls
    lb ls | grep -Eq '^inside +[0-9.]+ +exited' || { echo "ls does not show it as exited"; return 1; }
    [ "$(ls -A "$RUN/inside" | tr '\n' ' ')" = "$before" ] && [ -d "$CG/inside" ] ||
        { echo "ls changed something: records '$before' -> '$(ls -A "$RUN/inside" | tr '\n' ' ')'"; return 1; }
    echo "what init said when it ended: $(cat "$RUN/inside/exit")"
    said=$(lb stop inside 2>&1) && { echo "stop of a container that had ended succeeded"; return 1; }
    printf '%s\n' "$said"
    case $said in *"had stopped by itself"*) ;; *) echo "stop does not say what it found"; return 1 ;; esac
    echo "state after stop: $(state_of inside)"
    nothing_left inside && [ "$(state_of inside)" = exited ] || return 1
    # and it starts again
    start inside && [ "$(state_of inside)" = running ]
}

# A container that was started by a lightbox before 0.5 has its records in
# its own directory. After an upgrade it is still seen to be running, a
# command can be run in it, and stop stops it and takes the old records away.
t_container_started_before_the_upgrade() {
    up oldstyle || return 1
    pid=$(pid_of oldstyle)
    mv "$RUN/oldstyle/pid" "$C/oldstyle/.pid" && mv "$RUN/oldstyle/pid_start" "$C/oldstyle/.pid_start" &&
    mv "$RUN/oldstyle/state" "$C/oldstyle/.state" && rm -rf -- "$RUN/oldstyle" || return 1
    lb ls
    lb ls | grep -Eq "^oldstyle +[0-9.]+ +running +$pid" || { echo "ls does not show it as running"; return 1; }
    [ "$(sh_in oldstyle 'echo here')" = here ] || { echo "exec does not find it"; return 1; }
    refused lb start oldstyle 2>/dev/null || { echo "a container that is running was started again"; return 1; }
    alive "$pid" || { echo "the refused start ended the container"; return 1; }
    lb stop oldstyle || return 1
    gone "$pid" || { echo "init $pid is still there"; return 1; }
    echo "left in the container's directory: $(ls -A "$C/oldstyle" | tr '\n' ' ')"
    [ ! -e "$C/oldstyle/.pid" ] && [ ! -e "$C/oldstyle/.pid_start" ] && [ ! -e "$C/oldstyle/.state" ] &&
    nothing_left oldstyle && [ "$(state_of oldstyle)" = stopped ]
}

# After a reboot nothing runs and run_dir, on a tmpfs, is empty or gone. The
# containers are stopped, not stale, and start as they did.
t_after_a_reboot() {
    up was-up && box never-up || return 1
    pid=$(pid_of was-up)
    echo "run_dir is mode $(stat -c %a "$RUN"), a container's records $(stat -c %a "$RUN/was-up"), its PID record $(stat -c %a "$RUN/was-up/pid")"
    [ "$(stat -c %a "$RUN")" = 700 ] && [ "$(stat -c %a "$RUN/was-up")" = 700 ] && [ "$(stat -c %a "$RUN/was-up/pid")" = 600 ] || return 1
    # what a reboot does to it, as far as that can be done here
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || return 1
    wait_until 5 no_link "$(port_of was-up)" || return 1
    rm -rf -- "$RUN"
    lb ls
    lb ls | grep -Eq '^was-up +[0-9.]+ +stopped' && lb ls | grep -Eq '^never-up +[0-9.]+ +stopped' ||
        { echo "ls does not show them as stopped"; return 1; }
    [ ! -e "$RUN" ] || { echo "ls made run_dir"; return 1; }
    start was-up && start never-up || return 1
    [ "$(sh_in was-up 'echo back')" = back ] && [ "$(stat -c %a "$RUN")" = 700 ] && [ "$(state_of never-up)" = running ]
}

# A create that was killed half way leaves half a root filesystem. Such a
# container is not started.
t_half_made_container_is_not_started() {
    box halfmade || return 1
    : > "$C/halfmade/.creating"
    said=$(lb start halfmade 2>&1) && { echo "a half-made container was started"; return 1; }
    printf '%s\n' "$said"
    case $said in *'was not created completely'*) ;; *) return 1 ;; esac
    lb ls | grep -Eq '^halfmade +[0-9.]+ +creating' || { echo "ls does not show it as being created"; return 1; }
    nothing_left halfmade && lb rm halfmade && [ ! -e "$C/halfmade" ]
}

# Init has files of the host open: its log, and the record of how it ends.
# A process in the container cannot get at them by way of init.
t_init_is_closed_to_the_container() {
    up closedinit || return 1
    said=$(sh_in closedinit 'readlink /proc/1/fd/1; echo "readlink: $?"; ( : < /proc/1/fd/1 ) 2>/dev/null; echo "open: $?"; ( : < /proc/1/environ ) 2>/dev/null; echo "environ: $?"' 2>&1)
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -qx 'readlink: 1' && printf '%s\n' "$said" | grep -qx 'open: [12]' &&
    printf '%s\n' "$said" | grep -qx 'environ: [12]' || { echo "a process in the container looked into init"; return 1; }
    # and what it is closed for is there: the host's root can see both files
    holds() { # a path: is one of init's descriptors this file?
        local fd
        for fd in "/proc/$(pid_of closedinit)/fd"/*; do
            [ "$(readlink "$fd")" = "$1" ] && return 0
        done
        echo "init does not have $1 open"
        return 1
    }
    holds "$C/closedinit/console.log" && holds "$RUN/closedinit/exit"
}


# Two starts of one container at once: one starts it, and the other waits for
# the first to be done and then finds it running.
t_two_starts_at_once() {
    box twice || return 1
    "$LB" start twice >"$OUT/twice.1" 2>&1 </dev/null &
    first=$!
    "$LB" start twice >"$OUT/twice.2" 2>&1 </dev/null &
    second=$!
    wait "$first"; a=$?
    wait "$second"; b=$?
    echo "--- one (status $a):"; cat "$OUT/twice.1"
    echo "--- the other (status $b):"; cat "$OUT/twice.2"
    [ $((a + b)) -eq 1 ] || { echo "not exactly one of the two succeeded"; return 1; }
    cat "$OUT/twice.1" "$OUT/twice.2" | grep -q 'container is already running: twice' || { echo "the one that lost does not say why"; return 1; }
    settled twice || return 1
    [ "$(state_of twice)" = running ] || return 1
    [ "$(wc -l < "$CG/twice/cgroup.procs")" = 1 ] || { echo "the container's cgroup holds $(wc -l < "$CG/twice/cgroup.procs") processes"; return 1; }
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
    # a copy: the accounts are added from the host to a file of the base
    up late --copy || return 1
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

# Run a command line on a terminal: its output, without the carriage returns
# a terminal adds. script(1) makes the terminal. It passes the end of its own
# input on as an end of input on the terminal, so its input is held open until
# it is done: by the feeder a case names, or by nothing being typed at all.
on_a_terminal() { # command line [feeder function]
    command -v script >/dev/null 2>&1 || { echo "no script(1) to make a terminal with"; return 77; }
    rm -f "$OUT/script.done"
    {
        [ -z "${2:-}" ] || "$2"
        while [ ! -e "$OUT/script.done" ]; do sleep 0.1; done
    } | {
        timeout -k 2 40 script -qec "$1" /dev/null
        : > "$OUT/script.done"
    } | tr -d '\r'
}

# Typed at a terminal, exec gives the command a terminal of the container's:
# not the caller's, whose number and device are another's.
t_exec_on_a_terminal() {
    up term || return 1
    out=$(on_a_terminal "tty; stty rows 31 cols 97; stty -g > '$OUT/term.before'
        '$LB' exec term /bin/sh -c 'tty; stty size; echo \"devices: \$(stat -c %d /dev/pts) \$(stat -L -c %d /proc/self/fd/0) \$(stat -L -c %d /proc/self/fd/2)\"; ls /proc/self/fd | tr \"\\n\" \" \"; echo; exit 6'
        echo status \$?; stty -g > '$OUT/term.after'") || return $?
    printf '%s\n' "$out"
    outer=$(printf '%s\n' "$out" | sed -n 1p)
    inner=$(printf '%s\n' "$out" | sed -n 2p)
    case $outer in /dev/*) ;; *) echo "script gave no terminal"; return 1 ;; esac
    case $inner in /dev/pts/[0-9]*) ;; *) echo "the command has no terminal of the container's: $inner"; return 1 ;; esac
    devices=$(printf '%s\n' "$out" | sed -n 's/^devices: //p')
    # shellcheck disable=SC2086
    set -- $devices
    [ $# -eq 3 ] && [ "$1" = "$2" ] && [ "$1" = "$3" ] || { echo "the command's streams are not on the container's devpts: $devices"; return 1; }
    printf '%s\n' "$out" | grep -qx '31 97' || { echo "the command's terminal does not have the caller's size"; return 1; }
    printf '%s\n' "$out" | grep -qx '0 1 2 3 ' || { echo "the command has more than its three streams"; return 1; }
    printf '%s\n' "$out" | grep -qx 'status 6' || return 1
    cmp -s "$OUT/term.before" "$OUT/term.after" || { echo "the caller's terminal did not get its modes back"; return 1; }
}

# What is typed reaches the command, the key that interrupts is the command's
# to get, and a pipe stands in where only one side is a terminal.
t_exec_terminal_input_and_keys() {
    up keys || return 1
    feeder() {
        wait_until 10 test -e "$C/keys/rootfs/reading" && printf 'hello\n'
        wait_until 10 test -e "$C/keys/rootfs/waiting" && printf '\003'
    }
    out=$(on_a_terminal "'$LB' exec keys /bin/sh -c 'trap \"echo got-SIGINT; exit 3\" INT; : > /reading; read -r line; echo \"read: \$line\"; : > /waiting; sleep 20 & wait'
        echo status \$?" feeder) || return $?
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -qx 'read: hello' && printf '%s\n' "$out" | grep -q 'got-SIGINT' &&
    printf '%s\n' "$out" | grep -qx 'status 3' || return 1

    out=$(on_a_terminal "echo piped | '$LB' exec keys /bin/sh -c 'cat; test -t 1 && echo stdout-is-a-terminal; test -t 2 && echo stderr-is-a-terminal; echo to-stderr >&2'") || return $?
    printf '%s\n' "$out"
    [ "$out" = "piped
to-stderr" ]
}

# Without a terminal the command gets lightbox's streams as they are, leads a
# session of its own, and hears of a signal that asks exec to end.
t_exec_session_and_signals() {
    up session2 || return 1
    # the command is given none of what else the caller has open: here a file on descriptor 9
    said=$(echo typed | lb exec session2 /bin/sh -c 'cat; read -r pid _ _ _ _ sid _ < /proc/self/stat; [ "$pid" = "$sid" ] && echo "leads its session"; ls /proc/self/fd | tr "\n" " "' 9< "$C/session2/.conf")
    printf '%s\n' "$said"
    [ "$said" = "typed
leads its session
0 1 2 3 " ] || return 1

    "$LB" exec session2 /bin/sh -c 'trap "echo asked > /asked; exit 9" TERM; : > /started; sleep 20 & wait' >"$OUT/session2.exec" 2>&1 </dev/null &
    front=$!
    wait_until 5 test -e "$C/session2/rootfs/started" || { echo "the command did not start:"; cat "$OUT/session2.exec"; return 1; }
    kill -TERM "$front"
    wait "$front"
    rc=$?
    echo "exec returned $rc; the command: $(cat "$C/session2/rootfs/asked" 2>&1)"
    [ $rc -eq 9 ] && [ "$(cat "$C/session2/rootfs/asked")" = asked ]
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
    box vdir --vol "$T/vol/shared:/data" && volume_for vdir "$T/vol/shared" && start vdir || return 1
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

t_rmvol_applies_at_next_start() {
    mkdir -p "$T/vol/going" "$T/vol/staying"
    echo going > "$T/vol/going/in"
    echo staying > "$T/vol/staying/in"
    up rmvol --vol "$T/vol/going:/going" --vol "$T/vol/staying:/staying:ro" || return 1
    said=$(lb rm-vol rmvol /going) || return 1
    printf '%s\n' "$said"
    case $said in *'until the container is restarted'*) ;; *) echo "rm-vol does not say that the volume is still mounted"; return 1 ;; esac
    [ "$(sh_in rmvol 'cat /going/in')" = going ] || { echo "the volume went away without a restart"; return 1; }
    lb stop rmvol && start rmvol || return 1
    refused sh_in rmvol 'cat /going/in' 2>/dev/null || { echo "the removed volume is mounted after a restart"; return 1; }
    [ "$(sh_in rmvol 'cat /staying/in')" = staying ] || { echo "the other volume is gone as well"; return 1; }
    [ -e "$T/vol/going/in" ] || { echo "removing the volume removed what was in it"; return 1; }
}

# A container made by a lightbox from before the configuration had a version
# line: it starts as it is, with its limits and its volume.
t_conf_from_before_starts() {
    mkdir -p "$T/vol/old"
    echo old > "$T/vol/old/in"
    # a copy, as every container from before 0.7 is: the .conf of then names no snapshot
    box before --copy || return 1
    printf 'mem=32M\npids=40\ncpu=2\noom_score=200\nnote=by hand\nvol=%s:/old:ro\n' "$T/vol/old" > "$C/before/.conf"
    start before || return 1
    pid=$(pid_of before)
    echo "memory.max $(cat "$CG/before/memory.max"), pids.max $(cat "$CG/before/pids.max"), cpu.max $(cat "$CG/before/cpu.max"), oom_score_adj $(cat "/proc/$pid/oom_score_adj")"
    [ "$(cat "$CG/before/memory.max")" = 33554432 ] && [ "$(cat "$CG/before/pids.max")" = 40 ] &&
    [ "$(cat "$CG/before/cpu.max")" = '200000 100000' ] && [ "$(cat "/proc/$pid/oom_score_adj")" = 200 ] &&
    [ "$(sh_in before 'cat /old/in')" = old ] || return 1
    lb stop before
}

# A configuration that cannot be used: nothing is started from it and
# nothing is run in a container that has it, and the container is stopped
# all the same, with what stop could not do said.
# A configuration that cannot be used: exec and start refuse. stop stops the
# container all the same and takes away all it had, the rules of its links
# among them, which it knows from their record and not from the .conf.
t_unusable_conf() {
    if brnf 1; then
        box dpeer && box damaged --link dpeer || return 1
        start damaged || return 1
        iptables -n -L "$(chain_of damaged)" >/dev/null || { echo "the link put in no chain"; return 1; }
    else
        echo "br_netfilter is not loaded: the container has no link"
        up damaged || return 1
    fi
    pid=$(pid_of damaged)
    echo 'colour=blue' >> "$C/damaged/.conf"
    said=$(lb exec damaged /bin/true 2>&1 </dev/null) && { echo "exec ran a command without knowing what the container may do"; return 1; }
    printf '%s\n' "$said"
    case $said in *"$C/damaged/.conf: line "*': a key lightbox does not know') ;; *) return 1 ;; esac
    said=$(lb stop damaged 2>&1) || { printf '%s\n' "$said"; echo "stop failed"; return 1; }
    printf '%s\n' "$said"
    gone "$pid" && nothing_left damaged || { echo "the container was not stopped and cleared away"; return 1; }
    said=$(lb start damaged 2>&1) && { echo "a container with a damaged configuration was started"; return 1; }
    printf '%s\n' "$said"
    nothing_left damaged
}

# A start reads the container's configuration once. The command reads it,
# and init has it from the command; before, each key was looked up in the
# file again, by both.
t_start_reads_conf_once() {
    command -v strace >/dev/null 2>&1 || { echo "no strace to watch a start with"; return 77; }
    mkdir -p "$T/vol/traced"
    box traced --vol "$T/vol/traced:/data" --mem 64M || return 1
    is_up() { [ "$(state_of traced 2>/dev/null)" = running ]; }
    # strace follows the command and all it starts, init among them, so it
    # ends when init does
    timeout -k 5 80 strace -f -qq -e trace=%file,fsync,fdatasync,sync,syncfs -o "$T/traced.strace" \
        "$LB" start traced >"$OUT/traced.start" 2>&1 </dev/null &
    tracer=$!
    wait_until 60 is_up || { echo "the container did not start under strace:"; cat "$OUT/traced.start"; kill "$tracer" 2>/dev/null; return 1; }
    settled traced || return 1
    lb stop traced >/dev/null 2>&1 || { echo "stop failed"; return 1; }
    wait "$tracer"
    opens=$(grep -cE '\<open(at2?)?\(.*/traced/\.conf"' "$T/traced.strace")
    echo "the trace has $(wc -l < "$T/traced.strace") lines from $(awk '{ print $1 }' "$T/traced.strace" | sort -u | wc -l) processes"
    echo "times the container's .conf was opened: $opens"
    grep -E '/traced/\.conf"' "$T/traced.strace" | head -n 5
    [ "$opens" = 1 ] || return 1
    # A start writes its records where no disk has to be waited for: nothing
    # it does, and nothing it runs, asks for a write to reach the disk.
    syncs=$(grep -cE '\<(fsync|fdatasync|sync|syncfs)\(' "$T/traced.strace")
    echo "times the start waited for a disk: $syncs"
    grep -E '\<(fsync|fdatasync|sync|syncfs)\(' "$T/traced.strace" | head -n 5
    [ "$syncs" = 0 ]
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
    made_for vlink "$C/vlink/rootfs/srv" "$C/vlink/rootfs${host%/*}" "$C/vlink/rootfs/link" "$C/vlink/rootfs/away" || return 1
    start vlink || return 1
    [ "$(sh_in vlink 'cat /srv/data/in')" = through-a-link ] || { echo "the volume is not where the link leads in the container"; return 1; }
    [ "$(sh_in vlink 'cat /away/data/in')" = through-a-link ] || { echo "the second volume is not reachable through its link"; return 1; }
    [ -z "$(ls -A "$host")" ] || { echo "something was made on the host: $(ls -A "$host")"; return 1; }
    [ -d "$C/vlink/rootfs$host/data" ] || { echo "the destination was not made in the container's root filesystem"; return 1; }
    lb stop vlink >/dev/null || return 1

    # the same link when the container has no such directory: it leads nowhere, and the start says so
    box vnowhere --vol "$T/vol/linked:/away/data" || return 1
    ln -s "$host" "$C/vnowhere/rootfs/away" && made_for vnowhere "$C/vnowhere/rootfs/away" || return 1
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
    box vtmp --read-only --vol "$T/vol/cache:/tmp/cache" --vol "$T/vol/one.conf:/run/app/one.conf:ro" --vol "$T/vol/cache:/not/in/the/image" &&
        volume_for vtmp "$T/vol/cache" && start vtmp || return 1
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
    box nomount --copy || return 1      # a copy, as files of the base are taken out of it
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
    box bare --copy || return 1         # a copy, as directories of the base are taken out of it
    for d in dev proc sys tmp run var; do rm -rf -- "$C/bare/rootfs/$d"; done
    start bare || return 1
    [ "$(sh_in bare 'echo x > /dev/null && cat /proc/1/comm > /dev/null && ls /sys > /dev/null && echo x > /tmp/a && echo fine')" = fine ]
}

t_image_with_one_binary() {
    [ -n "$BB" ] || { echo "no static busybox to make the image from"; return 77; }
    mkdir -p "$T/base-one"
    cp "$BB" "$T/base-one/busybox"
    box one --rootfs "$T/base-one" || return 1
    start one || { echo "an image without mount, ip and sh did not start"; return 1; }
    [ "$(lb exec one /busybox echo runs </dev/null)" = runs ] && lb stop one
}

t_start_runs_nothing_from_the_image() {
    [ -n "$BB" ] || { echo "the recording stand-ins are made for the busybox image"; return 77; }
    box record || return 1
    # bin/ of the container's own, which the upper layer of an overlay lacks
    mkdir -p "$C/record/rootfs/bin" || return 1
    for tool in mount ip; do
        rm -f "$C/record/rootfs/bin/$tool"
        printf '#!/bin/sh\necho %s >> /run-from-the-image\nexec /bin/busybox %s "$@"\n' "$tool" "$tool" \
            > "$C/record/rootfs/bin/$tool" && chmod 755 "$C/record/rootfs/bin/$tool" || return 1
    done
    made_for record "$C/record/rootfs/bin" || return 1
    start record || return 1
    # what the container has at /bin/mount and /bin/ip is the stand-ins
    [ "$(sh_in record 'cat /bin/mount /bin/ip' | grep -c 'run-from-the-image')" = 2 ] ||
        { echo "the stand-ins are not what the container has"; return 1; }
    log="$C/record/rootfs/run-from-the-image"
    if [ -s "$log" ]; then
        echo "run from the image during start: $(sort "$log" | uniq -c | tr -s ' \n' ' ')"
        return 1
    fi
}

# ─── Cases: limits ──────────────────────────────────────────────────────────

# The limits are in the cgroup, with no swap and the whole container for the
# kernel to kill unless --swap gives some; init and what exec runs have the
# container's OOM score.
t_limits() {
    up limits --mem 64M --pids 50 --cpu 2 --oom-score 300 || return 1
    pid=$(pid_of limits)
    echo "memory.max $(cat "$CG/limits/memory.max"), pids.max $(cat "$CG/limits/pids.max"), cpu.max $(cat "$CG/limits/cpu.max"), oom_score_adj $(cat "/proc/$pid/oom_score_adj")"
    [ "$(cat "$CG/limits/memory.max")" = 67108864 ] && [ "$(cat "$CG/limits/pids.max")" = 50 ] &&
    [ "$(cat "$CG/limits/cpu.max")" = '200000 100000' ] && [ "$(cat "/proc/$pid/oom_score_adj")" = 300 ] || return 1
    echo "memory.swap.max $(cat "$CG/limits/memory.swap.max"), memory.oom.group $(cat "$CG/limits/memory.oom.group"), oom_score_adj of what exec runs $(sh_in limits 'cat /proc/self/oom_score_adj')"
    [ "$(cat "$CG/limits/memory.swap.max")" = 0 ] && [ "$(cat "$CG/limits/memory.oom.group")" = 1 ] &&
    [ "$(sh_in limits 'cat /proc/self/oom_score_adj')" = 300 ] || return 1
    # part of a CPU, no limit at all, and some swap
    up half --mem max --pids max --cpu 0.5 --oom-score -500 --swap 64M || return 1
    pid=$(pid_of half)
    echo "memory.max $(cat "$CG/half/memory.max"), pids.max $(cat "$CG/half/pids.max"), cpu.max $(cat "$CG/half/cpu.max"), oom_score_adj $(cat "/proc/$pid/oom_score_adj"), memory.swap.max $(cat "$CG/half/memory.swap.max")"
    [ "$(cat "$CG/half/memory.max")" = max ] && [ "$(cat "$CG/half/pids.max")" = max ] &&
    [ "$(cat "$CG/half/cpu.max")" = '50000 100000' ] && [ "$(cat "/proc/$pid/oom_score_adj")" = -500 ] &&
    [ "$(cat "$CG/half/memory.swap.max")" = 67108864 ] && [ "$(sh_in half 'cat /proc/self/oom_score_adj')" = -500 ]
}

# A whole disk of this host, as <major>:<minor>: not a partition, a loop
# device, a RAM disk or an optical drive.
whole_disk() {
    local d name
    for d in /sys/dev/block/*; do
        [ -e "$d/uevent" ] && [ ! -e "$d/partition" ] || continue
        name=$(sed -n 's/^DEVNAME=//p' "$d/uevent")
        case $name in loop*|ram*|zram*|sr*|'') continue ;; esac
        echo "${d##*/}"
        return 0
    done
    return 1
}

# --io-max reaches io.max.
t_io_limit() {
    disk=$(whole_disk) || { echo "this host has no whole disk to limit"; return 77; }
    up iolimit --io-max "$disk wbps=1048576 riops=max" || return 1
    echo "io.max: $(cat "$CG/iolimit/io.max")"
    grep -qx "$disk rbps=max wbps=1048576 riops=max wiops=max" "$CG/iolimit/io.max"
}

# Past its memory limit a process is killed, and does not go on in swap; and
# with it the whole container, which the next command clears away.
t_past_the_memory_limit() {
    chroot "$BASE" /bin/sh -c 'command -v dd' >/dev/null 2>&1 || { echo "this image has no dd to fill memory with"; return 77; }
    echo "swap on this host: $(awk 'NR > 1 { n++; k += $3 } END { print n + 0 " areas, " k + 0 " KiB" }' /proc/swaps)"
    up hungry --mem 32M || return 1
    pid=$(pid_of hungry)
    # 64 MiB in one buffer, which dd fills from /dev/zero
    sh_in hungry 'dd if=/dev/zero of=/dev/null bs=67108864 count=1' >"$OUT/hungry.dd" 2>&1
    rc=$?
    cat "$OUT/hungry.dd"
    echo "exec ended with status $rc"
    [ $rc -ne 0 ] || { echo "dd went past the memory limit and finished"; return 1; }
    echo "memory.events: $(tr '\n' ' ' < "$CG/hungry/memory.events")"
    kills=$(awk '$1 == "oom_kill" { print $2 }' "$CG/hungry/memory.events")
    [ "${kills:-0}" -ge 1 ] || { echo "the kernel killed nothing for the limit"; return 1; }
    wait_until 5 gone "$pid" || { echo "init $pid outlived the kill of a process in its container"; return 1; }
    lb stop hungry
    nothing_left hungry && [ "$(state_of hungry)" = failed ]
}

# Without the io controller, which a kernel may lack or a parent keep to
# itself, a container without an I/O limit starts and is told so once; one
# with an I/O limit is refused, and nothing of it is left. Here the suite's
# cgroup keeps io from the one below it, which this case's lightbox.conf has
# for its cgroup_root.
t_without_io_controller() {
    sub=$CG/noio
    mkdir -p "$T/noio/home/.config/lightbox" "$sub" || return 1
    echo -io > "$CG/cgroup.subtree_control" || { echo "io could not be kept from below the suite's cgroup"; return 1; }
    sed -e "s#^cgroup_root = .*#cgroup_root = $sub#" -e "s#^cgroup_base = .*#cgroup_base = $sub/base#" \
        "$HOME/.config/lightbox/lightbox.conf" > "$T/noio/home/.config/lightbox/lightbox.conf"
    echo "controllers below the suite's cgroup: $(cat "$sub/cgroup.controllers")"
    export LIGHTBOX_CONFIG="$T/noio/home/.config/lightbox/lightbox.conf"
    box plain || return 1
    lb start plain >"$OUT/plain.start" 2>&1 </dev/null || { cat "$OUT/plain.start"; return 1; }
    cat "$OUT/plain.start"
    [ "$(grep -c '^Warning:' "$OUT/plain.start")" = 1 ] && grep -q '^Warning: .* no io controller' "$OUT/plain.start" ||
        { echo "start did not warn once, about io"; return 1; }
    settled plain || return 1
    echo "the container's cgroup has: $(cat "$sub/base/plain/cgroup.controllers"); memory.max $(cat "$sub/base/plain/memory.max")"
    [ "$(cat "$sub/base/plain/memory.max")" = 268435456 ] || { echo "the other limits are not there"; return 1; }
    lb stop plain >/dev/null || return 1
    disk=$(whole_disk) || { echo "this host has no whole disk for an I/O limit, so that refusal is not tried"; return 0; }
    box limited --io-max "$disk wbps=1048576" || return 1
    said=$(lb start limited 2>&1 </dev/null) && { echo "a container with an I/O limit started without io"; return 1; }
    printf '%s\n' "$said"
    case $said in *"has no io controller, and the container has an I/O limit"*) ;; *) return 1 ;; esac
    [ ! -d "$sub/base/limited" ] && no_link "$(port_of limited)"
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
# /dev/null, the log twice, its signalfd, and the record of how it ends, once.
# The command here has a file on descriptor 9, and no standard streams of its
# own the second time.
t_init_keeps_nothing_of_the_command() {
    box clean || return 1
    look() { # name
        local pid fd n to log record records=0 bad=0
        pid=$(pid_of "$1") || return 1
        log=$C/$1/console.log
        record=$RUN/$1/exit
        for fd in "/proc/$pid/fd"/*; do
            n=${fd##*/}
            to=$(readlink "$fd")
            echo "  init $pid, descriptor $n: $to"
            # the same file, however its path is spelled
            if [ "$n" = 0 ] && [ "$fd" -ef /dev/null ]; then continue; fi
            if { [ "$n" = 1 ] || [ "$n" = 2 ]; } && [ "$fd" -ef "$log" ]; then continue; fi
            if [ "$n" -gt 2 ] && [ "$to" = 'anon_inode:[signalfd]' ]; then continue; fi
            if [ "$n" -gt 2 ] && [ "$fd" -ef "$record" ]; then records=$((records + 1)); continue; fi
            echo "  init should not have that"
            bad=1
        done
        [ -e "/proc/$pid/fd/0" ] && [ -e "/proc/$pid/fd/1" ] && [ -e "/proc/$pid/fd/2" ] || { echo "  init lacks a standard stream"; bad=1; }
        [ "$records" = 1 ] || { echo "  init has the record of how it ends open $records times, not once"; bad=1; }
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

# start stands still in the firewall transaction of the container's links,
# after init is built and before the byte that lets it run its hook. Killed
# there, it must not leave init behind. (Until 0.7 it stood still in nsenter,
# before the first byte; nothing is run there any more.)
t_killed_start_leaves_no_container() {
    box orphanpeer && box orphan --link orphanpeer || return 1
    restore=$(first_existing /usr/sbin/iptables-restore /sbin/iptables-restore /usr/bin/iptables-restore /bin/iptables-restore)
    real=$(readlink -f "$restore")
    cp "$real" "$T/real/iptables-program" || return 1
    # iptables, iptables-save and iptables-restore may be one program that
    # does what it is called: the stand-in passes the others on by their name
    printf '#!/bin/bash\ncase ${0##*/} in *-restore) : > %s; sleep 5; exit 1 ;; esac\nexec -a "$0" %s "$@"\n' \
        "'$T/restore.reached'" "'$T/real/iptables-program'" > "$T/shim/iptables-program" &&
        chmod 755 "$T/shim/iptables-program" || return 1
    mount --bind "$T/shim/iptables-program" "$real" && echo "$real" >> "$T/shims" || return 1
    "$LB" start orphan >"$OUT/orphan.start" 2>&1 </dev/null &
    starter=$!
    echo "$starter" >> "$T/background"
    wait_until 10 test -e "$T/restore.reached" ||
        { echo "start did not reach the firewall transaction:"; cat "$OUT/orphan.start"; return 1; }
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
    mkdir -p "$RUN/stale"
    printf '12345' > "$RUN/stale/pid_start"
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

# A subnet that is not a /24: the bridge, the address translation and the
# container's interface have its prefix, and a container at an address
# outside the gateway's /24 reaches the gateway. lightbox.conf here is the
# suite's but for the bridge and the network.
t_wide_subnet() {
    mkdir -p "$T/wide/home/.config/lightbox"
    sed -e "s#^bridge = .*#bridge = $WIDE_BR#" -e 's#^subnet = .*#subnet = 10.9.0.0/16#' -e 's#^gw = .*#gw = 10.9.0.1#' \
        "$HOME/.config/lightbox/lightbox.conf" > "$T/wide/home/.config/lightbox/lightbox.conf"
    suite_conf=$LIGHTBOX_CONFIG
    export LIGHTBOX_CONFIG="$T/wide/home/.config/lightbox/lightbox.conf"
    lb setup >"$OUT/wide.setup" 2>&1 || { cat "$OUT/wide.setup"; return 1; }
    ip -o -4 addr show dev "$WIDE_BR"
    ip -o -4 addr show dev "$WIDE_BR" | grep -q ' 10\.9\.0\.1/16 ' || { echo "the bridge does not have 10.9.0.1/16"; return 1; }
    iptables -t nat -C LIGHTBOX-POSTROUTING -s 10.9.0.0/16 ! -o "$WIDE_BR" -j MASQUERADE || { echo "no address translation for 10.9.0.0/16"; return 1; }
    # shellcheck disable=SC2046  # options of one word each
    lb create wide 10.9.5.2 $(mode_options) >"$OUT/wide.create" 2>&1 || { cat "$OUT/wide.create"; return 1; }
    start wide || return 1
    said=$(sh_in wide 'ip addr; ip route')
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -q 'inet 10\.9\.5\.2/16' && printf '%s\n' "$said" | grep -q '^default via 10\.9\.0\.1 ' ||
        { echo "the container does not have 10.9.5.2/16 and a route by 10.9.0.1"; return 1; }
    if [ -e "$T/have_nc" ]; then
        reaches wide 10.9.0.1 || return 1
    else
        echo "this image has no nc: whether the gateway answers is not tried"
    fi
    lb stop wide >/dev/null || return 1
    # on the suite's network that address is no container's, and start says so
    export LIGHTBOX_CONFIG="$suite_conf"
    said=$(lb start wide 2>&1) && { echo "a container outside the subnet was started"; return 1; }
    printf '%s\n' "$said"
    case $said in *'it is outside the subnet of lightbox.conf'*) ;; *) return 1 ;; esac
    nothing_left wide
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
    lb stop linked >/dev/null && nothing_left linked
}

# A start puts in a container's link rules with one process, iptables-restore.
t_link_rules_in_one_process() {
    command -v strace >/dev/null 2>&1 || { echo "no strace to watch a start with"; return 77; }
    brnf 1 || { echo "br_netfilter is not loaded, and a container with a link does not start without it"; return 77; }
    box onepeer && box onelinked --link onepeer || return 1
    is_up() { [ "$(state_of onelinked 2>/dev/null)" = running ]; }
    timeout -k 5 80 strace -f -qq -e trace=execve -o "$T/links.strace" \
        "$LB" start onelinked >"$OUT/onelinked.start" 2>&1 </dev/null &
    tracer=$!
    wait_until 60 is_up || { echo "the container did not start under strace:"; cat "$OUT/onelinked.start"; kill "$tracer" 2>/dev/null; return 1; }
    settled onelinked || return 1
    lb stop onelinked >/dev/null 2>&1 || { echo "stop failed"; return 1; }
    wait "$tracer"
    # but for the look at whether setup's rules are there, which every start has
    tools=$(grep -E 'execve\("[^"]*/(ip6?tables[^"]*|nft)"' "$T/links.strace" | grep -v ' = -1 ')
    printf '%s\n' "$tools"
    count=$(printf '%s\n' "$tools" | grep -v '"-C", "FORWARD", "-j", "LIGHTBOX-FORWARD"' | grep -c .)
    echo "firewall tools the start ran to put rules in: $count"
    [ "$count" = 1 ] && printf '%s\n' "$tools" | grep -v '"-C", "FORWARD"' | grep -q 'restore'
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
    pid=$(pid_of lmain)
    chain=$(chain_of lmain) || return 1
    iptables -S "$chain" && iptables -C LIGHTBOX-LINKS -j "$chain" || { echo "the link put in no chain to begin with"; return 1; }
    echo "the record: $(cat "$RUN/lmain/firewall")"
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || return 1
    lb rm lmain || return 1
    iptables -n -L "$chain" >/dev/null 2>&1 && { echo "the chain $chain is left"; return 1; }
    iptables -C LIGHTBOX-LINKS -j "$chain" 2>/dev/null && { echo "the jump to $chain is left"; return 1; }
    [ ! -e "$RUN/lmain" ] || { echo "left in run_dir: $(ls -A "$RUN/lmain")"; return 1; }
}

# An interface on the host by the name lightbox would give a container's,
# without lightbox's alias: start refuses, says so, and leaves it alone.
# One with the alias is what an earlier run left, and start takes it away.
t_start_spares_foreign_interface() {
    box clobber || return 1
    port=$(port_of clobber)
    ip link add "$port" type dummy 2>/dev/null || ip link add "$port" type veth peer name lbt-foreign || return 1
    said=$(lb start clobber 2>&1 </dev/null) && { echo "start went ahead"; return 1; }
    printf '%s\n' "$said"
    ip link show dev "$port" >/dev/null 2>&1 || { echo "start deleted an interface it had not created"; return 1; }
    case $said in *"interface $port that lightbox did not make"*) ;; *) return 1 ;; esac
    [ "$(state_of clobber)" = failed ] || [ "$(state_of clobber)" = stopped ] || { echo "state: $(state_of clobber)"; return 1; }
    ip link delete "$port" || return 1
    # what an earlier run of the container left: its own, which goes
    ip link add "$port" type dummy 2>/dev/null || ip link add "$port" type veth peer name lbt-foreign || return 1
    ip link set dev "$port" alias lightbox:clobber || return 1
    start clobber || return 1
    ip -d link show dev "$port" | grep -q 'veth' || { echo "the interface is not the container's veth"; return 1; }
}

# A start that fails after it made the container's interface takes it away.
# Here a veth has the bridge's name: it takes no ports, and the kernel refuses
# the container's interface as one (EOPNOTSUPP).
t_start_fails_at_the_bridge() {
    box nobridge || return 1
    ip link set dev "$BR" down && ip link set dev "$BR" name lbt-realbr || return 1
    ip link add "$BR" type veth peer name lbt-notbr || { put_the_bridge_back; return 1; }
    said=$(lb start nobridge 2>&1 </dev/null)
    rc=$?
    put_the_bridge_back || { echo "the bridge could not be put back"; return 1; }
    printf '%s\n' "$said"
    [ $rc -ne 0 ] || { echo "start went ahead without its bridge"; return 1; }
    case $said in *"failed to attach the container's interface to the bridge (errno 95)"*) ;; *) return 1 ;; esac
    nothing_left nobridge
}

# what t_start_fails_at_the_bridge took away, back, wherever it stopped
put_the_bridge_back() {
    ip link show dev lbt-realbr >/dev/null 2>&1 || return 0
    ip link delete "$BR" 2>/dev/null
    ip link set dev lbt-realbr name "$BR" && ip link set dev "$BR" up
}

# The host's end of a container's interface carries lightbox's alias, and the
# container's end is eth0, in the container only.
t_interface_is_tagged() {
    up tagged || return 1
    port=$(port_of tagged)
    ip link show dev "$port"
    ip link show dev "$port" | grep -q '^ *alias lightbox:tagged$' || { echo "no alias lightbox:tagged"; return 1; }
    ! ip link show dev eth0 2>/dev/null | grep -q 'link-netns' || { echo "an eth0 of a container is on the host"; return 1; }
}

# A name of 30 characters: start, exec, stop and rm, and nothing left.
t_long_name() {
    long='a-container-of-30-characters-x'
    box "$long" || return 1
    start "$long" || return 1
    [ "$(sh_in "$long" 'echo here')" = here ] || return 1
    [ "$(sh_in "$long" 'hostname')" = "$long" ] || { echo "the hostname is $(sh_in "$long" hostname)"; return 1; }
    lb stop "$long" >/dev/null && nothing_left "$long" && lb rm "$long" >/dev/null
}

t_interface_is_eth0() {
    up ifname || return 1
    said=$(sh_in ifname 'cat /proc/net/dev')
    printf '%s\n' "$said" | sed '1,2d' | awk -F: '{ gsub(/ /, "", $1); printf "%s ", $1 } END { print "" }'
    printf '%s\n' "$said" | grep -q '^ *eth0:' || return 1
    ! printf '%s\n' "$said" | grep -q '^ *ve-' || { echo "the container has a ve- interface"; return 1; }
    printf '%s\n' "$(sh_in ifname 'ip -4 addr show dev eth0')" | grep -q "inet $(addr_of ifname)/"
}

t_no_ipv6_in_container() {
    [ -e /proc/net/if_inet6 ] || { echo "this kernel runs without IPv6"; return 77; }
    up six || return 1
    said=$(sh_in six 'cat /proc/net/if_inet6 2>/dev/null')
    printf 'IPv6 addresses in the container:\n%s\n' "${said:-none}"
    [ -z "$said" ]
}

# start and stop take several names and do them one after the other. A name
# that is no container's ends nothing for the others, and is named at the end.
t_several_names() {
    box many1 && box many2 || return 1
    said=$(lb start many1 nosuch many2 2>&1 </dev/null) && { printf '%s\n' "$said"; echo "a start with the name of no container succeeded"; return 1; }
    printf '%s\n' "$said"
    [ "$(printf '%s\n' "$said" | tail -n 1)" = 'Error: not started: nosuch' ] || return 1
    settled many1 && settled many2 || return 1
    lb stop -t 5 many1 many2 || return 1
    [ "$(state_of many1)" = stopped ] && [ "$(state_of many2)" = stopped ] ||
        { echo "states: $(state_of many1) $(state_of many2)"; return 1; }
    nothing_left many1 && nothing_left many2
}

# inspect --json of a running container: running, its init's number as a
# number, and the start time beside it, as text inspect shows them.
t_inspect_json_running() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to decode JSON with"; return 77; }
    up seen || return 1
    json=$(lb inspect seen --json) || return 1
    printf '%s\n' "$json"
    printf '%s' "$json" | python3 -I -c '
import json, sys
c = json.load(sys.stdin)[0]
assert c["running"] is True and c["state"] == "running", "not running"
assert c["pid"] == int(sys.argv[1]), "pid %r" % c["pid"]
assert isinstance(c["pid_starttime"], str) and c["pid_starttime"].isdigit(), "pid_starttime %r" % c["pid_starttime"]
' "$(pid_of seen)" || return 1
    [ "$(lb inspect seen | sed -n 's/^pid_starttime: //p')" = "$(printf '%s' "$json" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["pid_starttime"])')" ]
}

# doctor as root on a host set up for lightbox finds nothing missing (see
# t_doctor). Each precondition of start broken in turn makes it exit 1, with
# the check that names it and, on the line after, what fixes it.
t_doctor_names_what_is_missing() {
    breaks() { # check, fix, doctor's words... : doctor fails that check and says the fix
        local check=$1 fix=$2
        shift 2
        said=$("$@" 2>&1) && { printf '%s\n' "$said"; echo "doctor exited 0 with $check broken"; return 1; }
        printf '%s\n' "$said" | grep -A1 "^$check: "
        printf '%s\n' "$said" | grep -A1 -E "^$check: (no|missing)" | tail -n 1 | grep -qF "  to fix: $fix" ||
            { echo "$check is not said to fail, with: $fix"; return 1; }
    }
    lb doctor >/dev/null || { lb doctor; echo "doctor finds something missing before anything is broken"; return 1; }
    cp_path=$(readlink -f "$(type -P cp)")
    mount --bind /dev/null "$cp_path" || return 1
    breaks bin.cp 'install coreutils' lb doctor; rc=$?
    umount "$cp_path" || return 1
    [ $rc = 0 ] || return 1
    lb doctor | grep -E '^bin\.(ip|nsenter): ' && { echo "doctor looks for a tool lightbox does not run"; return 1; }
    mkdir -p "$T/emptyroot" "$T/notcg"
    alt_conf docrootfs "rootfs = $T/emptyroot" || return 1
    breaks path.rootfs 'put a root filesystem there' alt_lb doctor || return 1
    alt_conf doccg "cgroup_root = $T/notcg" || return 1
    breaks cgroup2 'boot with cgroup_no_v1=all' alt_lb doctor || return 1
    alt_conf docfwd 'firewall_backend = nftables' || return 1
    echo 0 > /proc/sys/net/ipv4/ip_forward || return 1
    breaks ip_forwarding 'sysctl -w net.ipv4.ip_forward=1' alt_lb doctor || return 1
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if command -v setpriv >/dev/null 2>&1; then
        # a copy that another user can reach, which the checkout may not be
        pub=$(mktemp -d /tmp/lbt-pub.XXXXXX) && chmod 755 "$pub" && cp "$LB" "$pub/lightbox" && chmod 755 "$pub/lightbox" ||
            return 1
        breaks root 'run lightbox as root' setpriv --reuid=65534 --regid=65534 --clear-groups \
            env LIGHTBOX_CONFIG=/dev/null "$pub/lightbox" doctor
        rc=$?
        rm -rf -- "$pub"
        return $rc
    fi
    echo "no setpriv to run doctor as another user with"
}

# ─── Cases: restart, update, rm -f ──────────────────────────────────────────

limits_of() { echo "memory.max $(cat "$CG/$1/memory.max"), pids.max $(cat "$CG/$1/pids.max"), cpu.max $(cat "$CG/$1/cpu.max")"; }

# update of a running container changes its cgroup's limits at once, and its
# .conf, so that it has them after a restart too.
t_update_live() {
    up upd || return 1
    before=$(limits_of upd)
    echo "before: $before"
    lb update upd --mem 64M --pids 50 --cpu 0.5 || return 1
    echo "after:  $(limits_of upd)"
    want='memory.max 67108864, pids.max 50, cpu.max 50000 100000'
    [ "$(limits_of upd)" = "$want" ] || { echo "the running container did not take the limits"; return 1; }
    old=$(pid_of upd)
    lb restart upd || return 1
    settled upd || return 1
    [ "$(pid_of upd)" != "$old" ] || { echo "restart left the same init"; return 1; }
    echo "after a restart: $(limits_of upd)"
    [ "$(limits_of upd)" = "$want" ] || { echo "the limits did not outlast a restart"; return 1; }
}

# restart stops a container that runs and starts it, and starts one that is
# stopped.
t_restart() {
    up rst || return 1
    old=$(pid_of rst)
    lb restart -t 5 rst || return 1
    settled rst && [ "$(pid_of rst)" != "$old" ] || { echo "the container was not started again"; return 1; }
    wait_until 5 gone "$old" || { echo "the old init is still there"; return 1; }
    lb stop rst >/dev/null || return 1
    lb restart rst || return 1
    settled rst
}

# rm of a running container is refused; rm -f kills it first, as docker rm -f
# does, and removes it, leaving nothing.
t_rm_force() {
    up rmf || return 1
    pid=$(pid_of rmf)
    port_of rmf >/dev/null
    refused lb rm rmf || { echo "rm removed a running container"; return 1; }
    lb rm -f rmf || return 1
    wait_until 5 gone "$pid" || { echo "init is still there"; return 1; }
    [ ! -e "$C/rmf" ] || { echo "the container's directory is left"; return 1; }
    nothing_left rmf
}

# ─── Cases: the root as an overlay of a snapshot ────────────────────────────

base_of() { sed -n 's/^base=//p' "$C/$1/.conf"; }

# Two containers of one base overlay one snapshot of it, and each has only
# its own files in its rootfs/: what create wrote, and what it writes. The
# base's files are there in the container, what it changes and takes out is
# changed in rootfs/ only, and a change of the base afterwards reaches no
# container.
t_overlay_root() {
    OVERLAY=1
    box ov1 && box ov2 || return 1
    id=$(base_of ov1)
    echo "base snapshot: $id; of ov2: $(base_of ov2)"
    [ -n "$id" ] && [ "$(base_of ov2)" = "$id" ] || { echo "the two do not overlay one snapshot"; return 1; }
    snap=$T/lb/bases/$id/rootfs
    [ -x "$snap/bin/busybox" ] || { echo "the snapshot has no busybox"; return 1; }
    lb inspect ov1 | grep -x 'storage: overlay' && lb inspect ov1 | grep -x "base: $id" || return 1
    own=$(cd "$C/ov1/rootfs" && find . -type f | sort | paste -sd' ' -)
    echo "ov1's own files: $own"
    [ "$own" = './etc/hostname ./etc/hosts ./etc/resolv.conf' ] || { echo "rootfs/ has more than create wrote"; return 1; }
    start ov1 || return 1
    [ "$(sh_in ov1 'test -x /bin/busybox && cat /etc/hostname')" = ov1 ] || { echo "the base or the hostname is not there"; return 1; }
    sh_in ov1 'echo mine > /made-here && rm /etc/group' || return 1
    [ "$(cat "$C/ov1/rootfs/made-here")" = mine ] || { echo "what the container wrote is not in its rootfs/"; return 1; }
    [ ! -e "$snap/made-here" ] && [ -e "$snap/etc/group" ] || { echo "the snapshot was changed"; return 1; }
    sh_in ov1 'test ! -e /etc/group' || { echo "a file taken out in the container is still there"; return 1; }
    echo later > "$BASE/added-later"
    sh_in ov1 'test ! -e /added-later' || { rm -f "$BASE/added-later"; echo "a change of the base reached the container"; return 1; }
    rm -f "$BASE/added-later"
    lb stop ov1 >/dev/null && start ov1 || return 1
    [ "$(sh_in ov1 'cat /made-here')" = mine ] || { echo "what the container wrote did not outlast a restart"; return 1; }
}

# --copy: a copy of the base, as before 0.7, with no snapshot of its own.
t_copy_root() {
    box cp1 --copy || return 1
    [ -z "$(base_of cp1)" ] || { echo "a copy has a base snapshot: $(base_of cp1)"; return 1; }
    [ -x "$C/cp1/rootfs/bin/busybox" ] || { echo "rootfs/ is not a copy of the base"; return 1; }
    lb inspect cp1 | grep -x 'storage: copy' && lb inspect cp1 | grep -x 'base: -' || return 1
    start cp1 && [ "$(sh_in cp1 'cat /etc/hostname')" = cp1 ]
}

# base ls names each snapshot, its base and the containers on it; base rm
# refuses one that a container uses and removes one that none does; base add
# takes a new snapshot, which the containers made after it overlay.
t_base_commands() {
    OVERLAY=1
    box bu1 || return 1
    old=$(base_of bu1)
    listing=$(lb base ls) || return 1
    printf '%s\n' "$listing"
    printf '%s\n' "$listing" | grep -E "^$old  [0-9-]{10} [0-9:]{8}  $BASE  .*bu1" || { echo "base ls does not show bu1 on $old"; return 1; }
    said=$(lb base rm "$old" 2>&1) && { echo "a snapshot in use was removed"; return 1; }
    printf '%s\n' "$said"
    case $said in *"is used by: "*bu1*) ;; *) return 1 ;; esac
    said=$(lb base add "$BASE") || return 1
    printf '%s\n' "$said"
    new=$(printf '%s\n' "$said" | sed -n 's/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p')
    [ -n "$new" ] && [ "$new" != "$old" ] || { echo "base add took no new snapshot"; return 1; }
    box bu2 || return 1
    [ "$(base_of bu2)" = "$new" ] || { echo "a container made after base add does not overlay the new snapshot"; return 1; }
    [ "$(base_of bu1)" = "$old" ] || return 1
    lb rm bu1 >/dev/null && lb base rm "$old" || { echo "a snapshot that nothing uses was not removed"; return 1; }
    [ ! -e "$T/lb/bases/$old" ] || return 1
    refused lb base rm 000000000000 && refused lb base rm not-an-id
}

# ─── Cases: where the settings are ──────────────────────────────────────────

# Named by neither --config nor LIGHTBOX_CONFIG, the settings are those of
# /etc/lightbox/lightbox.conf, and a file at the old place in $HOME is said
# not to be read. /etc is an overlay in this mount namespace: nothing is
# written to the host's.
t_config_in_etc() {
    mkdir -p "$T/etc-up" "$T/etc-work" || return 1
    mount -t overlay overlay -o "lowerdir=/etc,upperdir=$T/etc-up,workdir=$T/etc-work" /etc 2>/dev/null ||
        { echo "no overlay can be put over /etc here"; return 77; }
    echo /etc >> "$T/shims"         # teardown takes it away
    mkdir -p /etc/lightbox &&
        sed 's#^bridge = .*#bridge = lbt-etc#' "$LIGHTBOX_CONFIG" > /etc/lightbox/lightbox.conf || return 1
    said=$(env -u LIGHTBOX_CONFIG "$LB" doctor 2>&1)
    printf '%s\n' "$said" | grep -E '^(Note|Warning|bridge):'
    printf '%s\n' "$said" | grep -qx 'bridge: lbt-etc' || { echo "/etc/lightbox/lightbox.conf was not read"; return 1; }
    printf '%s\n' "$said" | grep -qx "Note: $HOME/.config/lightbox/lightbox.conf is not read; /etc/lightbox/lightbox.conf is" ||
        { echo "the file in HOME was not said to be left"; return 1; }
    [ "$(lb doctor 2>/dev/null | grep '^bridge: ')" = "bridge: $BR" ] || { echo "LIGHTBOX_CONFIG did not come first"; return 1; }
    [ -f "$T/etc-up/lightbox/lightbox.conf" ] || { echo "the file is not in the overlay, but in the host's /etc"; return 1; }
}

# ─── Cases: after a reboot, and teardown ────────────────────────────────────

# What a reboot takes: the bridge, every firewall rule and chain, forwarding
# and run_dir. A start makes the host's side of the network again, as setup
# makes it, and says so; the container reaches the gateway and the outside.
t_start_after_a_reboot_of_the_network() {
    box rebuilt || return 1
    ip link delete "$BR" &&
    iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X && iptables -P FORWARD ACCEPT &&
    echo 0 > /proc/sys/net/ipv4/ip_forward || return 1
    rm -rf -- "$RUN"
    start rebuilt || return 1
    grep -q 'making it again' "$OUT/rebuilt.start" || { echo "start did not say that it made the network again"; return 1; }
    ip -o -4 addr show dev "$BR" | grep -q " $GW/24 " || { echo "the bridge is not there with $GW/24"; return 1; }
    iptables -C FORWARD -j LIGHTBOX-USER && iptables -C FORWARD -j LIGHTBOX-FORWARD &&
    iptables -t nat -C POSTROUTING -j LIGHTBOX-POSTROUTING || { echo "lightbox's jumps are not there"; return 1; }
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] && [ "$(iptables -S FORWARD | head -n 1)" = '-P FORWARD DROP' ] ||
        { echo "forwarding is not on with the FORWARD policy at DROP"; return 1; }
    if [ -e "$T/have_nc" ]; then
        reaches rebuilt "$GW" && reaches rebuilt "$OUTSIDE"
    else
        echo "this image has no nc: whether the container reaches anything is not tried"
    fi
}

# A start where everything is there looks once, and makes nothing.
t_start_with_the_network_there() {
    up steady || return 1
    ! grep -q 'making it again' "$OUT/steady.start" || { echo "start made the network again, which was there"; return 1; }
}

# With nftables: a firewall service that flushes the ruleset, and the bridge
# gone. A start makes the tables and the bridge again, and links hold.
t_nft_start_after_the_tables_went() {
    need_nc || return 77
    nft_setup nftre; rc=$?; [ $rc = 0 ] || return $rc
    box nrepeer && box nrelinked --link nrepeer || return 1
    ip link delete "$BR" && nft delete table ip lightbox && nft delete table bridge lightbox || return 1
    LIGHTBOX_CONFIG="$ALT_CONF" start nrepeer || return 1
    grep -q 'making it again' "$OUT/nrepeer.start" || { echo "start did not say that it made the network again"; return 1; }
    nft list table ip lightbox >/dev/null && nft list table bridge lightbox >/dev/null && ip link show dev "$BR" >/dev/null ||
        { echo "the tables or the bridge are not there"; return 1; }
    LIGHTBOX_CONFIG="$ALT_CONF" start nrelinked || return 1
    reaches nrelinked "$(addr_of nrepeer)" && reaches nrelinked "$OUTSIDE"
}

# iptables as it is, without counters and comments
saved_rules() { iptables-save | grep -v '^#' | sed -E 's/ \[[0-9]+:[0-9]+\]$//'; }

# what a firewall's reload or flush does to lightbox's rules, its policy left
flush_firewall() {
    iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X
}

# A firewall's flush took lightbox's rules while containers ran, and the link
# no longer holds. reload puts in again what setup made and the links of the
# linked container that runs, as they were, and a second reload changes
# nothing. A container without links has none to put back.
t_reload_puts_back_what_a_flush_took() {
    need_nc || return 77
    up rlpeer && up rllinked --link rlpeer && up rlalone || return 1
    reaches rllinked "$(addr_of rlpeer)" || { echo "the link did not hold before the flush"; return 1; }
    before=$(saved_rules)
    flush_firewall || return 1
    ! reaches rllinked "$(addr_of rlpeer)" || { echo "the link held without its rules"; return 1; }
    lb reload >"$OUT/reload" 2>&1 || { cat "$OUT/reload"; return 1; }
    cat "$OUT/reload"
    grep -qx "The links of container 'rllinked' are in again" "$OUT/reload" || return 1
    ! grep -q "'rlalone'\|'rlpeer'" "$OUT/reload" || { echo "reload put in links of a container that has none"; return 1; }
    [ "$(saved_rules)" = "$before" ] ||
        { echo "the rules are not as they were:"; diff <(printf '%s\n' "$before") <(saved_rules); return 1; }
    reaches rllinked "$(addr_of rlpeer)" && reaches rllinked "$OUTSIDE" || return 1
    lb reload >"$OUT/reload2" 2>&1 || { cat "$OUT/reload2"; return 1; }
    [ "$(saved_rules)" = "$before" ] ||
        { echo "a second reload changed the rules:"; diff <(printf '%s\n' "$before") <(saved_rules); return 1; }
    reaches rllinked "$(addr_of rlpeer)"
}

# The same flush, and then a start: it makes setup's rules again, puts back
# the links of the linked container that runs, and leaves the rules as they
# were before the flush.
t_start_after_a_flush_puts_back_links() {
    need_nc || return 77
    up sfpeer && up sflinked --link sfpeer || return 1
    before=$(saved_rules)
    flush_firewall || return 1
    up sfnew || return 1
    grep -q 'making it again' "$OUT/sfnew.start" && grep -qx "The links of container 'sflinked' are in again" "$OUT/sfnew.start" ||
        { echo "start did not make the network again and put back the links"; return 1; }
    [ "$(saved_rules)" = "$before" ] ||
        { echo "the rules are not as they were:"; diff <(printf '%s\n' "$before") <(saved_rules); return 1; }
    reaches sflinked "$(addr_of sfpeer)"
}

# With nftables: the tables went while a linked container ran. reload makes
# them again, with the container's link in the set.
t_nft_reload() {
    need_nc || return 77
    nft_setup nftrl; rc=$?; [ $rc = 0 ] || return $rc
    box nrlpeer && box nrllinked --link nrlpeer || return 1
    LIGHTBOX_CONFIG="$ALT_CONF" start nrlpeer && LIGHTBOX_CONFIG="$ALT_CONF" start nrllinked || return 1
    port=$(port_of nrllinked)
    nft delete table ip lightbox && nft delete table bridge lightbox || return 1
    alt_lb reload >"$OUT/nreload" 2>&1 || { cat "$OUT/nreload"; return 1; }
    cat "$OUT/nreload"
    grep -qx "The links of container 'nrllinked' are in again" "$OUT/nreload" || return 1
    nft list set bridge lightbox links
    nft list set bridge lightbox links | grep -qF "\"$port\"" || { echo "the link is not in the set"; return 1; }
    reaches nrllinked "$(addr_of nrlpeer)" && reaches nrllinked "$OUTSIDE"
}

# ─── Cases: user namespaces ─────────────────────────────────────────────────

# --userns on an overlay: the container's ids are the first range of the
# suite's /etc/subuid and /etc/subgid, on record in its .conf; its init is that
# uid on the host and root in it. The snapshot's files are its root's, and
# keep their other ids (4711 stays 4711); what it makes is in its upper layer,
# owned on the host by its range, and the snapshot stays host root's.
t_userns_overlay() {
    need_subids || return 77
    OVERLAY=1
    box unover --userns || return 1
    cat "$C/unover/.conf"
    u=$(conf_value unover uid_start) g=$(conf_value unover gid_start)
    [ "$(conf_value unover userns)" = 1 ] && [ "$u" = 2147483647 ] && [ "$g" = 2147483647 ] ||
        { echo "the range on record is not the first of the suite's"; return 1; }
    base=$(conf_value unover base)
    [ -n "$base" ] || { echo "the container is not an overlay"; return 1; }
    [ "$(stat -c %u:%g "$C/unover/rootfs")" = "$u:$g" ] && [ "$(stat -c %u:%g "$C/unover/rootfs/etc/hostname")" = "$u:$g" ] ||
        { echo "the upper layer and the files create wrote are not the container root's: $(stat -c %u:%g "$C/unover/rootfs" "$C/unover/rootfs/etc/hostname" | paste -sd' ')"; return 1; }
    start unover || return 1
    pid=$(pid_of unover)
    echo "init on the host: $(host_ids_of "$pid")"
    [ "$(host_ids_of "$pid")" = "$u $g" ] || { echo "init is not the container's root on the host"; return 1; }
    map=$(sh_in unover 'cat /proc/self/uid_map /proc/self/gid_map' | awk '{ print $1, $2, $3 }' | paste -sd'|')
    echo "maps: $map"
    [ "$map" = "0 $u 65536|0 $g 65536" ] || return 1
    inside=$(sh_in unover 'id -u; id -g; stat -c %u:%g /bin /etc/hostname /home/lbuser' | paste -sd' ')
    echo "in it: $inside"
    [ "$inside" = '0 0 0:0 0:0 4711:4711' ] || return 1
    sh_in unover 'echo made > /made && mkdir /dir && chown 4711:4712 /dir' || return 1
    [ "$(stat -c %u:%g "$C/unover/rootfs/made")" = "$u:$g" ] &&
        [ "$(stat -c %u:%g "$C/unover/rootfs/dir")" = "$((u + 4711)):$((g + 4712))" ] ||
        { echo "what the container made is not its range's on the host: $(stat -c %u:%g "$C/unover/rootfs/made" "$C/unover/rootfs/dir" | paste -sd' ')"; return 1; }
    [ "$(stat -c %u "$T/lb/bases/$base/rootfs/bin")" = 0 ] && [ ! -e "$T/lb/bases/$base/rootfs/made" ] ||
        { echo "the snapshot changed"; return 1; }
    [ "$(lb exec unover --user 4711 /bin/sh -c 'id -u' </dev/null)" = 4711 ] || { echo "exec --user is not that user in it"; return 1; }
    lb stop unover >/dev/null && lb rm unover >/dev/null || return 1
    nothing_left unover
}

# --userns with --copy: the copy is idmapped as it is, so its files are the
# container's root's in it and keep the base's ids on the host, and what the
# container makes is stored with the ids it has in the container.
t_userns_copy() {
    need_subids || return 77
    box uncopy --userns --copy || return 1
    [ -z "$(conf_value uncopy base)" ] && [ "$(conf_value uncopy userns)" = 1 ] || { echo "not a copy with --userns"; return 1; }
    u=$(conf_value uncopy uid_start) g=$(conf_value uncopy gid_start)
    start uncopy || return 1
    [ "$(host_ids_of "$(pid_of uncopy)")" = "$u $g" ] || { echo "init is not the container's root on the host"; return 1; }
    inside=$(sh_in uncopy 'id -u; stat -c %u:%g /bin /home/lbuser; echo made > /made' | paste -sd' ')
    echo "in it: $inside"
    [ "$inside" = '0 0:0 4711:4711' ] || return 1
    [ "$(stat -c %u:%g "$C/uncopy/rootfs/made")" = 0:0 ] || { echo "/made is $(stat -c %u:%g "$C/uncopy/rootfs/made") on the host"; return 1; }
    lb stop uncopy >/dev/null && lb rm uncopy >/dev/null || return 1
    nothing_left uncopy
}

# Two containers with --userns get two ranges, the second after the first,
# and one without it gets none.
t_userns_ranges_apart() {
    need_subids || return 77
    box unone --userns && box untwo --userns && PLAIN=1 box unnone || return 1
    echo "unone: $(conf_value unone uid_start) $(conf_value unone gid_start); untwo: $(conf_value untwo uid_start) $(conf_value untwo gid_start)"
    [ "$(conf_value untwo uid_start)" = $(( $(conf_value unone uid_start) + 65536 )) ] &&
        [ "$(conf_value untwo gid_start)" = $(( $(conf_value unone gid_start) + 65536 )) ] || return 1
    [ -z "$(conf_value unnone userns)$(conf_value unnone uid_start)" ] || { echo "a container without --userns has a range"; return 1; }
}

# Without a range for lightbox, create --userns says what to add, and makes
# nothing.
t_userns_without_a_range() {
    need_subids || return 77
    printf 'someone:100000:65536\n' > "$T/norange"
    mount --bind "$T/norange" /etc/subuid && echo /etc/subuid >> "$T/shims" || return 1
    ip=$(next_ip) || return 1
    said=$(lb create unrange "$ip" --userns 2>&1) && { echo "create --userns went ahead"; return 1; }
    printf '%s\n' "$said"
    case $said in *"no range of host ids"*"lightbox:2147483647:2147483648"*) ;; *) return 1 ;; esac
    [ ! -e "$C/unrange" ] || { echo "it left the container"; return 1; }
}

# setup --teardown does nothing while a container runs, and says which. With
# none running it takes away all that setup and the containers made: the
# interfaces are those there were before the first setup, no rule or chain of
# lightbox's is left, in iptables or nftables, and cgroup_base is gone. What
# setup changed of forwarding stays, and is said. A container that is only
# stopped stays as it is, and starts again, which makes the network again.
t_setup_teardown() {
    box kept && up busy || return 1
    said=$(lb setup --teardown 2>&1) && { printf '%s\n' "$said"; echo "teardown went ahead with a container running"; return 1; }
    printf '%s\n' "$said"
    case $said in *"container 'busy' is running"*) ;; *) return 1 ;; esac
    ip link show dev "$BR" >/dev/null || { echo "a teardown that was refused took the bridge away"; return 1; }
    lb stop busy >/dev/null || return 1
    # forwarding as before the first setup, so that setup turns it on and says so
    echo 0 > /proc/sys/net/ipv4/ip_forward && iptables -P FORWARD ACCEPT && lb setup >/dev/null || return 1
    nft_ok >/dev/null 2>&1 && { nft add table ip lightbox && nft add table bridge lightbox || return 1; }
    said=$(lb setup --teardown 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    links_now | diff "$T/links.before" - || { echo "the interfaces are not those there were before the first setup"; return 1; }
    left=$(iptables-save | grep -E '^(-A |:LIGHTBOX|:LB-)')
    [ -z "$left" ] || { echo "left in iptables:"; printf '%s\n' "$left"; return 1; }
    ! nft list tables 2>/dev/null | grep -q ' lightbox$' || { echo "left in nftables: $(nft list tables)"; return 1; }
    [ ! -d "$CG" ] || { echo "cgroup_base $CG is left"; return 1; }
    case $said in *'sysctl -w net.ipv4.ip_forward=0 && iptables -P FORWARD ACCEPT'*) ;; *)
        echo "teardown did not say what setup changed of forwarding"; return 1 ;; esac
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || { echo "teardown turned forwarding off"; return 1; }
    [ -e "$C/kept/.conf" ] || { echo "the stopped container was taken away"; return 1; }
    start kept
}

# ─── Cases: firewall_backend = nftables ─────────────────────────────────────

# Can this host have lightbox's tables: nft, and nf_tables with the bridge
# family and its meta match, in this network namespace?
nft_ok() {
    command -v nft >/dev/null 2>&1 || { echo "nft is not installed"; return 1; }
    printf '%s\n' 'table bridge lbt-probe {' '  chain f {' '    type filter hook forward priority filter; policy accept;' \
        '    meta ibrname "lbt-x" accept' '  }' '}' | nft -f - ||
        { echo "nf_tables here has no bridge family, or no meta ibrname"; return 1; }
    nft delete table bridge lbt-probe
}

# A lightbox.conf of the suite's with firewall_backend = nftables, and setup
# with it. As Docker asks of its nftables backend, the iptables FORWARD
# policy that drops (t_setup set it) is ACCEPT; teardown puts it back.
nft_setup() { # directory name, settings...
    nft_ok || return 77
    local dir=$1
    shift
    alt_conf "$dir" 'firewall_backend = nftables' "$@" || return 1
    iptables -P FORWARD ACCEPT || return 1
    alt_lb setup >"$OUT/$dir.setup" 2>&1 || { cat "$OUT/$dir.setup"; return 1; }
}

# setup makes lightbox's two tables and takes out what lightbox had in
# iptables, but for the host's LIGHTBOX-USER. A FORWARD policy that drops
# what nftables accepts is said, by setup and by doctor. A second setup
# changes nothing, and one with iptables takes the tables away again.
t_nft_setup() {
    nft_ok || return 77
    alt_conf nft 'firewall_backend = nftables' || return 1
    said=$(alt_lb setup 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    nft list table ip lightbox && nft list table bridge lightbox || return 1
    nft list chain ip lightbox forward | grep -qF "oifname \"$BR\" iifname != \"$BR\" drop" &&
    nft list chain ip lightbox forward | grep -qF "oifname \"$BR\" ct state established,related accept" &&
    nft list chain ip lightbox postrouting | grep -qF "ip saddr $SUBNET oifname != \"$BR\" masquerade" &&
    nft list chain bridge lightbox forward | grep -qF "ibrname \"$BR\" iifname . oifname @links accept" &&
    nft list chain bridge lightbox forward | grep -qF "ibrname \"$BR\" drop" || { echo "a rule is missing"; return 1; }
    iptables -n -L LIGHTBOX-FORWARD >/dev/null 2>&1 && { echo "LIGHTBOX-FORWARD is left"; return 1; }
    iptables -n -L LIGHTBOX-LINKS >/dev/null 2>&1 && { echo "LIGHTBOX-LINKS is left"; return 1; }
    iptables -t nat -n -L LIGHTBOX-POSTROUTING >/dev/null 2>&1 && { echo "LIGHTBOX-POSTROUTING is left"; return 1; }
    iptables -C FORWARD -j LIGHTBOX-USER || { echo "the host's LIGHTBOX-USER lost its jump"; return 1; }
    case $said in *'iptables FORWARD'*'iptables -P FORWARD ACCEPT'*) ;; *) echo "setup did not name the FORWARD policy that drops"; return 1 ;; esac
    alt_lb doctor | grep -x 'forward_drops: iptables FORWARD' || { echo "doctor did not name it"; return 1; }
    tables() { nft list table ip lightbox; nft list table bridge lightbox; }
    before=$(tables)
    alt_lb setup >/dev/null 2>&1 || return 1
    [ "$before" = "$(tables)" ] || { echo "a second setup changed the tables:"; tables; return 1; }
    said=$(lb setup 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    ! nft list tables | grep -q ' lightbox$' || { echo "left: $(nft list tables)"; return 1; }
    iptables -C FORWARD -j LIGHTBOX-FORWARD && iptables -t nat -C POSTROUTING -j LIGHTBOX-POSTROUTING
}

# Where nothing passes bridged traffic through iptables, linked containers
# reach each other and a third reaches neither. The peer has no link of its
# own and so an isolated port, as the third has: the bridge keeps those two
# apart. Between the third and the linked one, which shares the bridge, it is
# the bridge table that decides. Out, through nftables' masquerading.
t_nft_links_without_brnf() {
    need_nc || return 77
    if [ -e "$BRNF" ]; then brnf 0 || return 1; fi
    nft_setup nftlinks; rc=$?; [ $rc = 0 ] || return $rc
    box npeer && box nlinked --link npeer && box nthird || return 1
    LIGHTBOX_CONFIG="$ALT_CONF" start npeer && LIGHTBOX_CONFIG="$ALT_CONF" start nlinked && LIGHTBOX_CONFIG="$ALT_CONF" start nthird || return 1
    nft list set bridge lightbox links
    reaches nlinked "$(addr_of npeer)" && reaches npeer "$(addr_of nlinked)" || return 1
    reaches nthird "$(addr_of nlinked)" && { echo "a container without the link reached nlinked"; return 1; }
    reaches nthird "$(addr_of npeer)" && { echo "a container without the link reached npeer"; return 1; }
    reaches nthird "$OUTSIDE" || { echo "the outside was not reached through masquerading"; return 1; }
    alt_lb stop nlinked >/dev/null && nothing_left nlinked
}

# A start puts in a container's links with one process, nft.
t_nft_one_process() {
    command -v strace >/dev/null 2>&1 || { echo "no strace to watch a start with"; return 77; }
    nft_setup nftone; rc=$?; [ $rc = 0 ] || return $rc
    box nonepeer && box nonelinked --link nonepeer || return 1
    is_up() { [ "$(state_of nonelinked 2>/dev/null)" = running ]; }
    LIGHTBOX_CONFIG="$ALT_CONF" timeout -k 5 80 strace -f -qq -e trace=execve -o "$T/nftlinks.strace" \
        "$LB" start nonelinked >"$OUT/nonelinked.start" 2>&1 </dev/null &
    tracer=$!
    wait_until 60 is_up || { echo "the container did not start under strace:"; cat "$OUT/nonelinked.start"; kill "$tracer" 2>/dev/null; return 1; }
    settled nonelinked || return 1
    alt_lb stop nonelinked >/dev/null 2>&1 || { echo "stop failed"; return 1; }
    wait "$tracer"
    # but for the look at whether setup's tables are there, which every start has
    tools=$(grep -E 'execve\("[^"]*/(ip6?tables[^"]*|nft)"' "$T/nftlinks.strace" | grep -v ' = -1 ' |
            grep -v '"list", "tables"')
    printf '%s\n' "$tools"
    [ "$(printf '%s\n' "$tools" | grep -c .)" = 1 ] && printf '%s\n' "$tools" | grep -q '/nft"'
}

# rm of a container whose init died takes its links out of the set, by its
# record, and leaves the peer's in.
t_nft_rm_leaves_nothing() {
    nft_setup nftrm; rc=$?; [ $rc = 0 ] || return $rc
    box nrpeer --link nrmain && box nrmain --link nrpeer && box nrother --link nrpeer || return 1
    LIGHTBOX_CONFIG="$ALT_CONF" start nrpeer && LIGHTBOX_CONFIG="$ALT_CONF" start nrmain && LIGHTBOX_CONFIG="$ALT_CONF" start nrother || return 1
    port=$(port_of nrmain) other=$(port_of nrother)
    nft list set bridge lightbox links
    nft list set bridge lightbox links | grep -qF "\"$port\"" || { echo "the link is not in the set"; return 1; }
    echo "the record: $(cat "$RUN/nrmain/firewall")"
    pid=$(pid_of nrmain)
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || return 1
    alt_lb rm nrmain || return 1
    nft list set bridge lightbox links
    ! nft list set bridge lightbox links | grep -qF "\"$port\"" || { echo "an element naming $port is left"; return 1; }
    nft list set bridge lightbox links | grep -qF "\"$other\"" || { echo "the link of nrother went with it"; return 1; }
    [ ! -e "$RUN/nrmain" ] || { echo "left in run_dir: $(ls -A "$RUN/nrmain")"; return 1; }
    # the peer linked to nrmain as well, and its stop finds that pair gone;
    # nrother's pair with it is nrother's, and goes when nrother stops
    alt_lb stop nrother >/dev/null && alt_lb stop nrpeer >/dev/null && nothing_left nrpeer && nothing_left nrother
}

# As Docker with nftables: setup does not turn forwarding on, and with it
# off and ip_forward = true it stops before it changes anything.
t_nft_forwarding() {
    nft_ok || return 77
    alt_conf nftfwd 'firewall_backend = nftables' || return 1
    echo 0 > /proc/sys/net/ipv4/ip_forward || return 1
    before=$(nft list tables)
    said=$(alt_lb setup 2>&1) && { printf '%s\n' "$said"; echo "setup went ahead with forwarding off"; return 1; }
    printf '%s\n' "$said"
    case $said in *'IPv4 forwarding is off'*'ip_forward = false'*) ;; *) return 1 ;; esac
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] || { echo "setup turned forwarding on"; return 1; }
    [ "$before" = "$(nft list tables)" ] || { echo "setup changed the firewall before it stopped"; return 1; }
    alt_conf nftfwd 'firewall_backend = nftables' 'ip_forward = false' || return 1
    said=$(alt_lb setup 2>&1) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ] || { echo "setup turned forwarding on"; return 1; }
    nft list table bridge lightbox >/dev/null
}

# What comes in from outside to a container is dropped; with
# bridge_accept_fwmark, what a chain of the host's marks before lightbox's
# chains is accepted.
t_nft_accept_fwmark() {
    command -v ping >/dev/null 2>&1 || { echo "no ping to try the way in with"; return 77; }
    nft_setup nftmark 'bridge_accept_fwmark = 0x10/0xf0'; rc=$?; [ $rc = 0 ] || return $rc
    box nmarked && LIGHTBOX_CONFIG="$ALT_CONF" start nmarked || return 1
    ip=$(addr_of nmarked) outside=$(cat "$T/outside")
    nsenter -t "$outside" -n ip route add "$SUBNET" via 192.0.2.2 || return 1
    nsenter -t "$outside" -n ping -c 1 -W 2 "$ip" && { echo "a new connection from outside was not dropped"; return 1; }
    nft -f - <<EOF || return 1
table ip lbt-mine {
    chain tagging {
        type filter hook forward priority filter - 1; policy accept;
        ip daddr $ip meta mark set 0x13
    }
}
EOF
    nsenter -t "$outside" -n ping -c 1 -W 2 "$ip" || { echo "the marked packets were not accepted"; return 1; }
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
    # as on a host that forwards nothing until lightbox's setup
    echo 0 > /proc/sys/net/ipv4/ip_forward || return 1
    # A second namespace stands for the internet: setup wants a default route,
    # and address translation needs somewhere to go.
    unshare --net -- sleep 86400 >/dev/null 2>&1 </dev/null &
    local outside=$!
    echo "$outside" > "$T/outside"
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
    build_rootfs && network && links_now > "$T/links.before" && mask_ip_and_nsenter && subids
}

# The ranges a container with --userns takes its ids from: the suite's own
# /etc/subuid and /etc/subgid over the host's, in this mount namespace only,
# with one range for lightbox, as README says to add it. A host without the
# two files has nothing to put them over: the cases of --userns skip, and
# with LIGHTBOX_TEST_USERNS the suite does not run.
SUBIDS='lightbox:2147483647:2147483648'
subids() {
    [ -e /etc/subuid ] && [ -e /etc/subgid ] || return 0
    printf 'someone:100000:65536\n%s\n' "$SUBIDS" > "$T/subids" &&
        mount --bind "$T/subids" /etc/subuid && mount --bind "$T/subids" /etc/subgid && : > "$T/have_subids"
}

need_subids() {
    [ -e "$T/have_subids" ] || { echo "this host has no /etc/subuid and /etc/subgid for the suite's range"; return 77; }
}

# a process's uid and gid on the host
host_ids_of() { awk '/^Uid:/ { u = $2 } /^Gid:/ { g = $2 } END { print u, g }' "/proc/$1/status"; }

# lightbox runs neither ip nor nsenter since 0.7 (ROADMAP 7.2). In this mount
# namespace both are stand-ins that note who ran them and fail, so that a
# command of lightbox's that ran one fails where it ran it, and a case at the
# end looks at the notes. The suite looks with the real ones, copied to
# $T/bin, which is first in PATH.
mask_ip_and_nsenter() {
    local tool path real masked=" "
    mkdir -p "$T/bin" "$T/mask" && : > "$T/masked.ran" || return 1
    for tool in ip nsenter; do
        path=$(type -P "$tool") && cp -L "$path" "$T/bin/$tool" || return 1
        printf '#!/bin/sh\necho "%s $*" >> %s\nexit 127\n' "$tool" "'$T/masked.ran'" > "$T/mask/$tool" &&
            chmod 755 "$T/mask/$tool" || return 1
        for path in "/sbin/$tool" "/usr/sbin/$tool" "/bin/$tool" "/usr/bin/$tool"; do
            [ -e "$path" ] || continue
            real=$(readlink -f "$path")
            case $masked in *" $real "*) continue ;; esac
            mount --bind "$T/mask/$tool" "$real" || return 1
            masked="$masked$real "
        done
    done
    export PATH="$T/bin:$PATH"
}

# Every case ran with ip and nsenter masked: nothing ran either of them.
t_no_ip_or_nsenter_ran() {
    local tool path
    [ -e "$T/masked.ran" ] || { echo "ip and nsenter were not masked"; return 1; }
    for tool in ip nsenter; do
        for path in "/sbin/$tool" "/usr/sbin/$tool" "/bin/$tool" "/usr/bin/$tool"; do
            [ -e "$path" ] || continue
            cmp -s "$path" "$T/mask/$tool" || { echo "$path is not the stand-in"; return 1; }
        done
    done
    [ ! -s "$T/masked.ran" ] || { echo "ran with ip and nsenter masked:"; cat "$T/masked.ran"; return 1; }
}

kill_cgroup() { # directory, after every cgroup below it
    [ -d "$1" ] || return 0
    local sub
    for sub in "$1"/*/; do
        [ -d "$sub" ] && kill_cgroup "${sub%/}"
    done
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
    for p in $(ip -o link show | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }' | grep -E "^(vb-|ve-|lbt-foreign\$|$WIDE_BR\$)"); do
        ip link delete "$p"
    done
    put_the_bridge_back
    [ -s "$T/firewall" ] && iptables-restore < "$T/firewall"
    # what a case of firewall_backend = nftables made, and the forwarding
    # setup turned on, which a case may have turned off
    for p in "ip lightbox" "bridge lightbox" "ip lbt-mine"; do
        nft list table $p >/dev/null 2>&1 && nft delete table $p
    done
    echo 1 > /proc/sys/net/ipv4/ip_forward
    nsenter -t "$(cat "$T/outside")" -n ip route del "$SUBNET"
    [ -w "$BRNF" ] && echo 1 > "$BRNF"
    find "$C" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    # and the records of the ones that ran; a case may have taken run_dir away
    [ -d "$RUN" ] && find "$RUN" -mindepth 1 -maxdepth 1 ! -name .forwarding -exec rm -rf -- {} +
    rm -f "$T/restore.reached" "$T/mount.ran"
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
    SUITE=lifecycle
    case $USERNS_MODE in
        overlay) SUITE="lifecycle with --userns"
                 echo "lifecycle: every container with --userns" ;;
        copy)    SUITE="lifecycle with --userns --copy"
                 echo "lifecycle: every container with --userns, and with --copy but in the cases about overlays" ;;
    esac
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
        summary "$SUITE"
        exit 1
    fi
    iptables-save > "$T/firewall"

    check 'setup again changes no mount and adds no rule'                 t_setup_again
    check 'setup refuses a cgroup_root that is not cgroup v2'             t_setup_refuses_other_cgroup_root
    check 'setup refuses a gateway outside the subnet, and changes nothing' t_setup_refuses_a_gateway_outside
    check 'setup takes out the rules lightbox 0.4 put in FORWARD and POSTROUTING' t_setup_takes_out_old_rules
    check 'ip_forward_no_drop = true leaves the FORWARD policy'           t_ip_forward_no_drop
    check 'firewall = false: no rule is made, and a container with links is refused' t_firewall_false
    check 'doctor finds nothing missing'                                  t_doctor
    check 'doctor names each precondition of start that is broken, and its fix' t_doctor_names_what_is_missing

    check 'create, start, exec, stop and rm'                              t_lifecycle
    check 'start and stop take several names, and name those they could not do' t_several_names
    check 'update changes the limits of a running container, and they outlast a restart' t_update_live
    check 'restart stops a running container and starts it, and starts a stopped one' t_restart
    check 'rm -f kills a running container and removes it'                t_rm_force
    check 'ls and inspect show a running container'                       t_queries_show_running
    check 'inspect --json of a running container has its init, as numbers'  t_inspect_json_running
    check 'exec returns the exit status of the command'                   t_exec_status
    check 'exec without a command runs a shell on standard input'         t_exec_default_shell
    check 'a container has its own hostname, processes and root'          t_own_world
    check 'a running container cannot be started again or removed'        t_running_container_is_protected
    check 'a stopped container starts again and keeps its files'          t_restart_keeps_files
    check 'a container whose init died starts again'                      t_start_after_init_died
    check 'stop of a container whose init died clears it away, as failed' t_stop_of_a_dead_container_cleans_up
    check 'a container stopped from inside is exited, and cleared away by the next command' t_stopped_from_inside_is_exited
    check 'after a reboot containers are stopped, and start'              t_after_a_reboot
    check 'a container started before the upgrade is seen, and stopped'   t_container_started_before_the_upgrade
    check 'a container that create did not finish is not started'         t_half_made_container_is_not_started
    check 'a process in the container cannot get at what init has open'   t_init_is_closed_to_the_container
    check 'of two starts at once, one starts the container and one finds it running' t_two_starts_at_once
    check 'a start that fails leaves no interface, cgroup or runtime file' t_failed_start_leaves_nothing

    check 'exec --user takes a name or a number and sets groups and HOME' t_exec_user
    check 'exec keeps none of the caller'"'"'s groups, with --user or without' t_exec_unknown_uid_drops_groups
    check 'exec --user refuses a malformed value, and names a missing one' t_exec_user_is_strict
    check 'exec finds an account late in the container'"'"'s passwd'           t_exec_finds_a_late_account
    check 'exec finds a command on PATH'                                  t_exec_searches_path
    check 'exec passes every argument'                                    t_exec_passes_every_argument
    check 'exec sets --env and --workdir, and passes TERM and nothing else' t_exec_environment
    check 'exec runs from a sealed copy of the binary'                    t_exec_runs_from_a_sealed_copy
    check 'on a terminal, exec gives the command a terminal of the container'"'"'s' t_exec_on_a_terminal
    check 'typed input and the interrupt key reach the command; a pipe for half a terminal' t_exec_terminal_input_and_keys
    check 'a command leads its own session, and a signal for exec reaches it' t_exec_session_and_signals

    check 'a directory volume is shared in both directions'               t_volume_directory
    check 'a file volume is mounted'                                      t_volume_file
    check 'a read-only volume cannot be written'                          t_volume_read_only
    check 'add-vol takes effect at the next start'                        t_addvol_applies_at_next_start
    check 'rm-vol takes effect at the next start'                         t_rmvol_applies_at_next_start
    check 'a container from before the version line starts as it is'      t_conf_from_before_starts
    check 'a configuration that cannot be used: no start, no exec, a stop' t_unusable_conf
    check 'a start opens the container'"'"'s configuration once and waits for no disk' t_start_reads_conf_once
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

    check 'limits reach the cgroup, without swap, and the oom score init and exec' t_limits
    check '--io-max reaches io.max'                                        t_io_limit
    check 'past its memory limit a process is killed, and its container with it' t_past_the_memory_limit
    check 'without io, a container starts and is told once; with an I/O limit, not' t_without_io_controller
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
    check 'on a /16, a container far from the gateway has its prefix and reaches it' t_wide_subnet
    check 'the host'"'"'s own rules in LIGHTBOX-USER decide first, and setup keeps them' t_user_chain
    check 'a host firewall that drops the rest does not stop the bridge'   t_host_firewall_drops_the_rest
    check 'ip_masq = false: nothing is masqueraded'                       t_ip_masq_false
    check 'containers cannot reach each other when bridged traffic is filtered' t_isolated_when_filtered
    check 'containers cannot reach each other without br_netfilter'      t_isolated_when_not_filtered
    check 'a container with a link is refused where nothing filters bridged traffic' t_link_needs_filtering
    check 'linked containers reach each other, and a third reaches neither' t_linked_containers
    check 'a link to a container created later applies'                  t_link_to_later_container
    check 'a start puts in its link rules with one process'               t_link_rules_in_one_process
    check 'rm of a dead container leaves no firewall rule'                t_rm_leaves_no_rule
    check 'start leaves alone an interface it did not create, and says so' t_start_spares_foreign_interface
    check 'a start that fails at the bridge takes away the interface it made' t_start_fails_at_the_bridge
    check 'the interface in the container is eth0'                       t_interface_is_eth0
    check 'the host'"'"'s end of the interface carries lightbox'"'"'s alias'  t_interface_is_tagged
    check 'a name of 30 characters works from create to rm'              t_long_name
    check 'a container has no IPv6 address'                               t_no_ipv6_in_container

    check 'nftables: setup makes the two tables, and takes lightbox'"'"'s iptables chains out' t_nft_setup
    check 'nftables: linked containers reach each other without br_netfilter, a third neither' t_nft_links_without_brnf
    check 'nftables: a start puts in its links with one process'          t_nft_one_process
    check 'nftables: rm of a dead container takes its links out of the set' t_nft_rm_leaves_nothing
    check 'nftables: setup does not turn forwarding on, as Docker does not' t_nft_forwarding
    check 'nftables: what comes in is dropped, and bridge_accept_fwmark accepts it' t_nft_accept_fwmark
    check 'after a reboot took the network, start makes it again'         t_start_after_a_reboot_of_the_network
    check 'a start where the network is there makes nothing'              t_start_with_the_network_there
    check 'nftables: after the tables went, start makes them again'       t_nft_start_after_the_tables_went
    check 'reload puts back what a flush took: setup'"'"'s rules and the links of running containers' t_reload_puts_back_what_a_flush_took
    check 'a start after a flush makes the rules again and puts back running containers'"'"' links' t_start_after_a_flush_puts_back_links
    check 'nftables: reload makes the tables again, with the links of running containers' t_nft_reload
    check '--userns on an overlay: root in it is its range on the host, and its files are' t_userns_overlay
    check '--userns with --copy: the copy is idmapped, and init is its range on the host' t_userns_copy
    check 'containers with --userns get ranges apart, and one without gets none' t_userns_ranges_apart
    check 'without a range for lightbox, create --userns says what to add'  t_userns_without_a_range
    check 'setup --teardown leaves the host as before the first setup'    t_setup_teardown
    check 'without --config or LIGHTBOX_CONFIG, /etc/lightbox/lightbox.conf is read' t_config_in_etc
    check 'a container overlays a snapshot of its base, and keeps its own files apart' t_overlay_root
    check '--copy makes a container a copy of its base'                   t_copy_root
    check 'base ls, base rm and base add manage the snapshots'            t_base_commands
    check 'no case ran ip or nsenter, which were masked in every one'     t_no_ip_or_nsenter_ran

    # last: it may leave a kernel setting changed for the rest of this suite's life
    check 'exec works where a memfd may not be executed'                  t_exec_where_memfds_may_not_be_executed

    summary "$SUITE"
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

    case ${LIGHTBOX_TEST_USERNS:-} in
        '') ;;
        overlay|copy)
            [ -e /etc/subuid ] && [ -e /etc/subgid ] ||
                stop_early "LIGHTBOX_TEST_USERNS needs an /etc/subuid and an /etc/subgid to put the suite's own over" ;;
        *)  stop_early "LIGHTBOX_TEST_USERNS is overlay or copy, not: $LIGHTBOX_TEST_USERNS" ;;
    esac

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

# lightbox enables controllers at the cgroup root, which its containers' cgroups
# need, and leaves them enabled. Switch off the ones that were off before.
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
