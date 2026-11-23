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
# Every image, the suite's own or one of LIGHTBOX_TEST_ROOTFS, gets that busybox
# at /lbt/busybox too, and a case that looks at the network from inside a
# container runs its nc, ip and hostname from there. What an image has of its
# own differs: Debian's has none of the three, and Alpine's nc says nothing of
# a refusal. Everything else a case runs in a container is the image's own.
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
#   LIGHTBOX_TEST_IMAGE=/path   an image of a registry's, as an OCI image layout that
#                               tests/fetch_image.sh --oci fetched: one case makes it a
#                               base (ROADMAP I.9), and is skipped without it
#   LIGHTBOX_TEST_USERNS=overlay
#                               make every container with --userns: every case is
#                               then one of a container whose root is an
#                               unprivileged uid of the host's (ROADMAP 8.1)
#   LIGHTBOX_TEST_USERNS=copy   the same, and with --copy but in the cases about
#                               overlays
#   LIGHTBOX_TEST_SECCOMP=deny  make every container with --seccomp deny, but where
#                               a case chooses the profile (ROADMAP 8.3); with
#                               either of the two above, or alone. Without it a
#                               container has the default, the allow-list, which
#                               =allow names
#   BUSYBOX=/path               the static busybox to build the root filesystem from,
#                               and to put in every image at /lbt/busybox
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
ALLOWED_CAPS=00000000200405fb   # ALLOWED_CAPS of lightbox.c as /proc/<pid>/status prints a set
KIT=/lbt/busybox            # in every image: the suite's own busybox, to look at the network with
BRNF=/proc/sys/net/bridge/bridge-nf-call-iptables

settings() { # after LIFECYCLE_T is known
    T=$LIFECYCLE_T
    LB=$LIFECYCLE_LB
    BB=${LIFECYCLE_BB:-}
    [ -n "$T" ] && [ -d "$T" ] || { echo "lifecycle: no work directory" >&2; exit 2; }
    C="$T/lb/containers"
    USERNS_MODE=${LIGHTBOX_TEST_USERNS:-}
    SECCOMP_MODE=${LIGHTBOX_TEST_SECCOMP:-}
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

# The same with import: a container of an image, on the next free address,
# which $ip then is, with what import said in $OUT/<name>.import.
imported() { # image, name, [options]
    local image=$1 name=$2
    shift 2
    ip=$(next_ip) || return 1
    # shellcheck disable=SC2046  # options of one word each
    lb import "$image" "$name" "$ip" "$@" $(mode_options "$@") >"$OUT/$name.import" 2>&1 </dev/null || { cat "$OUT/$name.import"; return 1; }
    cat "$OUT/$name.import"
    port_of "$name" >/dev/null
}

# What LIGHTBOX_TEST_USERNS adds to a create: --userns, and with copy --copy
# too, where the case did not give them. A case about overlays sets OVERLAY=1,
# which keeps --copy out; a container that is to have no range is made with
# PLAIN=1 box ..., which adds nothing of the two. LIGHTBOX_TEST_SECCOMP adds
# --seccomp with its profile where the case gives no --seccomp.
mode_options() { # the options the case gives
    local given=" $* "
    if [ -n "$SECCOMP_MODE" ]; then
        case $given in *' --seccomp '*) ;; *) echo --seccomp "$SECCOMP_MODE" ;; esac
    fi
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
    if [ -n "$port" ] && { [ -e "$RUN/$1/egress" ] || iptables -n -L "LO-${port#vb-}" >/dev/null 2>&1; }; then
        echo "the firewall chain LO-${port#vb-} of its --net outside, or the record of it, is left"; bad=1
    fi
    if [ -e "$C/$1/.ip" ] && nft list set ip lightbox outside 2>/dev/null | grep -qw "$(addr_of "$1")"; then
        echo "the nftables set of --net outside has its address"; bad=1
    fi
    if [ -e "$C/$1/.ip" ] && nft list set ip lightbox proxied 2>/dev/null | grep -qw "$(addr_of "$1")"; then
        echo "the nftables set of --net proxy has its address"; bad=1
    fi
    if [ -n "$port" ] && nft list set bridge lightbox sealed 2>/dev/null | grep -q "\"$port\""; then
        echo "the nftables set of the ports of --net proxy names $port"; bad=1
    fi
    if [ -e "$C/$1/.ip" ] && iptables -S LIGHTBOX-LINKS 2>/dev/null | grep -q -- " $(addr_of "$1")/32 -j DROP"; then
        echo "a drop of --net proxy for its address is left in LIGHTBOX-LINKS"; bad=1
    fi
    echo "state: $(state_of "$1")"
    return $bad
}

need_nc() { [ -e "$T/have_nc" ] || { echo "the suite's busybox has no nc to open connections with"; return 77; }; }

# Does a TCP connection from the container get an answer from that address?
# Nothing listens on the port, so the answer is a refusal. Traffic that is
# filtered or not routed gets none, and the attempt times out.
reaches() { # name address
    local answer
    answer=$(sh_in "$1" "$KIT nc -w 3 $2 9 </dev/null" 2>&1)
    printf '%s -> %s: %s\n' "$1" "$2" "${answer:-no answer}"
    case $answer in *[Rr]efused*) return 0 ;; *) return 1 ;; esac
}

# Listeners on port 7 of the host and of the namespace that stands for the
# internet, on every address of theirs, which answer "here": started with
# the network, for as long as the suite runs. The firewall refuses TCP with a
# reset, as a port that nothing listens on does, so a refusal is the
# firewall's only where a listener is.
ECHO_PORT=7
need_listeners() { [ -e "$T/have_listeners" ] || { echo "no python3 for the listeners on port $ECHO_PORT"; return 77; }; }

# Does the listener at that address and port answer the container with that
# line?
answers() { # name address port line
    local answer
    answer=$(sh_in "$1" "$KIT nc -w 3 $2 $3 </dev/null" 2>&1)
    printf '%s -> %s port %s: %s\n' "$1" "$2" "$3" "${answer:-no answer}"
    [ "$answer" = "$4" ]
}
answered() { answers "$1" "$2" "$ECHO_PORT" here; }   # name address

# Does the firewall refuse a TCP connection from the container to that port,
# where a listener is, at once, as --net outside and proxy do: a reset,
# which a client says as refused, within a second, exec's own time with it?
rejected() { # name address [port]
    local answer t0 t1 ms port=${3:-$ECHO_PORT}
    t0=$(date +%s%N)
    answer=$(sh_in "$1" "$KIT nc -w 3 $2 $port </dev/null" 2>&1)
    t1=$(date +%s%N)
    ms=$(( (t1 - t0) / 1000000 ))
    printf '%s -> %s port %s: %s, in %s ms\n' "$1" "$2" "$port" "${answer:-no answer}" "$ms"
    case $answer in *[Rr]efused*) [ "$ms" -lt 1000 ] ;; *) return 1 ;; esac
}

# Addresses beyond the host that a container of --net outside may not reach,
# in the namespace that stands for the internet: a private one, a name
# server on another, and the metadata address of the clouds.
PRIVATE=172.31.255.1
PRIVATE_DNS=172.31.255.53
METADATA=169.254.169.254
private_addresses() {
    local outside a
    outside=$(cat "$T/outside")
    for a in "$PRIVATE" "$PRIVATE_DNS" "$METADATA"; do
        nsenter -t "$outside" -n ip addr show dev lo | grep -q " $a/32 " ||
            nsenter -t "$outside" -n ip addr add "$a/32" dev lo || return 1
        ip route show "$a/32" | grep -q . || ip route add "$a/32" via "$OUTSIDE" || return 1
    done
}

# A name server at that address in the namespace that stands for the
# internet, which answers every question for an address with 192.0.2.77,
# and with a log file writes there each name it is asked: its PID, or
# nothing without python3.
dns_responder() { # address [log]
    command -v python3 >/dev/null 2>&1 || return 1
    cat > "$T/dns.py" <<'PYTHON'
import socket, sys
log = open(sys.argv[2], "a", buffering=1) if len(sys.argv) > 2 else None
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 53))
while True:
    q, peer = s.recvfrom(512)
    end = 12
    labels = []
    while end < len(q) and q[end] != 0:
        labels.append(q[end + 1:end + 1 + q[end]].decode("ascii", "replace"))
        end += q[end] + 1
    if log:
        log.write(".".join(labels) + "\n")
    if len(q) < 12 or end + 5 > len(q):
        continue
    question = q[12:end + 5]
    a = q[end + 1:end + 3] == b"\x00\x01"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([192, 0, 2, 77]) if a else b""
    s.sendto(q[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if a else b"\x00\x00") + b"\x00\x00\x00\x00" +
             question + answer, peer)
PYTHON
    nsenter -t "$(cat "$T/outside")" -n python3 -I "$T/dns.py" "$@" >/dev/null 2>&1 &
    echo $!
}

# A TCP listener that answers each connection with a line and closes it,
# once it has read what the other end sends, up to a blank line or for half a
# second: closed with that unread, the connection would be reset and the
# answer lost. Its PID, or nothing without python3. With a namespace's PID,
# in that namespace's network.
tcp_listener() { # address port line [pid of the namespace]
    command -v python3 >/dev/null 2>&1 || return 1
    # written once: a second listener does not rewrite what the first reads
    [ -e "$T/listener.py" ] || cat > "$T/listener.py" <<'PYTHON'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(8)
while True:
    c, _ = s.accept()
    c.settimeout(0.5)
    asked = b""
    try:
        while b"\r\n\r\n" not in asked and len(asked) < 65536:
            more = c.recv(4096)
            if not more:
                break
            asked += more
    except OSError:
        pass
    try:
        c.sendall(sys.argv[3].encode() + b"\n")
    except OSError:
        pass
    c.close()
PYTHON
    if [ -n "${4:-}" ]; then
        nsenter -t "$4" -n python3 -I "$T/listener.py" "$1" "$2" "$3" >/dev/null 2>&1 &
    else
        python3 -I "$T/listener.py" "$1" "$2" "$3" >/dev/null 2>&1 &
    fi
    echo $!
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
    # --net outside: INPUT begins with the jump to LIGHTBOX-INPUT, and what
    # leaves the bridge or reaches the host goes through LIGHTBOX-EGRESS
    [ "$(iptables -S INPUT | sed -n 2p)" = '-A INPUT -j LIGHTBOX-INPUT' ] ||
        { echo "INPUT does not begin with the jump to LIGHTBOX-INPUT"; iptables -S INPUT; return 1; }
    iptables -C LIGHTBOX-FORWARD -i "$BR" ! -o "$BR" -j LIGHTBOX-EGRESS &&
    iptables -C LIGHTBOX-INPUT -i "$BR" -j LIGHTBOX-EGRESS &&
    iptables -C LIGHTBOX-OUTSIDE -m addrtype --dst-type LOCAL -p tcp -j REJECT --reject-with tcp-reset &&
    iptables -C LIGHTBOX-OUTSIDE -m addrtype --dst-type LOCAL -j REJECT --reject-with icmp-admin-prohibited &&
    iptables -C LIGHTBOX-OUTSIDE -d 169.254.0.0/16 -p tcp -j REJECT --reject-with tcp-reset &&
    iptables -C LIGHTBOX-OUTSIDE -d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited ||
        { echo "a rule of --net outside is missing:"; iptables-save; return 1; }
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
    box fwpeer --net nat && box fwlinked --net nat --link fwpeer || return 1
    said=$(alt_lb start fwlinked 2>&1 </dev/null) && { echo "a container with links started with firewall = false"; return 1; }
    printf '%s\n' "$said"
    case $said in *'has links, and firewall = false'*) ;; *) return 1 ;; esac
    nothing_left fwlinked || return 1
    # and one of --net outside, which only lightbox's rules keep to it
    box fwoutside || return 1
    said=$(alt_lb start fwoutside 2>&1 </dev/null) && { echo "a container of --net outside started with firewall = false"; return 1; }
    printf '%s\n' "$said"
    case $said in *'has --net outside, and firewall = false'*) ;; *) return 1 ;; esac
    nothing_left fwoutside
}

# firewall = false: lightbox makes no rule, so it does not turn forwarding on
# either, at setup or at a start: the host would forward between all its
# interfaces with nothing of lightbox's to say what. setup says that it left
# it, and a start does not take it for a part of the network that is missing.
t_firewall_false_leaves_forwarding() {
    alt_conf nofwfwd 'firewall = false' || return 1
    echo 0 > /proc/sys/net/ipv4/ip_forward || return 1
    rules=$(firewall_rules)
    started=
    said=$(alt_lb setup 2>&1)
    rc=$?
    printf '%s\n' "$said"
    forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ $rc = 0 ] && [ "$forwarding" = 0 ]; then
        box fwnat --net nat && started=$(alt_lb start fwnat 2>&1 </dev/null)
        rc=$?
        printf '%s\n' "$started"
        forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
    fi
    after=$(firewall_rules)
    alt_lb rm -f fwnat >/dev/null 2>&1
    echo 1 > /proc/sys/net/ipv4/ip_forward      # as the cases after this one found it
    [ $rc = 0 ] || { echo "setup, or the start of a container of --net nat, failed with firewall = false"; return 1; }
    [ "$forwarding" = 0 ] || { echo "forwarding was turned on with firewall = false"; return 1; }
    [ "$rules" = "$after" ] || { echo "the firewall changed with firewall = false:"; printf '%s\n' "$after"; return 1; }
    case $said in *'IPv4 forwarding is off, and firewall = false'*'leaves forwarding as it is'*) ;; *)
        echo "setup did not say that it left forwarding off"; return 1 ;; esac
    case $started in *'making it again'*)
        echo "a start took forwarding for a part of lightbox's network that is missing"; return 1 ;; esac
    return 0
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

# exec's status (ROADMAP 8.7) is the command's, or 128 and its signal; 126
# and 127 are a command that could not be run, and 125 a failure of
# lightbox's own, such as a container that is not running.
t_exec_status() {
    up status || return 1
    sh_in status 'exit 0';         a=$?
    sh_in status 'exit 7';         b=$?
    sh_in status 'kill -TERM $$';  c=$?
    lb exec status /no/such/program </dev/null; d=$?
    sh_in status ': > /not-executable'
    lb exec status /not-executable </dev/null; e=$?
    lb exec status --workdir /no/such/dir /bin/true </dev/null; f=$?
    lb stop status >/dev/null || return 1
    lb exec status /bin/true </dev/null; g=$?
    echo "exit 0 -> $a, exit 7 -> $b, killed by SIGTERM -> $c, a missing program -> $d," \
         "a file that cannot be executed -> $e, a --workdir that is not there -> $f, a stopped container -> $g"
    [ $a -eq 0 ] && [ $b -eq 7 ] && [ $c -eq 143 ] && [ $d -eq 127 ] && [ $e -eq 126 ] && [ $f -eq 126 ] && [ $g -eq 125 ]
}

# Is a process running with this command line, its words joined by spaces?
running_cmd() { # words
    local f
    for f in /proc/[0-9]*/cmdline; do
        [ "$(tr '\0' ' ' < "$f" 2>/dev/null)" = "$1 " ] && return 0
    done
    return 1
}
exec_cgroups() { ls -d "$CG/$1"/exec-* 2>/dev/null; }    # name
cgroup_empty() { grep -qx 'populated 0' "$1/cgroup.events"; }  # path

# Every exec runs in a cgroup of its own below the container's, which goes
# when the command ends. Without --timeout what it starts in the background
# goes on, in that cgroup, which stays until it has ended and is then taken
# away by the next exec; stop takes away one that still has a process.
t_exec_cgroup() {
    local said kept
    up excg || return 1
    said=$(sh_in excg 'cat /proc/self/cgroup')
    echo "the cgroup of an exec: $said"
    printf '%s\n' "$said" | grep -Eq '/excg/exec-[0-9]+-[0-9]+$' || { echo "it is not in a cgroup of its own"; return 1; }
    [ -z "$(exec_cgroups excg)" ] || { echo "left after the exec: $(exec_cgroups excg)"; return 1; }
    sh_in excg "$KIT setsid sleep 1071 >/dev/null 2>&1 </dev/null &" || return 1
    wait_until 5 running_cmd 'sleep 1071' || { echo "what it started is not running"; return 1; }
    kept=$(exec_cgroups excg)
    echo "left with a process in it: $kept"
    [ "$(printf '%s\n' "$kept" | grep -c .)" = 1 ] && running_cmd 'sleep 1071' &&
        [ -n "$(cat "$kept/cgroup.procs")" ] || { echo "what it started is not there, in its cgroup"; return 1; }
    kill $(cat "$kept/cgroup.procs")
    wait_until 5 cgroup_empty "$kept" || { echo "the process did not end"; return 1; }
    sh_in excg true || return 1
    [ ! -d "$kept" ] || { echo "the next exec did not take away the empty cgroup $kept"; return 1; }
    sh_in excg "$KIT setsid sleep 1072 >/dev/null 2>&1 </dev/null &" || return 1
    wait_until 5 running_cmd 'sleep 1072' || { echo "the second is not running"; return 1; }
    [ -n "$(exec_cgroups excg)" ] || { echo "no cgroup was left with the second"; return 1; }
    lb stop excg >/dev/null || return 1
    ! running_cmd 'sleep 1072' || { echo "stop left what the exec started"; return 1; }
    nothing_left excg
}

# exec --timeout ends the command and all it started, in the background and
# in sessions of their own, at the deadline, and exec returns 124. A command
# that ends before it returns its own status, and what it left in the
# background is ended with it.
t_exec_timeout() {
    local began ms rc
    up extime || return 1
    began=$(date +%s%N)
    lb exec extime --timeout 2s /bin/sh -c "$KIT setsid sleep 1073 & sleep 1074" >"$OUT/extime.out" 2>"$OUT/extime.err" </dev/null
    rc=$?
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    cat "$OUT/extime.err"
    echo "status $rc in $ms ms"
    [ "$rc" = 124 ] && [ "$ms" -lt 3000 ] || return 1
    grep -q 'ran past its time limit, --timeout 2s' "$OUT/extime.err" || { echo "exec did not say why"; return 1; }
    [ -z "$(exec_cgroups extime)" ] || { echo "left: $(exec_cgroups extime)"; return 1; }
    ! running_cmd 'sleep 1073' && ! running_cmd 'sleep 1074' || { echo "a sleep is left"; return 1; }
    began=$(date +%s%N)
    # the second's sleep has begun when the shell ends
    lb exec extime --timeout 30s /bin/sh -c "$KIT setsid sleep 1075 >/dev/null 2>&1 </dev/null & sleep 1; exit 3" </dev/null
    rc=$?
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    echo "a command that ended before its deadline: status $rc in $ms ms"
    [ "$rc" = 3 ] && [ "$ms" -lt 5000 ] || return 1
    ! running_cmd 'sleep 1075' || { echo "what it left in the background goes on"; return 1; }
    [ -z "$(exec_cgroups extime)" ] || { echo "left: $(exec_cgroups extime)"; return 1; }
    [ "$(state_of extime)" = running ] || { echo "the container: $(state_of extime)"; return 1; }
}

none_running() { local w; for w; do running_cmd "$w" && return 1; done; return 0; }  # command lines

# A box created with nothing but --profile agent and --workspace (ROADMAP
# 8.10) has each setting of the profile in its .conf under its own key, and
# Phase 8's first two exit conditions hold for it: its uid 0 is an
# unprivileged uid on the host, the allow-list filter is installed, its only
# interface is lo, and a file it writes in its workspace, where every exec
# runs, belongs on the host to the workspace's owner.
t_agent_profile() {
    need_subids || return 77
    local key inside ifaces u g said
    mkdir -p "$T/vol/agentws" && chown 2345:2346 "$T/vol/agentws" || return 1
    lb create agent --profile agent --workspace "$T/vol/agentws" >"$OUT/agent.create" 2>&1 </dev/null ||
        { cat "$OUT/agent.create"; return 1; }
    port_of agent >/dev/null
    cat "$C/agent/.conf"
    for key in profile=agent userns=1 seccomp=allow net=none mem=2G pids=512 cpu=2 ttl=8h workdir=/workspace \
               "vol=$T/vol/agentws:/workspace"; do
        grep -qxF -- "$key" "$C/agent/.conf" || { echo "the .conf has no $key"; return 1; }
    done
    [ -n "$(conf_value agent base)" ] && [ ! -e "$C/agent/.ip" ] || { echo "not an overlay, or it has an address"; return 1; }
    lb inspect agent | grep -qx 'profile: agent' || { echo "inspect does not say the profile"; return 1; }
    start agent || return 1
    u=$(conf_value agent uid_start) g=$(conf_value agent gid_start)
    echo "init on the host: $(host_ids_of "$(pid_of agent)"), its range from $u $g"
    [ "$u" -gt 0 ] && [ "$(host_ids_of "$(pid_of agent)")" = "$u $g" ] || { echo "uid 0 in the box is not an unprivileged uid"; return 1; }
    inside=$(lb exec agent /bin/sh -c "id -u; pwd; grep '^Seccomp:' /proc/self/status | tr -d '\t'; echo made > made" </dev/null | paste -sd' ')
    echo "in it: $inside"
    [ "$inside" = '0 /workspace Seccomp:2' ] || return 1
    said=$(sh_in agent "$KIT hostname another" 2>&1) && { echo "the box took sethostname"; return 1; }
    case $said in *'not implemented'*) ;; *) echo "not the allow-list, which answers ENOSYS: $said"; return 1 ;; esac
    ifaces=$(sh_in agent 'cat /proc/net/dev' | sed '1,2d' | awk -F: '{ gsub(/ /, "", $1); print $1 }' | paste -sd' ')
    echo "its interfaces: $ifaces; what it made in its workspace, on the host: $(stat -c %u:%g "$T/vol/agentws/made")"
    [ "$ifaces" = lo ] && [ "$(stat -c %u:%g "$T/vol/agentws/made")" = 2345:2346 ] || return 1
    [ "$(lb exec agent --workdir /tmp /bin/sh -c pwd </dev/null)" = /tmp ] || { echo "--workdir does not hold over the workspace"; return 1; }
    lb stop agent >/dev/null && lb rm agent >/dev/null || return 1
    nothing_left agent
}

# run --profile agent (ROADMAP 8.10, and 8.8's exit condition): the status
# of the command, run in its workspace, and nothing of the box left; the
# same after SIGTERM to run.
t_agent_run() {
    need_subids || return 77
    local out rc name front
    mkdir -p "$T/vol/agentrun" && chown 2345:2346 "$T/vol/agentrun" || return 1
    out=$(lb run --profile agent --workspace "$T/vol/agentrun" -- /bin/sh -c 'hostname; pwd; echo made > made; exit 3' </dev/null)
    rc=$?
    name=$(printf '%s\n' "$out" | sed -n 1p)
    echo "run --profile agent: status $rc, $(printf '%s\n' "$out" | paste -sd' '); made: $(stat -c %u:%g "$T/vol/agentrun/made" 2>&1)"
    [ "$rc" = 3 ] && [ "$(printf '%s\n' "$out" | sed -n 2p)" = /workspace ] &&
        [ "$(stat -c %u:%g "$T/vol/agentrun/made")" = 2345:2346 ] && run_left "$name" || return 1
    # "$LB" and not lb, whose timeout would be $! and take the SIGTERM alone
    "$LB" run --profile agent -- /bin/sh -c 'hostname; exec sleep 1118' >"$OUT/agentrun.out" 2>"$OUT/agentrun.err" </dev/null &
    front=$!
    wait_until 30 test -s "$OUT/agentrun.out" && wait_until 5 running_cmd 'sleep 1118' ||
        { echo "the command did not start"; cat "$OUT/agentrun.err"; kill -KILL "$front"; return 1; }
    name=$(cat "$OUT/agentrun.out")
    kill -TERM "$front"
    wait "$front"
    rc=$?
    echo "SIGTERM to run --profile agent of $name: status $rc"
    [ "$rc" = 143 ] && ! running_cmd 'sleep 1118' && run_left "$name"
}

# ─── The agent group (ROADMAP 8.11) ─────────────────────────────────────────
#
# Phase 8's exit conditions for boxes of --profile agent, with t_agent_profile
# and t_agent_run above: what doctor --profile agent says, the proxy, exec
# --timeout and lightbox's own statuses, reset, --ttl and the audit log; and
# the commands of README's "Running an agent in a box", in a copy of the
# suite's own. The boxes are made with lb create and not box, whose
# mode_options would give them --seccomp deny or --copy, which the profile
# refuses.

# A box of the profile, created with lb create: what create said on failure.
agent_box() { # name [address] [create options]
    local name=$1
    shift
    lb create "$name" "$@" --profile agent >"$OUT/$name.create" 2>&1 </dev/null || { cat "$OUT/$name.create"; return 1; }
    port_of "$name" >/dev/null
}

# doctor --profile agent finds nothing missing on a host set up for the
# profile; with nft masked it exits 1, and says that agent.nft is missing and
# what fixes it.
t_agent_doctor() {
    need_subids || return 77
    local said rc nft check
    said=$(lb doctor --profile agent 2>&1)
    rc=$?
    printf '%s\n' "$said" | grep -A1 '^agent\.'
    [ "$rc" = 0 ] || { echo "doctor --profile agent exited $rc on a host set up for the profile"; return 1; }
    for check in kernel userns_ranges idmap nft cgroup_kill; do
        printf '%s\n' "$said" | grep -Eq "^agent\.$check: (yes|ok) " || { echo "agent.$check does not pass"; return 1; }
    done
    nft=$(printf '%s\n' "$said" | sed -n 's/^agent\.nft: ok (\(.*\))$/\1/p')
    nft=$(readlink -f "$nft") && [ -n "$nft" ] || { echo "the path of nft is not said"; return 1; }
    mount --bind /dev/null "$nft" || return 1
    said=$(lb doctor --profile agent 2>&1)
    rc=$?
    umount "$nft" || return 1
    printf '%s\n' "$said" | grep -A1 '^agent\.nft: '
    [ "$rc" = 1 ] || { echo "doctor --profile agent exited $rc with nft masked"; return 1; }
    printf '%s\n' "$said" | grep -A1 '^agent\.nft: missing (' | tail -n 1 | grep -q '^  to fix: install nftables' ||
        { echo "agent.nft is not said to be missing, with its fix"; return 1; }
    lb doctor --profile agent >/dev/null || { echo "doctor --profile agent fails with nft back"; return 1; }
}

# With --net proxy:<port>, a box of the profile reaches that port of the
# gateway and nothing else: another port of the gateway, the proxy's port on
# the host's other address, the outside and a name server on TCP, each with
# a listener, are refused within a second; its resolv.conf names no name
# server. A listener on the gateway stands in for the proxy.
t_agent_proxy() {
    need_subids || return 77
    need_nc || return 77
    need_listeners || return 77
    private_addresses || return 1
    local proxy tcp53 try said rc=0
    agent_box aprx "$(next_ip)" --net "proxy:$PROXY_PORT" || return 1
    [ "$(conf_value aprx net)" = "proxy:$PROXY_PORT" ] && [ -s "$C/aprx/.ip" ] || { cat "$C/aprx/.conf"; return 1; }
    proxy=$(tcp_listener 0.0.0.0 "$PROXY_PORT" 'the proxy here') &&
        tcp53=$(tcp_listener 0.0.0.0 53 'a name server on TCP' "$(cat "$T/outside")") || return 1
    start aprx || rc=1
    if [ "$rc" = 0 ]; then
        for try in 1 2 3 4 5; do
            answers aprx "$GW" "$PROXY_PORT" 'the proxy here' && break
            [ "$try" = 5 ] && { echo "the box did not reach its proxy"; rc=1; }
            sleep 0.3
        done
    fi
    if [ "$rc" = 0 ]; then
        rejected aprx "$GW" && rejected aprx 192.0.2.2 "$PROXY_PORT" && rejected aprx "$OUTSIDE" &&
            rejected aprx "$PRIVATE_DNS" 53 || { echo "it was not refused within a second"; rc=1; }
        said=$(sh_in aprx 'cat /etc/resolv.conf')
        echo "its resolv.conf: $said"
        printf '%s\n' "$said" | grep -q nameserver && { echo "it names a name server"; rc=1; }
    fi
    kill "$proxy" "$tcp53" 2>/dev/null
    port_free() { ! ss -ltn | grep -q ":$PROXY_PORT "; }
    wait_until 5 port_free || { echo "the listener on port $PROXY_PORT is still there"; rc=1; }
    [ "$rc" = 0 ] && lb stop aprx >/dev/null && nothing_left aprx && lb rm aprx >/dev/null
}

# In a box of the profile, exec --timeout ends the command and all it
# started, a process in a session of its own among them, and returns 124; a
# command's own status is its own, one that is not there is 127, and an exec
# into a box that does not run is 125, lightbox's own.
t_agent_timeout() {
    need_subids || return 77
    local began ms rc
    agent_box atime && start atime || return 1
    began=$(date +%s%N)
    lb exec atime --timeout 2s /bin/sh -c "$KIT setsid sleep 1123 & sleep 1124" >/dev/null 2>"$OUT/atime.err" </dev/null
    rc=$?
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    cat "$OUT/atime.err"
    echo "--timeout 2s: status $rc in $ms ms"
    [ "$rc" = 124 ] && [ "$ms" -lt 3000 ] || return 1
    none_running 'sleep 1123' 'sleep 1124' || { echo "a sleep is left"; return 1; }
    [ -z "$(exec_cgroups atime)" ] || { echo "left: $(exec_cgroups atime)"; return 1; }
    lb exec atime /bin/sh -c 'exit 3' </dev/null
    rc=$?
    lb exec atime /not-there </dev/null 2>/dev/null
    rc="$rc $?"
    lb stop atime >/dev/null || return 1
    lb exec atime /bin/true </dev/null 2>"$OUT/atime.err"
    rc="$rc $?"
    echo "exit 3, a command that is not there, and an exec into a box that does not run: $rc; $(cat "$OUT/atime.err")"
    [ "$rc" = '3 127 125' ] && nothing_left atime && lb rm atime >/dev/null
}

# reset of a box of the profile: what it wrote outside its workspace is gone
# and nothing of its base was copied, as its rootfs/ has no more than what
# create wrote; what it wrote in its workspace stays.
t_agent_reset() {
    need_subids || return 77
    local own more
    mkdir -p "$T/vol/agentreset" && chown 2345:2346 "$T/vol/agentreset" || return 1
    agent_box arst --workspace "$T/vol/agentreset" && start arst || return 1
    sh_in arst 'echo mine > /made-here && echo kept > kept && rm /etc/group' || return 1
    lb reset arst </dev/null || return 1
    nothing_left arst || return 1
    own=$(cd "$C/arst/rootfs" && find . -type f | sort | paste -sd' ' -)
    echo "its own files: $own"
    more=$(cd "$C/arst/rootfs" && find . -type f ! -path ./etc/hostname ! -path ./etc/hosts ! -path ./etc/resolv.conf)
    [ -z "$more" ] || { echo "rootfs/ has more than create wrote: $more"; return 1; }
    [ "$(cat "$T/vol/agentreset/kept")" = kept ] || { echo "the workspace lost its file"; return 1; }
    start arst || return 1
    [ "$(sh_in arst 'test ! -e /made-here && test -e /etc/group && cat kept')" = kept ] ||
        { echo "what the box did is still there, or its workspace is not"; return 1; }
    lb stop arst >/dev/null && lb rm arst >/dev/null
}

# A box of the profile with --ttl 2s ends on time, with what it started, and
# is expired; the --ttl given is its, not agent_ttl's.
t_agent_ttl() {
    need_subids || return 77
    local began ms
    agent_box attl --ttl 2s || return 1
    [ "$(conf_value attl ttl)" = 2s ] || { echo "ttl=$(conf_value attl ttl)"; return 1; }
    began=$(date +%s%N)
    start attl || return 1
    sh_in attl "$KIT setsid sleep 1125 >/dev/null 2>&1 </dev/null &" || return 1
    wait_until 5 running_cmd 'sleep 1125' || { echo "what the exec started is not running"; return 1; }
    shows_expired() { lb ls | grep -Eq '^attl +[^ ]+ +expired'; }
    wait_until 6 shows_expired || { lb ls; echo "ls does not show it as expired"; return 1; }
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    lb ls
    echo "expired $ms ms after its start began"
    [ "$ms" -ge 2000 ] && [ "$ms" -lt 4000 ] || return 1
    ! running_cmd 'sleep 1125' || { echo "a process is left"; return 1; }
    lb stop attl >/dev/null 2>&1
    nothing_left attl && [ "$(state_of attl)" = expired ] && lb rm attl >/dev/null
}

# The exec of a box of the profile and the command of a run --profile agent
# are each in the audit log, start and end, by the box's name and id; and no
# file the box can read has the log's lines, but the one it wrote itself,
# which the search has to find.
t_agent_audit() {
    need_subids || return 77
    local id name rc found
    agent_box aaud && start aaud || return 1
    id=$(conf_value aaud id)
    lb exec aaud /bin/sh -c 'exit 5' agentmarker4712 </dev/null
    rc=$?
    name=$(lb run --profile agent -- /bin/sh -c hostname </dev/null) || return 1
    echo "exec: $rc; run of $name; their lines:"
    { lb logs --audit aaud; lb logs --audit "$name"; } | tee "$OUT/aaud.lines"
    [ "$rc" = 5 ] || return 1
    python3 -I -c '
import json, sys
box_id, run = sys.argv[2], sys.argv[3]
lines = [json.loads(l) for l in open(sys.argv[1])]
assert len(lines) == 4, "%d lines" % len(lines)
a, b, c, d = lines
assert [l["event"] for l in lines] == ["start", "end", "start", "end"], "the events"
assert a["box"] == b["box"] == "aaud" and a["box_id"] == b["box_id"] == box_id, "the box"
assert a["via"] == "exec" and a["argv"] == ["/bin/sh", "-c", "exit 5", "agentmarker4712"] and b["status"] == 5, "the exec"
assert c["box"] == d["box"] == run and c["box_id"] == d["box_id"] != box_id, "the box of run"
assert c["via"] == "run" and c["argv"] == ["/bin/sh", "-c", "hostname"] and d["status"] == 0, "the command of run"
' "$OUT/aaud.lines" "$id" "$name" || return 1
    found=$(LB_TIMEOUT=120 lb exec aaud /bin/sh -c \
        "echo agentmarker4712 > /tmp/control; for d in /*; do case \$d in /proc|/sys|/dev) ;;
         *) $KIT find \"\$d\" -type f -exec $KIT grep -l 'agentmarke[r]4712' {} + ;; esac; done" \
        </dev/null 2>/dev/null)
    echo "files in the box with what the log has: $found"
    [ "$found" = /tmp/control ] && lb stop aaud >/dev/null && lb rm aaud >/dev/null
}

# README's "Running an agent in a box", its fenced commands in the order it
# has them, kept in step with it by hand, as no case reads README. Here lb
# stands for sudo ./lightbox, guide for the name agent, and a directory of
# the case's, owned by an unprivileged uid as one of the reader's is, for
# ~/agent-work.
t_agent_guide() {
    need_subids || return 77
    local ws=$T/vol/agentguide said
    # sudo ./lightbox doctor --profile agent
    lb doctor --profile agent >"$OUT/guide.doctor" 2>&1 || { cat "$OUT/guide.doctor"; return 1; }
    # mkdir -p ~/agent-work
    mkdir -p "$ws" && chown 2345:2346 "$ws" || return 1
    # sudo ./lightbox create agent --profile agent --workspace ~/agent-work
    lb create guide --profile agent --workspace "$ws" </dev/null || return 1
    port_of guide >/dev/null
    # sudo ./lightbox start agent
    start guide || return 1
    # sudo ./lightbox exec agent --timeout 10m -- /bin/sh -c 'id -u; pwd; echo done > result.txt'
    said=$(lb exec guide --timeout 10m -- /bin/sh -c 'id -u; pwd; echo done > result.txt' </dev/null | paste -sd' ')
    echo "exec: $said"
    [ "$said" = '0 /workspace' ] || return 1
    # cat ~/agent-work/result.txt
    [ "$(cat "$ws/result.txt")" = done ] && [ "$(stat -c %u:%g "$ws/result.txt")" = 2345:2346 ] ||
        { echo "result.txt: $(cat "$ws/result.txt"), $(stat -c %u:%g "$ws/result.txt")"; return 1; }
    # sudo ./lightbox logs --audit agent
    said=$(lb logs --audit guide)
    printf '%s\n' "$said"
    [ "$(printf '%s\n' "$said" | grep -c '"box":"guide"')" = 2 ] || { echo "not the start and the end of the exec"; return 1; }
    # sudo ./lightbox reset agent
    lb reset guide </dev/null || return 1
    # sudo ./lightbox rm agent
    lb rm guide </dev/null || return 1
    [ ! -e "$C/guide" ] || { echo "the box is still there"; return 1; }
    # sudo ./lightbox run --profile agent --workspace ~/agent-work --timeout 10m -- /bin/sh -c 'cat result.txt'
    said=$(lb run --profile agent --workspace "$ws" --timeout 10m -- /bin/sh -c 'cat result.txt' </dev/null)
    echo "run: $said"
    [ "$said" = done ] || return 1
    # sudo ./lightbox create agent --profile agent --net proxy:3128 --workspace ~/agent-work
    lb create guide --profile agent --net proxy:3128 --workspace "$ws" </dev/null || return 1
    port_of guide >/dev/null
    # sudo ./lightbox start agent
    start guide || return 1
    # sudo ./lightbox exec agent -- /bin/sh -c 'echo "$HTTPS_PROXY"'
    said=$(lb exec guide -- /bin/sh -c 'echo "$HTTPS_PROXY"' </dev/null)
    echo "HTTPS_PROXY in the box: $said"
    [ "$said" = "http://$GW:3128" ] || return 1
    # sudo ./lightbox stop agent
    lb stop guide </dev/null || return 1
    nothing_left guide || return 1
    # sudo ./lightbox rm agent
    lb rm guide </dev/null && [ ! -e "$C/guide" ]
}

# Every exec writes two lines to the audit log of the host (ROADMAP 8.9): one
# as its command starts and one when it has ended. They parse as JSON, name
# the box by its name and id, and carry what was asked, --env by its keys
# only, and how it ended. The lines of a run are kept when its box is gone.
# No file in the box has what the log has.
t_audit_log() {
    local log=$T/lb/audit.log id rc found name
    up audit || return 1
    id=$(conf_value audit id)
    lb exec audit --env TOKEN=not-for-the-log --workdir /tmp /bin/sh -c 'exit 7' auditmarker4711 </dev/null
    rc=$?
    lb exec audit --timeout 1s /bin/sleep 1116 </dev/null 2>/dev/null
    echo "statuses $rc and $?; the log: $(stat -c '%a %U' "$log"), its directory $(stat -c '%a' "$T/lb")"
    lb logs --audit audit
    lb logs --audit audit | python3 -I -c '
import json, re, sys
box_id = sys.argv[1]
lines = [json.loads(l) for l in sys.stdin]
assert len(lines) == 4, "%d lines" % len(lines)
a, b, c, d = lines
for l in lines:
    assert l["box"] == "audit" and l["box_id"] == box_id, "the box"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", l["time"]), l["time"]
assert [l["event"] for l in lines] == ["start", "end", "start", "end"], "the events"
assert a["exec_id"] == b["exec_id"] != c["exec_id"] == d["exec_id"], "the exec ids"
assert a["via"] == "exec" and a["uid"] == 0 and a["user"] is None and a["workdir"] == "/tmp" and a["timeout"] is None
assert a["env"] == ["TOKEN"] and a["argv"] == ["/bin/sh", "-c", "exit 7", "auditmarker4711"], "what was asked"
assert b["status"] == 7 and b["timed_out"] is False and b["duration_ms"] >= 0, "its end"
assert c["timeout"] == "1s" and c["argv"] == ["/bin/sleep", "1116"], "the second"
assert d["status"] == 124 and d["timed_out"] is True and d["duration_ms"] >= 1000, "its end"
' "$id" || return 1
    [ "$rc" = 7 ] && [ "$(stat -c '%a %U' "$log")" = '600 root' ] || return 1
    ! grep -q not-for-the-log "$log" || { echo "the value of an --env is in the log"; return 1; }
    # what the box can read, but /proc, /sys and lightbox's own /dev, with one
    # file the box writes that has it, which the search has to find: the
    # pattern does not match itself, which is in the command lines of /proc
    found=$(LB_TIMEOUT=120 lb exec audit /bin/sh -c \
        "echo auditmarker4711 > /tmp/control; for d in /*; do case \$d in /proc|/sys|/dev) ;;
         *) $KIT find \"\$d\" -type f -exec $KIT grep -l 'auditmarke[r]4711' {} + ;; esac; done" \
        </dev/null 2>/dev/null)
    echo "files in the box with what the log has: $found"
    [ "$found" = /tmp/control ] || return 1

    # shellcheck disable=SC2046
    name=$(lb run $(mode_options) -- /bin/sh -c 'hostname; exit 5' </dev/null)
    rc=$?
    echo "run of $name: $rc; its lines:"
    lb logs --audit "$name"
    [ "$rc" = 5 ] && [ ! -e "$C/$name" ] || return 1
    lb logs --audit "$name" | python3 -I -c '
import json, re, sys
lines = [json.loads(l) for l in sys.stdin]
assert [l["event"] for l in lines] == ["start", "end"] and lines[0]["via"] == "run", "the lines of run"
assert re.fullmatch("[0-9a-f]{16}", lines[0]["box_id"]) and lines[1]["status"] == 5, "its box and status"
'
}

# exec --timeout holds without the process that ran exec: its worker, which
# the container cannot reach, ends the command and all it started at once
# when that process is killed, and a second past the deadline when it is
# stopped, after which it returns 124.
t_exec_timeout_without_its_exec() {
    local front began ms rc
    up exkeep || return 1
    "$LB" exec exkeep --timeout 60s /bin/sh -c "$KIT setsid sleep 1077 >/dev/null 2>&1 </dev/null & exec sleep 1078" \
        >/dev/null 2>&1 </dev/null &
    front=$!
    wait_until 5 running_cmd 'sleep 1077' && wait_until 5 running_cmd 'sleep 1078' ||
        { echo "the command did not start"; kill -KILL "$front"; return 1; }
    kill -KILL "$front"
    wait "$front" 2>/dev/null
    wait_until 3 none_running 'sleep 1077' 'sleep 1078' || { echo "the command outlived its exec"; return 1; }
    sh_in exkeep true || return 1
    [ -z "$(exec_cgroups exkeep)" ] || { echo "left: $(exec_cgroups exkeep)"; return 1; }

    "$LB" exec exkeep --timeout 1s /bin/sh -c "exec sleep 1079" >/dev/null 2>"$OUT/exkeep.err" </dev/null &
    front=$!
    wait_until 5 running_cmd 'sleep 1079' || { echo "the second did not start"; kill -KILL "$front"; return 1; }
    kill -STOP "$front"
    began=$(date +%s%N)
    wait_until 5 none_running 'sleep 1079' || { kill -KILL "$front"; echo "the command outlived its deadline"; return 1; }
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    kill -CONT "$front"
    wait "$front"
    rc=$?
    cat "$OUT/exkeep.err"
    echo "with exec stopped, the command ended $ms ms after that; exec returned $rc"
    [ "$ms" -lt 3000 ] && [ "$rc" = 124 ]
}

# --ttl (ROADMAP 8.8): a container ends at the end of its lifetime from its
# start, as stop ends it, with what its hook and an exec left running, and
# ls and inspect show it as expired, as its log says; the next stop clears
# away what it left and keeps it expired, and a start gives it a lifetime
# again.
t_ttl() {
    local began ms
    box ttlbox --ttl 2s || return 1
    hook ttlbox <<EOF
$KIT setsid sleep 1101 >/dev/null 2>&1 </dev/null &
EOF
    began=$(date +%s%N)
    start ttlbox || return 1
    sh_in ttlbox "$KIT setsid sleep 1102 >/dev/null 2>&1 </dev/null &" || return 1
    wait_until 5 running_cmd 'sleep 1101' && wait_until 5 running_cmd 'sleep 1102' ||
        { echo "what the hook and the exec started is not running"; return 1; }
    shows_expired() { lb ls | grep -Eq '^ttlbox +[0-9.]+ +expired'; }
    wait_until 6 shows_expired || { lb ls; echo "ls does not show it as expired"; return 1; }
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    lb ls
    echo "expired $ms ms after its start began"
    [ "$ms" -ge 2000 ] && [ "$ms" -lt 4000 ] || return 1
    lb inspect ttlbox | grep -qx 'state: expired' || { echo "inspect does not show it as expired"; return 1; }
    none_running 'sleep 1101' 'sleep 1102' || { echo "a process is left"; return 1; }
    cgroup_empty "$CG/ttlbox" || { echo "its cgroup is not empty"; return 1; }
    grep -q -- '--ttl is over; it stops' "$C/ttlbox/console.log" || { echo "the log does not say why"; return 1; }
    lb stop ttlbox >"$OUT/ttlbox.stop" 2>&1
    cat "$OUT/ttlbox.stop"
    grep -q 'came to the end of its --ttl' "$OUT/ttlbox.stop" || return 1
    nothing_left ttlbox && [ "$(state_of ttlbox)" = expired ] || return 1
    start ttlbox && [ "$(state_of ttlbox)" = running ]
}

# What is left of a box of run that is gone: nothing, no directory, cgroup,
# record, interface or firewall rule.
run_left() { # name [address]
    local bad=0
    [ ! -e "$C/$1" ] || { echo "the directory of $1 is left"; bad=1; }
    [ ! -e "$CG/$1" ] || { echo "the cgroup of $1 is left"; bad=1; }
    [ ! -e "$RUN/$1" ] || { echo "the records of $1 are left"; bad=1; }
    ! ip -o link show | grep -qF "lightbox:$1" || { echo "the interface of $1 is left"; bad=1; }
    if [ -n "${2:-}" ]; then
        ! iptables-save 2>/dev/null | grep -qF -- "$2/32" || { echo "an iptables rule names $2"; bad=1; }
        ! nft list ruleset 2>/dev/null | grep -qwF -- "$2" || { echo "an nftables rule names $2"; bad=1; }
    fi
    return $bad
}

# run (ROADMAP 8.8): a box for one command. What it prints is the command's
# alone, its status is the command's, and nothing of the box is left. Its
# create options reach the box and its exec options the command; --timeout
# ends the command with 124, a command that is not there is 127, and an
# option create refuses is 125, with no box made.
t_run() {
    local out rc name ip began ms said
    # shellcheck disable=SC2046  # options of one word each
    out=$(lb run $(mode_options) -- /bin/sh -c "hostname; $KIT ip -o -4 addr show eth0 | $KIT awk '{ print \$4 }'; echo to-stderr >&2; exit 3" \
          2>"$OUT/run.err" </dev/null)
    rc=$?
    printf '%s\n' "$out"
    echo "status $rc; on stderr: $(cat "$OUT/run.err")"
    name=$(printf '%s\n' "$out" | sed -n 1p)
    ip=$(printf '%s\n' "$out" | sed -n 2p)
    ip=${ip%/*}
    [ "$rc" = 3 ] && [ "$(printf '%s\n' "$out" | grep -c .)" = 2 ] && [ "$(cat "$OUT/run.err")" = to-stderr ] ||
        { echo "run printed more than the command, or did not return its status"; return 1; }
    printf '%s\n' "$name" | grep -Eqx 'run-[0-9a-f]{12}' && [ -n "$ip" ] || { echo "the box was not run-<12 hex digits> with an address"; return 1; }
    run_left "$name" "$ip" || return 1

    # shellcheck disable=SC2046
    out=$(lb run $(mode_options) --net none --env GREETING=hi --workdir /tmp -- \
          /bin/sh -c 'echo "$GREETING $(pwd)"; cat /proc/net/dev' </dev/null)
    said=$(printf '%s\n' "$out" | sed '1,3d' | awk -F: '{ gsub(/ /, "", $1); print $1 }' | paste -sd' ' -)
    echo "with --net none, --env and --workdir: $(printf '%s\n' "$out" | sed -n 1p); its interfaces: $said"
    [ "$(printf '%s\n' "$out" | sed -n 1p)" = 'hi /tmp' ] && [ "$said" = lo ] || return 1
    began=$(date +%s%N)
    # shellcheck disable=SC2046
    lb run $(mode_options) --timeout 1s -- /bin/sleep 1113 </dev/null
    rc=$?
    ms=$(( ($(date +%s%N) - began) / 1000000 ))
    echo "--timeout 1s: status $rc in $ms ms"
    [ "$rc" = 124 ] && [ "$ms" -lt 6000 ] && ! running_cmd 'sleep 1113' || return 1
    # shellcheck disable=SC2046
    lb run $(mode_options) -- /no/such/program </dev/null 2>/dev/null
    rc=$?
    echo "a program that is not there: $rc"
    [ "$rc" = 127 ] || return 1
    out=$(lb run --mem 1x -- /bin/true 2>&1 </dev/null)
    rc=$?
    echo "--mem 1x: $rc, $out"
    [ "$rc" = 125 ] && [ "$out" = 'Error: --mem takes <number>[K|M|G|T] or max, not: 1x' ] || return 1
    [ -z "$(ls -d "$C"/run-* 2>/dev/null)" ] || { echo "boxes are left: $(ls -d "$C"/run-*)"; return 1; }
}

# A box of run whose command a SIGTERM to run ends is removed, and run
# returns the command's status; one whose run was killed outright is
# removed by the next run, which says so.
t_run_ends() {
    local front rc name said
    # the command says the box's name on run's stdout, which goes to a file:
    # a volume would need to be the box's root's, whose range is not known
    # before run has made the box
    # shellcheck disable=SC2046
    "$LB" run $(mode_options) -- /bin/sh -c 'hostname; exec sleep 1114' \
        >"$OUT/runsig.out" 2>"$OUT/runsig.err" </dev/null &
    front=$!
    wait_until 20 test -s "$OUT/runsig.out" && wait_until 5 running_cmd 'sleep 1114' ||
        { echo "the command did not start"; cat "$OUT/runsig.err"; kill -KILL "$front"; return 1; }
    name=$(cat "$OUT/runsig.out")
    kill -TERM "$front"
    wait "$front"
    rc=$?
    echo "SIGTERM to run of $name: status $rc; $(cat "$OUT/runsig.err")"
    [ "$rc" = 143 ] && ! running_cmd 'sleep 1114' && run_left "$name" || return 1

    # shellcheck disable=SC2046
    "$LB" run $(mode_options) -- /bin/sh -c 'hostname; exec sleep 1115' \
        >"$OUT/runkill.out" 2>&1 </dev/null &
    front=$!
    wait_until 20 test -s "$OUT/runkill.out" && wait_until 5 running_cmd 'sleep 1115' ||
        { echo "the second did not start"; cat "$OUT/runkill.out"; kill -KILL "$front"; return 1; }
    name=$(cat "$OUT/runkill.out")
    kill -KILL "$front"
    wait "$front" 2>/dev/null
    echo "its run killed, $name: $(state_of "$name"); .runner: $(cat "$C/$name/.runner" 2>&1)"
    [ "$(state_of "$name")" = running ] && [ -s "$C/$name/.runner" ] || { echo "the box of a killed run is not there"; return 1; }
    # shellcheck disable=SC2046
    said=$(lb run $(mode_options) -- /bin/true 2>&1 </dev/null) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -qxF "Note: removing the box '$name', whose run is gone" || return 1
    ! running_cmd 'sleep 1115' && run_left "$name"
}

# A container whose init died with an exec's cgroup left below its own is
# cleared away whole, the exec's cgroup first.
t_exec_cgroup_of_a_dead_init() {
    local pid
    up exdead || return 1
    sh_in exdead "$KIT setsid sleep 1076 >/dev/null 2>&1 </dev/null &" || return 1
    wait_until 5 running_cmd 'sleep 1076' || { echo "what it started is not running"; return 1; }
    [ -n "$(exec_cgroups exdead)" ] || { echo "no cgroup was left"; return 1; }
    pid=$(pid_of exdead)
    kill -KILL "$pid"
    wait_until 5 gone "$pid" || return 1
    # stop clears it away and says that it does not run
    lb stop exdead >"$OUT/exdead.stop" 2>&1
    cat "$OUT/exdead.stop"
    grep -q "had ended without a stop; what it left has been cleared away" "$OUT/exdead.stop" || return 1
    ! running_cmd 'sleep 1076' || { echo "the sleep is left"; return 1; }
    nothing_left exdead
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
# It has the network of then, nat: the records of --net outside, of 0.8, are
# in run_dir, which a lightbox before 0.5 did not have.
t_container_started_before_the_upgrade() {
    up oldstyle --net nat || return 1
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
# lightbox are not among them, with --user or without. Root's are 0 and those
# the image's /etc/group lists it in, which Alpine's does in ten.
t_exec_unknown_uid_drops_groups() {
    command -v setpriv >/dev/null 2>&1 || { echo "no setpriv to put the caller in a group with"; return 77; }
    up nogroups || return 1
    said=$(setpriv --groups 4242 timeout -k 5 60 "$LB" exec nogroups --user 1234 /bin/sh -c 'id -G' </dev/null) || return 1
    echo "groups of uid 1234 in the container: $said (the caller was in group 4242)"
    [ "$said" = 1234 ] || return 1
    uid=$(setpriv --groups 4242 timeout -k 5 60 "$LB" exec nogroups /bin/sh -c 'id -u' </dev/null) &&
    said=$(setpriv --groups 4242 timeout -k 5 60 "$LB" exec nogroups /bin/sh -c 'id -G' </dev/null) || return 1
    said=$(printf '%s\n' "$said" | tr ' ' '\n' | sort -n -u | paste -sd' ' -)
    want=$(awk -F: '$3 == 0 || ("," $4 ",") ~ /,root,/ { print $3 }' "$BASE/etc/group" | sort -n -u | paste -sd' ' -)
    echo "uid and groups without --user: $uid, $said; the image gives root $want"
    [ "$uid" = 0 ] && [ "$said" = "$want" ]
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

# Nothing in a container gives a file the setuid or the setgid bit, in its own
# files or in a volume, which are on the host too (ROADMAP 8.2): chmod asks for
# either and is refused, and a plain mode is taken.
t_no_setuid_or_setgid_bits() {
    mkdir -p "$T/vol/bits" || return 1
    box bits --vol "$T/vol/bits:/bits" && volume_for bits "$T/vol/bits" && start bits || return 1
    sh_in bits 'echo x > /bits/file && echo x > /file && chmod 750 /bits/file /file' || return 1
    for change in 'u+s /bits/file' 'g+s /bits/file' '4755 /file' '2755 /file' '6755 /bits/file'; do
        if said=$(sh_in bits "chmod $change" 2>&1); then
            echo "chmod $change was taken"
            return 1
        fi
        echo "chmod $change: $said"
        case $said in *'not permitted'*) ;; *) echo "refused for another reason than the bits"; return 1 ;; esac
    done
    modes=$(stat -c %a "$T/vol/bits/file" "$C/bits/rootfs/file" | paste -sd' ')
    echo "on the host: $modes"
    [ "$modes" = '750 750' ]
}

# --seccomp allow (ROADMAP 8.3): the .conf and inspect say so, and what exec
# runs is under the allow-list: a call it does not name answers ENOSYS, as
# sethostname does, which the deny-list lets through to be refused for want
# of CAP_SYS_ADMIN; and the rest works. --seccomp deny is the deny-list, which
# a .conf without the line has, as one made before 0.8 does.
t_seccomp_profiles() {
    box sallow --seccomp allow && box sdeny --seccomp deny && start sallow && start sdeny || return 1
    [ "$(conf_value sallow seccomp)" = allow ] && [ -z "$(conf_value sdeny seccomp)" ] ||
        { echo "the .conf of each: $(conf_value sallow seccomp), $(conf_value sdeny seccomp)"; return 1; }
    lb inspect sallow | grep -qx 'seccomp: allow' && lb inspect sdeny | grep -qx 'seccomp: deny' ||
        { echo "inspect does not say which profile each has"; return 1; }
    said_allow=$(sh_in sallow "$KIT hostname another" 2>&1) && { echo "the allow-list took sethostname"; return 1; }
    said_deny=$(sh_in sdeny "$KIT hostname another" 2>&1) && { echo "the deny-list container set its hostname"; return 1; }
    echo "allow-list: $said_allow"
    echo "deny-list:  $said_deny"
    case $said_allow in *'not implemented'*) ;; *) echo "the allow-list did not answer ENOSYS"; return 1 ;; esac
    case $said_deny in *'not permitted'*) ;; *) echo "the deny-list did not leave it to the kernel"; return 1 ;; esac
    for name in sallow sdeny; do
        sh_in "$name" 'grep -q "^Seccomp:.2" /proc/self/status && echo works' | grep -qx works ||
            { echo "$name: a command does not run under a filter"; return 1; }
    done
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
    box record || return 1
    # Where the image's /bin is: /usr/bin in an image of merged /usr, such as
    # Debian's, in which /bin is a link. A directory bin/ in the upper layer
    # would hide that link, and with it the image's /bin/sh.
    bin=$(chroot "$BASE" "$KIT" readlink -f /bin) && [ -n "$bin" ] || return 1
    # that directory of the container's own, which the upper layer of an
    # overlay lacks
    mkdir -p "$C/record/rootfs$bin" || return 1
    for tool in mount ip; do
        rm -f "$C/record/rootfs$bin/$tool"
        printf '#!/bin/sh\necho %s >> /run-from-the-image\nexec %s %s "$@"\n' "$tool" "$KIT" "$tool" \
            > "$C/record/rootfs$bin/$tool" && chmod 755 "$C/record/rootfs$bin/$tool" || return 1
    done
    top=${bin#/}
    made_for record "$C/record/rootfs/${top%%/*}" || return 1
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
    # the exec's own, below the container's (ROADMAP 8.7)
    case $where in *"/${CG##*/}/member/exec-"[0-9]*-[0-9]*) ;; *) return 1 ;; esac
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

# The cgroup device program (ROADMAP 8.4): a container opens the devices of
# its /dev and no other. The suite makes nodes as host root in the
# container's /dev, a tmpfs that is not nodev, and the program refuses them
# by their numbers whatever their name: /dev/kmsg's, /dev/mem's and a block
# device's. A node of /dev/null's numbers under another name opens, and
# /dev/urandom is read and not written, which its read-only mount did not
# keep it from. A block device in a volume is refused too, as volumes are
# nodev. A privileged container has no program, and opens the same nodes. The
# /dev of a container with a user namespace of its own is that namespace's,
# in which host root has no id: the suite cannot make a node there at all.
t_device_filter() {
    mkdir -p "$T/vol/devs" && mknod -m 666 "$T/vol/devs/loop" b 7 0 || return 1
    up devs --vol "$T/vol/devs:/devs" && PLAIN=1 up devpriv --privileged || return 1
    plant() { # name
        local dev
        dev=/proc/$(pid_of "$1")/root/dev
        mknod -m 666 "$dev/lbt-kmsg" c 1 11 && mknod -m 666 "$dev/lbt-mem" c 1 1 &&
        mknod -m 666 "$dev/lbt-loop" b 7 0 && mknod -m 666 "$dev/lbt-null" c 1 3
    }
    plant devpriv || { echo "the suite cannot make nodes in the /dev of devpriv"; return 1; }
    refusals=('echo x > /dev/urandom' ': < /devs/loop')
    if [ "$(conf_value devs userns)" = 1 ]; then
        said=$(plant devs 2>&1) && { echo "host root made a node in the /dev of a container with --userns"; return 1; }
        echo "in the /dev of a container with --userns: $said"
        [ ! -e "/proc/$(pid_of devs)/root/dev/lbt-kmsg" ] || { echo "a node was left there"; return 1; }
    else
        plant devs || { echo "the suite cannot make nodes in the /dev of devs"; return 1; }
        refusals+=(': < /dev/lbt-kmsg' ': < /dev/lbt-mem' ': < /dev/lbt-loop')
        sh_in devs ': < /dev/lbt-null && echo x > /dev/lbt-null' ||
            { echo "a node of /dev/null's numbers under another name does not open"; return 1; }
    fi

    said=$(sh_in devs ': < /dev/null && echo x > /dev/null &&
                       head -c 8 /dev/zero | wc -c && head -c 8 /dev/urandom | wc -c' 2>&1)
    said=$(printf '%s\n' "$said" | tr -d ' ' | paste -sd' ' -)
    echo "its own devices: $said"
    [ "$said" = '8 8' ] || { echo "a device of its own does not work"; return 1; }

    # the volume's nodev refuses first, with EACCES; the program refuses with EPERM
    for what in "${refusals[@]}"; do
        said=$(sh_in devs "$what" 2>&1) && { echo "taken: $what"; return 1; }
        echo "$what: $said"
        case $what:$said in
            *'/devs/'*:*denied*) ;;
            *'/dev/'*:*'not permitted'*) ;;
            *) echo "not refused as the device program or the volume's nodev refuses"; return 1 ;;
        esac
    done

    sh_in devpriv ': < /dev/lbt-kmsg && : < /dev/lbt-null && echo x > /dev/urandom' ||
        { echo "the privileged container cannot open them"; return 1; }
    echo "the privileged container opens /dev/kmsg's numbers and writes /dev/urandom"
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
    said=$(sh_in net "$KIT ip addr; $KIT ip route")
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -q 'inet 127\.0\.0\.1/8' &&
    printf '%s\n' "$said" | grep -q "inet $(addr_of net)/24" &&
    printf '%s\n' "$said" | grep -q "^default via $GW "
}

# --net outside, the default (ROADMAP 8.5): a container reaches the outside
# and resolves a name through its name server, which is on a private
# address, and is refused at once the host, on the bridge's address and on
# its other one, a private address, the metadata address, and its name
# server on any port but 53. A container of --net nat beside it reaches all
# of them, so that it is the rules that refuse them. Then stopped, nothing of
# the rules is left. starter: the command that starts a container.
net_outside() { # prefix, starter...
    local p=$1 dns_pid said a
    shift
    need_nc || return 77
    need_listeners || return 77
    private_addresses || return 1
    box "${p}out" --dns "$PRIVATE_DNS" && box "${p}nat" --net nat --dns "$PRIVATE_DNS" || return 1
    [ "$(conf_value "${p}out" net)" = outside ] || { echo "the default is not outside: $(conf_value "${p}out" net)"; return 1; }
    "$@" "${p}out" && "$@" "${p}nat" || return 1
    for a in "$GW" 192.0.2.2 "$PRIVATE" "$METADATA" "$PRIVATE_DNS"; do
        answered "${p}nat" "$a" || { echo "the container of --net nat does not reach $a"; return 1; }
        rejected "${p}out" "$a" || { echo "$a was not refused at once"; return 1; }
    done
    answered "${p}out" "$OUTSIDE" || { echo "the container of --net outside does not reach the outside"; return 1; }
    if dns_pid=$(dns_responder "$PRIVATE_DNS"); then
        sleep 0.5
        said=$(sh_in "${p}out" "$KIT nslookup lbt.example $PRIVATE_DNS" 2>&1)
        kill "$dns_pid" 2>/dev/null
        printf '%s\n' "$said"
        printf '%s\n' "$said" | grep -q '192\.0\.2\.77' || { echo "the name was not resolved"; return 1; }
    else
        echo "no python3 for a name server: that a name is resolved is not tried"
    fi
    lb stop "${p}out" >/dev/null && nothing_left "${p}out"
}
t_net_outside() { net_outside n start; }

# --net none: loopback and nothing else. start makes no interface on the
# host for it, and the container has no address, no route and no eth0.
t_net_none() {
    # without an address: box gives one, which --net none refuses
    # shellcheck disable=SC2046  # options of one word each
    lb create nonet --net none $(mode_options --net none) >"$OUT/nonet.create" 2>&1 ||
        { cat "$OUT/nonet.create"; return 1; }
    cat "$OUT/nonet.create"
    grep -q '(no network)' "$OUT/nonet.create" || { echo "create does not say it has no network"; return 1; }
    [ ! -e "$C/nonet/.ip" ] || { echo "it has an address on record"; return 1; }
    lb inspect nonet | grep -qx 'net: none' && lb inspect nonet | grep -qx 'ip: -' ||
        { echo "inspect does not say it"; return 1; }
    before=$(links_now)
    start nonet || return 1
    [ "$(links_now)" = "$before" ] || { echo "start made an interface on the host: $(links_now | tr '\n' ' ')"; return 1; }
    said=$(sh_in nonet 'cat /proc/net/dev' | sed '1,2d' | awk -F: '{ gsub(/ /, "", $1); print $1 }' | paste -sd' ' -)
    echo "its interfaces: $said"
    [ "$said" = lo ] || return 1
    said=$(sh_in nonet "$KIT ip -4 addr; $KIT ip route" 2>&1)
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -q 'inet 127\.0\.0\.1/8' && ! printf '%s\n' "$said" | grep -q 'default' ||
        { echo "it has more than loopback"; return 1; }
    said=$(sh_in nonet "$KIT nc -w 2 $OUTSIDE 9 </dev/null" 2>&1) && { echo "it reached the outside"; return 1; }
    echo "the outside: $said"
    case $said in *'unreachable'*) ;; *) return 1 ;; esac
    lb stop nonet >/dev/null && nothing_left nonet
}

PROXY_PORT=3128

# --net proxy:<port> (ROADMAP 8.6), with a listener on the gateway standing
# in for the proxy: the container reaches that port of the gateway and
# nothing else. Another port of the gateway, the proxy's port on the host's
# other address, the outside and a name server on TCP, each with a listener,
# are refused within a second, and a name server on UDP does not answer it;
# its resolv.conf names none; exec and the hook have the variables of its
# proxy, and --env replaces one. A container of --net nat beside it reaches
# all of them. With links, that one names it with --link, made before it so
# that create could not refuse the link, and neither reaches the other. With
# both stopped, nothing of their rules is left. links: whether links can be
# had here; starter: what starts a container.
net_proxy() { # prefix, links (yes|no), starter...
    local p=$1 links=$2 rc=0
    shift 2
    need_nc || return 77
    need_listeners || return 77
    private_addresses || return 1
    if [ "$links" = yes ]; then
        box "${p}lnk" --net nat --link "${p}prx" || return 1
    else
        box "${p}lnk" --net nat || return 1
    fi
    box "${p}prx" --net "proxy:$PROXY_PORT" || return 1
    [ "$(conf_value "${p}prx" net)" = "proxy:$PROXY_PORT" ] || { echo "net=$(conf_value "${p}prx" net)"; return 1; }
    hook "${p}prx" <<'EOF'
env > /hook.env
EOF
    # in place of the proxy, on every address of the host; and a name server
    # on TCP beyond it
    local proxy tcp53
    proxy=$(tcp_listener 0.0.0.0 "$PROXY_PORT" 'the proxy here') &&
        tcp53=$(tcp_listener 0.0.0.0 53 'a name server on TCP' "$(cat "$T/outside")") || return 1
    "$@" "${p}lnk" && "$@" "${p}prx" && net_proxy_checks "$p" "$links" || rc=1
    kill "$proxy" "$tcp53" 2>/dev/null
    port_free() { ! ss -ltn | grep -q ":$PROXY_PORT "; }
    wait_until 5 port_free || { echo "the listener on port $PROXY_PORT is still there"; rc=1; }
    # both: the nftables elements of the link name the container of --net
    # proxy too, and are the other's, which take them out when it stops
    [ "$rc" = 0 ] && lb stop "${p}prx" >/dev/null && lb stop "${p}lnk" >/dev/null &&
        nothing_left "${p}prx" && nothing_left "${p}lnk"
}
net_proxy_checks() { # prefix, links
    local p=$1 links=$2 said v url dns_pid try
    for try in 1 2 3 4 5; do
        answers "${p}prx" "$GW" "$PROXY_PORT" 'the proxy here' && break
        [ "$try" = 5 ] && { echo "the container did not reach its proxy"; return 1; }
        sleep 0.3
    done
    answered "${p}lnk" "$GW" && answers "${p}lnk" 192.0.2.2 "$PROXY_PORT" 'the proxy here' &&
    answered "${p}lnk" "$OUTSIDE" && answers "${p}lnk" "$PRIVATE_DNS" 53 'a name server on TCP' ||
        { echo "the container of --net nat does not reach one of them"; return 1; }
    rejected "${p}prx" "$GW" && rejected "${p}prx" 192.0.2.2 "$PROXY_PORT" && rejected "${p}prx" "$OUTSIDE" &&
    rejected "${p}prx" "$PRIVATE_DNS" 53 || { echo "it was not refused within a second"; return 1; }
    if dns_pid=$(dns_responder "$PRIVATE_DNS"); then
        sleep 0.5
        said=$(sh_in "${p}lnk" "$KIT nslookup lbt.example $PRIVATE_DNS" 2>&1)
        printf '%s\n' "$said" | grep -q '192\.0\.2\.77' || { kill "$dns_pid"; echo "the name server did not answer --net nat: $said"; return 1; }
        said=$(LB_TIMEOUT=20 lb exec "${p}prx" /bin/sh -c "$KIT nslookup lbt.example $PRIVATE_DNS" </dev/null 2>&1)
        kill "$dns_pid" 2>/dev/null
        printf '%s\n' "$said"
        printf '%s\n' "$said" | grep -q '192\.0\.2\.77' && { echo "the container of --net proxy had a name looked up"; return 1; }
    fi
    said=$(sh_in "${p}prx" 'cat /etc/resolv.conf')
    echo "its resolv.conf: $said"
    printf '%s\n' "$said" | grep -q nameserver && { echo "it names a name server"; return 1; }
    url="http://$GW:$PROXY_PORT"
    for v in "HTTP_PROXY=$url" "HTTPS_PROXY=$url" "http_proxy=$url" "https_proxy=$url" \
             'NO_PROXY=localhost,127.0.0.1,::1' 'no_proxy=localhost,127.0.0.1,::1'; do
        sh_in "${p}prx" env | grep -qxF "$v" || { echo "exec has no $v:"; sh_in "${p}prx" env; return 1; }
        sh_in "${p}prx" 'cat /hook.env' | grep -qxF "$v" || { echo "the hook had no $v"; return 1; }
    done
    said=$(lb exec "${p}prx" --env HTTP_PROXY=http://elsewhere:1 -- env </dev/null | grep '^HTTP_PROXY=')
    [ "$said" = 'HTTP_PROXY=http://elsewhere:1' ] || { echo "--env did not replace it: $said"; return 1; }
    sh_in "${p}lnk" env | grep -qi '_proxy=' && { echo "a container of --net nat has the variables"; return 1; }
    if [ "$links" = yes ]; then
        # nothing listens on port 9 of either: reaching it is a refusal, and
        # what the bridge drops gets no answer at all
        reaches "${p}lnk" "$(addr_of "${p}prx")" && { echo "a container linked to it reached it"; return 1; }
        reaches "${p}prx" "$(addr_of "${p}lnk")" && { echo "it reached a container linked to it"; return 1; }
    fi
    return 0
}
t_net_proxy() {
    local links=yes
    brnf 1 || { links=no; echo "br_netfilter is not loaded: that a link to it reaches nothing is not tried"; }
    net_proxy x "$links" start
}

# contrib/proxy/squid.conf (ROADMAP 8.6), as it is but for where it listens,
# the subnet it serves and where its list of domains is: from a container of
# --net proxy, through the variables exec gives it, a name on the list is
# reached on port 80 and through CONNECT on port 443, and Squid looks it up
# from a hosts file; a name not on the list, an address, a name on the list
# that is a private address and CONNECT to another port are refused; and the
# name not on the list is never asked of the name server, so that a lookup
# carries nothing out.
t_proxy_example() {
    need_nc || return 77
    command -v squid >/dev/null 2>&1 || { echo "no squid"; return 77; }
    command -v python3 >/dev/null 2>&1 || { echo "no python3 for a name server and the outside's servers"; return 77; }
    private_addresses || return 1
    local example sq squid_pid web tls dns_pid said rc=0 outside
    example=$(cd "$(dirname "$SELF")/.." && pwd)/contrib/proxy
    # Squid gives up root for nobody, who has to reach its files
    sq=$(mktemp -d /tmp/lbt-squid.XXXXXX) && chmod 755 "$sq" || return 1
    printf '%s\n' allowed.lbt.test private.lbt.test > "$sq/allowed"
    # and not refused.lbt.test: were it looked up, the name server would be asked
    printf '%s\n' "$OUTSIDE allowed.lbt.test" "$PRIVATE private.lbt.test" > "$sq/hosts"
    sed -e "s|^http_port 10\.0\.0\.1:3128\$|http_port $GW:$PROXY_PORT|" \
        -e "s|^acl lightbox src 10\.0\.0\.0/24\$|acl lightbox src $SUBNET|" \
        -e "s|\"/etc/squid/lightbox-allowed-domains\"|\"$sq/allowed\"|" "$example/squid.conf" > "$sq/squid.conf"
    grep -qx "http_port $GW:$PROXY_PORT" "$sq/squid.conf" && grep -qx "acl lightbox src $SUBNET" "$sq/squid.conf" &&
        grep -qF "\"$sq/allowed\"" "$sq/squid.conf" || { echo "the example is not as this case expects it"; rm -rf -- "$sq"; return 1; }
    cat >> "$sq/squid.conf" <<EOF
# the case's own
visible_hostname lbt-proxy
hosts_file $sq/hosts
dns_nameservers $PRIVATE_DNS
cache_effective_user nobody
pid_filename $sq/squid.pid
cache_log $sq/cache.log
access_log stdio:$sq/access.log
coredump_dir $sq
shutdown_lifetime 1 seconds
EOF
    chown -R 65534 "$sq" || { rm -rf -- "$sq"; return 1; }
    squid -k parse -f "$sq/squid.conf" > "$OUT/squid.parse" 2>&1 || { cat "$OUT/squid.parse"; rm -rf -- "$sq"; return 1; }
    outside=$(cat "$T/outside")
    : > "$T/dns.log"
    dns_pid=$(dns_responder "$PRIVATE_DNS" "$T/dns.log")
    web=$(tcp_listener 0.0.0.0 80 "$(printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 17\r\n\r\nfrom the outside')" "$outside")
    tls=$(tcp_listener 0.0.0.0 443 'a tunnel to the outside' "$outside")
    squid -N -f "$sq/squid.conf" > "$OUT/squid.out" 2>&1 &
    squid_pid=$!
    listening() { ss -ltn | grep -qF "$GW:$PROXY_PORT"; }
    wait_until 20 listening || { echo "squid does not listen:"; cat "$OUT/squid.out" "$sq/cache.log"; rc=1; }
    if [ "$rc" = 0 ]; then
        box sqprx --net "proxy:$PROXY_PORT" && start sqprx || rc=1
    fi
    if [ "$rc" = 0 ]; then
        said=$(sh_in sqprx "$KIT wget -q -O - http://allowed.lbt.test/" 2>&1)
        echo "http://allowed.lbt.test/: $said"
        [ "$said" = 'from the outside' ] || { echo "a name on the list was not reached on port 80"; rc=1; }
        # nc's input stays open a while: at its end nc half-closes the
        # connection, which Squid takes for the client giving up
        connect() { # authority
            { printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$1" "$1"; sleep 2; } |
                lb exec sqprx /bin/sh -c "$KIT nc -w 3 $GW $PROXY_PORT" 2>&1 | tr -d '\r'
        }
        said=$(connect allowed.lbt.test:443)
        printf 'CONNECT allowed.lbt.test:443: %s\n' "$said"
        printf '%s\n' "$said" | grep -q '^HTTP/1\.1 200 ' && printf '%s\n' "$said" | grep -qx 'a tunnel to the outside' ||
            { echo "CONNECT to a name on the list did not go through"; rc=1; }
        for authority in refused.lbt.test:443 "$OUTSIDE:443" private.lbt.test:443 allowed.lbt.test:22; do
            said=$(connect "$authority" | head -n 1)
            printf 'CONNECT %s: %s\n' "$authority" "$said"
            case $said in 'HTTP/1.1 403 '*) ;; *) echo "CONNECT $authority was not refused"; rc=1 ;; esac
        done
        said=$(sh_in sqprx "$KIT wget -q -O - http://refused.lbt.test/" 2>&1) && { echo "a name not on the list was reached"; rc=1; }
        echo "http://refused.lbt.test/: $said"
        echo "what the name server was asked: $(paste -sd' ' "$T/dns.log")"
        grep -q refused "$T/dns.log" && { echo "a name not on the list was looked up"; rc=1; }
        lb stop sqprx >/dev/null || rc=1
    fi
    kill "$squid_pid" 2>/dev/null
    squid_ended() { ! alive "$squid_pid"; }
    wait_until 10 squid_ended || kill -KILL "$squid_pid" 2>/dev/null
    wait "$squid_pid" 2>/dev/null
    kill "$web" "$tls" "$dns_pid" 2>/dev/null
    if [ "$rc" != 0 ]; then
        echo "squid's log:"; cat "$sq/cache.log" 2>/dev/null | tail -n 30
        echo "its access log:"; cat "$sq/access.log" 2>/dev/null
    fi
    rm -rf -- "$sq"
    return "$rc"
}

t_reaches_gateway() {
    need_nc || return 77
    up togw --net nat || return 1
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
    lb create wide 10.9.5.2 --net nat $(mode_options) >"$OUT/wide.create" 2>&1 || { cat "$OUT/wide.create"; return 1; }
    start wide || return 1
    said=$(sh_in wide "$KIT ip addr; $KIT ip route")
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -q 'inet 10\.9\.5\.2/16' && printf '%s\n' "$said" | grep -q '^default via 10\.9\.0\.1 ' ||
        { echo "the container does not have 10.9.5.2/16 and a route by 10.9.0.1"; return 1; }
    if [ -e "$T/have_nc" ]; then
        reaches wide 10.9.0.1 || return 1
    else
        echo "the suite's busybox has no nc: whether the gateway answers is not tried"
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
    up iso1 --net nat && up iso2 --net nat || return 1
    reaches iso1 "$(addr_of iso2)" && { echo "iso1 reached iso2"; return 1; }
    reaches iso2 "$(addr_of iso1)" && { echo "iso2 reached iso1"; return 1; }
    reaches iso1 "$GW"      # it is the firewall that stops them, not a network that does not work
}

# A host without br_netfilter: bridged traffic does not pass through iptables.
# Containers without links are kept apart at the bridge itself.
t_isolated_when_not_filtered() {
    need_nc || return 77
    if [ -e "$BRNF" ]; then brnf 0 || return 1; fi
    up iso3 --net nat && up iso4 --net nat || return 1
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

# A start puts in a container's link rules, and with them the rules of
# --net outside, the default, with one process, iptables-restore.
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
    # but for the looks at whether setup's jumps are there, which every start
    # has; the links and the rules of --net outside, the default, go in as one
    tools=$(grep -E 'execve\("[^"]*/(ip6?tables[^"]*|nft)"' "$T/links.strace" | grep -v ' = -1 ')
    printf '%s\n' "$tools"
    put_in=$(printf '%s\n' "$tools" | grep -v -e '"-C", "FORWARD", "-j", "LIGHTBOX-FORWARD"' \
                                              -e '"-C", "INPUT", "-j", "LIGHTBOX-INPUT"')
    count=$(printf '%s\n' "$put_in" | grep -c .)
    echo "firewall tools the start ran to put rules in: $count"
    [ "$count" = 1 ] && printf '%s\n' "$put_in" | grep -q 'restore'
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
    printf '%s\n' "$(sh_in ifname "$KIT ip -4 addr show dev eth0")" | grep -q "inet $(addr_of ifname)/"
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
    [ -x "$snap$KIT" ] || { echo "the snapshot has no $KIT"; return 1; }
    lb inspect ov1 | grep -x 'storage: overlay' && lb inspect ov1 | grep -x "base: $id" || return 1
    own=$(cd "$C/ov1/rootfs" && find . -type f | sort | paste -sd' ' -)
    echo "ov1's own files: $own"
    [ "$own" = './etc/hostname ./etc/hosts ./etc/resolv.conf' ] || { echo "rootfs/ has more than create wrote"; return 1; }
    start ov1 || return 1
    [ "$(sh_in ov1 "test -x $KIT && cat /etc/hostname")" = ov1 ] || { echo "the base or the hostname is not there"; return 1; }
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

# reset (ROADMAP 8.8): a container that runs is stopped, and its root
# filesystem is its base's again, with only the files create wrote in its
# rootfs/, which is still its root's, and nothing copied; its /etc is as
# create made it, and its volume as the container left it. A container
# marked as half made, as a reset cut short leaves it, is not started, and
# reset makes it whole. A copy of its base is refused, and runs on.
t_reset() {
    local said etc own owner
    OVERLAY=1
    mkdir -p "$T/vol/resetvol"
    box rst --vol "$T/vol/resetvol:/data" && volume_for rst "$T/vol/resetvol" && start rst || return 1
    etc=$(sh_in rst 'cat /etc/hostname /etc/hosts /etc/resolv.conf')
    owner=$(stat -c %u:%g "$C/rst/rootfs")
    sh_in rst 'echo mine > /made-here && echo kept > /data/kept && rm /etc/group && echo changed > /etc/resolv.conf' || return 1
    said=$(lb reset rst </dev/null) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -qx "Container 'rst' reset: its root filesystem is its base's again" || return 1
    nothing_left rst || return 1
    own=$(cd "$C/rst/rootfs" && find . -type f | sort | paste -sd' ' -)
    echo "its own files: $own; rootfs/ $(stat -c %u:%g "$C/rst/rootfs"), was $owner"
    [ "$own" = './etc/hostname ./etc/hosts ./etc/resolv.conf' ] || { echo "rootfs/ has more than create wrote"; return 1; }
    [ "$(stat -c %u:%g "$C/rst/rootfs")" = "$owner" ] || { echo "rootfs/ changed hands"; return 1; }
    [ "$(cat "$T/vol/resetvol/kept")" = kept ] || { echo "the volume lost its file"; return 1; }
    start rst || return 1
    sh_in rst 'test ! -e /made-here && test -e /etc/group' || { echo "what the container did is still there"; return 1; }
    [ "$(sh_in rst 'cat /etc/hostname /etc/hosts /etc/resolv.conf')" = "$etc" ] || { echo "/etc is not as create made it"; return 1; }
    [ "$(sh_in rst 'cat /data/kept')" = kept ] || { echo "the container does not see its volume's file"; return 1; }

    lb stop rst >/dev/null || return 1
    : > "$C/rst/.creating"
    lb start rst >/dev/null 2>&1 </dev/null && { echo "a half made container was started"; return 1; }
    lb reset rst </dev/null || return 1
    [ ! -e "$C/rst/.creating" ] || { echo "reset left the mark"; return 1; }
    start rst || return 1

    up rstc --copy || return 1
    said=$(lb reset rstc 2>&1 </dev/null) && { echo "a copy was reset"; return 1; }
    printf '%s\n' "$said"
    case $said in *"is a copy of its base"*) ;; *) return 1 ;; esac
    [ "$(state_of rstc)" = running ] || { echo "the copy did not run on: $(state_of rstc)"; return 1; }
}

# --copy: a copy of the base, as before 0.7, with no snapshot of its own.
t_copy_root() {
    box cp1 --copy || return 1
    [ -z "$(base_of cp1)" ] || { echo "a copy has a base snapshot: $(base_of cp1)"; return 1; }
    [ -x "$C/cp1/rootfs$KIT" ] || { echo "rootfs/ is not a copy of the base"; return 1; }
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

# ─── Cases: images (ROADMAP Track I) ────────────────────────────────────────

# export (ROADMAP I.5) of a container that ran. One that overlays a snapshot
# is two layers: the snapshot, whose digest and size the snapshot keeps, and
# the container's own files, with a file it removed and a directory it made
# anew marked as an image marks them. What its root made is uid 0 in the
# image, whatever range of the host's the container has; the device the
# kernel left for the removed file is host root's, and its mark is written
# all the same. Two containers of one snapshot have one first layer. A
# container that runs is refused and nothing is left of an image; after its
# export it starts as before. A copy is one layer.
# tests/image_check.py holds each image to the digests and sizes it names.
t_export() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to read the image with"; return 77; }
    local said out id two
    OVERLAY=1
    up exp --mem 300M --ttl 2h || return 1
    sh_in exp 'echo mine > /made-here && rm /etc/group && rm -r /lbt && mkdir /lbt && echo again > /lbt/again' || return 1
    said=$(lb export exp "$T/image-running" 2>&1 </dev/null) && { echo "a running container was exported"; return 1; }
    printf '%s\n' "$said"
    [ "$said" = 'Error: container is running (stop it first): exp' ] && [ ! -e "$T/image-running" ] ||
        { echo "a running container was not refused as one, or left a directory"; return 1; }
    lb stop exp >/dev/null || return 1
    # a directory that is there and another user's is not written into
    mkdir "$T/image-of-another" && chown 4711:4711 "$T/image-of-another" || return 1
    said=$(lb export exp "$T/image-of-another" 2>&1 </dev/null) && { echo "an image was written into another user's directory"; return 1; }
    case $said in *"and this is another user's"*) ;; *) printf '%s\n' "$said"; return 1 ;; esac
    [ -z "$(ls -A "$T/image-of-another")" ] || { echo "a refused export left files"; return 1; }
    echo "in rootfs/: $(cd "$C/exp/rootfs" && find . -mindepth 1 \( -name group -o -name lbt -o -name made-here \) -printf '%p %y %U:%G; ')"

    said=$(lb export exp "$T/image" 2>&1 </dev/null) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    out=$(python3 -I "$HERE/image_check.py" "$T/image") || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out" | grep -v '^entry 1 '
    printf '%s\n' "$said" | grep -q "^Container 'exp' exported: 2 layers, " && printf '%s\n' "$out" | grep -qx 'layers 2' ||
        { echo "an overlay is not two layers"; return 1; }
    printf '%s\n' "$out" | grep -qx 'annotation ac.ozkr.lightbox.mem=300M' &&
        printf '%s\n' "$out" | grep -qx 'annotation ac.ozkr.lightbox.ttl=2h' &&
        printf '%s\n' "$out" | grep -qx 'annotation ac.ozkr.lightbox.name=exp' || { echo "the limits are not in the image"; return 1; }

    # the snapshot, with what the container took out still in it
    id=$(base_of exp)
    [ "$(cat "$T/lb/bases/$id/layer")" = "$(printf '%s\n' "$out" | sed -n 's/^layer 1 //p')" ] ||
        { echo "the snapshot does not keep its layer's digest and size: $(cat "$T/lb/bases/$id/layer" 2>&1)"; return 1; }
    printf '%s\n' "$out" | grep -qE "^entry 1 (file|hardlink) .* ${KIT#/}( -> .*)?\$" &&
        printf '%s\n' "$out" | grep -qE '^entry 1 file [0-7]{4} [0-9]+:[0-9]+ [0-9]+ etc/group$' &&
        ! printf '%s\n' "$out" | grep -qE '^entry 1 .* made-here$' || { echo "the first layer is not the snapshot"; return 1; }
    # its own files, root's as uid 0, and the marks
    two=$(printf '%s\n' "$out" | sed -n 's/^entry 2 //p')
    printf '%s\n' "$two" | grep -qE '^file [0-7]{4} 0:0 5 made-here$' || { echo "what the container's root made is not uid 0 in the image"; return 1; }
    printf '%s\n' "$two" | grep -qE '^file [0-7]{4} 0:0 0 etc/\.wh\.group$' || { echo "the file it removed is not marked"; return 1; }
    printf '%s\n' "$two" | grep -qE '^file [0-7]{4} 0:0 0 lbt/\.wh\.\.wh\.\.opq$' &&
        printf '%s\n' "$two" | grep -qE '^file [0-7]{4} 0:0 6 lbt/again$' &&
        ! printf '%s\n' "$two" | grep -q " ${KIT#/}\$" || { echo "the directory it made anew does not hide its base's"; return 1; }
    printf '%s\n' "$two" | grep -qE '^file [0-7]{4} 0:0 4 etc/hostname$' || { echo "the files create wrote are not in the second layer"; return 1; }
    ! printf '%s\n' "$two" | grep -qE '^(char|block) ' || { echo "a device is in the second layer"; return 1; }

    # a second container of the same base has the same first layer
    box exp2 && lb export exp2 "$T/image2" >/dev/null 2>&1 </dev/null || return 1
    [ "$(python3 -I "$HERE/image_check.py" "$T/image2" | sed -n 's/^layer 1 //p')" = "$(printf '%s\n' "$out" | sed -n 's/^layer 1 //p')" ] ||
        { echo "two containers of one snapshot have two first layers"; return 1; }

    # the container is as it was
    start exp && [ "$(sh_in exp 'cat /made-here /lbt/again; test -e /etc/group || echo no-group')" = 'mine
again
no-group' ] || { echo "after its export the container is not what it was"; return 1; }

    # a copy of its base is one layer, with its files as they are in it
    OVERLAY=
    box expc --copy && lb export expc "$T/image-copy" >/dev/null 2>&1 </dev/null || return 1
    out=$(python3 -I "$HERE/image_check.py" "$T/image-copy") || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out" | grep -qx 'layers 1' && printf '%s\n' "$out" | grep -qE '^entry 1 file [0-7]{4} 0:0 5 etc/hostname$' &&
        printf '%s\n' "$out" | grep -qE "^entry 1 (file|hardlink) .* ${KIT#/}( -> .*)?\$" || { echo "a copy is not one layer of its files"; return 1; }
}

# import (ROADMAP I.6): a container that ran, with files added, changed and
# removed, links, a second name and owners of several ids, is exported and
# made a container again under another name. What it shows inside is what
# the first showed, with its own name and address in /etc; its limits are
# the first one's, which are within lightbox.conf's; it overlays the snapshot the first overlays, which is
# found by the layer export wrote it as, so that nothing of it is unpacked.
# Its own files are its root's on this host, whatever range it has, and the
# marks of the image are the overlay's own: a device for the file that was
# removed, the attribute for the directory that was made anew. The same
# image with its layers compressed is the same container. A copy, exported,
# is an image of one layer, which import unpacks into a snapshot once: a
# second import of it finds that one.
t_import() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to read the image with"; return 77; }
    local said ip first second owner before
    # what a container shows of the two directories the case made in it
    shown_in() {
        sh_in "$1" 'cd / && { find work lbt -type f -exec stat -c "%n file %a %u:%g %s %Y %h" {} + ; find work lbt ! -type f -exec stat -c "%N %F %a %u:%g %Y" {} + ; } | sort'
    }
    OVERLAY=1
    up imp --mem 200M --ttl 2h || return 1
    # no mode with the setgid bit: a container's seccomp filter refuses one
    sh_in imp 'mkdir -p /work/sub && echo mine > /work/file && ln -s file /work/link && ln /work/file /work/sub/second &&
        chown 1000:1001 /work/sub && chmod 750 /work/sub && echo more >> /etc/passwd && rm /etc/group &&
        rm -r /lbt && mkdir /lbt && echo again > /lbt/again && chown 12:34 /lbt/again && touch -d "2020-02-02 02:02:02" /work/file' || return 1
    first=$(shown_in imp) && [ -n "$first" ] || return 1
    printf '%s\n' "$first"
    lb stop imp >/dev/null && lb export imp "$T/imp-image" </dev/null || return 1

    imported "$T/imp-image" imp2 || return 1
    grep -qx "Container 'imp2' imported (ip=$ip)" "$OUT/imp2.import" || { echo "import does not say what it made"; return 1; }
    [ -n "$(base_of imp)" ] && [ "$(base_of imp2)" = "$(base_of imp)" ] &&
        grep -q ", on the base snapshot $(base_of imp), which was here\$" "$OUT/imp2.import" ||
        { echo "the import does not overlay the snapshot the container overlays"; return 1; }
    [ "$(conf_value imp2 mem)" = 200M ] && [ "$(conf_value imp2 ttl)" = 2h ] && grep -q "^Limits of the image's: mem=200M " "$OUT/imp2.import" ||
        { echo "the limits are not the image's"; return 1; }
    # its own files: its root's on this host, and the overlay's marks
    owner=0:0
    [ "$(conf_value imp2 userns)" = 1 ] && owner="$(conf_value imp2 uid_start):$(conf_value imp2 gid_start)"
    [ "$(stat -c %u:%g "$C/imp2/rootfs/work/file")" = "$owner" ] && [ "$(stat -c %u:%g "$C/imp2/rootfs")" = "$owner" ] ||
        { echo "its own files are not its root's on the host: $(stat -c %u:%g "$C/imp2/rootfs" "$C/imp2/rootfs/work/file" | paste -sd' '), not $owner"; return 1; }
    [ "$(stat -c '%F %t:%T' "$C/imp2/rootfs/etc/group")" = 'character special file 0:0' ] || { echo "the file that was removed is not marked as the overlay marks it"; return 1; }
    [ "$(python3 -I -c 'import os, sys; print(os.getxattr(sys.argv[1], "trusted.overlay.opaque").decode())' "$C/imp2/rootfs/lbt")" = y ] ||
        { echo "the directory that was made anew is not marked as one that hides its base's"; return 1; }

    start imp2 || return 1
    second=$(shown_in imp2)
    [ "$second" = "$first" ] || { echo "the import shows another tree:"; printf '%s\n' "$second"; return 1; }
    said=$(sh_in imp2 'cat /etc/hostname /work/file; tail -n 1 /etc/passwd; test -e /etc/group || echo no-group; test -e /lbt/busybox || echo no-busybox')
    [ "$said" = 'imp2
mine
more
no-group
no-busybox' ] || { echo "in the import: $said"; return 1; }
    sh_in imp2 "grep -q '^$ip	imp2\$' /etc/hosts && ! grep -q '	imp\$' /etc/hosts" || { echo "its hosts file is not its own: $(sh_in imp2 'cat /etc/hosts' | paste -sd'|')"; return 1; }
    lb stop imp2 >/dev/null || return 1

    # its layers compressed: the same container, on the same snapshot
    cp -r "$T/imp-image" "$T/imp-gz" && python3 -I "$HERE/image_edit.py" "$T/imp-gz" gzip || return 1
    imported "$T/imp-gz" imp3 && [ "$(base_of imp3)" = "$(base_of imp)" ] && start imp3 || return 1
    [ "$(shown_in imp3)" = "$first" ] || { echo "the image with its layers compressed is another tree"; return 1; }
    lb stop imp3 >/dev/null || return 1
    # and one that is not what it is named by makes nothing
    cp -r "$T/imp-image" "$T/imp-bad" && python3 -I "$HERE/image_edit.py" "$T/imp-bad" byte layer || return 1
    refused lb import "$T/imp-bad" imp-bad </dev/null && [ ! -e "$C/imp-bad" ] || { echo "an image with a byte changed was imported, or left a container"; return 1; }

    # a copy is one layer, and import makes a snapshot of it, once
    OVERLAY=
    up impc --copy && sh_in impc 'echo copied > /made-here' && lb stop impc >/dev/null && lb export impc "$T/impc-image" >/dev/null </dev/null || return 1
    OVERLAY=1
    before=$(ls "$T/lb/bases" | wc -l)
    imported "$T/impc-image" imp4 || return 1
    grep -q ", on the new base snapshot $(base_of imp4)\$" "$OUT/imp4.import" && [ "$(ls "$T/lb/bases" | wc -l)" = $((before + 1)) ] &&
        [ "$(cat "$T/lb/bases/$(base_of imp4)/rootfs/made-here")" = copied ] || { echo "a copy's image was not unpacked into a new snapshot"; return 1; }
    lb base ls | grep -E "^$(base_of imp4)  .*  sha256:[0-9a-f]{64}  imp4\$" || { lb base ls; echo "base ls does not show the snapshot of an image"; return 1; }
    imported "$T/impc-image" imp5 || return 1
    [ "$(base_of imp5)" = "$(base_of imp4)" ] && [ "$(ls "$T/lb/bases" | wc -l)" = $((before + 1)) ] &&
        grep -q ", which was here\$" "$OUT/imp5.import" || { echo "a second import took a second snapshot"; return 1; }
    start imp4 && [ "$(sh_in imp4 'cat /made-here /etc/hostname' | paste -sd' ')" = 'copied imp4' ] || { echo "the import of a copy does not start as itself"; return 1; }
    # a container made of a base after it does not take the image's snapshot for its base's
    box impn && [ "$(base_of impn)" != "$(base_of imp4)" ] || { echo "a snapshot of an image was taken for one of the base"; return 1; }
}

# To a registry and back (ROADMAP I.8), with a container that ran: it is
# exported, skopeo copies the image to tests/registry.py, a registry of this
# case's own on the loopback, and back into an empty directory, and import
# makes of that a container that starts and has the first one's files, on the
# snapshot the first one overlays. skopeo runs as another user than root,
# with its home, its runtime directory and its temporary files in the work
# directory: it keeps a record of what it copied, and root's would be the
# host's.
t_registry() {
    command -v python3 >/dev/null 2>&1 && command -v skopeo >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1 ||
        { echo "no python3, skopeo or setpriv to carry an image to a registry with"; return 77; }
    local pid port n=0 rc said ip
    OVERLAY=1
    up reg --mem 200M || return 1
    sh_in reg 'echo there > /made-here && rm /etc/group' || return 1
    lb stop reg >/dev/null && lb export reg "$T/reg-image" >/dev/null </dev/null || return 1
    mkdir -p "$T/carry/home" "$T/carry/run" "$T/carry/tmp" && cp -r "$T/reg-image" "$T/carry/image" && chown -R 4711:4711 "$T/carry" || return 1
    python3 -I "$HERE/registry.py" "$T/carry/registry" "$T/carry/port" "$T/carry/log" > "$T/carry/registry.out" 2>&1 &
    pid=$!
    while [ ! -s "$T/carry/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    port=$(cat "$T/carry/port" 2>/dev/null)
    carried() {
        [ -n "$port" ] || { cat "$T/carry/registry.out"; echo "the registry did not start"; return 1; }
        python3 -I -c 'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 3)' "$port" 2>/dev/null ||
            { echo "the loopback reaches no listener in the suite's namespace"; return 77; }
        # with nothing of the caller's environment: an XDG_CONFIG_HOME in it, as
        # CI's runners have one, names a directory of another user's, which
        # skopeo looks in for a registry's password and ends when it may not
        copy() {
            setpriv --reuid=4711 --regid=4711 --clear-groups env -i PATH="$PATH" HOME="$T/carry/home" \
                XDG_RUNTIME_DIR="$T/carry/run" XDG_CONFIG_HOME="$T/carry/home/.config" TMPDIR="$T/carry/tmp" \
                timeout 120 skopeo --insecure-policy copy --dest-tls-verify=false --src-tls-verify=false "$@" </dev/null
        }
        copy "oci:$T/carry/image" "docker://127.0.0.1:$port/boxes/reg:latest" || { echo "skopeo did not copy the image to the registry"; return 1; }
        copy "docker://127.0.0.1:$port/boxes/reg:latest" "oci:$T/carry/back" || { echo "skopeo did not copy the image back"; return 1; }
    }
    carried
    rc=$?
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    cat "$T/carry/log" 2>/dev/null
    [ $rc -ne 77 ] || return 77
    [ $rc -eq 0 ] || return 1
    imported "$T/carry/back" reg2 || return 1
    [ "$(base_of reg2)" = "$(base_of reg)" ] || { echo "what came back does not overlay the snapshot it was exported from"; return 1; }
    start reg2 || return 1
    said=$(sh_in reg2 'cat /made-here /etc/hostname; test -e /etc/group || echo no-group')
    [ "$said" = 'there
reg2
no-group' ] || { echo "what came back from the registry: $said"; return 1; }
}

# A registry's image as a base (ROADMAP I.9), with one made here as somebody
# else builds one: the export of a copy, with nothing of lightbox's said in
# it, a command to start, and a second layer over the first that adds a file
# and takes one out. base import unpacks both layers into one snapshot, and
# create --base makes a container that overlays it, starts, and shows the
# image's files with its own name in /etc; its snapshot is not removed under
# it. A reset gives it the whole image again, as both layers are its base.
# import of the same image is a container on that snapshot with nothing of
# its own: only an image that export wrote has its second layer as the
# container's own files, which a reset takes away. --copy is a copy of the
# snapshot.
t_base_import() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to make the image with"; return 77; }
    local said id
    box bisrc --copy && lb export bisrc "$T/bi-export" >/dev/null </dev/null || return 1
    python3 -I -c '
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w", format=tarfile.PAX_FORMAT) as t:
    d = tarfile.TarInfo("added"); d.type = tarfile.DIRTYPE; d.mode = 0o755; t.addfile(d)
    f = tarfile.TarInfo("added/file"); f.size = 7; f.mode = 0o644; f.uid, f.gid = 12, 34; t.addfile(f, io.BytesIO(b"second\n"))
    w = tarfile.TarInfo("etc/.wh.group"); t.addfile(w)
' "$T/bi-second.tar" && cp -r "$T/bi-export" "$T/bi-image" && python3 -I "$HERE/image_edit.py" "$T/bi-image" no-annotations &&
        python3 -I "$HERE/image_edit.py" "$T/bi-image" command && python3 -I "$HERE/image_edit.py" "$T/bi-image" add-layer "$T/bi-second.tar" ||
        { echo "no image to import"; return 1; }

    said=$(lb base import "$T/bi-image" 2>&1 </dev/null) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    id=$(printf '%s\n' "$said" | sed -n 's/^Base \([0-9a-f]\{12\}\) unpacked from the image sha256:[0-9a-f]\{64\}, 2 layers$/\1/p')
    [ -n "$id" ] || { echo "base import does not say what it made"; return 1; }
    printf '%s\n' "$said" | grep -q '^Note: the image names a command to start, which lightbox does not read' ||
        { echo "the image's command, which is not read, is not said"; return 1; }
    [ "$(cat "$T/lb/bases/$id/rootfs/added/file")" = second ] && [ "$(stat -c %u:%g "$T/lb/bases/$id/rootfs/added/file")" = 12:34 ] &&
        [ ! -e "$T/lb/bases/$id/rootfs/etc/group" ] && [ -e "$T/lb/bases/$id/rootfs$KIT" ] ||
        { echo "the snapshot is not the two layers, one over the other"; return 1; }
    said=$(lb base import "$T/bi-image" 2>&1 </dev/null) && printf '%s\n' "$said" | grep -q "^Base $id is the image sha256:[0-9a-f]\{64\} already, 2 layers: nothing was unpacked\$" ||
        { printf '%s\n' "$said"; echo "a second base import took a second snapshot"; return 1; }

    OVERLAY=1
    up bi1 --base "$id" || return 1
    [ "$(base_of bi1)" = "$id" ] || { echo "the container does not overlay the snapshot it was given: $(base_of bi1)"; return 1; }
    said=$(sh_in bi1 'cat /added/file /etc/hostname; stat -c %u:%g /added/file; test -e /etc/group || echo no-group')
    [ "$said" = 'second
bi1
12:34
no-group' ] || { echo "in the container of the image: $said"; return 1; }
    lb base ls | grep -E "^$id  .*  bi1\$" || { lb base ls; echo "base ls does not show the container on its snapshot"; return 1; }
    refused lb base rm "$id" || { echo "a snapshot was removed under its container"; return 1; }
    # its base is the whole image: a reset gives back both layers
    sh_in bi1 'echo mine > /added/mine && rm /added/file' && lb reset bi1 >/dev/null 2>&1 </dev/null && start bi1 || return 1
    [ "$(sh_in bi1 'cat /added/file; test -e /added/mine || echo gone')" = 'second
gone' ] || { echo "after a reset the container is not the image again"; return 1; }

    # import of that image: all of it is the snapshot, and its own files are what create writes
    imported "$T/bi-image" bi2 || return 1
    [ "$(base_of bi2)" = "$id" ] && grep -q ", on the base snapshot $id, which was here\$" "$OUT/bi2.import" ||
        { echo "an image that export did not write is not all snapshot"; return 1; }
    [ -z "$(cd "$C/bi2/rootfs" && find . -type f ! -path './etc/hostname' ! -path './etc/hosts' ! -path './etc/resolv.conf')" ] ||
        { echo "its own files are more than create writes: $(cd "$C/bi2/rootfs" && find . -type f | paste -sd' ')"; return 1; }
    start bi2 && lb reset bi2 >/dev/null 2>&1 </dev/null && start bi2 && [ "$(sh_in bi2 'cat /added/file /etc/hostname' | paste -sd' ')" = 'second bi2' ] ||
        { echo "the import of the image is not the image after a reset"; return 1; }

    # and a copy of the snapshot
    OVERLAY=
    up bi3 --base "$id" --copy || return 1
    [ -z "$(base_of bi3)" ] && [ "$(sh_in bi3 'cat /added/file /etc/hostname' | paste -sd' ')" = 'second bi3' ] ||
        { echo "create --base --copy is no copy of the snapshot"; return 1; }
    refused lb create bi4 --base 000000000000 </dev/null && [ ! -e "$C/bi4" ] || { echo "a snapshot that is not there was taken, or left a container"; return 1; }
}

# Alpine's or Debian's image as its registry has it (ROADMAP I.9): the
# directory LIGHTBOX_TEST_IMAGE names, which tests/fetch_image.sh --oci
# filled with skopeo, by the digest of the manifest that is pinned there.
# Its layers are compressed, and written by another program than lightbox's
# tests. base import makes a snapshot of it, a container of that starts with
# no /init.sh of its own and runs the image's own shell and package tool, and
# a file of another group than root's is that group's inside. import of the
# directory is a container on the same snapshot.
t_registry_image() {
    [ -n "${LIGHTBOX_TEST_IMAGE:-}" ] ||
        { echo "LIGHTBOX_TEST_IMAGE names no image of a registry's; tests/fetch_image.sh --oci alpine|debian <dir> fetches one"; return 77; }
    local said id os tool
    said=$(lb base import "$LIGHTBOX_TEST_IMAGE" 2>&1 </dev/null) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    id=$(printf '%s\n' "$said" | sed -n 's/^Base \([0-9a-f]\{12\}\) unpacked from the image sha256:[0-9a-f]\{64\}, [0-9]* layers\{0,1\}$/\1/p')
    [ -n "$id" ] || { echo "base import does not say what it made"; return 1; }
    echo "in the snapshot: $(find "$T/lb/bases/$id/rootfs" | wc -l) entries, $(du -sh "$T/lb/bases/$id/rootfs" | cut -f1)"
    OVERLAY=1
    up rimg --base "$id" || return 1
    os=$(sh_in rimg '. /etc/os-release && echo "$ID"')
    case $os in
        alpine) tool='apk --version' ;;
        debian) tool='dpkg --version' ;;
        *)      echo "the image says it is neither Alpine nor Debian: $os"; return 1 ;;
    esac
    said=$(sh_in rimg "$tool" 2>&1) && [ -n "$said" ] || { echo "the image's own $tool did not run: $said"; return 1; }
    printf '%s\n' "$said" | head -n 1
    said=$(sh_in rimg 'cat /etc/hostname; stat -c %u:%g /etc/shadow; test -e /init.sh || echo no-hook')
    [ "$said" = 'rimg
0:42
no-hook' ] || { echo "in the container of the image: $said"; return 1; }
    imported "$LIGHTBOX_TEST_IMAGE" rimg2 || return 1
    [ "$(base_of rimg2)" = "$id" ] && grep -q ", on the base snapshot $id, which was here\$" "$OUT/rimg2.import" ||
        { echo "import of the image took another snapshot than base import made"; return 1; }
    start rimg2 && sh_in rimg2 "$tool" >/dev/null || { echo "the import of the image does not start, or run $tool"; return 1; }
}

# An import takes no work away (ROADMAP I.10), with containers that run. One
# is exported, and its image imported: both are generation 1 of one line. The
# second works and is exported, generation 2, and that image takes the place
# of the first, which was not started since its export: it has the second's
# files, and its own name, address and limits, and starts. Started, it is on
# record as changed, and the same exchange the other way is refused with both
# generations named, as each has what the other has not; --force does it all
# the same. A reset is a change too.
t_import_replace() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 for the case's listener"; return 77; }
    local said line
    OVERLAY=1
    up gena --mem 200M || return 1
    sh_in gena 'echo one > /work.txt' && lb stop gena >/dev/null && lb export gena "$T/gen-1" > "$OUT/gen-1.export" 2>&1 </dev/null || { cat "$OUT/gen-1.export"; return 1; }
    grep -qx "Generation 1, the first of the container's line" "$OUT/gen-1.export" || { cat "$OUT/gen-1.export"; echo "the first export is not generation 1"; return 1; }
    line=$(cut -d' ' -f1 "$C/gena/.generation")
    imported "$T/gen-1" genb --mem 100M >/dev/null || return 1
    [ "$(cat "$C/genb/.generation")" = "$(cat "$C/gena/.generation")" ] && [ ! -e "$C/genb/.changed" ] || { echo "the import is not the generation its image is"; return 1; }

    # the second one works: started, it is on record as changed, and its export is generation 2
    start genb && [ -e "$C/genb/.changed" ] || { echo "a start left no record that the container changed"; return 1; }
    sh_in genb 'echo two >> /work.txt && rm /etc/group' && lb stop genb >/dev/null && lb export genb "$T/gen-2" > "$OUT/gen-2.export" 2>&1 </dev/null || { cat "$OUT/gen-2.export"; return 1; }
    grep -qx 'Generation 2: the container was started since the one before' "$OUT/gen-2.export" && [ ! -e "$C/genb/.changed" ] &&
        grep -qxE "$line 2 [0-9a-f]{8},[0-9a-f]{8}" "$C/genb/.generation" || { cat "$OUT/gen-2.export"; echo "the export of a container that was started is not generation 2"; return 1; }

    # and takes the place of the first, which was not started since its export
    said=$(lb import "$T/gen-2" gena --replace 2>&1 </dev/null) || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    printf '%s\n' "$said" | grep -qx "Container 'gena' replaced: generation 2 in the place of generation 1" || { echo "replace does not say what it did"; return 1; }
    [ "$(cat "$C/gena/.generation")" = "$(cat "$C/genb/.generation")" ] && [ "$(conf_value gena mem)" = 200M ] &&
        [ "$(base_of gena)" = "$(base_of genb)" ] || { echo "the container is not the image's generation with its own limits, on the snapshot"; return 1; }
    start gena || return 1
    said=$(sh_in gena 'cat /work.txt /etc/hostname; test -e /etc/group || echo no-group' | paste -sd' ')
    [ "$said" = 'one two gena no-group' ] || { echo "in the container that was replaced: $said"; return 1; }
    sh_in gena "grep -q '	gena\$' /etc/hosts && ! grep -q '	genb\$' /etc/hosts" || { echo "its hosts file is not its own"; return 1; }

    # it was started: the exchange the other way is refused, with both generations
    sh_in gena 'echo three >> /work.txt' && lb stop gena >/dev/null || return 1
    start genb && sh_in genb 'echo other >> /work.txt' && lb stop genb >/dev/null && lb export genb "$T/gen-3" >/dev/null 2>&1 </dev/null || return 1
    said=$(lb import "$T/gen-3" gena --replace 2>&1 </dev/null) && { echo "an image took the place of a container that was started since"; return 1; }
    printf '%s\n' "$said"
    case $said in *"the container was started since generation 2, and the image is generation 3, which continues generation 2 too: each has what the other has not"*) ;;
        *) echo "the refusal does not name both generations"; return 1 ;; esac
    start gena && [ "$(sh_in gena 'cat /work.txt' | paste -sd' ')" = 'one two three' ] && lb stop gena >/dev/null ||
        { echo "a refused replace changed the container"; return 1; }
    # --force does it all the same
    lb import "$T/gen-3" gena --replace --force > "$OUT/gena.force" 2>&1 </dev/null || { cat "$OUT/gena.force"; return 1; }
    start gena && [ "$(sh_in gena 'cat /work.txt' | paste -sd' ')" = 'one two other' ] || { echo "--force did not put the image in its place"; return 1; }
    # a reset is a change too
    lb reset genb >/dev/null 2>&1 </dev/null && [ -e "$C/genb/.changed" ] || { echo "a reset left no record that the container changed"; return 1; }
}

# A container's files are all in its rootfs/ (ROADMAP I.14). Its overlay is
# mounted with redirect_dir and metacopy off, which the mount shows where
# the host's own setting is the other; a directory of the snapshot that the
# container moves is copied, and its export is whole. create puts on record
# that its upper directory is whole. One from before whose rootfs/ has a
# redirect, as an overlay with redirect_dir on leaves one, is looked
# through at its start and refused, with the entry named; without it, it
# starts and is on record as whole.
t_overlay_whole() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to set an attribute with"; return 77; }
    local pid opts said out
    OVERLAY=1
    up whole || return 1
    [ -n "$(base_of whole)" ] && [ -e "$C/whole/.overlay-whole" ] || { echo "create did not put on record that the upper directory is whole"; return 1; }
    pid=$(pid_of whole)
    opts=$(awk '$5 == "/" { for (i = 7; i <= NF; i++) if ($i == "-") { print $(i + 3); exit } }' "/proc/$pid/mountinfo")
    echo "the container's root: $opts; the host's: redirect_dir=$(cat /sys/module/overlay/parameters/redirect_dir 2>/dev/null) metacopy=$(cat /sys/module/overlay/parameters/metacopy 2>/dev/null)"
    case ",$opts," in *,redirect_dir=on,*|*,metacopy=on,*) echo "the overlay is mounted with redirect_dir or metacopy on"; return 1 ;; esac
    case ",$opts," in *,upperdir=*) ;; *) echo "the container's root is no overlay: $opts"; return 1 ;; esac
    sh_in whole 'mv /lbt /lbt-moved && test -x /lbt-moved/busybox && ! test -e /lbt' || { echo "a directory of the snapshot could not be moved"; return 1; }
    lb stop whole >/dev/null && lb export whole "$T/whole-image" >/dev/null 2>&1 </dev/null || { echo "the container that moved a directory is not exported"; return 1; }
    out=$(python3 -I "$HERE/image_check.py" "$T/whole-image") || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out" | grep -qE "^entry 2 (file|hardlink) .* lbt-moved/busybox( -> .*)?\$" &&
        printf '%s\n' "$out" | grep -qE '^entry 2 file [0-7]{4} 0:0 0 \.wh\.lbt$' || { echo "the moved directory is not whole in the container's own layer"; return 1; }

    # one from before, with a redirect in its own files
    setfattr_py() { python3 -I -c 'import os, sys; os.setxattr(sys.argv[1], "trusted.overlay.redirect", b"/lbt")' "$1"; }
    rm "$C/whole/.overlay-whole" && setfattr_py "$C/whole/rootfs/lbt-moved" || return 1
    said=$(lb start whole 2>&1 </dev/null) && { echo "a container with a redirect in its own files was started"; return 1; }
    printf '%s\n' "$said"
    case $said in *"has in its own files what an overlay leaves"*"  lbt-moved"*"so it is not started"*) ;; *) echo "the refusal does not name the entry"; return 1 ;; esac
    [ ! -e "$C/whole/.overlay-whole" ] && [ "$(state_of whole)" = stopped ] || { echo "a refused start left a record"; return 1; }
    python3 -I -c 'import os, sys; os.removexattr(sys.argv[1], "trusted.overlay.redirect")' "$C/whole/rootfs/lbt-moved" || return 1
    start whole && [ -e "$C/whole/.overlay-whole" ] || { echo "a container that is whole was not started, or not put on record"; return 1; }
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
# makes it, and says so; the container, of --net outside, reaches the outside
# and is refused the gateway, as its rules are made again with it.
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
    iptables -C INPUT -j LIGHTBOX-INPUT &&
    iptables -t nat -C POSTROUTING -j LIGHTBOX-POSTROUTING || { echo "lightbox's jumps are not there"; return 1; }
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] && [ "$(iptables -S FORWARD | head -n 1)" = '-P FORWARD DROP' ] ||
        { echo "forwarding is not on with the FORWARD policy at DROP"; return 1; }
    if [ -e "$T/have_nc" ] && [ -e "$T/have_listeners" ]; then
        rejected rebuilt "$GW" && answered rebuilt "$OUTSIDE"
    else
        echo "no nc in the suite's busybox, or no python3 for listeners: whether the container reaches anything is not tried"
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
# The chains of containers' --net outside and the jumps to them go in as
# each container starts, or as reload puts them back, in whatever order that
# is: those lines are compared as a set, and the rest as they stand.
saved_rules() {
    local all egress='^(:LO-|-A LO-|-A LIGHTBOX-EGRESS )'
    all=$(iptables-save | grep -v '^#' | sed -E 's/ \[[0-9]+:[0-9]+\]$//')
    printf '%s\n' "$all" | grep -Ev "$egress"
    printf '%s\n' "$all" | grep -E "$egress" | sort
}

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
    # what every running container has, as reload puts it in, whatever
    # backend an earlier case started it with
    lb reload >/dev/null 2>&1 || return 1
    before=$(saved_rules)
    flush_firewall || return 1
    ! reaches rllinked "$(addr_of rlpeer)" || { echo "the link held without its rules"; return 1; }
    lb reload >"$OUT/reload" 2>&1 || { cat "$OUT/reload"; return 1; }
    cat "$OUT/reload"
    grep -qx "The links of container 'rllinked' are in again" "$OUT/reload" || return 1
    ! grep -q "links of container 'rlalone'\|links of container 'rlpeer'" "$OUT/reload" ||
        { echo "reload put in links of a container that has none"; return 1; }
    grep -qx "The --net outside rules of container 'rlalone' are in again" "$OUT/reload" ||
        { echo "reload did not put back the rules of --net outside"; return 1; }
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
    lb reload >/dev/null 2>&1 || return 1
    before=$(saved_rules)
    flush_firewall || return 1
    up sfnew --net nat || return 1
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

# A volume of a --userns container is idmapped to its source's owner
# (ROADMAP 8.2): the container's root is uid 1000 and gid 1001 there, a file of
# theirs is root's in it, and what it makes is theirs on the host. No other id
# is mapped: a file of 2000's is nobody's in it, its root cannot give a file
# another id, and its uid 4711 makes nothing in it, though the directory lets
# anyone write. A file volume is idmapped too, and a read-only one stays so.
t_userns_volume_owner() {
    need_subids || return 77
    mkdir -p "$T/vol/work" && echo theirs > "$T/vol/work/theirs" && echo other > "$T/vol/work/other" &&
        chown 1000:1001 "$T/vol/work" "$T/vol/work/theirs" && chown 2000:2000 "$T/vol/work/other" &&
        chmod 777 "$T/vol/work" || return 1
    up unvol --userns --vol "$T/vol/work:/work" --vol "$T/vol/work/theirs:/etc/theirs" --vol "$T/vol/work:/fixed:ro" ||
        return 1
    inside=$(sh_in unvol 'stat -c %u:%g /work /work/theirs /work/other /etc/theirs /fixed' | paste -sd' ')
    echo "in it: $inside"
    [ "$inside" = '0:0 0:0 65534:65534 0:0 0:0' ] || return 1
    sh_in unvol 'echo made > /work/made && mkdir /work/dir && echo more >> /etc/theirs' || return 1
    made=$(stat -c %u:%g "$T/vol/work/made" "$T/vol/work/dir" "$T/vol/work/theirs" | paste -sd' ')
    echo "on the host: $made"
    [ "$made" = '1000:1001 1000:1001 1000:1001' ] && [ "$(tail -n 1 "$T/vol/work/theirs")" = more ] || return 1
    sh_in unvol 'chown 4711 /work/made' && { echo "the container gave a file an id that is not mapped"; return 1; }
    said=$(lb exec unvol --user 4711 /bin/sh -c 'echo x > /work/by4711' 2>&1 </dev/null) &&
        { echo "uid 4711 made a file"; return 1; }
    printf '%s\n' "$said"
    case $said in *'too large'*) ;; *) echo "uid 4711 is refused for another reason than its id"; return 1 ;; esac
    sh_in unvol 'echo x > /fixed/x' && { echo "the read-only volume took a file"; return 1; }
    # what is 1000's on the host is never setuid or setgid
    sh_in unvol 'chmod u+s /work/made' && { echo "the container made a file of 1000's setuid"; return 1; }
    [ ! -e "$T/vol/work/by4711" ] && [ ! -e "$T/vol/work/x" ] && [ "$(stat -c %u "$T/vol/work/made")" = 1000 ] &&
        [ -z "$(find "$T/vol/work/made" -perm /6000)" ]
}

# A volume whose source is host root's, by its uid or by its gid, is bound as
# it is: host uid 0 and gid 0 are never mapped, its files are nobody's in the
# container, and the container's root makes nothing in it.
t_userns_volume_of_root() {
    need_subids || return 77
    mkdir -p "$T/vol/root-uid" "$T/vol/root-gid" && echo root > "$T/vol/root-uid/file" &&
        chown 1000:0 "$T/vol/root-gid" && chmod 775 "$T/vol/root-gid" || return 1
    up unrootvol --userns --vol "$T/vol/root-uid:/a" --vol "$T/vol/root-gid:/b" || return 1
    inside=$(sh_in unrootvol 'stat -c %u:%g /a /a/file /b; cat /a/file' | paste -sd' ')
    echo "in it: $inside"
    [ "$inside" = '65534:65534 65534:65534 65534:65534 root' ] || return 1
    sh_in unrootvol 'echo x > /a/new' && { echo "the container made a file in a volume of host uid 0's"; return 1; }
    sh_in unrootvol 'echo x > /b/new' && { echo "the container made a file in a volume of host gid 0's"; return 1; }
    [ ! -e "$T/vol/root-uid/new" ] && [ ! -e "$T/vol/root-gid/new" ]
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

# --net outside with firewall_backend = nftables, as with iptables.
t_nft_net_outside() {
    nft_setup nftout || return $?
    net_outside f with_alt_start
}

# --net proxy with firewall_backend = nftables, as with iptables; links need
# no br_netfilter here.
t_nft_net_proxy() {
    nft_setup nftprx || return $?
    net_proxy g yes with_alt_start
}
with_alt_start() { LIGHTBOX_CONFIG="$ALT_CONF" start "$1"; }

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
    nft list chain bridge lightbox forward | grep -qF "ibrname \"$BR\" drop" &&
    nft list chain ip lightbox forward | grep -qF "iifname \"$BR\" oifname != \"$BR\" ip saddr @outside jump egress" &&
    nft list chain ip lightbox input | grep -qF "iifname \"$BR\" ip saddr @outside jump egress_host" &&
    nft list chain ip lightbox egress_host | grep -qF "reject with tcp reset" &&
    nft list chain ip lightbox egress_host | grep -qF "reject with icmp admin-prohibited" &&
    nft list chain ip lightbox forward | grep -qF "iifname \"$BR\" oifname != \"$BR\" ip saddr @proxied jump egress_proxy" &&
    nft list chain ip lightbox input | grep -qF "iifname \"$BR\" ip saddr @proxied jump egress_proxy" &&
    nft list chain ip lightbox egress_proxy | grep -qF "ip saddr . ip daddr . tcp dport @proxy_to return" &&
    nft list chain bridge lightbox forward | grep -qF "ibrname \"$BR\" iifname @sealed drop" &&
    nft list chain bridge lightbox forward | grep -qF "ibrname \"$BR\" oifname @sealed drop" ||
        { echo "a rule is missing"; return 1; }
    iptables -n -L LIGHTBOX-FORWARD >/dev/null 2>&1 && { echo "LIGHTBOX-FORWARD is left"; return 1; }
    iptables -n -L LIGHTBOX-LINKS >/dev/null 2>&1 && { echo "LIGHTBOX-LINKS is left"; return 1; }
    for chain in LIGHTBOX-INPUT LIGHTBOX-EGRESS LIGHTBOX-OUTSIDE; do
        iptables -n -L "$chain" >/dev/null 2>&1 && { echo "$chain is left"; return 1; }
    done
    ! iptables -S | grep -q '^-N LO-' || { echo "a chain of a container's --net outside is left"; return 1; }
    iptables -C INPUT -j LIGHTBOX-INPUT 2>/dev/null && { echo "the jump to LIGHTBOX-INPUT is left"; return 1; }
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
    iptables -C FORWARD -j LIGHTBOX-FORWARD && iptables -C INPUT -j LIGHTBOX-INPUT &&
    iptables -t nat -C POSTROUTING -j LIGHTBOX-POSTROUTING
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

# A start puts in a container's links with one process, nft, and with them
# the rules of --net outside, the default.
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
    # but for the look at whether setup's tables are there, which every start
    # has; the links and the rules of --net outside, the default, go in as one
    tools=$(grep -E 'execve\("[^"]*/(ip6?tables[^"]*|nft)"' "$T/nftlinks.strace" | grep -v ' = -1 ' |
            grep -v '"list", "chains"')
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
    mkdir -p "$BASE${KIT%/*}" && cp "$BB" "$BASE$KIT" && chmod 755 "$BASE$KIT" || return 1
    if "$BB" --list | grep -qx nc; then : > "$T/have_nc"; fi
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
    ip route add default via "$OUTSIDE" dev "$WAN" || return 1
    # from a subshell, so that they are no job of the suite's shell
    if (tcp_listener 0.0.0.0 "$ECHO_PORT" here >/dev/null) && (tcp_listener 0.0.0.0 "$ECHO_PORT" here "$outside" >/dev/null); then
        : > "$T/have_listeners"
    fi
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
    if [ -z "${LIGHTBOX_TEST_ROOTFS:-}" ]; then
        echo "lifecycle: root filesystem from $BB ($("$BB" 2>&1 | head -n 1))"
    else
        echo "lifecycle: root filesystem copied from $LIGHTBOX_TEST_ROOTFS ($(chroot "$BASE" "$KIT" sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')), and $BB at $KIT"
    fi
    SUITE=lifecycle
    case $USERNS_MODE in
        overlay) SUITE="lifecycle with --userns"
                 echo "lifecycle: every container with --userns" ;;
        copy)    SUITE="lifecycle with --userns --copy"
                 echo "lifecycle: every container with --userns, and with --copy but in the cases about overlays" ;;
    esac
    if [ -n "$SECCOMP_MODE" ]; then
        SUITE="$SUITE under the $SECCOMP_MODE-list"
        echo "lifecycle: every container with --seccomp $SECCOMP_MODE, but where a case chooses"
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
    check 'firewall = false: forwarding is left as it is, by setup and by a start' t_firewall_false_leaves_forwarding
    check 'doctor finds nothing missing'                                  t_doctor
    check 'doctor names each precondition of start that is broken, and its fix' t_doctor_names_what_is_missing

    check 'create, start, exec, stop and rm'                              t_lifecycle
    check 'start and stop take several names, and name those they could not do' t_several_names
    check 'update changes the limits of a running container, and they outlast a restart' t_update_live
    check 'restart stops a running container and starts it, and starts a stopped one' t_restart
    check 'rm -f kills a running container and removes it'                t_rm_force
    check 'ls and inspect show a running container'                       t_queries_show_running
    check 'inspect --json of a running container has its init, as numbers'  t_inspect_json_running
    check "exec returns the command's status, and 125, 126 and 127 for what is not the command's" t_exec_status
    check 'an exec runs in a cgroup of its own, and stop takes away one that is left' t_exec_cgroup
    check 'exec --timeout ends the command and all it started, and returns 124' t_exec_timeout
    check 'exec --timeout holds when the exec is killed or stopped'      t_exec_timeout_without_its_exec
    check "the cgroup an exec left goes with a container whose init died" t_exec_cgroup_of_a_dead_init
    check 'a container with --ttl ends on time, with all it started, and is expired' t_ttl
    check "run prints and returns the command's, and leaves nothing of its box" t_run
    check 'a box of run goes when run is asked to end, or with the next run when run was killed' t_run_ends
    check 'each exec writes its start and its end to the audit log, which the box cannot see' t_audit_log
    check 'a box of --profile agent with a workspace has the profile, and Phase 8 holds for it' t_agent_profile
    check 'run --profile agent returns the status, runs in the workspace and leaves nothing' t_agent_run
    check 'doctor --profile agent finds nothing missing, and says that nft is when it is masked' t_agent_doctor
    check 'a box of --profile agent with --net proxy reaches its proxy and nothing else' t_agent_proxy
    check "exec --timeout in a box of --profile agent returns 124, and lightbox's own statuses are its own" t_agent_timeout
    check 'reset of a box of --profile agent leaves its workspace and copies nothing' t_agent_reset
    check 'a box of --profile agent with --ttl ends on time and is expired' t_agent_ttl
    check 'the exec and run of a box of --profile agent are in the audit log, which it cannot see' t_agent_audit
    check "the commands of README's agent section, in the suite's copy, do what it says" t_agent_guide
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
    check 'nothing in a container makes a file setuid or setgid'          t_no_setuid_or_setgid_bits
    check '--seccomp allow gives the allow-list, and --seccomp deny the deny-list' t_seccomp_profiles
    check 'an image without /dev, /proc, /sys, /tmp and /run starts'      t_image_without_mount_points
    check 'an image of one static binary starts'                          t_image_with_one_binary
    check 'start runs nothing from the image'                             t_start_runs_nothing_from_the_image

    check 'limits reach the cgroup, without swap, and the oom score init and exec' t_limits
    check '--io-max reaches io.max'                                        t_io_limit
    check 'past its memory limit a process is killed, and its container with it' t_past_the_memory_limit
    check 'without io, a container starts and is told once; with an I/O limit, not' t_without_io_controller
    check "init is in the container's cgroup, and a command run by exec in its exec's below it" t_cgroup_membership

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
    check 'a container opens the devices of its /dev and no other'       t_device_filter
    check 'another user cannot reach container files'                     t_storage_closed_to_others

    check 'a container has loopback, its address and a default route'     t_network_inside
    check 'a container of --net outside reaches the outside and its name server, and nothing else' t_net_outside
    check 'a container of --net none has loopback and nothing else'      t_net_none
    check 'a container of --net proxy reaches its proxy and nothing else, and has its variables' t_net_proxy
    check 'contrib/proxy: Squid lets on the names of its list and looks up no other' t_proxy_example
    check 'a container of --net nat reaches the bridge address'          t_reaches_gateway
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
    check 'nftables: a container of --net outside reaches the outside and its name server, and nothing else' t_nft_net_outside
    check 'nftables: a container of --net proxy reaches its proxy and nothing else' t_nft_net_proxy
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
    check '--userns: a volume is its source'"'"'s owner'"'"'s, whom the container'"'"'s root stands for, and no other id' t_userns_volume_owner
    check '--userns: a volume of host root'"'"'s is bound as it is, and the container makes nothing in it' t_userns_volume_of_root
    check 'setup --teardown leaves the host as before the first setup'    t_setup_teardown
    check 'without --config or LIGHTBOX_CONFIG, /etc/lightbox/lightbox.conf is read' t_config_in_etc
    check 'a container overlays a snapshot of its base, and keeps its own files apart' t_overlay_root
    check '--copy makes a container a copy of its base'                   t_copy_root
    check "reset makes a container's root its base's again, and keeps its volume" t_reset
    check 'base ls, base rm and base add manage the snapshots'            t_base_commands
    check 'export writes a container that ran as an image: its snapshot, and its own files and marks' t_export
    check 'import makes a container of an image that shows what the exported one showed' t_import
    check 'an image goes to a registry and back with skopeo, and is the container again' t_registry
    check "base import makes a snapshot of an image's layers, and create --base a container that starts" t_base_import
    check "a registry's own image is a base, and a container of it runs the image's tools" t_registry_image
    check 'import --replace puts an image in the place of the container it continues, and of none that was started since' t_import_replace
    check "an overlay is mounted with redirect_dir and metacopy off, and a container's own files are whole" t_overlay_whole
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
        [ ! -e "$LIGHTBOX_TEST_ROOTFS${KIT%/*}" ] ||
            stop_early "LIGHTBOX_TEST_ROOTFS=$LIGHTBOX_TEST_ROOTFS has a ${KIT%/*} of its own, where the suite puts its busybox"
    fi
    # with an image of yours too, to put in it at /lbt/busybox
    LIFECYCLE_BB=$(find_busybox) || stop_early "no statically linked busybox was found${BUSYBOX:+ at $BUSYBOX}.
  Install busybox-static, or give one with BUSYBOX=/path.
  (${TMPDIR:-/tmp} must not be mounted noexec either.)"

    case ${LIGHTBOX_TEST_USERNS:-} in
        '') ;;
        overlay|copy)
            [ -e /etc/subuid ] && [ -e /etc/subgid ] ||
                stop_early "LIGHTBOX_TEST_USERNS needs an /etc/subuid and an /etc/subgid to put the suite's own over" ;;
        *)  stop_early "LIGHTBOX_TEST_USERNS is overlay or copy, not: $LIGHTBOX_TEST_USERNS" ;;
    esac
    case ${LIGHTBOX_TEST_SECCOMP:-} in
        ''|allow|deny) ;;
        *) stop_early "LIGHTBOX_TEST_SECCOMP is allow or deny, not: $LIGHTBOX_TEST_SECCOMP" ;;
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
