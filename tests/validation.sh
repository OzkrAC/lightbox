#!/usr/bin/env bash
#
# Unprivileged validation suite (ROADMAP 0.4).
#
# Runs the built lightbox as an ordinary user. HOME and every directory
# lightbox is configured to use point into one temporary directory, so the
# suite needs no root, starts no container and touches nothing else.
#
#   tests/validation.sh [path/to/lightbox]     default: ./lightbox
#   KEEP=1 tests/validation.sh                 keep the work directory
#   V=1    tests/validation.sh                 show the output of every case
#
# The case runner (check, xfail, summary) is tests/lib.sh.

set -u

LB=${1:-./lightbox}
if [ ! -x "$LB" ]; then
    echo "validation: $LB is not an executable; run make first" >&2
    exit 2
fi
LB=$(cd "$(dirname "$LB")" && pwd)/$(basename "$LB")

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/lightbox-validation.XXXXXX") || exit 2
cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "validation: work directory kept at $ROOT"
    else
        rm -rf -- "$ROOT"
    fi
}
trap cleanup EXIT

# ─── Fixture ────────────────────────────────────────────────────────────────

# Every case gets its own directory tree and configuration:
#   $W       root of the tree            $C     container_dir
#   $BASE    base rootfs to copy         $CONF  the host configuration file
#   $R       run_dir: the records of a container that runs are in $R/<name>/
sandbox() {
    W="$ROOT/$1"
    C="$W/data/containers"
    R="$W/run"
    BASE="$W/base"
    CONF="$W/home/.config/lightbox/lightbox.conf"
    mkdir -p "$W/home/.config/lightbox" "$C" "$BASE/etc" "$BASE/bin" "$BASE/dev" \
             "$W/cgroup" "$W/run" "$W/vol"
    printf 'root:x:0:0:root:/root:/bin/sh\n' > "$BASE/etc/passwd"
    printf 'placeholder\n' > "$BASE/bin/placeholder"
    {
        printf 'lightbox_dir = %s\n'  "$W/data"
        printf 'rootfs = %s\n'        "$BASE"
        printf 'container_dir = %s\n' "$C"
        printf 'run_dir = %s\n'       "$W/run"
        printf 'cgroup_root = %s\n'   "$W/cgroup"
    } > "$CONF"
}

lb() { HOME="$W/home" LIGHTBOX_CONFIG="$CONF" "$LB" "$@"; }

# Succeeds when the command fails. Output is kept for the report.
refused() { ! "$@"; }

conf_has()  { grep -qxF -- "$2" "$C/$1/.conf"; }
vol_count() { grep -c '^vol=' "$C/$1/.conf"; }
mode_of()   { stat -c %a "$1"; }
tree_sum()  { (cd "$1" && find . -print0 | sort -z | xargs -0 stat -c '%n %F %s %Y' | sha256sum); }
# everything lightbox keeps: the containers, and the records of the ones that run
kept_sum()  { tree_sum "$W/data"; tree_sum "$R"; }

# The runtime records of a container, as a start leaves them.
record() { # name, pid, start time, state
    mkdir -p "$R/$1"
    printf '%s' "$2" > "$R/$1/pid"
    printf '%s' "$3" > "$R/$1/pid_start"
    printf '%s\n' "$4" > "$R/$1/state"
}

# Reads stdin. 0 valid JSON, 1 invalid, 77 no tool to tell.
json_valid() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json, sys; json.load(sys.stdin)' 2>/dev/null
    elif command -v jq >/dev/null 2>&1; then
        jq -e . >/dev/null 2>&1
    else
        cat >/dev/null
        return 77
    fi
}

# A path of exactly $2 characters that begins with $1.
pad_path() {
    local p=$1 rest
    while [ ${#p} -lt $(($2 - 60)) ]; do p="$p/$(printf 'x%.0s' $(seq 1 50))"; done
    rest=$(($2 - ${#p} - 1))
    [ "$rest" -gt 0 ] && p="$p/$(printf 'y%.0s' $(seq 1 "$rest"))"
    printf '%s' "$p"
}

# A long but valid directory name, to reach the configuration size limits.
long_vol() { # index
    printf '%s/vol/application-data-directory-number-%s/with/a/reasonably/deep/nested/path/segment' "$W" "$1"
}

# ─── Runner ─────────────────────────────────────────────────────────────────

case_setup() { sandbox "$1"; }
SHOW_FILTER="s#$ROOT/[0-9]*#<W>#g"
. "$(dirname "$0")/lib.sh"

# ─── Cases: behaviour that works and must keep working ──────────────────────

t_create_stores_options() {
    lb create web 10.0.0.2 --mem 64M --pids 50 --cpu 2 --oom-score 300 \
        --vol "$W/vol:/data:ro" || return 1
    conf_has web 'mem=64M' && conf_has web 'pids=50' && conf_has web 'cpu=2' &&
    conf_has web 'oom_score=300' && conf_has web "vol=$W/vol:/data:ro" &&
    [ "$(cat "$C/web/.ip")" = 10.0.0.2 ] || return 1
    # what a container may do is in the file only when it was asked for
    ! grep -q '^privileged=\|^readonly=' "$C/web/.conf" || { echo "a flag nobody gave is stored"; return 1; }
    lb create open 10.0.0.3 --privileged --read-only || return 1
    cat "$C/open/.conf"
    conf_has open 'privileged=1' && conf_has open 'readonly=1' &&
    lb inspect open | grep -x 'privileged: 1' && lb inspect open | grep -x 'readonly: 1' &&
    lb inspect web | grep -x 'privileged: 0' && lb inspect web | grep -x 'readonly: 0'
}

t_create_copies_base() {
    lb create web 10.0.0.2 || return 1
    [ -f "$C/web/rootfs/bin/placeholder" ] && [ -f "$C/web/rootfs/etc/passwd" ]
}

t_create_refuses_existing_name() {
    lb create web 10.0.0.2 || return 1
    refused lb create web 10.0.0.3
}

t_create_refuses_bad_names() {
    refused lb create 'bad name' 10.0.0.2 &&
    refused lb create 'bad/name' 10.0.0.2 &&
    refused lb create a-name-of-thirty-one-characters 10.0.0.2 &&
    [ -z "$(ls -A "$C")" ]
}

# A name of 30 characters is a container's, and one of 31 is not. On the host
# a container is called by twelve digits of its name's hash, which inspect
# shows, the same for a name every time and another for another name.
t_long_names() {
    long=a-name-of-thirty-characters-0k
    [ ${#long} -eq 30 ] || return 1
    lb create "$long" || return 1
    lb ls | grep -q "^$long " || { echo "ls does not show it"; return 1; }
    port=$(lb inspect "$long" | sed -n 's/^host_interface: //p')
    echo "host interface of $long: $port"
    case $port in vb-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
        *) echo "not vb- and twelve hex digits"; return 1 ;; esac
    lb create web || return 1
    [ "$(lb inspect web | sed -n 's/^host_interface: //p')" = vb-5ea0e1194872 ] || { echo "web is not vb-5ea0e1194872"; return 1; }
    lb rm "$long" >/dev/null && lb create "$long" >/dev/null || return 1
    [ "$(lb inspect "$long" | sed -n 's/^host_interface: //p')" = "$port" ] || { echo "the name changed for the same container name"; return 1; }
}

t_create_refuses_bad_addresses() {
    refused lb create a 192.168.5.5 &&
    refused lb create b 10.0.0 &&
    refused lb create c 10.0.0.300 &&
    refused lb create d not-an-address
}

t_volume_spec_rules() {
    refused lb create a 10.0.0.2 --vol relative:/data &&
    refused lb create b 10.0.0.3 --vol "$W/vol:/proc/x" &&
    refused lb create c 10.0.0.4 --vol "$W/vol:/sys" &&
    refused lb create d 10.0.0.5 --vol "$W/vol:/data:rw" &&
    refused lb create e 10.0.0.6 --vol "$W/vol" &&
    # a reserved place by another spelling, and a path that goes up
    refused lb create f 10.0.0.7 --vol "$W/vol://proc/x" &&
    refused lb create g 10.0.0.8 --vol "$W/vol:/data/../proc" &&
    refused lb create h 10.0.0.9 --vol "$W/vol/../vol:/data" || return 1
    # what is stored is one spelling of what was typed, from create and from add-vol
    lb create web 10.0.0.2 --vol "$W//vol/./:/data//x/:ro" || return 1
    lb add-vol web "$W/vol/:/more/" || return 1
    grep '^vol=' "$C/web/.conf"
    conf_has web "vol=$W/vol:/data/x:ro" && conf_has web "vol=$W/vol:/more" || return 1
    refused lb add-vol web "$W/vol:/a/../b" || return 1
    # the same volume in another spelling is the same volume
    lb add-vol web "$W/vol//:/more" | grep -q 'already present'
}

t_unknown_option_refused() {
    refused lb create web 10.0.0.2 --bogus
}

t_ls_lists_containers() {
    lb create web 10.0.0.2 && lb create db 10.0.0.3 || return 1
    listing=$(lb ls) || return 1
    printf '%s\n' "$listing"
    printf '%s\n' "$listing" | grep -Eq '^web +10\.0\.0\.2 +stopped' &&
    printf '%s\n' "$listing" | grep -Eq '^db +10\.0\.0\.3 +stopped'
}

t_ls_json_is_json() {
    lb create web 10.0.0.2 && lb create db 10.0.0.3 || return 1
    json=$(lb ls --json) || return 1
    printf '%s\n' "$json"
    printf '%s' "$json" | json_valid || return $?
    printf '%s' "$json" | grep -q '"name":"web"' && printf '%s' "$json" | grep -q '"ip":"10.0.0.3"'
}

t_inspect_basics() {
    lb create web 10.0.0.2 || return 1
    report=$(lb inspect web) || return 1
    printf '%s\n' "$report"
    printf '%s\n' "$report" | grep -qx 'name: web' &&
    printf '%s\n' "$report" | grep -qx 'ip: 10.0.0.2' &&
    printf '%s\n' "$report" | grep -qx 'running: no'
}

t_missing_container_is_an_error() {
    refused lb inspect nosuch && refused lb rm nosuch && refused lb stop nosuch &&
    refused lb add-vol nosuch "$W/vol:/data"
}

t_addvol_appends() {
    lb create web 10.0.0.2 && lb add-vol web "$W/vol:/more:ro" || return 1
    conf_has web "vol=$W/vol:/more:ro"
}

t_rm_removes() {
    lb create web 10.0.0.2 && lb rm web || return 1
    [ ! -e "$C/web" ]
}

t_stopped_container_cannot_stop_or_exec() {
    lb create web 10.0.0.2 || return 1
    refused lb stop web && refused lb exec web /bin/true
}

# exec's status is its command's (ROADMAP 8.7), so a failure of lightbox's
# own is 125 there, wherever it comes from: the options, --timeout among
# them, root, a lightbox.conf that cannot be read. For every other command it
# is 1, as it was.
t_exec_failures_are_125() {
    local bad=0 want rc long
    expect_status() { # status, words...
        want=$1
        shift
        lb "$@" >/dev/null 2>"$W/said"
        rc=$?
        echo "lightbox $*: $rc, $(head -n 1 "$W/said")"
        [ "$rc" -eq "$want" ] || bad=1
    }
    expect_status 125 exec
    expect_status 125 exec web --bogus
    expect_status 125 exec web --timeout
    expect_status 125 exec web --timeout 0 /bin/true
    expect_status 125 exec web --timeout 1ms /bin/true
    expect_status 125 exec web --timeout 366d /bin/true
    expect_status 125 exec web --workdir relative /bin/true
    expect_status 125 exec 'not a name' /bin/true
    expect_status 125 exec web /bin/true
    expect_status 125 exec web --timeout 2s -- /bin/true
    grep -qx 'Error: lightbox exec must be run as root' "$W/said" || { echo "a valid --timeout is not taken"; bad=1; }
    expect_status 0 exec --help
    expect_status 1 start web
    expect_status 1 stop web
    expect_status 1 create 'not a name'
    lb exec web --timeout 2x /bin/true 2>&1 | grep -qx 'Error: --timeout takes a duration above 0 and up to 365d, such as 30s, 5m or 1.5h: 2x' ||
        { echo "--timeout does not say what it takes"; bad=1; }
    long=$(printf '/%0600d' 0)
    printf 'container_dir = %s\n' "$long" > "$W/long.conf"
    HOME="$W/home" LIGHTBOX_CONFIG="$W/long.conf" "$LB" exec web /bin/true >/dev/null 2>&1
    rc=$?
    echo "exec with a lightbox.conf it cannot take: $rc"
    [ "$rc" -eq 125 ] || bad=1
    HOME="$W/home" LIGHTBOX_CONFIG="$W/long.conf" "$LB" ls >/dev/null 2>&1
    rc=$?
    echo "ls with it: $rc"
    [ "$rc" -eq 1 ] || bad=1
    return $bad
}

t_unknown_command_prints_usage() {
    usage=$(lb frobnicate 2>&1)
    [ $? -ne 0 ] && printf '%s\n' "$usage" | grep -q '^Usage: lightbox' &&
    [ "$(printf '%s\n' "$usage" | head -n 1)" = 'Error: unknown command: frobnicate' ] &&
    [ -z "$(lb frobnicate 2>/dev/null)" ]
}

# ─── Cases: open findings ───────────────────────────────────────────────────

# create with six long volumes: all six stored, or the command refuses.
t_create_keeps_every_volume() {
    args=()
    for i in 1 2 3 4 5 6; do
        mkdir -p "$(long_vol "$i")"
        args+=(--vol "$(long_vol "$i"):/srv/application/mounted/volume/number/$i/with/a/reasonably/deep/path:ro")
    done
    lb create web 10.0.0.2 "${args[@]}" || return 0
    echo "stored $(vol_count web) of 6 volumes, .conf is $(stat -c %s "$C/web/.conf") bytes"
    [ "$(vol_count web)" -eq 6 ] && ! grep '^vol=' "$C/web/.conf" | grep -qv ':ro$'
}

# add-vol until it stops: every stored line is whole, the count matches the
# successes, and a refusal gives the real reason, not a complaint about a
# specification that was well-formed.
t_addvol_fails_honestly() {
    lb create web 10.0.0.2 || return 1
    ok=0 bogus=0
    for i in $(seq 1 40); do
        mkdir -p "$(long_vol "$i")"
        if msg=$(lb add-vol web "$(long_vol "$i"):/mnt/volume/number/$i/with/some/longer/destination/path:ro" 2>&1); then
            ok=$((ok + 1))
        else
            case $msg in *'volume format'*) bogus=$((bogus + 1)) ;; esac
        fi
    done
    echo "40 add-vol calls: $ok succeeded, $bogus refused as malformed; $(vol_count web) lines stored"
    [ "$ok" -eq 16 ] && [ "$bogus" -eq 0 ] && [ "$(vol_count web)" -eq "$ok" ] &&
    ! grep '^vol=' "$C/web/.conf" | grep -qv ':ro$'
}

# The largest legal configuration: sixteen volumes whose source and destination
# are 500 characters each, and a link, which is stored after them. Everything
# is stored exactly, and add-vol reads all of it back.
t_largest_config_round_trips() {
    lb create other 10.0.0.3 || return 1
    args=()
    for i in $(seq 1 16); do
        src=$(pad_path "$W/v/$i" 500); dst=$(pad_path "/d/$i" 500)
        mkdir -p "$src"
        args+=(--vol "$src:$dst:ro")
    done
    lb create web 10.0.0.2 "${args[@]}" --link other || return 1
    echo ".conf is $(stat -c %s "$C/web/.conf") bytes and holds $(vol_count web) volumes"
    [ "$(vol_count web)" -eq 16 ] || return 1
    for i in $(seq 1 16); do
        conf_has web "vol=$(pad_path "$W/v/$i" 500):$(pad_path "/d/$i" 500):ro" || { echo "volume $i is not stored exactly"; return 1; }
    done
    conf_has web 'link=other' || { echo "the link after the volumes is missing"; return 1; }
    # the reader sees the last volume whole: adding it again is recognised
    lb add-vol web "$(pad_path "$W/v/16" 500):$(pad_path "/d/16" 500):ro" | grep -q 'already present' || return 1
    # and it counts all sixteen: one more is refused for that reason
    msg=$(lb add-vol web /tmp:/one-more 2>&1) && return 1
    printf '%s\n' "$msg"
    case $msg in *'maximum of 16 volumes'*) ;; *) return 1 ;; esac
    [ "$(vol_count web)" -eq 16 ]
}

t_addvol_respects_the_volume_limit() {
    lb create web 10.0.0.2 || return 1
    # Short paths, so that the configuration size limit is not what stops it.
    for i in $(seq 1 16); do lb add-vol web "/tmp:/m$i" >/dev/null || return 1; done
    echo "16 volumes stored; adding one more"
    refused lb add-vol web "/tmp:/m17"
}

# The address of another container, the gateway's, and the first and the
# last of the subnet: each refused with the reason, and nothing is made.
t_duplicate_address_refused() {
    lb create a 10.0.0.9 || return 1
    msg=$(lb create b 10.0.0.9 2>&1) && { echo "a second container got 10.0.0.9"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *"it is the address of the container 'a'"*) ;; *) return 1 ;; esac
    [ ! -e "$C/b" ] || { echo "the refused create left $C/b"; return 1; }
    # whether a holds it or not is what a's record says, not what was typed
    refused lb create c 10.0.0.9 --mem 64M 2>/dev/null
}
reserved_address_refused() { # address, what the refusal says
    msg=$(lb create a "$1" 2>&1) && { echo "a container got $1"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *"$2"*) ;; *) return 1 ;; esac
    [ ! -e "$C/a" ] || { echo "the refused create left $C/a"; return 1; }
}
t_gateway_address_refused()   { reserved_address_refused 10.0.0.1 "the gateway's"; }
t_network_address_refused()   { reserved_address_refused 10.0.0.0 'the address of the subnet itself'; }
t_broadcast_address_refused() { reserved_address_refused 10.0.0.255 'the broadcast address'; }

# Without an address, create takes the lowest that is free: not the
# gateway's, and one that rm gave back.
t_create_takes_the_lowest_free_address() {
    lb create a && lb create b 10.0.0.3 && lb create c && lb create d --mem 64M || return 1
    lb ls
    [ "$(cat "$C/a/.ip")" = 10.0.0.2 ] && [ "$(cat "$C/c/.ip")" = 10.0.0.4 ] && [ "$(cat "$C/d/.ip")" = 10.0.0.5 ] ||
        { echo "the addresses taken: $(cat "$C"/*/.ip | tr '\n' ' ')"; return 1; }
    conf_has d 'mem=64M' || { echo "the option after the name was not taken as one"; return 1; }
    lb rm a >/dev/null && lb create e || return 1
    [ "$(cat "$C/e/.ip")" = 10.0.0.2 ] || { echo "after rm a, the next got $(cat "$C/e/.ip")"; return 1; }
    printf 'subnet = 10.0.0.0/24\ngw = 10.0.0.9\n' >> "$CONF"
    lb rm e >/dev/null && lb create f && lb create g || return 1
    # with the gateway elsewhere, the first address is a container's
    [ "$(cat "$C/f/.ip")" = 10.0.0.1 ] && [ "$(cat "$C/g/.ip")" = 10.0.0.2 ] ||
        { echo "with gw = 10.0.0.9: f got $(cat "$C/f/.ip"), g got $(cat "$C/g/.ip")"; return 1; }
}

# A subnet with every address taken refuses the next container, and makes
# nothing of it.
t_full_subnet() {
    printf 'subnet = 192.168.7.0/30\ngw = 192.168.7.1\n' >> "$CONF"
    lb create one || return 1
    msg=$(lb create two 2>&1) && { echo "a container was made on a full subnet: $(cat "$C/two/.ip")"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *'every address of the subnet has a container: 192.168.7.0/30'*) ;; *) return 1 ;; esac
    [ "$(cat "$C/one/.ip")" = 192.168.7.2 ] && [ ! -e "$C/two" ]
}

# On a /16, an address in a /24 other than the gateway's is a container's;
# the broadcast address is the last of the /16.
t_wide_subnet() {
    printf 'subnet = 10.9.0.0/16\ngw = 10.9.0.1\n' >> "$CONF"
    lb create wide 10.9.5.2 && lb create last 10.9.255.254 && lb create next || return 1
    refused lb create bcast 10.9.255.255 && refused lb create out 10.10.0.2 || return 1
    [ "$(cat "$C/wide/.ip")" = 10.9.5.2 ] && [ "$(cat "$C/next/.ip")" = 10.9.0.2 ]
}

# subnet and gw that are no network end every command that would use them,
# before anything is made; doctor says so.
t_network_settings_are_checked() {
    cp "$CONF" "$W/conf.good"
    bad=0
    for settings in 'subnet = 10.9.0.0/16|gw = 10.8.0.1' 'subnet = 10.0.0.0/31|gw = 10.0.0.1' \
                    'subnet = 10.0.0.0|gw = 10.0.0.1' 'subnet = 10.0.0.0/24|gw = 10.0.0.255' \
                    'subnet = 10.0.0.0/24|gw = 10.0.0.01'; do
        { cat "$W/conf.good"; printf '%s\n' "$settings" | tr '|' '\n'; } > "$CONF"
        msg=$(lb create x 2>&1) && { echo "create worked with: $settings"; bad=1; continue; }
        case $msg in "Error: subnet in lightbox.conf "*|"Error: gw in lightbox.conf "*) ;;
            *) echo "with $settings, create said: $msg"; bad=1 ;; esac
        [ ! -e "$C/x" ] || { echo "with $settings, create left $C/x"; bad=1; }
        report=$(lb doctor 2>&1) && { echo "doctor exits 0 with: $settings"; bad=1; }
        printf '%s\n' "$report" | grep -q '^network: unusable (' || { echo "doctor does not say: $settings"; bad=1; }
        echo "$settings: $msg"
    done
    cp "$W/conf.good" "$CONF"
    lb doctor | grep -x 'network: 10.0.0.0/24' || { echo "doctor does not show the network"; bad=1; }
    return $bad
}

# A zero in front of a number is read as octal by some of the programs an
# address is handed to and refused by others: an address has none.
t_address_with_leading_zeros_refused() {
    refused lb create a 10.0.0.05 && refused lb create b 010.0.0.5 && refused lb create c 10.0.0.007 &&
    [ ! -e "$C/a" ] && [ ! -e "$C/b" ] && [ ! -e "$C/c" ]
}

# Two creates at once, neither given an address, get two: the second chooses
# when the first has made its choice, which the copy here makes long.
t_creates_at_once_get_two_addresses() {
    unshare -r --mount true 2>/dev/null || { echo "user namespaces are not available to this user"; return 77; }
    real=$(readlink -f "$(type -P cp)") && cp "$real" "$W/cp.real" || return 1
    printf '#!/bin/sh\nsleep 1\nexec %s "$@"\n' "$W/cp.real" > "$W/cp.shim"
    chmod +x "$W/cp.shim"
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- sh -c '
        for cp in /bin/cp /usr/bin/cp; do
            [ -e "$cp" ] && { mount --bind "$1/cp.shim" "$(readlink -f "$cp")" || exit 77; }
        done
        "$2" create one > "$1/one.out" 2>&1 &
        "$2" create two > "$1/two.out" 2>&1 &
        wait
    ' _ "$W" "$LB"
    rc=$?
    cat "$W/one.out" "$W/two.out"
    [ $rc -ne 77 ] || { echo "a stand-in could not be mounted over cp here"; return 77; }
    one=$(cat "$C/one/.ip" 2>/dev/null) && two=$(cat "$C/two/.ip" 2>/dev/null) || { echo "a create failed"; return 1; }
    echo "one got $one, two got $two"
    [ "$(printf '%s\n%s\n' "$one" "$two" | sort | paste -sd' ' -)" = '10.0.0.2 10.0.0.3' ]
}

# ─── Option values ──────────────────────────────────────────────────────────

# A value is what its option takes, or the command says which option it was
# and makes nothing.
option_refused() { # option, value
    msg=$(lb create web 10.0.0.2 "$1" "$2" 2>&1) && { echo "$1 '$2' was accepted"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *"$1"*) ;; *) echo "the message does not name $1"; return 1 ;; esac
    [ ! -e "$C/web" ] || { echo "$1 '$2' was refused, and a container was made all the same"; return 1; }
}
t_pids_must_be_a_count() {
    option_refused --pids 123456789 && option_refused --pids 0 && option_refused --pids 010 &&
    option_refused --pids -5
}
t_cpu_must_be_cpus() {
    option_refused --cpu 1024 && option_refused --cpu 0 && option_refused --cpu 0.001 &&
    option_refused --cpu .5 && option_refused --cpu 1. && option_refused --cpu 1e3 && option_refused --cpu abc
}
t_mem_must_be_a_size() {
    option_refused --mem not-a-size && option_refused --mem 0 && option_refused --mem 0100M &&
    option_refused --mem 1.5G && option_refused --mem 1GB && option_refused --mem 99999999999999999999
}
t_oom_score_must_be_a_number() {
    option_refused --oom-score abc && option_refused --oom-score 1001 && option_refused --oom-score -1001
}
t_number_with_trailing_text_refused() {
    option_refused --oom-score 12abc && option_refused --pids 12abc && option_refused --cpu 2x &&
    option_refused --mem 64Mb
}

# What is taken is stored as it was given.
t_limits_are_stored_as_given() {
    lb create a 10.0.0.2 --mem 512m --pids max --cpu 0.5 --oom-score -1000 &&
    lb create b 10.0.0.3 --mem max --pids 4194304 --cpu 1.25 --oom-score 1000 &&
    lb create c 10.0.0.4 || return 1
    cat "$C/a/.conf" "$C/b/.conf" "$C/c/.conf"
    conf_has a 'mem=512m' && conf_has a 'pids=max' && conf_has a 'cpu=0.5' && conf_has a 'oom_score=-1000' &&
    conf_has b 'mem=max' && conf_has b 'pids=4194304' && conf_has b 'cpu=1.25' && conf_has b 'oom_score=1000' &&
    conf_has c 'mem=256M' && conf_has c 'pids=128' && conf_has c 'cpu=1' && conf_has c 'oom_score=500' || return 1
    lb inspect a | grep -x 'cpu: 0.5' && lb inspect a | grep -x 'mem: 512m'
}

# --swap takes what --mem does, and 0. Without it the file says nothing, and
# the container has none.
t_swap_option() {
    lb create a --swap 64M && lb create b && lb create c --swap 0 && lb create d --swap max || return 1
    conf_has a 'swap=64M' && conf_has c 'swap=0' && conf_has d 'swap=max' || return 1
    ! grep -q '^swap=' "$C/b/.conf" || { echo "a swap limit nobody gave is stored"; return 1; }
    lb inspect a | grep -x 'swap: 64M' && lb inspect b | grep -x 'swap: 0' || return 1
    for value in lots 0100M 00 -1 '' MAX '64M
privileged=1'; do
        msg=$(lb create e --swap "$value" 2>&1) && { echo "--swap '$value' was taken"; return 1; }
        case $msg in 'Error: --swap takes '*) ;; *) echo "--swap '$value': $msg"; return 1 ;; esac
        [ ! -e "$C/e" ] || { echo "--swap '$value' left a container"; return 1; }
    done
}

# --seccomp takes allow and deny (ROADMAP 8.3). allow, as no option, is
# stored and shown; deny leaves the file without the line, which is the
# deny-list, as in a .conf made before 0.8; a privileged container has no
# profile to show. Anything else is refused, and a .conf with another value
# cannot be used.
t_seccomp_option() {
    lb create a --seccomp allow && lb create b --seccomp deny && lb create c && lb create d --privileged --seccomp allow ||
        return 1
    conf_has a 'seccomp=allow' && conf_has c 'seccomp=allow' || return 1
    ! grep -q '^seccomp=' "$C/b/.conf" || { echo "a deny-list is stored"; return 1; }
    shown=$(for n in a b c d; do lb inspect "$n" | grep '^seccomp: '; done | paste -sd'|')
    echo "$shown"
    [ "$shown" = 'seccomp: allow|seccomp: deny|seccomp: allow|seccomp: -' ] || return 1
    command -v python3 >/dev/null 2>&1 && {
        lb inspect a --json | python3 -I -c 'import json, sys; assert json.load(sys.stdin)[0]["seccomp"] == "allow"' &&
        lb inspect d --json | python3 -I -c 'import json, sys; assert json.load(sys.stdin)[0]["seccomp"] is None' ||
            { echo "inspect --json does not say it"; return 1; }
    }
    for value in Allow deny-list '' 1 'allow
privileged=1'; do
        msg=$(lb create e --seccomp "$value" 2>&1) && { echo "--seccomp '$value' was taken"; return 1; }
        case $msg in 'Error: --seccomp takes allow or deny, not: '*) ;; *) echo "--seccomp '$value': $msg"; return 1 ;; esac
        [ ! -e "$C/e" ] || { echo "--seccomp '$value' left a container"; return 1; }
    done
    echo 'seccomp=none' >> "$C/b/.conf"
    msg=$(lb inspect b 2>&1) && { echo "a .conf of seccomp=none was used"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *'seccomp is not allow or deny'*) ;; *) return 1 ;; esac
}

# --net takes nat, outside and none (ROADMAP 8.5). outside, the default, is
# stored with the name servers it may ask; nat, as a .conf from before 0.8,
# leaves the file without either line; none is stored, has no address and
# takes neither an address nor --link. With firewall = false lightbox makes
# no rules, and so no container of outside. Anything else is refused and
# makes nothing, and a .conf of another net cannot be used.
t_net_option() {
    lb create a && lb create b --net nat && lb create c --net none &&
        lb create d --net outside --dns 10.0.0.2 --dns 1.1.1.1 && lb create p --net proxy:3128 || return 1
    conf_has a 'net=outside' && grep -q '^dns=[0-9]' "$C/a/.conf" || { echo "a: no net=outside and dns="; return 1; }
    ! grep -q '^net=\|^dns=' "$C/b/.conf" || { echo "nat is stored"; return 1; }
    conf_has c 'net=none' && ! grep -q '^dns=' "$C/c/.conf" && [ ! -e "$C/c/.ip" ] ||
        { echo "none is not stored, or has an address"; return 1; }
    conf_has d 'dns=10.0.0.2,1.1.1.1' || { echo "the name servers of --dns are not stored"; return 1; }
    # --net proxy: no name server to ask, on record or in resolv.conf
    conf_has p 'net=proxy:3128' && ! grep -q '^dns=' "$C/p/.conf" && [ -s "$C/p/.ip" ] ||
        { echo "proxy is not stored, or has name servers, or no address"; return 1; }
    echo "p's resolv.conf: $(paste -sd'|' "$C/p/rootfs/etc/resolv.conf")"
    ! grep -q nameserver "$C/p/rootfs/etc/resolv.conf" || { echo "a container of --net proxy has a name server"; return 1; }
    shown=$(for n in a b c d p; do lb inspect "$n" | grep '^net: '; done | paste -sd'|')
    echo "$shown"
    [ "$shown" = 'net: outside|net: nat|net: none|net: outside|net: proxy:3128' ] || return 1
    lb inspect c | grep -qx 'ip: -' || { echo "inspect shows c with an address"; return 1; }
    command -v python3 >/dev/null 2>&1 && {
        lb inspect a --json | python3 -I -c 'import json, sys; assert json.load(sys.stdin)[0]["net"] == "outside"' &&
        lb inspect c --json | python3 -I -c 'import json, sys; c = json.load(sys.stdin)[0]; assert c["net"] == "none" and c["ip"] is None' &&
        lb inspect p --json | python3 -I -c 'import json, sys; assert json.load(sys.stdin)[0]["net"] == "proxy:3128"' ||
            { echo "inspect --json does not say it"; return 1; }
    }
    expect_refused() { # what it says, create arguments...
        local want=$1
        shift
        msg=$(lb create e "$@" 2>&1) && { echo "create e $* was taken"; return 1; }
        [ "$msg" = "$want" ] || { echo "create e $*: $msg"; return 1; }
        [ ! -e "$C/e" ] || { echo "create e $* left a container"; return 1; }
    }
    expect_refused 'Error: a container with --net none has no address: 10.0.0.9' 10.0.0.9 --net none || return 1
    expect_refused 'Error: a container with --net none has no network for --link' --net none --link a || return 1
    expect_refused 'Error: a container with --net proxy reaches its proxy and nothing else: no --link' \
        --net proxy:3128 --link a || return 1
    expect_refused 'Error: a container with --net proxy has its proxy look up names: no --dns' \
        --net proxy:3128 --dns 1.1.1.1 || return 1
    expect_refused 'Error: --link names a container of --net proxy, which reaches its proxy and nothing else: p' \
        --link p || return 1
    for value in Outside internet '' nat,none proxy proxy: proxy:0 proxy:65536 proxy:03128 proxy:+3128 'proxy:3128 ' \
                 proxy:3128,3129 Proxy:3128; do
        expect_refused "Error: --net takes nat, outside, none or proxy:<port>, not: $value" --net "$value" || return 1
    done
    cp "$CONF" "$W/conf.good"
    echo 'firewall = false' >> "$CONF"
    expect_refused 'Error: --net outside, the default, needs lightbox'"'"'s firewall rules, and lightbox.conf has
firewall = false; create the container with --net nat or --net none' || { cp "$W/conf.good" "$CONF"; return 1; }
    expect_refused 'Error: --net proxy needs lightbox'"'"'s firewall rules, and lightbox.conf has firewall = false' \
        --net proxy:3128 || { cp "$W/conf.good" "$CONF"; return 1; }
    lb create f --net nat >/dev/null && lb create g --net none >/dev/null || { cp "$W/conf.good" "$CONF"; return 1; }
    cp "$W/conf.good" "$CONF"
    echo 'net=internet' >> "$C/b/.conf"
    msg=$(lb inspect b 2>&1) && { echo "a .conf of net=internet was used"; return 1; }
    case $msg in *'net is not nat, outside, none or proxy:<port>'*) ;; *) echo "$msg"; return 1 ;; esac
}

# A whole disk of this host, as <major>:<minor>; with "partition", one of its
# partitions instead.
block_device() {
    local d
    for d in /sys/dev/block/*; do
        [ -e "$d/uevent" ] || continue
        if [ "${1:-}" = partition ]; then [ -e "$d/partition" ] || continue; else [ ! -e "$d/partition" ] || continue; fi
        echo "${d##*/}"
        return 0
    done
    return 1
}

# --io-max is a line of io.max for one disk that this host has: a partition,
# a device that is not there, a second --io-max and anything the kernel
# would read otherwise are refused, and nothing is made.
t_io_max_option() {
    bad=0
    for value in 8:0 '8:0 rbps' '8:0 rbps=01' '8:0 xbps=1' '8:0 rbps=1 rbps=2' '08:0 rbps=1' '8:0 rbps=1
privileged=1'; do
        msg=$(lb create e --io-max "$value" 2>&1) && { echo "--io-max '$value' was taken"; bad=1; continue; }
        case $msg in 'Error: --io-max takes '*) ;; *) echo "--io-max '$value': $msg"; bad=1 ;; esac
    done
    msg=$(lb create e --io-max '4095:1048575 rbps=1' 2>&1) && { echo "a device that is not there was taken"; bad=1; }
    printf '%s\n' "$msg"
    case $msg in *'no block device with that number'*) ;; *) bad=1 ;; esac
    if part=$(block_device partition); then
        msg=$(lb create e --io-max "$part wbps=1048576" 2>&1) && { echo "the partition $part was taken"; bad=1; }
        printf '%s\n' "$msg"
        case $msg in *'that is a partition'*) ;; *) bad=1 ;; esac
    else
        echo "this host has no partition to try"
    fi
    [ ! -e "$C/e" ] || { echo "a refused --io-max left a container"; bad=1; }
    disk=$(block_device) || { echo "this host has no whole disk to give a limit for"; return $bad; }
    msg=$(lb create e --io-max "$disk wbps=1" --io-max "$disk rbps=1" 2>&1) && { echo "two --io-max were taken"; bad=1; }
    case $msg in *'--io-max is given once'*) ;; *) echo "two --io-max: $msg"; bad=1 ;; esac
    lb create io --io-max "$disk wbps=1048576 riops=max" || return 1
    conf_has io "io=$disk wbps=1048576 riops=max" && lb inspect io | grep -x "io: $disk wbps=1048576 riops=max" || bad=1
    lb inspect e >/dev/null 2>&1 && { echo "a refused --io-max left a container"; bad=1; }
    return $bad
}

t_missing_value_is_named() {
    for option in --mem --swap --pids --cpu --oom-score --io-max --vol --dns --link --rootfs --seccomp --net; do
        msg=$(lb create web 10.0.0.2 "$option" 2>&1) && { echo "$option without a value was accepted"; return 1; }
        printf '%s\n' "$msg"
        [ "$msg" = "Error: option $option requires a value" ] || return 1
        [ ! -e "$C/web" ] || { echo "a container was made"; return 1; }
    done
}

# A container's configuration is a file of lines. No value that is more than
# one line gets into it, from any option: the rest of it would be read as
# settings of the container that nobody gave.
t_no_value_adds_a_line() {
    nl='
'
    bad=0
    for option in --mem --pids --cpu --oom-score --link; do
        refused lb create a 10.0.0.2 "$option" "1${nl}privileged=1" 2>/dev/null || { echo "$option took two lines"; bad=1; }
    done
    mkdir -p "$W/vol${nl}privileged=1"
    refused lb create a 10.0.0.2 --vol "$W/vol${nl}privileged=1:/data" 2>/dev/null || { echo "--vol took a source of two lines"; bad=1; }
    refused lb create a 10.0.0.2 --vol "$W/vol:/data${nl}privileged=1" 2>/dev/null || { echo "--vol took a destination of two lines"; bad=1; }
    [ ! -e "$C/a" ] || { echo "a container was made"; bad=1; }

    lb create web 10.0.0.2 || return 1
    before=$(cat "$C/web/.conf")
    msg=$(lb add-vol web "$W/vol${nl}privileged=1:/data" 2>&1) && { echo "add-vol took a source of two lines"; bad=1; }
    printf '%s\n' "$msg"
    case $msg in *'control characters'*) ;; *) echo "the refusal does not say why"; bad=1 ;; esac
    refused lb add-vol web "$W/vol:/data${nl}privileged=1" 2>/dev/null || { echo "add-vol took a destination of two lines"; bad=1; }
    refused lb add-vol web "$W/vol:/da$(printf '\t')ta" 2>/dev/null || { echo "add-vol took a tab"; bad=1; }
    refused lb add-vol web "$W/vol:/data$(printf '\r')" 2>/dev/null || { echo "add-vol took a carriage return"; bad=1; }
    [ "$(cat "$C/web/.conf")" = "$before" ] || { echo "the configuration changed:"; cat "$C/web/.conf"; bad=1; }
    lb inspect web | grep -x 'privileged: 0' || { echo "the container is privileged"; bad=1; }
    return $bad
}

# ─── Volumes of a container that exists ─────────────────────────────────────

# Two volumes at one place would be mounted one over the other, and only the
# later one would ever be seen.
t_one_volume_at_a_destination() {
    mkdir -p "$W/other"
    msg=$(lb create two 10.0.0.3 --vol "$W/vol:/data" --vol "$W/other:/data/" 2>&1) && { echo "create took two volumes at one place"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *'already a volume at that destination'*) ;; *) return 1 ;; esac
    [ ! -e "$C/two" ] || return 1

    lb create web 10.0.0.2 --vol "$W/vol:/data" || return 1
    msg=$(lb add-vol web "$W/other:/data" 2>&1) && { echo "add-vol took a second volume at one place"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *'already a volume at that destination'*) ;; *) return 1 ;; esac
    # the same source there, read-only now: also a second volume, not the same one
    refused lb add-vol web "$W/vol:/data:ro" || return 1
    [ "$(vol_count web)" -eq 1 ] && conf_has web "vol=$W/vol:/data" || return 1
    # a place inside another volume is another place
    lb add-vol web "$W/other:/data/inner" && [ "$(vol_count web)" -eq 2 ]
}

t_rmvol_removes_a_volume() {
    mkdir -p "$W/other"
    lb create web 10.0.0.2 --vol "$W/vol:/data:ro" --vol "$W/other:/more" || return 1
    # by the place it is at, in whatever spelling
    msg=$(lb rm-vol web //data/) || return 1
    printf '%s\n' "$msg"
    cat "$C/web/.conf"
    [ "$(vol_count web)" -eq 1 ] && conf_has web "vol=$W/other:/more" || return 1
    # the place is free again
    lb add-vol web "$W/other:/data" && [ "$(vol_count web)" -eq 2 ] || return 1

    before=$(cat "$C/web/.conf")
    msg=$(lb rm-vol web /nowhere 2>&1) && { echo "rm-vol removed a volume that is not there"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *'no volume at that destination'*) ;; *) return 1 ;; esac
    refused lb rm-vol web 2>/dev/null && refused lb rm-vol web /data extra 2>/dev/null &&
    refused lb rm-vol nosuch /data 2>/dev/null && refused lb rm-vol web data 2>/dev/null &&
    refused lb rm-vol web /a/../data 2>/dev/null || return 1
    # a volume as it was added is not where it is: said, not looked for
    msg=$(lb rm-vol web "$W/other:/data" 2>&1) && return 1
    printf '%s\n' "$msg"
    case $msg in *'no colon'*) ;; *) return 1 ;; esac
    [ "$(cat "$C/web/.conf")" = "$before" ] || { echo "a refused rm-vol changed the configuration"; return 1; }
    [ "$(mode_of "$C/web/.conf")" = 600 ] || return 1
    # a container from before this rule can have two at one place: both go
    printf 'mem=64M\nvol=%s:/twice\nvol=%s:/twice:ro\nvol=%s:/kept\n' "$W/vol" "$W/other" "$W/vol" > "$C/web/.conf"
    lb rm-vol web /twice || return 1
    cat "$C/web/.conf"
    [ "$(vol_count web)" -eq 1 ] && conf_has web "vol=$W/vol:/kept"
}

# ─── The configuration file of a container ──────────────────────────────────

t_conf_has_a_version() {
    lb create web 10.0.0.2 --vol "$W/vol:/data" || return 1
    cat "$C/web/.conf"
    [ "$(head -n 1 "$C/web/.conf")" = 'version=1' ] || return 1

    # written by a lightbox newer than this one: not guessed at, and not rewritten
    sed -i '1s/.*/version=2/' "$C/web/.conf"
    before=$(cat "$C/web/.conf")
    msg=$(lb add-vol web "$W/vol:/more" 2>&1) && { echo "add-vol rewrote a configuration it cannot read"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *"$C/web/.conf: line 1: was written by a newer lightbox"*) ;; *) return 1 ;; esac
    refused lb rm-vol web /data 2>/dev/null || return 1
    refused lb inspect web >/dev/null 2>&1 || { echo "inspect showed a configuration it cannot read"; return 1; }
    [ "$(cat "$C/web/.conf")" = "$before" ] || return 1

    # damaged: said with the line it is on
    printf 'version=1\nmem=64M\ncolour=blue\n' > "$C/web/.conf"
    msg=$(lb inspect web 2>&1 >/dev/null) && return 1
    printf '%s\n' "$msg"
    case $msg in *"$C/web/.conf: line 3: a key lightbox does not know") ;; *) return 1 ;; esac
    # none of which stops the container from being removed
    lb ls >/dev/null && lb rm web && [ ! -e "$C/web" ]
}

# A container made before the file had a version line keeps working, and the
# next change to it writes the file as it is written now.
t_conf_from_before_is_read() {
    lb create web 10.0.0.2 || return 1
    # with a key lightbox never wrote, and a first uid without the user
    # namespace it would be for, which says nothing and is not written again
    printf 'mem=64M\npids=32\ncpu=2\nreadonly=1\noom_score=100\nnote=by hand\nuid_start=100000\nvol=%s:/data:ro\n' "$W/vol" > "$C/web/.conf"
    report=$(lb inspect web) || { echo "inspect failed"; return 1; }
    printf '%s\n' "$report" | grep -E '^(mem|pids|cpu|readonly|oom_score|privileged): '
    for line in 'mem: 64M' 'pids: 32' 'cpu: 2' 'readonly: 1' 'oom_score: 100' 'privileged: 0'; do
        printf '%s\n' "$report" | grep -qx "$line" || { echo "missing: $line"; return 1; }
    done
    lb add-vol web "$W/vol:/more" || return 1
    cat "$C/web/.conf"
    [ "$(head -n 1 "$C/web/.conf")" = 'version=1' ] && conf_has web 'mem=64M' && conf_has web 'pids=32' &&
    conf_has web 'cpu=2' && conf_has web 'readonly=1' && conf_has web 'oom_score=100' &&
    conf_has web "vol=$W/vol:/data:ro" && conf_has web "vol=$W/vol:/more" &&
    ! grep -q '^note=\|^uid_start=' "$C/web/.conf"
}

# ─── Settings ───────────────────────────────────────────────────────────────

# A default_* setting is held to what the option takes. One that is not a
# limit is said by every command and stops only the one that would have had
# to use it: no container gets a limit that nobody chose.
# The four firewall settings, as Docker's daemon.json has them: doctor shows
# what they are; one that is not true or false is said, and the built-in
# value is kept, so that a mistake does not open the firewall.
t_firewall_settings() {
    report=$(lb doctor 2>&1)
    printf '%s\n' "$report" | grep -E '^(firewall|ip_forward|ip_forward_no_drop|ip_masq):'
    printf '%s\n' "$report" | grep -qx 'firewall: true' && printf '%s\n' "$report" | grep -qx 'ip_forward: true' &&
    printf '%s\n' "$report" | grep -qx 'ip_forward_no_drop: false' && printf '%s\n' "$report" | grep -qx 'ip_masq: true' ||
        { echo "the built-in values are not what Docker's are"; return 1; }
    cp "$CONF" "$W/conf.good"
    printf 'firewall = false\nip_forward = false\nip_forward_no_drop = true\n' >> "$CONF"
    report=$(lb doctor 2>&1)
    printf '%s\n' "$report" | grep -qx 'firewall: false (lightbox makes no firewall rules)' &&
    printf '%s\n' "$report" | grep -qx 'ip_forward: false' && printf '%s\n' "$report" | grep -qx 'ip_forward_no_drop: true' &&
    printf '%s\n' "$report" | grep -qx 'ip_masq: true' || { echo "the settings were not taken"; return 1; }
    { cat "$W/conf.good"; echo 'ip_masq = false'; } > "$CONF"
    report=$(lb doctor 2>&1)
    printf '%s\n' "$report" | grep -qx 'ip_masq: false' && printf '%s\n' "$report" | grep -qx 'ip_forward: true' &&
    printf '%s\n' "$report" | grep -qx 'firewall: true' || { echo "ip_masq = false was not taken by itself"; return 1; }
    cp "$W/conf.good" "$CONF"
    sed -i -e '/^firewall = /d' -e '/^ip_forward/d' -e '/^ip_masq = /d' "$CONF"
    printf 'firewall = no\nip_forward_no_drop = yes\nip_masq = 0\n' >> "$CONF"
    report=$(lb doctor 2>&1)
    printf '%s\n' "$report" | grep '^Warning'
    printf '%s\n' "$report" | grep -qx 'Warning: firewall in lightbox.conf is not true or false: no; using true' &&
    printf '%s\n' "$report" | grep -qx 'Warning: ip_forward_no_drop in lightbox.conf is not true or false: yes; using false' &&
    printf '%s\n' "$report" | grep -qx 'Warning: ip_masq in lightbox.conf is not true or false: 0; using true' &&
    printf '%s\n' "$report" | grep -qx 'firewall: true' && printf '%s\n' "$report" | grep -qx 'ip_forward_no_drop: false'
}

# firewall_backend and bridge_accept_fwmark, as Docker's firewall-backend and
# bridge-accept-fwmark: iptables and no mark unless lightbox.conf says
# otherwise. doctor looks for the firewall tools of the backend in use and not
# the other's, and a value that is not one is said and not taken.
t_firewall_backend_settings() {
    shown() { printf '%s\n' "$report" | grep -E '^(Warning|that a packet|firewall_backend|bridge_accept_fwmark|bridge_filtering|forward_drops|bin\.(iptables|iptables-restore|nft))'; }
    has() { printf '%s\n' "$report" | grep -qx -- "$1"; }
    report=$(lb doctor 2>&1); shown
    has 'firewall_backend: iptables' && has 'bridge_accept_fwmark: none' &&
    printf '%s\n' "$report" | grep -q '^bin.iptables-restore: ' && ! printf '%s\n' "$report" | grep -q '^bin.nft: ' ||
        { echo "the built-in values are not Docker's, or doctor looks for nft"; return 1; }
    cp "$CONF" "$W/conf.good"
    printf 'firewall_backend = nftables\nbridge_accept_fwmark = 0x10/0xf0\n' >> "$CONF"
    report=$(lb doctor 2>&1); shown
    has 'firewall_backend: nftables' && has 'bridge_accept_fwmark: 0x10/0xf0' &&
    has 'bridge_filtering: not needed (firewall_backend = nftables filters at the bridge)' &&
    printf '%s\n' "$report" | grep -q '^bin.nft: ' && ! printf '%s\n' "$report" | grep -q '^bin.iptables' ||
        { echo "the settings were not taken"; return 1; }
    # what drops forwarded packets is root's to read
    if [ "$(id -u)" != 0 ]; then
        has 'forward_drops: unknown (doctor is not run as root)' || { echo "forward_drops is not said to need root"; return 1; }
    fi
    { cat "$W/conf.good"; echo 'bridge_accept_fwmark = 0x10'; } > "$CONF"
    report=$(lb doctor 2>&1); shown
    has 'bridge_accept_fwmark: 0x10 (not used: with iptables, rules in LIGHTBOX-USER decide first)' ||
        { echo "with iptables the mark is not said to go unused"; return 1; }
    ! printf '%s\n' "$report" | grep -q '^forward_drops' || { echo "forward_drops is shown for iptables"; return 1; }
    { cat "$W/conf.good"; printf 'firewall_backend = nft\nbridge_accept_fwmark = 0\n'; } > "$CONF"
    report=$(lb doctor 2>&1); shown
    has 'Warning: firewall_backend in lightbox.conf is not iptables or nftables: nft; using iptables' &&
    has 'that a packet can carry: 0; using none' && has 'firewall_backend: iptables' && has 'bridge_accept_fwmark: none' ||
        { echo "a value that is not one was taken, or not said"; return 1; }
    # one that is wrong after one that is right keeps the right one
    { cat "$W/conf.good"; printf 'firewall_backend = nftables\nfirewall_backend = both\n'
      printf 'bridge_accept_fwmark = 0x4\nbridge_accept_fwmark = 0x4/0x1\n'; } > "$CONF"
    report=$(lb doctor 2>&1); shown
    has 'Warning: firewall_backend in lightbox.conf is not iptables or nftables: both; using nftables' &&
    has 'that a packet can carry: 0x4/0x1; using 0x4' && has 'firewall_backend: nftables' && has 'bridge_accept_fwmark: 0x4'
}

t_default_settings_are_checked() {
    printf 'default_mem = 64M\ndefault_pids = 32\ndefault_cpu = 0.5\ndefault_oom = -200\n' >> "$CONF"
    lb create web 10.0.0.2 || return 1
    cat "$C/web/.conf"
    conf_has web 'mem=64M' && conf_has web 'pids=32' && conf_has web 'cpu=0.5' && conf_has web 'oom_score=-200' || return 1

    printf 'default_mem = 1Gb\n' >> "$CONF"
    msg=$(lb ls 2>&1 >/dev/null) || { echo "ls failed over a default it does not use"; return 1; }
    printf '%s\n' "$msg"
    case $msg in 'Warning: default_mem in lightbox.conf is not '*': 1Gb; a container that needs it will be refused') ;; *) return 1 ;; esac
    lb inspect web 2>/dev/null | grep -qx 'mem: 64M' || { echo "inspect of a container with its own limit failed"; return 1; }
    msg=$(lb create db 10.0.0.3 2>&1) && { echo "a container was created with a limit nobody chose"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *'Error: default_mem: '*) ;; *) return 1 ;; esac
    [ ! -e "$C/db" ] || { echo "the refused container is there"; return 1; }
    lb create db 10.0.0.3 --mem 32M 2>/dev/null && conf_has db 'mem=32M' && conf_has db 'pids=32' || return 1

    sed -i '$d' "$CONF"

    # each of the four by itself, with the container given every limit but that one
    n=0
    for setting in 'default_mem = 0100M:--pids 5 --cpu 1 --oom-score 0' \
                   'default_pids = 123456789:--mem 32M --cpu 1 --oom-score 0' \
                   'default_cpu = 1024:--mem 32M --pids 5 --oom-score 0' \
                   'default_oom = 12abc:--mem 32M --pids 5 --cpu 1'; do
        printf '%s\n' "${setting%%:*}" >> "$CONF"
        key=${setting%% *}
        n=$((n + 1))
        lb ls 2>&1 >/dev/null | grep "^Warning: $key in lightbox.conf is not " || { echo "no warning for: ${setting%%:*}"; return 1; }
        # shellcheck disable=SC2086     # the options are words
        msg=$(lb create "x$n" 10.0.0.4 ${setting#*:} 2>&1) && { echo "a container was created without a usable $key"; return 1; }
        case $msg in *"Error: $key: "*) ;; *) echo "the refusal does not name $key: $msg"; return 1 ;; esac
        [ ! -e "$C/x$n" ] || { echo "the refused container is there"; return 1; }
        sed -i '$d' "$CONF"
    done
    # and with nothing wrong any more, nothing is said but that this user can mount no overlay
    msg=$(lb create y 10.0.0.5 2>&1 >/dev/null | grep -v '^Note: an overlay cannot be mounted here') || true
    [ -z "$msg" ] && conf_has y 'mem=64M' && conf_has y 'oom_score=-200'
}

# Where the base root filesystem is: --rootfs, then LIGHTBOX_ROOTFS, then the
# rootfs setting, then what is built in. The variable does not need a
# lightbox.conf to count.
t_rootfs_from_the_environment() {
    mkdir -p "$W/other/etc" "$W/nohome"
    echo other > "$W/other/etc/which"
    echo base > "$BASE/etc/which"
    built_in=/var/lib/lightbox/rootfs

    # without a lightbox.conf, which an empty one is, so that this host's
    # /etc/lightbox counts for nothing: the variable, and without it what is built in
    said=$(HOME="$W/nohome" LIGHTBOX_CONFIG=/dev/null LIGHTBOX_ROOTFS="$W/other" "$LB" doctor 2>/dev/null | grep '^rootfs: ')
    echo "no lightbox.conf, with the variable: $said"
    [ "$said" = "rootfs: $W/other" ] || return 1
    said=$(HOME="$W/nohome" LIGHTBOX_CONFIG=/dev/null "$LB" doctor 2>/dev/null | grep '^rootfs: ')
    echo "no lightbox.conf, without it: $said"
    [ "$said" = "rootfs: $built_in" ] || return 1
    # an empty variable is no variable, and neither is another that begins like it
    said=$(HOME="$W/nohome" LIGHTBOX_CONFIG=/dev/null LIGHTBOX_ROOTFS='' LIGHTBOX_ROOTFS_OLD="$W/other" "$LB" doctor 2>/dev/null | grep '^rootfs: ')
    [ "$said" = "rootfs: $built_in" ] || { echo "an empty variable: $said"; return 1; }
    # no HOME at all, as under some service managers
    said=$(env -u HOME LIGHTBOX_CONFIG=/dev/null LIGHTBOX_ROOTFS="$W/other" "$LB" doctor 2>/dev/null | grep '^rootfs: ')
    [ "$said" = "rootfs: $W/other" ] || { echo "without HOME: $said"; return 1; }

    # with a lightbox.conf: the variable comes before the setting, and --rootfs before both
    [ "$(lb doctor 2>/dev/null | grep '^rootfs: ')" = "rootfs: $BASE" ] || return 1
    LIGHTBOX_ROOTFS="$W/other" lb create fromenv 10.0.0.2 || return 1
    lb create fromconf 10.0.0.3 || return 1
    LIGHTBOX_ROOTFS="$W/nowhere" lb create fromflag 10.0.0.4 --rootfs "$W/other" || return 1
    echo "copied from: $(cat "$C/fromenv/rootfs/etc/which") $(cat "$C/fromconf/rootfs/etc/which") $(cat "$C/fromflag/rootfs/etc/which")"
    [ "$(cat "$C/fromenv/rootfs/etc/which")" = other ] && [ "$(cat "$C/fromconf/rootfs/etc/which")" = base ] &&
    [ "$(cat "$C/fromflag/rootfs/etc/which")" = other ] || return 1

    # the variable is held to what the setting is held to
    msg=$(HOME="$W/nohome" LIGHTBOX_CONFIG=/dev/null LIGHTBOX_ROOTFS="$(pad_path "$W/other" 460)" "$LB" doctor 2>&1) && { echo "a variable of 460 characters was accepted"; return 1; }
    printf '%s\n' "$msg" | cut -c1-80
    case $msg in 'Error: LIGHTBOX_ROOTFS is too long: '*) ;; *) return 1 ;; esac
}

# A setting that does not fit where it is kept is refused whole. Cut short,
# a directory would be another directory and a bridge another bridge.
t_settings_are_not_cut() {
    printf 'container_dir = %s\n' "$(pad_path "$C" 460)" >> "$CONF"
    msg=$(lb ls 2>&1) && { echo "a directory of 460 characters was accepted"; return 1; }
    printf '%s\n' "$msg" | cut -c1-120
    case $msg in 'Error: container_dir is longer than the 448 characters a directory setting may have: '*) ;; *) return 1 ;; esac
    sed -i '$d' "$CONF"
    # the longest that is accepted still leaves room for every path below it
    long=$(pad_path "$C" 448)
    mkdir -p "$long"
    printf 'container_dir = %s\n' "$long" >> "$CONF"
    lb create web 10.0.0.2 --vol "$W/vol:/data" && lb add-vol web "$W/vol:/more" && lb inspect web >/dev/null &&
    [ -f "$long/web/.conf" ] && [ -f "$long/web/rootfs/etc/hostname" ] && lb rm web && [ ! -e "$long/web" ] ||
        { echo "a directory of 448 characters does not work"; return 1; }
    sed -i '$d' "$CONF"

    printf 'bridge = %s\n' "$(printf 'b%.0s' $(seq 1 40))" >> "$CONF"
    msg=$(lb ls 2>&1) && { echo "a bridge name of 40 characters was accepted"; return 1; }
    printf '%s\n' "$msg"
    case $msg in 'Error: bridge in lightbox.conf is too long: bbbb'*) ;; *) return 1 ;; esac
    sed -i '$d' "$CONF"

    printf 'rootfs = %s\n' "$(printf '/r%.0s' $(seq 1 300))" >> "$CONF"
    msg=$(lb ls 2>&1) && { echo "a value of 600 characters was accepted"; return 1; }
    printf '%s\n' "$msg"
    case $msg in 'Error: lightbox.conf has a value that is too long, for rootfs') ;; *) return 1 ;; esac
    sed -i '$d' "$CONF"

    # the file itself: read to its last line, or not at all
    comment() { for i in $(seq 1 "$1"); do echo "# a comment that fills the file and says nothing, line $i"; done; }
    { comment 100; echo 'bridge = br9'; } >> "$CONF"
    echo "a configuration of $(stat -c %s "$CONF") bytes"
    lb doctor 2>/dev/null | grep -x 'bridge: br9' || { echo "the last line of a long file was not read"; return 1; }
    { comment 300; echo 'bridge = br8'; } >> "$CONF"
    echo "a configuration of $(stat -c %s "$CONF") bytes"
    msg=$(lb doctor 2>&1) && { echo "a file longer than lightbox reads was read in part"; return 1; }
    printf '%s\n' "$msg"
    case $msg in 'Error: the configuration is larger than lightbox reads: '*) ;; *) return 1 ;; esac
}

# A record of a process that no longer exists. Listing must not rewrite it.
stale_record() {
    lb create web 10.0.0.2 || return 1
    sleep 0 & dead=$!
    wait "$dead"
    record web "$dead" 12345 running
}
# A record that is not the number of a process is no record. It is not the
# process whose number it begins with.
t_pid_record_is_a_number() {
    lb create web 10.0.0.2 || return 1
    mkdir -p "$R/web"
    for record in "$$abc" "$$ 1" "-$$" 0 '' 99999999999999999999 0x10; do
        printf '%s' "$record" > "$R/web/pid"
        printf '12345' > "$R/web/pid_start"
        report=$(lb inspect web) || { echo "inspect failed with the record '$record'"; return 1; }
        printf '%s\n' "$report" | grep -qx 'pid: -' && printf '%s\n' "$report" | grep -qx 'running: no' &&
        printf '%s\n' "$report" | grep -qx 'state: stopped' ||
            { echo "the record '$record' was taken for a process:"; printf '%s\n' "$report" | grep -E '^(pid|running|state): '; return 1; }
    done
    # with a newline after it, as an editor leaves a file, the number is the record
    printf '%s\n' "$$" > "$R/web/pid"
    lb inspect web | grep -x "pid: $$"
}

t_ls_writes_nothing() {
    stale_record || return 1
    before=$(kept_sum)
    lb ls >/dev/null
    [ -e "$R/web/pid" ] || echo "the PID record was deleted"
    echo "state is now: $(cat "$R/web/state")"
    [ "$before" = "$(kept_sum)" ]
}
t_inspect_writes_nothing() {
    stale_record || return 1
    before=$(kept_sum)
    lb inspect web >/dev/null
    [ -e "$R/web/pid" ] || echo "the PID record was deleted"
    echo "state is now: $(cat "$R/web/state")"
    [ "$before" = "$(kept_sum)" ]
}

# What a container is made of is in its directory, and what is known about it
# while it runs is in run_dir, which a reboot empties. Without those records a
# container is stopped.
t_runtime_records_are_apart() {
    lb create web 10.0.0.2 || return 1
    echo "the container's directory: $(ls -A "$C/web" | tr '\n' ' ')"
    echo "run_dir: $(ls -A "$R" | tr '\n' ' ')"
    [ "$(ls -A "$C/web" | tr '\n' ' ')" = '.conf .ip .resolv rootfs ' ] || { echo "create left more than a container is made of"; return 1; }
    [ "$(cat "$C/web/.resolv")" = "$(cat "$C/web/rootfs/etc/resolv.conf")" ] || { echo ".resolv is not what create wrote"; return 1; }
    [ "$(mode_of "$C/web/.resolv")" = 600 ] || { echo ".resolv is $(mode_of "$C/web/.resolv")"; return 1; }
    [ -z "$(ls -A "$R")" ] || { echo "create made a runtime record"; return 1; }
    report=$(lb inspect web)
    for line in 'state: stopped' 'running: no' 'pid: -' "pid_path: $R/web/pid" "pid_start_path: $R/web/pid_start" \
                "state_path: $R/web/state" "config_path: $C/web/.conf"; do
        printf '%s\n' "$report" | grep -qxF -- "$line" || { echo "inspect does not say: $line"; return 1; }
    done
    lb doctor 2>/dev/null | grep -x "run_dir: $R" || return 1

    # A container that was removed by hand, and not by rm, leaves its
    # records. A new container of that name does not take them for its own.
    record again 1 1 running
    lb create again 10.0.0.3 >/dev/null || return 1
    lb inspect again | grep -x 'state: stopped' && [ ! -e "$R/again" ] ||
        { echo "a new container has the records of an old one: $(ls -A "$R/again" | tr '\n' ' ')"; return 1; }

    # a stand-in for init, with the records a start leaves
    [ "$(id -u)" -ne 0 ] || return 0
    sleep 30 &
    holder=$!
    record web "$holder" "$(awk '{ printf "%s", $22 }' "/proc/$holder/stat")" running
    lb ls | grep -Eq '^web +10\.0\.0\.2 +running' || { kill "$holder"; echo "the records in run_dir are not read"; return 1; }
    # a reboot: nothing runs and run_dir is empty. The container is stopped, not stale.
    kill "$holder"
    find "$R" -mindepth 1 -delete
    lb ls
    lb ls | grep -Eq '^web +10\.0\.0\.2 +stopped' && lb inspect web | grep -qx 'state: stopped' || return 1
    # and without run_dir itself, as after a reboot with /run on a tmpfs
    rmdir "$R"
    lb ls | grep -Eq '^web +10\.0\.0\.2 +stopped' && [ ! -e "$R" ] || { echo "a query made run_dir, or failed without it"; return 1; }
}

# A create that was killed half way leaves a container with half a root
# filesystem. It says so for as long as it is there.
t_half_made_container() {
    lb create web 10.0.0.2 || return 1
    : > "$C/web/.creating"
    lb ls
    lb ls | grep -Eq '^web +10\.0\.0\.2 +creating' && lb inspect web | grep -qx 'state: creating' || return 1
    lb rm web && [ ! -e "$C/web" ]
}

# Before 0.5 the records of a running container were files in its own
# directory. A container that such a lightbox started, and that is still
# running after an upgrade, is seen to be running.
t_records_from_before_are_read() {
    [ "$(id -u)" -ne 0 ] || return 77
    lb create web 10.0.0.2 || return 1
    sleep 30 &
    holder=$!
    printf '%s' "$holder" > "$C/web/.pid"
    awk '{ printf "%s", $22 }' "/proc/$holder/stat" > "$C/web/.pid_start"
    printf 'running\n' > "$C/web/.state"
    lb ls
    report=$(lb inspect web)
    kill "$holder"
    lb ls | grep -Eq "^web +10\.0\.0\.2 +exited" || { echo "the container is not seen to have been running"; return 1; }
    printf '%s\n' "$report" | grep -qx 'running: yes' && printf '%s\n' "$report" | grep -qx "pid: $holder" &&
    printf '%s\n' "$report" | grep -qx 'state: running' || { echo "inspect did not see it running"; return 1; }
    # what is recorded where records are kept now comes first
    record web "$$" "$(awk '{ printf "%s", $22 }' /proc/$$/stat)" stopping
    lb inspect web | grep -x "pid: $$" && lb inspect web | grep -x 'state: running'
}

# A create that is killed while it copies the root filesystem. It runs here
# as the root of a user namespace, in a mount namespace where a stand-in is
# mounted over cp: one that looks whether the container is marked as being
# created when the copy begins, and, the second time, ends the lightbox that
# runs it.
t_create_killed_half_way() {
    unshare -r --mount true 2>/dev/null || { echo "user namespaces are not available to this user"; return 77; }
    real=$(readlink -f "$(type -P cp)") && cp "$real" "$W/cp.real" || return 1
    {
        echo '#!/bin/sh'
        echo 'for last; do :; done'                             # the destination: <container>/rootfs, or a snapshot
        echo "case \"\$last\" in $C/*) if [ -e \"\${last%/rootfs}/.creating\" ]; then echo marked; else echo unmarked; fi >> $W/seen ;; esac"
        echo "if [ -e $W/end-it ]; then kill -KILL \$PPID; exit 1; fi"
        echo "case \"\$last\" in */bases/.*.new/rootfs) if [ -e $W/end-snapshot ]; then kill -KILL \$PPID; exit 1; fi ;; esac"
        echo "exec $W/cp.real \"\$@\""
    } > "$W/cp.shim"
    chmod +x "$W/cp.shim"
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- sh -c '
        for cp in /bin/cp /usr/bin/cp; do
            [ -e "$cp" ] && { mount --bind "$1/cp.shim" "$(readlink -f "$cp")" || exit 77; }
        done
        "$2" create whole 10.0.0.2 --copy || exit 1
        : > "$1/end-it"
        "$2" create half 10.0.0.3 --copy
        echo "the create that was killed: status $?"
        "$2" ls
        "$2" start half
        echo "start of the half-made container: status $?"
        "$2" rm half
        rm -f "$1/end-it"
        cp "$1/seen" "$1/seen.copies"
        # killed while it takes a snapshot of a base, where an overlay mounts here
        cp -a "$1/base" "$1/base2" && : > "$1/end-snapshot"
        "$2" create snapped 10.0.0.4 --rootfs "$1/base2"
        echo "the create killed in its snapshot: status $?"
        "$2" ls
        "$2" base ls
        "$2" start snapped
        echo "start of the container whose snapshot was cut: status $?"
        "$2" rm snapped
        rm -f "$1/end-snapshot"
        "$2" create again 10.0.0.4 --rootfs "$1/base2" || exit 1
        "$2" base ls
    ' _ "$W" "$LB" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -ne 77 ] || { echo "a stand-in could not be mounted over cp here"; return 77; }
    [ $rc -eq 0 ] || return 1
    echo "the mark, when each copy began: $(paste -sd' ' "$W/seen.copies")"
    [ "$(paste -sd' ' "$W/seen.copies")" = 'marked marked' ] || { echo "a container was being copied into without being marked"; return 1; }
    [ ! -e "$C/whole/.creating" ] || { echo "a finished container is still marked"; return 1; }
    grep -Eq '^whole +10\.0\.0\.2 +stopped' "$W/ns.out" && grep -Eq '^half +- +creating' "$W/ns.out" ||
        { echo "ls does not tell the finished container from the half-made one"; return 1; }
    grep -q 'was not created completely' "$W/ns.out" && grep -qx 'start of the half-made container: status 1' "$W/ns.out" ||
        { echo "the half-made container was not refused by start as one"; return 1; }
    [ ! -e "$C/half" ] || { echo "rm did not remove the half-made container"; return 1; }
    if ! grep -qx 'the create killed in its snapshot: status 137' "$W/ns.out"; then
        echo "no overlay mounts in this user namespace, so no snapshot was taken to cut short"
        return 0
    fi
    grep -Eq '^snapped +- +creating' "$W/ns.out" && grep -qx 'start of the container whose snapshot was cut: status 1' "$W/ns.out" ||
        { echo "the container whose snapshot was cut short was not shown and refused as half made"; return 1; }
    # the snapshot cut short is no snapshot, and the next create takes a whole one
    [ "$(grep -c "  $W/base2  " "$W/ns.out")" = 1 ] && grep -Eq "  $W/base2  again\$" "$W/ns.out" ||
        { echo "a snapshot cut short was listed, or the next create did not take a whole one"; return 1; }
    id=$(sed -n 's/^base=//p' "$C/again/.conf")
    [ -n "$id" ] && [ -f "$W/data/bases/$id/rootfs/bin/placeholder" ] || { echo "the container made after does not overlay a whole snapshot"; return 1; }
}

# rm clears away what a container that ended without a stop still had, and
# its runtime records go with it.
t_rm_of_a_dead_container() {
    stale_record || return 1
    printf '0\n' > "$R/web/exit"
    msg=$(lb rm web 2>&1) || { printf '%s\n' "$msg"; return 1; }
    printf '%s\n' "$msg"
    case $msg in *"Note: container 'web' had stopped by itself"*"Container 'web' removed") ;; *) echo "rm does not say what it found"; return 1 ;; esac
    [ ! -e "$C/web" ] && [ ! -e "$R/web" ] || { echo "left: $(ls -A "$C" "$R" | tr '\n' ' ')"; return 1; }
    # a container that was simply stopped has nothing to be said about
    lb create web 10.0.0.2 >/dev/null && msg=$(lb rm web 2>&1) || return 1
    case $msg in *Note:*) echo "rm found something to clear away in a stopped container"; return 1 ;; esac
}

# PID 1 is alive and belongs to root. For an ordinary user kill(1, 0) fails
# with EPERM, which is not "no such process".
t_other_users_process_is_not_gone() {
    [ "$(id -u)" -ne 0 ] || return 77
    lb create web 10.0.0.2 || return 1
    record web 1 "$(awk '{ printf "%s", $22 }' /proc/1/stat)" running
    before=$(kept_sum)
    json=$(lb ls --json)
    printf '%s\n' "$json"
    lb inspect web | grep -x 'running: yes' || return 1
    printf '%s' "$json" | grep -q '"status":"running"' && [ "$before" = "$(kept_sum)" ]
}

# What a query shows for a container whose init is gone, without recording it.
t_dead_container_shown_as_exited() {
    stale_record || return 1
    lb ls
    lb ls | grep -Eq '^web +10\.0\.0\.2 +exited' && lb inspect web | grep -x 'state: exited' &&
    lb inspect web | grep -x 'running: no'
}

# setup, start, stop and exec need root. They say so before they look at
# anything, and change nothing: the record of a dead init, which stop would
# clean up, is as it was.
t_root_is_asked_for_first() {
    [ "$(id -u)" -ne 0 ] || return 77
    stale_record || return 1
    chmod 755 "$W/data" "$C"
    before=$(kept_sum)
    bad=0
    for words in setup 'setup --teardown' reload 'start web' 'stop web' 'exec web /bin/true' 'reset web'; do
        # shellcheck disable=SC2086
        msg=$(lb $words 2>&1) && { echo "lightbox $words succeeded"; bad=1; }
        echo "lightbox $words: $msg"
        [ "$msg" = "Error: lightbox ${words%% web*} must be run as root" ] || bad=1
    done
    [ "$before" = "$(kept_sum)" ] || { echo "something under $W/data or $R changed"; bad=1; }
    [ "$(mode_of "$C")" = 755 ] || { echo "setup changed the mode of container_dir"; bad=1; }
    return $bad
}

# setup takes --teardown and nothing else, and says so before it asks for root.
t_setup_arguments() {
    bad=0
    for words in 'setup --teardown now' 'setup --tear-down' 'setup br0'; do
        # shellcheck disable=SC2086
        msg=$(lb $words 2>&1) && { echo "lightbox $words succeeded"; bad=1; }
        echo "lightbox $words: $msg"
        [ "$msg" = 'Usage: lightbox setup [--teardown]' ] || bad=1
    done
    lb 2>&1 | grep -F 'setup --teardown' || { echo "the usage does not name setup --teardown"; bad=1; }
    return $bad
}

# Two commands that change one container do it one after the other. Eight
# add-vol at once all get their volume in: each reads the configuration,
# adds to it and writes it back, and without a lock some would write over
# what another had just added.
t_commands_take_turns() {
    lb create web 10.0.0.2 || return 1
    for i in 1 2 3 4 5 6 7 8; do
        lb add-vol web "$W/vol:/data/$i" >"$W/addvol.$i" 2>&1 &
    done
    wait
    echo "volumes after eight add-vol at once: $(vol_count web)"
    [ "$(vol_count web)" = 8 ] || { cat "$W"/addvol.*; return 1; }
    for i in 1 2 3 4 5 6 7 8; do conf_has web "vol=$W/vol:/data/$i" || return 1; done
}

# A command waits for the lock and says that it does; a query never waits.
t_lock_is_waited_for() {
    command -v flock >/dev/null 2>&1 || { echo "no flock(1) to hold a lock with"; return 77; }
    lb create web 10.0.0.2 || return 1
    flock "$C/web" sleep 2 &
    holder=$!
    sleep 0.3
    began=$SECONDS
    listed=$(lb ls) || return 1
    [ $((SECONDS - began)) -lt 2 ] || { echo "ls waited for the lock"; return 1; }
    printf '%s\n' "$listed" | grep -q '^web ' || return 1
    msg=$(lb add-vol web "$W/vol:/data" 2>&1) || { echo "$msg"; return 1; }
    printf '%s\n' "$msg"
    wait "$holder"
    case $msg in *"Waiting for another lightbox command to finish with container 'web'"*) ;; *) echo "it did not say that it waited"; return 1 ;; esac
    conf_has web "vol=$W/vol:/data" || return 1

    # create waits for the lock of the whole store
    flock "$C" sleep 1 &
    holder=$!
    sleep 0.3
    msg=$(lb create db 10.0.0.3 2>&1) || { echo "$msg"; return 1; }
    wait "$holder"
    printf '%s\n' "$msg"
    case $msg in *"Waiting for another lightbox command to finish with the container store"*) ;; *) return 1 ;; esac

    # a container that is removed while a command waits for it is gone for that command
    flock "$C/db" sh -c "sleep 1; rm -rf '$C/db'" &
    holder=$!
    sleep 0.3
    msg=$(lb add-vol db "$W/vol:/data" 2>&1) && { echo "add-vol worked on a container that was removed meanwhile"; return 1; }
    wait "$holder"
    printf '%s\n' "$msg"
    case $msg in *'container does not exist: db'*) ;; *) return 1 ;; esac
}

t_ls_json_escapes_names() {
    lb create web 10.0.0.2 || return 1
    mkdir "$C/we\"ird"
    json=$(lb ls --json)
    printf '%s\n' "$json"
    printf '%s' "$json" | json_valid || return $?
    printf '%s' "$json" | grep -q '"name":"web"'
}

# one field of the first entry of ls --json, decoded by a real JSON parser
json_field() { python3 -I -c 'import json, sys; sys.stdout.write(str(json.load(sys.stdin)[0][sys.argv[1]]))' "$1"; }

# A record is a file anyone with access can damage. Whatever the state record
# holds, the listing stays JSON and gives the value back unchanged; an address
# record that is no address is not shown at all.
t_ls_json_escapes_values() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to decode JSON with"; return 77; }
    lb create web 10.0.0.2 || return 1
    mkdir -p "$R/web"
    printf '1"2\\3\t4\001' > "$R/web/state"
    json=$(lb ls --json)
    printf '%s\n' "$json"
    printf '%s' "$json" | json_valid || return 1
    [ "$(printf '%s' "$json" | json_field status | od -An -c | tr -s ' ')" = "$(printf '1"2\\3\t4\001' | od -An -c | tr -s ' ')" ] ||
        { echo "the state record did not come back as it is"; return 1; }
    printf '1"2\\3\t4\001' > "$C/web/.ip"
    json=$(lb ls --json)
    printf '%s\n' "$json"
    printf '%s' "$json" | json_valid && [ "$(printf '%s' "$json" | json_field ip)" = - ]
}

t_ls_json_pid_is_null_when_stopped() {
    lb create web 10.0.0.2 || return 1
    json=$(lb ls --json)
    printf '%s\n' "$json"
    printf '%s' "$json" | json_valid || return $?
    printf '%s' "$json" | grep -q '"pid":null}'
}

t_ls_is_sorted() {
    lb create zeta 10.0.0.2 && lb create alpha 10.0.0.3 && lb create mid 10.0.0.4 || return 1
    text=$(lb ls | sed '1,2d' | awk '{print $1}' | tr '\n' ' ')
    json=$(lb ls --json | grep -o '"name":"[a-z]*"' | tr '\n' ' ')
    echo "text: $text"
    echo "json: $json"
    [ "$text" = "alpha mid zeta " ] && [ "$json" = '"name":"alpha" "name":"mid" "name":"zeta" ' ]
}

# containers/ may hold things that are not containers. Only directories with a
# valid container name are listed.
t_ls_lists_only_containers() {
    lb create web 10.0.0.2 || return 1
    mkdir "$C/has space" "$C/a-name-of-thirty-one-characters" "$C/.hidden"
    : > "$C/afile"
    ln -s web "$C/alink"
    listing=$(lb ls | sed '1,2d' | awk '{print $1}' | tr '\n' ' ')
    json=$(lb ls --json)
    echo "listed: $listing"
    printf '%s\n' "$json"
    [ "$listing" = "web " ] && [ "$(printf '%s' "$json" | grep -o '"name"' | wc -l)" -eq 1 ]
}

t_symlinked_base_is_copied() {
    ln -s "$BASE" "$W/base-current"
    lb create web 10.0.0.2 --rootfs "$W/base-current" || return 0
    echo "container rootfs is a $(stat -c %F "$C/web/rootfs")"
    [ ! -L "$C/web/rootfs" ] && [ -d "$C/web/rootfs" ]
}
t_create_leaves_the_base_alone() {
    ln -s "$BASE" "$W/base-current"
    before=$(tree_sum "$BASE")
    lb create web 10.0.0.2 --rootfs "$W/base-current" || return 0
    [ -e "$BASE/etc/resolv.conf" ] && echo "resolv.conf was written into the base"
    [ "$before" = "$(tree_sum "$BASE")" ]
}

# A base that cannot make a container is refused by name, before anything is
# created.
t_empty_base_refused() {
    mkdir "$W/empty"
    msg=$(lb create web 10.0.0.2 --rootfs "$W/empty" 2>&1) && return 1
    printf '%s\n' "$msg"
    case $msg in *"$W/empty"*) ;; *) return 1 ;; esac
    [ ! -e "$C/web" ]
}
t_unusable_base_refused() {
    : > "$W/a-file"
    refused lb create a 10.0.0.2 --rootfs "$W/a-file" &&
    refused lb create b 10.0.0.3 --rootfs "$W/does-not-exist" &&
    [ -z "$(ls -A "$C")" ]
}

# inspect shows what a container is configured with, its volumes and links
# among it, a line each, and its log; "-" where there is none.
t_inspect_shows_volumes_and_links() {
    lb create db 10.0.0.3 && lb create web 10.0.0.2 --vol "$W/vol:/data:ro" --link db || return 1
    report=$(lb inspect web)
    printf '%s\n' "$report"
    printf '%s\n' "$report" | grep -qx "volume: $W/vol:/data:ro" && printf '%s\n' "$report" | grep -qx 'link: db' &&
    printf '%s\n' "$report" | grep -qx "log_path: $C/web/console.log" || return 1
    report=$(lb inspect db)
    printf '%s\n' "$report" | grep -qx 'volume: -' && printf '%s\n' "$report" | grep -qx 'link: -'
}

# inspect --json: the same, as a JSON array of one object, with numbers,
# true and false, null for what is not there, and arrays of volumes and
# links. A configuration that cannot be used is an error before anything is
# printed: a JSON document is whole or not there.
t_inspect_json() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to decode JSON with"; return 77; }
    lb create db 10.0.0.3 && lb create web 10.0.0.2 --vol "$W/vol:/data:ro" --vol "$W/vol:/rw" --link db --swap 32M || return 1
    json=$(lb inspect web --json) || return 1
    printf '%s\n' "$json"
    [ "$json" = "$(lb inspect --json web)" ] || { echo "--json before the name gives another answer"; return 1; }
    printf '%s' "$json" | python3 -I -c '
import json, sys
doc = json.load(sys.stdin)
assert isinstance(doc, list) and len(doc) == 1, "not an array of one"
c = doc[0]
want = {"name": "web", "ip": "10.0.0.2", "state": "stopped", "running": False, "pid": None,
        "pid_starttime": None, "mem": "256M", "swap": "32M", "io": None, "oom_score": 500,
        "privileged": False, "readonly": False, "links": ["db"],
        "volumes": [{"src": sys.argv[1], "dst": "/data", "ro": True}, {"src": sys.argv[1], "dst": "/rw", "ro": False}]}
bad = [k for k in want if c.get(k) != want[k]]
assert not bad, "differ: " + ", ".join("%s=%r" % (k, c.get(k)) for k in bad)
assert c["log_path"].endswith("/web/console.log") and c["host_interface"].startswith("vb-"), "paths"
assert c["userns"] is False and c["uid_start"] is None and c["gid_start"] is None, "user namespace keys"
assert c["seccomp"] == "allow", "the profile"
' "$W/vol" || return 1
    echo 'colour=blue' >> "$C/web/.conf"
    out=$(lb inspect web --json 2>"$W/err") && { echo "inspect --json of a configuration that cannot be used succeeded"; return 1; }
    cat "$W/err"
    [ -z "$out" ] || { echo "it printed: $out"; return 1; }
    grep -q "^Error: the container's configuration cannot be used: " "$W/err"
}

# A carriage return at the end of a line is no part of the value, as a file
# written on Windows has it, and neither is a # after a space: the rest of
# the line is a comment. A # with no space before it is part of the value.
t_config_strips_carriage_returns() {
    printf 'bridge = br9\r\n' >> "$CONF"
    lb doctor 2>/dev/null | grep -x 'bridge: br9' || return 1
    printf 'bridge = br8 # the test bridge\r\n\r\n# a comment\r\n' >> "$CONF"
    lb doctor 2>/dev/null | grep -x 'bridge: br8' || return 1
    [ -z "$(lb doctor 2>&1 >/dev/null)" ] || { echo "CRLF lines were warned about:"; { lb doctor >/dev/null; } 2>&1; return 1; }
}
t_config_strips_inline_comments() {
    printf 'bridge = br9 # the test bridge\n' >> "$CONF"
    lb doctor 2>/dev/null | grep -x 'bridge: br9' || return 1
    printf 'bridge = br#7\ndns = 9.9.9.9\t# tab before\n' >> "$CONF"
    lb doctor 2>/dev/null | grep -x 'bridge: br#7'
}
# A key that lightbox does not know, and a line that is no setting, are said
# with the file and the line, and change nothing; the command goes on.
t_config_reports_unknown_keys() {
    lines=$(wc -l < "$CONF")
    printf 'defualt_mem = 1G\nthis is not a setting\n' >> "$CONF"
    said=$(lb doctor 2>&1 >/dev/null)
    printf '%s\n' "$said"
    [ "$said" = "Warning: $CONF: line $((lines + 1)): a key lightbox does not know: defualt_mem
Warning: $CONF: line $((lines + 2)): not a setting, which is <key> = <value>: this is not a setting" ] || return 1
    lb create web 10.0.0.2 >/dev/null 2>&1 && grep -qx 'mem=256M' "$C/web/.conf" ||
        { echo "the misspelt key changed default_mem: $(grep '^mem=' "$C/web/.conf")"; return 1; }
}

# Where the settings come from: --config, then LIGHTBOX_CONFIG, then
# /etc/lightbox/lightbox.conf, then the place in $HOME that lightbox read
# before, which it says it will stop reading. A file that is named and not
# there is an error. (No case here writes /etc: the lifecycle suite has that.)
t_config_lookup_order() {
    first=$W/first.conf second=$W/second.conf
    { cat "$CONF"; echo 'bridge = brfirst'; } > "$first"
    { cat "$CONF"; echo 'bridge = brsecond'; } > "$second"
    { cat "$CONF"; echo 'bridge = brhome'; } > "$CONF.home" && mv "$CONF.home" "$CONF"
    bridge() { grep '^bridge: ' | cut -d' ' -f2; }
    bad=0
    got=$(LIGHTBOX_CONFIG="$second" HOME="$W/home" "$LB" --config "$first" doctor 2>/dev/null | bridge)
    [ "$got" = brfirst ] || { echo "--config and LIGHTBOX_CONFIG: $got"; bad=1; }
    got=$(LIGHTBOX_CONFIG="$second" HOME="$W/home" "$LB" doctor 2>/dev/null | bridge)
    [ "$got" = brsecond ] || { echo "LIGHTBOX_CONFIG and HOME: $got"; bad=1; }
    if [ ! -e /etc/lightbox/lightbox.conf ]; then
        said=$(LIGHTBOX_CONFIG='' HOME="$W/home" "$LB" doctor 2>&1)
        [ "$(printf '%s\n' "$said" | bridge)" = brhome ] || { echo "an empty LIGHTBOX_CONFIG, and HOME: $(printf '%s\n' "$said" | bridge)"; bad=1; }
        printf '%s\n' "$said" | grep -F "Warning: the configuration is read from $CONF, where lightbox 0.7 will" ||
            { echo "the place in HOME was not said to be going"; bad=1; }
    else
        echo "this host has /etc/lightbox/lightbox.conf: HOME is not looked at, and that is not tried"
    fi
    for words in "--config $W/none.conf ls" "--config $W ls"; do
        # shellcheck disable=SC2086
        said=$(env -u LIGHTBOX_CONFIG "$LB" $words 2>&1) && { echo "lightbox $words succeeded"; bad=1; }
        path=${words#--config }
        [ "$said" = "Error: cannot read the configuration: ${path% ls}" ] || { echo "lightbox $words: $said"; bad=1; }
    done
    said=$(LIGHTBOX_CONFIG="$W/none.conf" "$LB" ls 2>&1) && { echo "a LIGHTBOX_CONFIG that is not there was taken"; bad=1; }
    [ "$said" = "Error: cannot read the configuration: $W/none.conf" ] || { echo "LIGHTBOX_CONFIG not there: $said"; bad=1; }
    said=$("$LB" --config 2>&1) && bad=1
    [ "$said" = 'Error: --config needs the path of a lightbox.conf' ] || { echo "--config alone: $said"; bad=1; }
    "$LB" --config "$first" --help | grep -q '^Usage: lightbox \[--config <path>\]' || { echo "help after --config"; bad=1; }
    return $bad
}

# make install puts everything under DESTDIR, the configuration in
# DESTDIR/etc/lightbox, and writes nothing in the home of whoever runs it. A
# configuration that is there already is kept.
t_make_install_stays_in_destdir() {
    src=$(dirname "$LB")
    [ -f "$src/Makefile" ] && [ -f "$src/lightbox.conf.example" ] || { echo "no source tree beside $LB"; return 77; }
    mkdir -p "$W/installer"
    inst() { env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS HOME="$W/installer" make -s -C "$src" install DESTDIR="$W/dest" >"$W/install.out" 2>&1; }
    inst || { cat "$W/install.out"; return 1; }
    find "$W/dest" -type f | sed "s#^$W/dest##" | sort
    [ -x "$W/dest/usr/local/bin/lightbox" ] && cmp -s "$W/dest/etc/lightbox/lightbox.conf" "$src/lightbox.conf.example" ||
        { echo "the binary or the configuration is not under DESTDIR"; return 1; }
    [ -z "$(ls -A "$W/installer")" ] || { echo "written in the home of whoever ran it: $(find "$W/installer")"; return 1; }
    echo 'bridge = brkept' >> "$W/dest/etc/lightbox/lightbox.conf"
    inst || { cat "$W/install.out"; return 1; }
    grep -qx 'bridge = brkept' "$W/dest/etc/lightbox/lightbox.conf" || { echo "a second install replaced the configuration"; return 1; }
}

# Help that is asked for goes to standard output and is no error: the whole
# usage, or one command's part of it. It reads no lightbox.conf, and says
# nothing about one. --version names lightbox's version and lightc's.
t_help_exits_zero() {
    echo 'firewall = maybe' >> "$CONF"
    usage=$(lb --help 2>/dev/null) || return 1
    printf '%s\n' "$usage" | grep -q '^Usage: lightbox' || return 1
    bad=0
    for words in -h help 'help start' 'start --help' 'rm -h' 'exec --help' 'setup --help' 'ls -h'; do
        # shellcheck disable=SC2086
        out=$(lb $words 2>&1) || { echo "lightbox $words: exit $?"; bad=1; continue; }
        printf '%s\n' "$out" | grep -q '^Usage: lightbox' || { echo "lightbox $words printed no usage"; bad=1; }
        ! printf '%s\n' "$out" | grep -q '^Warning' || { echo "lightbox $words read lightbox.conf"; bad=1; }
    done
    commands=$(lb start --help | grep -c '^  [a-z]')
    [ "$commands" = 1 ] || { echo "start --help shows $commands commands"; bad=1; }
    lb help | grep -q -- '--version' || { echo "the usage does not name --version"; bad=1; }
    out=$(lb help nosuch 2>&1) && { echo "help of no command succeeded"; bad=1; }
    [ "$out" = 'Error: there is no such command: nosuch' ] || { echo "help nosuch: $out"; bad=1; }
    v=$(lb --version) || { echo "--version: exit $?"; bad=1; }
    echo "$v"
    printf '%s\n' "$v" | grep -Eqx 'lightbox [0-9]+\.[0-9]+\.[0-9]+(-dev)? \(lightc [0-9]+\.[0-9]+\.[0-9]+\)' || bad=1
    out=$(lb --version now 2>&1) && bad=1
    [ "$out" = 'Error: unexpected argument: now' ] || { echo "--version now: $out"; bad=1; }
    return $bad
}

# rm with two names removes both, or refuses and removes neither.
# rm takes several names, as Docker's does: each is removed or says why not,
# the others are removed all the same, and those that were not are named.
t_rm_handles_every_argument() {
    lb create a 10.0.0.2 && lb create b 10.0.0.3 && lb create c 10.0.0.4 || return 1
    lb rm a b || return 1
    [ ! -e "$C/a" ] && [ ! -e "$C/b" ] || { echo "rm a b left one of them"; return 1; }
    said=$(lb rm nosuch c 2>&1) && { printf '%s\n' "$said"; echo "rm of a container that does not exist succeeded"; return 1; }
    printf '%s\n' "$said"
    [ ! -e "$C/c" ] || { echo "rm stopped at the name it could not remove"; return 1; }
    [ "$(printf '%s\n' "$said" | tail -n 1)" = 'Error: not removed: nosuch' ]
}

# A word that a command will not use is an error that names it, and the
# command does nothing.
t_surplus_arguments_are_errors() {
    lb create web 10.0.0.2 || return 1
    bad=0
    expect() { # message, words...
        local want=$1
        shift
        msg=$(lb "$@" 2>&1) && { echo "lightbox $*: succeeded"; bad=1; return; }
        echo "lightbox $*: $msg"
        [ "$msg" = "$want" ] || bad=1
    }
    expect 'Error: unexpected argument: b' inspect web b
    expect 'Error: unknown option: --all' inspect web --all
    expect 'Error: unexpected argument: extra' doctor extra
    expect 'Error: unexpected argument: all' reload all
    expect 'Error: unknown option: --all' reload --all
    expect 'Error: unknown option: --jsno' ls --jsno
    expect 'Error: unexpected argument: all' ls all
    expect 'Error: unexpected argument: /mnt' add-vol web /tmp:/srv /mnt
    expect 'Error: unexpected argument: /var' rm-vol web /srv /var
    expect 'Error: unexpected argument: again' create web2 10.0.0.3 again
    expect 'Error: unknown option: --all' rm web --all
    expect 'Error: unknown option: --now' stop web --now
    expect 'Error: not a number of seconds from 0 to 86400: soon' start web other -t soon
    expect 'Usage: lightbox start <name>... [-t <seconds>]' start -t 5
    [ -e "$C/web/.conf" ] && [ ! -e "$C/web2" ] || { echo "a command that was refused changed something"; bad=1; }
    grep -q '/srv' "$C/web/.conf" && { echo "add-vol added the volume"; bad=1; }
    return $bad
}

# Without root, start says so and leaves the container's state alone.
t_start_without_root_is_a_clean_error() {
    [ "$(id -u)" -ne 0 ] || return 77
    lb create web 10.0.0.2 || return 1
    before=$(kept_sum)
    msg=$(lb start web 2>&1) && return 1
    printf '%s\n' "$msg" | head -5
    lb inspect web | grep -x 'state: stopped' || return 1
    printf '%s\n' "$msg" | grep -qi 'root' && [ "$(kept_sum)" = "$before" ]
}

# start reads its options before it touches anything, so a mistyped one
# changes nothing, with or without root.
t_start_options_are_checked() {
    lb create web 10.0.0.2 || return 1
    before=$(kept_sum)
    said() { msg=$(lb start web "$@" 2>&1) && { echo "start web $* succeeded"; return 1; }; echo "start web $*: $msg"; }
    said -t soon   && case $msg in *soon*) ;; *) return 1 ;; esac || return 1
    said -t 86401  && case $msg in *86401*) ;; *) return 1 ;; esac || return 1
    said -t -1     && case $msg in *'number of seconds'*) ;; *) return 1 ;; esac || return 1
    said -t        && case $msg in *'number of seconds'*) ;; *) return 1 ;; esac || return 1
    said --bogus   && case $msg in *'unknown option'*--bogus*) ;; *) return 1 ;; esac || return 1
    # a second word is a second name, and is checked as one before anything else
    said 'an@other' && case $msg in *'container name must only contain'*) ;; *) return 1 ;; esac || return 1
    [ "$before" = "$(kept_sum)" ] || { echo "the container's records changed"; return 1; }
}

# doctor run by an ordinary user says that lightbox needs root, and how to
# run it, and exits 1. Each check that fails is followed by what fixes it.
# A rootfs with nothing in it is one create cannot copy.
t_doctor_says_how_to_fix() {
    [ "$(id -u)" -ne 0 ] || { echo "run as root: root is no failure to show"; return 77; }
    report=$(lb doctor 2>&1) && { printf '%s\n' "$report"; echo "doctor exited 0 for an ordinary user"; return 1; }
    printf '%s\n' "$report" | sed -n '/^root: /,$p'
    printf '%s\n' "$report" | grep -qx "root: no (uid $(id -u))" || return 1
    printf '%s\n' "$report" | grep -Eqx 'kernel: (yes|no) \(.+; lightbox needs Linux 5\.10 or later\)' || return 1
    printf '%s\n' "$report" | grep -q '^syscalls: ' && printf '%s\n' "$report" | grep -q '^bin.cp: ' || return 1
    # lightbox runs neither since 0.7, and doctor looks for neither
    ! printf '%s\n' "$report" | grep -Eq '^bin\.(ip|nsenter): ' || { echo "doctor looks for ip or nsenter"; return 1; }
    # from root on the lines are checks, and one that fails has its fix next
    printf '%s\n' "$report" | awk '/^root: / { on = 1 }
        on && want { if ($0 !~ /^  to fix: ./) { print "no fix after " name; bad = 1 } want = 0; next }
        on && /^[a-z_.0-9-]+: (no|missing|unusable)( |$)/ { want = 1; name = $1 }
        END { if (want) { print "no fix after " name; bad = 1 } exit bad }' || return 1
    mkdir "$W/emptyroot" && echo "rootfs = $W/emptyroot" >> "$CONF"
    report=$(lb doctor 2>&1)
    printf '%s\n' "$report" | grep -A1 '^path.rootfs: '
    printf '%s\n' "$report" | grep -qx "path.rootfs: missing ($W/emptyroot is empty)" &&
    printf '%s\n' "$report" | grep -A1 '^path.rootfs: ' | grep -q '^  to fix: put a root filesystem there'
}

# doctor --json: the settings, and every check as an object with ok as true
# or false, the text of its line, and the fix of one that fails.
t_doctor_json() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to decode JSON with"; return 77; }
    json=$(lb doctor --json)
    rc=$?
    printf '%s\n' "$json" | cut -c1-300
    # 0 or 1 as the overall verdict says, 3 when the document is not as it should be
    printf '%s' "$json" | python3 -I -c '
import json, sys
def wrong(why):
    print("not as it should be:", why)
    sys.exit(3)
try:
    d = json.load(sys.stdin)
except ValueError as e:
    wrong(e)
checks = {c["check"]: c for c in d["checks"]}
for name in ("root", "kernel", "syscalls", "network", "cgroup2", "device_filter", "path.rootfs", "bin.cp", "bin.rm", "exec_sealing"):
    if name not in checks:
        wrong("no check " + name)
for name in ("bin.ip", "bin.nsenter"):
    if name in checks:
        wrong("a check of " + name)
for c in d["checks"]:
    if not isinstance(c["ok"], bool):
        wrong(c)
    if (c["fix"] is None) != c["ok"]:
        wrong(c)
    if not (c["text"].startswith(("yes", "no", "ok", "missing", "unusable")) or c["check"] == "network"):
        wrong(c)
if d["overall"] != ("ok" if all(c["ok"] is True for c in d["checks"]) else "degraded"):
    wrong("overall " + repr(d["overall"]))
if d["settings"]["firewall"] is not True or d["settings"]["bridge_accept_fwmark"] is not None:
    wrong("settings")
sys.exit(0 if d["overall"] == "ok" else 1)
'
    verdict=$?
    [ $verdict != 3 ] || return 1
    [ $verdict = "$rc" ] || { echo "the exit status $rc is not that of the overall verdict, $verdict"; return 1; }
    said=$(lb doctor --json --bogus 2>&1) && return 1
    [ "$said" = 'Error: unknown option: --bogus' ]
}

# update takes --mem, --pids and --cpu, held to what create holds them to,
# and refuses anything else before it looks at the container; restart takes
# -t, and rm -f; each needs root as the command it is made of does.
t_update_restart_rm_options() {
    lb create web 10.0.0.2 || return 1
    before=$(cat "$C/web/.conf")
    bad=0
    expect() { # message, words...
        local want=$1
        shift
        msg=$(lb "$@" 2>&1) && { echo "lightbox $*: succeeded"; bad=1; return; }
        echo "lightbox $*: $msg"
        [ "$msg" = "$want" ] || bad=1
    }
    usage='Usage: lightbox update <name> [--mem <limit>] [--pids <limit>] [--cpu <num>]'
    expect "$usage" update
    expect "$usage" update web
    expect 'Error: --mem takes <number>[K|M|G|T] or max, not: 1x' update web --mem 1x
    expect 'Error: --cpu takes a number of CPUs from 0.01 to 512, such as 2 or 0.5, not: 0' update web --cpu 0
    expect 'Error: --pids takes a number from 1 to 4194304 or max, not: 0' update web --pids 0
    expect 'Error: unknown option: --swap' update web --swap 1G
    expect 'Error: unexpected argument: db' update web db --mem 64M
    expect 'Error: not a number of seconds from 0 to 86400: soon' restart web -t soon
    expect 'Usage: lightbox restart <name>... [-t <seconds>]' restart
    expect 'Usage: lightbox rm [-f] <name>...' rm -f
    expect 'Error: unknown option: --forcefully' rm --forcefully web
    expect 'Usage: lightbox reset <name>... [-t <seconds>]' reset
    expect 'Error: not a number of seconds from 0 to 86400: soon' reset web -t soon
    expect 'Error: unknown option: --hard' reset web --hard
    expect 'Error: container name must only contain [a-zA-Z0-9_-]' reset 'we b'
    if [ "$(id -u)" -ne 0 ]; then
        expect 'Error: lightbox update must be run as root' update web --mem 64M
        expect 'Error: lightbox restart must be run as root' restart web
    fi
    [ "$before" = "$(cat "$C/web/.conf")" ] || { echo "a refused command changed the .conf"; bad=1; }
    for words in 'update --help' 'restart --help' 'rm --help'; do
        # shellcheck disable=SC2086
        lb $words | grep -q '^  [a-z]' || { echo "no help for $words"; bad=1; }
    done
    return $bad
}

# update of a container that is not running writes its .conf, the limits
# given and nothing else changed, and says that it has them from its next
# start. rm -f of one that is not running removes it as rm does.
t_update_rewrites_the_conf() {
    unshare -r --mount true 2>/dev/null || { echo "user namespaces are not available to this user"; return 77; }
    lb create web 10.0.0.2 --vol "$W/vol:/data:ro" --swap 32M || return 1
    lb create gone 10.0.0.3 || return 1
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- sh -c '
        "$1" update web --mem 64M --cpu 0.5 || exit 1
        "$1" update web --pids 50 || exit 1
        "$1" rm -f gone || exit 1
    ' _ "$LB" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    cat "$C/web/.conf"
    [ $rc -eq 0 ] || return 1
    grep -qx 'It is not running: it has them from its next start' "$W/ns.out" || return 1
    for line in mem=64M cpu=0.5 pids=50 swap=32M "vol=$W/vol:/data:ro" oom_score=500 version=1; do
        grep -qx "$line" "$C/web/.conf" || { echo "the .conf has no $line"; return 1; }
    done
    [ ! -e "$C/gone" ] || { echo "rm -f left the container"; return 1; }
}

# create --userns gives out host ids, which root alone may do: an ordinary
# user is refused before anything is made. A .conf with userns=1 and its
# range is read, and inspect shows the range, as numbers in JSON. doctor says
# how many ranges /etc/subuid and /etc/subgid give lightbox.
t_userns_as_a_user_sees_it() {
    [ "$(id -u)" -ne 0 ] || return 77
    msg=$(lb create web 10.0.0.2 --userns 2>&1) && { echo "create --userns succeeded"; return 1; }
    echo "$msg"
    [ "$msg" = 'Error: lightbox create --userns must be run as root' ] && [ ! -e "$C/web" ] || return 1
    lb create web 10.0.0.2 >/dev/null 2>&1 || return 1
    printf 'userns=1\nuid_start=2147483647\ngid_start=2147549183\n' >> "$C/web/.conf"
    report=$(lb inspect web) || { echo "inspect failed"; return 1; }
    printf '%s\n' "$report" | grep -E '^(userns|uid_start|gid_start): '
    [ "$(printf '%s\n' "$report" | grep -E '^(userns|uid_start|gid_start): ' | paste -sd'|')" = \
      'userns: 1|uid_start: 2147483647|gid_start: 2147549183' ] || return 1
    lb inspect web --json | python3 -c '
import json, sys
c = json.load(sys.stdin)[0]
assert c["userns"] is True and c["uid_start"] == 2147483647 and c["gid_start"] == 2147549183, c
' || return 1
    said=$(lb doctor 2>&1 | grep '^userns_ranges: ')
    echo "$said"
    case $said in 'userns_ranges: '[0-9]*' ('*|'userns_ranges: unreadable ('*) ;; *) return 1 ;; esac
}

# base ls, add and rm, as an ordinary user can have them: a snapshot of a
# base is taken and listed with its source; one that a container's .conf
# names is not removed, and one that none names is.
t_base_snapshots() {
    lb create web 10.0.0.2 || return 1
    listing=$(lb base ls) || return 1
    # web is a copy, as this user can mount no overlay, and took no snapshot
    [ "$listing" = 'ID            TAKEN (UTC)          SOURCE  CONTAINERS' ] || { printf '%s\n' "$listing"; return 1; }
    said=$(lb base add "$BASE") || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    id=$(printf '%s\n' "$said" | sed -n 's/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p')
    [ -n "$id" ] && [ -f "$W/data/bases/$id/rootfs/bin/placeholder" ] || { echo "no snapshot of the base"; return 1; }
    lb base ls | grep -E "^$id  [0-9-]{10} [0-9:]{8}  $BASE  -$" || { lb base ls; echo "base ls does not show it"; return 1; }
    # a container on it, as its .conf says
    echo "base=$id" >> "$C/web/.conf"
    lb base ls | grep -E "^$id .* web$" || { lb base ls; return 1; }
    said=$(lb base rm "$id" 2>&1) && { echo "a snapshot that a container names was removed"; return 1; }
    [ "$said" = "Error: base $id is used by: web" ] || { echo "$said"; return 1; }
    sed -i '$d' "$C/web/.conf"
    lb base rm "$id" && [ ! -e "$W/data/bases/$id" ] || { echo "an unused snapshot was not removed"; return 1; }
    bad=0
    for words in "base rm not-an-id" "base rm 000000000000" "base add $W/nothing" "base" "base list" "base ls x"; do
        # shellcheck disable=SC2086
        lb $words >/dev/null 2>&1 && { echo "lightbox $words succeeded"; bad=1; }
    done
    return $bad
}

# A start_timeout or stop_timeout that cannot be read is said so, and stops
# no command.
t_start_timeout_setting() {
    lb create web 10.0.0.2 || return 1
    printf 'start_timeout = soon\nstop_timeout = 1m\n' >> "$CONF"
    out=$(lb ls 2>"$W/err")
    rc=$?
    cat "$W/err"
    [ $rc -eq 0 ] && grep -q 'start_timeout.*soon; using 30' "$W/err" && grep -q 'stop_timeout.*1m; using 10' "$W/err" || return 1
    printf '%s\n' "$out" | grep -q '^web ' || return 1
    # ones that can be read are not mentioned
    sed -i -e 's/^start_timeout = soon$/start_timeout = 5/' -e 's/^stop_timeout = 1m$/stop_timeout = 60/' "$CONF"
    err=$(lb ls 2>&1 >/dev/null)
    [ -z "$err" ] || { echo "with settings that can be read: $err"; return 1; }
}

# stop reads its options before it looks at the container.
t_stop_options_are_checked() {
    lb create web 10.0.0.2 || return 1
    before=$(kept_sum)
    said() { msg=$(lb stop web "$@" 2>&1) && { echo "stop web $* succeeded"; return 1; }; echo "stop web $*: $msg"; }
    said -t soon   && case $msg in *soon*) ;; *) return 1 ;; esac || return 1
    said -t        && case $msg in *'number of seconds'*) ;; *) return 1 ;; esac || return 1
    said --bogus   && case $msg in *'unknown option'*--bogus*) ;; *) return 1 ;; esac || return 1
    # a second word is a second name, and is checked as one before anything else
    said 'an@other' && case $msg in *'container name must only contain'*) ;; *) return 1 ;; esac || return 1
    # with options that are fine it goes on: to who runs it, and as root to the container, which is not running
    said -t 3      && case $msg in *'must be run as root'*|*'not running'*) ;; *) return 1 ;; esac || return 1
    [ "$before" = "$(kept_sum)" ] || { echo "the container's records changed"; return 1; }
}

# logs prints the container's log, and nothing for a container that has none.
t_logs_prints_the_log() {
    lb create web 10.0.0.2 || return 1
    out=$(lb logs web) || { echo "logs failed for a container that was never started"; return 1; }
    [ -z "$out" ] || { echo "a container without a log printed: $out"; return 1; }
    printf 'one\ntwo\n' > "$C/web/console.log"
    [ "$(lb logs web)" = "one
two" ] || return 1
    # a container that is not running has nothing to follow
    followed=$(HOME="$W/home" LIGHTBOX_CONFIG="$CONF" timeout 5 "$LB" logs web -f) || { echo "logs -f of a stopped container did not end by itself"; return 1; }
    [ "$followed" = "one
two" ] || return 1
    refused lb logs missing || return 1
    msg=$(lb logs web --bogus 2>&1) && return 1
    case $msg in *'unknown option'*--bogus*) ;; *) return 1 ;; esac
    # the log is never followed through a link
    ln -sf "$CONF" "$C/web/console.log"
    refused lb logs web
}

# logs -f goes on while the container runs and ends when it has ended, with
# what was written last. An ordinary user's own process stands in for init:
# to such a user it reads as running, since PID 1 is not theirs to look at.
t_logs_follows() {
    [ "$(id -u)" -ne 0 ] || return 77
    lb create web 10.0.0.2 || return 1
    sleep 30 &
    holder=$!
    record web "$holder" "$(awk '{ printf "%s", $22 }' "/proc/$holder/stat")" running
    lb inspect web | grep -qx 'running: yes' || { echo "the stand-in does not read as running"; kill "$holder"; return 77; }
    printf 'first\n' > "$C/web/console.log"
    lb logs web -f > "$W/followed" 2>&1 &
    follower=$!
    sleep 0.5
    printf 'second\n' >> "$C/web/console.log"
    sleep 0.5
    kill -0 "$follower" 2>/dev/null || { echo "logs -f ended while the container was running:"; cat "$W/followed"; kill "$holder"; return 1; }
    printf 'last\n' >> "$C/web/console.log"
    kill "$holder"
    wait "$holder" 2>/dev/null
    i=0
    while kill -0 "$follower" 2>/dev/null && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
    if kill -0 "$follower" 2>/dev/null; then
        echo "logs -f did not end with the container"
        kill "$follower"
        return 1
    fi
    cat "$W/followed"
    [ "$(cat "$W/followed")" = "first
second
last" ]
}

# A command that is run with its standard streams closed must not take a file
# of its own for one of them: its messages would be written into the file.
t_closed_streams_are_harmless() {
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" "$LB" create web 10.0.0.2 <&- >&- 2>&- || { echo "create failed with status $?"; return 1; }
    echo "$(lb inspect web | grep '^state: '), ip: $(cat "$C/web/.ip")"
    lb inspect web | grep -qx 'state: stopped' && [ ! -e "$C/web/.creating" ] &&
    [ "$(cat "$C/web/.ip")" = 10.0.0.2 ] && conf_has web 'mem=256M' || return 1
    ! grep -rl "Creating container" "$C/web" "$W/home" 2>/dev/null | grep -q . || { echo "a message was written into a file"; return 1; }
    lb ls | grep -q '^web '
}

# What create puts into a new container's etc: where it asks for names, what
# it is called, and its own name beside its address.
t_create_writes_names() {
    lb create web 10.0.0.2 --dns 9.9.9.9 --dns 149.112.112.112 || return 1
    etc=$C/web/rootfs/etc
    echo "resolv.conf: $(paste -sd'|' "$etc/resolv.conf"); hostname: $(cat "$etc/hostname"); hosts: $(paste -sd'|' "$etc/hosts")"
    [ "$(cat "$etc/resolv.conf")" = "nameserver 9.9.9.9
nameserver 149.112.112.112" ] && [ "$(cat "$etc/hostname")" = web ] &&
    [ "$(cat "$etc/hosts")" = "$(printf '127.0.0.1\tlocalhost\n10.0.0.2\tweb')" ] &&
    [ "$(mode_of "$etc/resolv.conf")" = 644 ] || return 1

    # a hosts file that the image has is kept, and added to
    printf '10.9.9.9 elsewhere' > "$BASE/etc/hosts"
    lb create db 10.0.0.3 || return 1
    [ "$(cat "$C/db/rootfs/etc/hosts")" = "$(printf '10.9.9.9 elsewhere\n10.0.0.3\tdb')" ] || { cat "$C/db/rootfs/etc/hosts"; return 1; }
    # without --dns and without a setting: something a container can ask, whatever this host asks
    echo "by default: $(paste -sd'|' "$C/db/rootfs/etc/resolv.conf")"
    grep -q '^nameserver ' "$C/db/rootfs/etc/resolv.conf" && ! grep -qv '^nameserver [0-9.]*$' "$C/db/rootfs/etc/resolv.conf" &&
    ! grep -q '^nameserver 127\.' "$C/db/rootfs/etc/resolv.conf" || return 1

    # the dns setting, and --dns before it
    printf 'dns = 9.9.9.10, 149.112.112.10\n' >> "$CONF"
    lb create a 10.0.0.4 && lb create b 10.0.0.5 --dns 9.9.9.9 || return 1
    [ "$(paste -sd' ' "$C/a/rootfs/etc/resolv.conf")" = "nameserver 9.9.9.10 nameserver 149.112.112.10" ] &&
    [ "$(cat "$C/b/rootfs/etc/resolv.conf")" = "nameserver 9.9.9.9" ] || return 1

    refused lb create c 10.0.0.6 --dns 127.0.0.53 && refused lb create c 10.0.0.6 --dns ::1 &&
    refused lb create c 10.0.0.6 --dns nine &&
    refused lb create c 10.0.0.6 --dns 1.1.1.1 --dns 2.2.2.2 --dns 3.3.3.3 --dns 4.4.4.4 || return 1
    sed -i 's/^dns = .*/dns = nonsense/' "$CONF"
    refused lb create d 10.0.0.7 || return 1
    [ ! -e "$C/c" ] && [ ! -e "$C/d" ]
}

# An image shapes its own etc: a link, in one of the ways images have them.
# Whatever it is, what create writes is written where the container will see
# it, in the copy of the image, and a link that leads nowhere there fails.
t_create_writes_stay_in_the_rootfs() {
    rm -rf "${BASE:?}/etc"
    mkdir -p "$BASE/usr/etc"
    ln -s usr/etc "$BASE/etc"
    lb create rel 10.0.0.2 --dns 9.9.9.9 || return 1
    [ -L "$C/rel/rootfs/etc" ] && [ "$(cat "$C/rel/rootfs/usr/etc/resolv.conf")" = "nameserver 9.9.9.9" ] || { echo "etc -> usr/etc was not followed inside the image"; return 1; }

    rm "$BASE/etc"
    ln -s /usr/etc "$BASE/etc"
    lb create abs 10.0.0.3 --dns 9.9.9.9 || return 1
    [ -L "$C/abs/rootfs/etc" ] && [ "$(cat "$C/abs/rootfs/usr/etc/hostname")" = abs ] || { echo "etc -> /usr/etc was not followed inside the image"; return 1; }

    # resolv.conf as a link, the way an image set up for a local resolver has it: the file takes its place
    rm "$BASE/etc"
    mkdir "$BASE/etc"
    ln -s ../run/stub-resolv.conf "$BASE/etc/resolv.conf"
    lb create stub 10.0.0.4 --dns 9.9.9.9 || return 1
    [ ! -L "$C/stub/rootfs/etc/resolv.conf" ] && [ "$(cat "$C/stub/rootfs/etc/resolv.conf")" = "nameserver 9.9.9.9" ] &&
    [ ! -e "$C/stub/rootfs/run/stub-resolv.conf" ] || { echo "resolv.conf was written through the link"; return 1; }

    # an image without an etc gets one
    rm -rf "${BASE:?}/etc"
    lb create bare 10.0.0.6 --dns 9.9.9.9 || return 1
    [ -d "$C/bare/rootfs/etc" ] && [ ! -L "$C/bare/rootfs/etc" ] && [ "$(cat "$C/bare/rootfs/etc/hostname")" = bare ] || { echo "an image without etc did not get one"; return 1; }

    # a link that names a directory the host has and the image does not: nothing is written, anywhere
    mkdir "$W/named-on-the-host"
    rm -rf "${BASE:?}/etc"
    ln -s "$W/named-on-the-host" "$BASE/etc"
    msg=$(lb create out 10.0.0.5 --dns 9.9.9.9 2>&1) && { echo "create succeeded: $msg"; return 1; }
    printf '%s\n' "$msg"
    [ -z "$(ls -A "$W/named-on-the-host")" ] || { echo "something was written on the host: $(ls -A "$W/named-on-the-host")"; return 1; }
    [ ! -e "$C/out" ]
}

t_storage_is_private() {
    lb create web 10.0.0.2 || return 1
    echo "modes: dir $(mode_of "$C/web"), .conf $(mode_of "$C/web/.conf"), .ip $(mode_of "$C/web/.ip")"
    [ "$(mode_of "$C/web")" = 700 ] && [ "$(mode_of "$C/web/.conf")" = 600 ] &&
    [ "$(mode_of "$C/web/.ip")" = 600 ] &&
    lb add-vol web "$W/vol:/more" >/dev/null && [ "$(mode_of "$C/web/.conf")" = 600 ] &&
    [ "$(mode_of "$C/web/rootfs/etc/resolv.conf")" = 644 ]   # the container's own file
}

# setup restricts storage directories that an older installation left open. As
# an ordinary user setup still fails later, at the bridge, which is expected.

# ─── The list ───────────────────────────────────────────────────────────────

check 'create stores the options it was given'              t_create_stores_options
check 'create copies the base rootfs'                       t_create_copies_base
check 'create refuses a name that exists'                   t_create_refuses_existing_name
check 'create refuses malformed names'                      t_create_refuses_bad_names
check 'a name has 30 characters, and on the host twelve hex digits' t_long_names
check 'create refuses malformed and out-of-subnet addresses' t_create_refuses_bad_addresses
check 'volume specifications are validated'                 t_volume_spec_rules
check 'an unknown option is refused'                        t_unknown_option_refused
check 'ls lists containers'                                 t_ls_lists_containers
check 'ls --json prints JSON'                               t_ls_json_is_json
check 'inspect prints name, address and state'              t_inspect_basics
check 'commands fail for a container that does not exist'   t_missing_container_is_an_error
check 'add-vol appends a volume'                            t_addvol_appends
check 'rm removes the container directory'                  t_rm_removes
check 'stop and exec refuse a stopped container'            t_stopped_container_cannot_stop_or_exec
check "exec's own failures are 125, and other commands' 1"  t_exec_failures_are_125
check 'an unknown command prints usage and fails'           t_unknown_command_prints_usage
check 'ls writes nothing'                                   t_ls_writes_nothing
check 'a PID record is a number and nothing else'           t_pid_record_is_a_number
check 'runtime records are in run_dir, and none means stopped' t_runtime_records_are_apart
check 'records an older lightbox left in the container are read' t_records_from_before_are_read
check 'a half-made container says that it is one'           t_half_made_container
check 'a create that is killed leaves a container start refuses' t_create_killed_half_way
check 'rm clears away a container that ended without a stop' t_rm_of_a_dead_container
check 'inspect writes nothing'                              t_inspect_writes_nothing
check 'a process owned by another user is not gone'         t_other_users_process_is_not_gone
check 'a dead container is shown as exited'                 t_dead_container_shown_as_exited
check 'setup, start, stop, exec and reset ask for root first' t_root_is_asked_for_first
check 'eight add-vol at once all take effect'               t_commands_take_turns
check 'a command waits for a lock and says so; ls does not' t_lock_is_waited_for
check 'start checks its options before it does anything'    t_start_options_are_checked
check 'a timeout setting that cannot be read is a warning'  t_start_timeout_setting
check 'stop checks its options before it does anything'     t_stop_options_are_checked
check 'logs prints the log, and nothing where there is none' t_logs_prints_the_log
check 'logs -f follows a running container and ends with it' t_logs_follows
check 'a command with its standard streams closed is harmless' t_closed_streams_are_harmless
check 'create writes name servers, hostname and hosts'      t_create_writes_names
check 'what create writes stays in the new root filesystem' t_create_writes_stay_in_the_rootfs
check 'container storage is private to root'                t_storage_is_private
check 'create keeps every volume or refuses'                t_create_keeps_every_volume
check 'add-vol stores whole lines and fails honestly'       t_addvol_fails_honestly
check 'add-vol respects the volume limit'                   t_addvol_respects_the_volume_limit
check 'the largest legal config is stored and read back'    t_largest_config_round_trips
check 'a symlinked base is copied, not linked'              t_symlinked_base_is_copied
check 'create leaves the base rootfs alone'                 t_create_leaves_the_base_alone
check 'an empty base is refused by name'                    t_empty_base_refused
check 'a missing or non-directory base is refused'          t_unusable_base_refused
check '--pids takes a count or max, and says so'            t_pids_must_be_a_count
check '--cpu takes CPUs or parts of one, and says so'       t_cpu_must_be_cpus
check '--mem takes a size or max, and says so'              t_mem_must_be_a_size
check '--oom-score takes a number in its range'             t_oom_score_must_be_a_number
check 'a number with trailing text is refused'              t_number_with_trailing_text_refused
check 'limits are stored as they were given'                t_limits_are_stored_as_given
check 'an option without its value is named'                t_missing_value_is_named
check 'no value adds a line to the configuration'           t_no_value_adds_a_line
check 'one volume at a destination, from create and add-vol' t_one_volume_at_a_destination
check 'rm-vol removes the volume at a destination'          t_rmvol_removes_a_volume
check 'a .conf has a version, and a strange one is not used' t_conf_has_a_version
check 'a .conf from before the version line is read'        t_conf_from_before_is_read
check 'default_* settings are checked, and said if unusable' t_default_settings_are_checked
check 'a setting or a settings file is never cut to fit'    t_settings_are_not_cut
check 'LIGHTBOX_ROOTFS counts with or without a lightbox.conf' t_rootfs_from_the_environment

check 'a duplicate address is refused, with its holder named' t_duplicate_address_refused
check 'the gateway address is refused'                        t_gateway_address_refused
check 'the network address is refused'                        t_network_address_refused
check 'the broadcast address is refused'                      t_broadcast_address_refused
check 'create without an address takes the lowest free one'   t_create_takes_the_lowest_free_address
check 'a full subnet refuses one more container'              t_full_subnet
check 'a /16 subnet has the addresses of a /16'               t_wide_subnet
check 'subnet and gw that are no network are refused'         t_network_settings_are_checked
check 'an address with a zero in front of a number is refused' t_address_with_leading_zeros_refused
check 'two creates at once get two addresses'                 t_creates_at_once_get_two_addresses
check '--swap takes what --mem does and 0, and is none unless given' t_swap_option
check '--seccomp takes allow or deny, allow is the default, and it is stored and shown' t_seccomp_option
check '--net takes nat, outside, none or proxy:<port>, outside is the default, and it is stored and shown' t_net_option
check '--io-max is a line of io.max for a whole disk that is there' t_io_max_option
check 'the firewall settings are Docker'"'"'s, and a wrong one keeps the built-in' t_firewall_settings
check 'firewall_backend and bridge_accept_fwmark: Docker'"'"'s, and a wrong one is not taken' t_firewall_backend_settings
check 'setup takes --teardown and no other argument'                    t_setup_arguments
check 'ls --json stays JSON next to an odd directory name'    t_ls_json_escapes_names
check 'ls --json escapes whatever a record holds'             t_ls_json_escapes_values
check 'ls --json gives pid as null for a stopped container'   t_ls_json_pid_is_null_when_stopped
check 'ls is sorted by name'                                  t_ls_is_sorted
check 'ls lists only directories with a container name'       t_ls_lists_only_containers
check 'inspect shows volumes, links and the log'                       t_inspect_shows_volumes_and_links
check 'inspect --json is one JSON object, typed, or nothing'             t_inspect_json
check 'configuration: carriage returns are stripped'                   t_config_strips_carriage_returns
check 'configuration: inline comments are stripped'                    t_config_strips_inline_comments
check 'configuration: unknown keys and lines that are no setting are said, with the line' t_config_reports_unknown_keys
check 'configuration: --config, LIGHTBOX_CONFIG, /etc, then HOME with a warning' t_config_lookup_order
check 'make install writes under DESTDIR only, and keeps a configuration' t_make_install_stays_in_destdir
check 'help goes to standard output with status 0, and --version names the release' t_help_exits_zero
check 'rm takes several names, and names those it did not remove'      t_rm_handles_every_argument
check 'a surplus argument is an error that names it'                    t_surplus_arguments_are_errors
check 'doctor says how to fix each thing it finds missing'              t_doctor_says_how_to_fix
check 'doctor --json: settings and checks, typed'                       t_doctor_json
check 'update, restart, rm -f and reset check their options before anything'  t_update_restart_rm_options
check 'update writes the limits into a stopped container'"'"'s .conf'       t_update_rewrites_the_conf
check 'create --userns is root'"'"'s, and inspect and doctor show the ranges' t_userns_as_a_user_sees_it
check 'base add, ls and rm manage the snapshots of bases'              t_base_snapshots
check 'start without root is a clean error'                   t_start_without_root_is_a_clean_error

summary validation
