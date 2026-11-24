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

# skopeo with nothing of the caller's environment but PATH: what it keeps and
# what it looks for, a registry's password among it, is under the case's own
# directory, whatever HOME and XDG_CONFIG_HOME say where the suite runs.
skopeo_here() {
    mkdir -p "$W/home/run" &&
        env -i PATH="$PATH" HOME="$W/home" XDG_RUNTIME_DIR="$W/home/run" XDG_CONFIG_HOME="$W/home/.config" skopeo "$@"
}

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

# run (ROADMAP 8.8) tells create's options and exec's from its command: each
# option that create --help names, and exec's, gets past it to the question
# of root, with a value where it takes one. Unknown options, missing values
# and exec's options that are not right are refused first, with 125, and as
# an ordinary user nothing is made.
t_run_options() {
    [ "$(id -u)" -ne 0 ] || return 77
    local bad=0 opt kind msg rc count=0 before
    before=$(kept_sum)
    root='Error: lightbox run must be run as root'
    while read -r opt kind; do
        count=$((count + 1))
        if [ "$kind" = value ]; then
            msg=$(lb run "$opt" x -- /bin/true 2>&1)
        else
            msg=$(lb run "$opt" -- /bin/true 2>&1)
        fi
        rc=$?
        [ "$msg" = "$root" ] && [ $rc -eq 125 ] || { echo "run $opt: $rc, $msg"; bad=1; }
    done <<EOF
$(lb create --help | awk '$1 ~ /^--/ { print $1, (($2 ~ /^</ || $2 ~ /\|/) ? "value" : "flag") }')
EOF
    echo "create's options that run takes: $count"
    [ "$count" -ge 17 ] || { echo "create --help names fewer than 17"; bad=1; }
    msg=$(lb run --user nobody -u 0 --env A=b -e B=c --workdir / -w /tmp --timeout 1s -- /bin/true 2>&1)
    [ "$msg" = "$root" ] || { echo "exec's options: $msg"; bad=1; }
    msg=$(lb run --mem 64M --ttl 2s --net none --userns /bin/echo hi 2>&1)
    [ "$msg" = "$root" ] || { echo "a command without --: $msg"; bad=1; }
    expect_125() { # message, words...
        local want=$1
        shift
        msg=$(lb "$@" 2>&1)
        rc=$?
        [ "$msg" = "$want" ] && [ $rc -eq 125 ] || { echo "lightbox $*: $rc, $msg"; bad=1; }
    }
    expect_125 'Error: unknown option: --bogus
A command that begins with a dash goes after --.' run --bogus /bin/true
    expect_125 'Error: option --mem requires a value' run --mem
    expect_125 'Error: option --timeout requires a value' run --timeout
    expect_125 'Error: --timeout takes a duration above 0 and up to 365d, such as 30s, 5m or 1.5h: 0' run --timeout 0 -- /bin/true
    expect_125 'Error: --workdir takes an absolute path: tmp' run --workdir tmp -- /bin/true
    expect_125 'Error: --env takes KEY=VALUE: A' run --env A -- /bin/true
    [ "$before" = "$(kept_sum)" ] || { echo "run as an ordinary user changed what lightbox keeps"; bad=1; }
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
# --ttl (ROADMAP 8.8): a duration, stored as it was given and shown by
# inspect; none without it. What is not a duration is refused, and leaves no
# container.
t_ttl_option() {
    local msg value
    lb create a --ttl 1.5h && lb create b || return 1
    conf_has a 'ttl=1.5h' && ! grep -q '^ttl=' "$C/b/.conf" || { echo "the ttl is not stored as given"; return 1; }
    lb inspect a | grep -qx 'ttl: 1.5h' && lb inspect b | grep -qx 'ttl: -' || { echo "inspect does not show it"; return 1; }
    command -v python3 >/dev/null 2>&1 && {
        lb inspect a --json | python3 -I -c 'import json, sys; assert json.load(sys.stdin)[0]["ttl"] == "1.5h"' &&
        lb inspect b --json | python3 -I -c 'import json, sys; assert json.load(sys.stdin)[0]["ttl"] is None' ||
            { echo "inspect --json does not say it"; return 1; }
    }
    for value in 0 0s 1ms 366d 2x -1 '' '2 s'; do
        msg=$(lb create e --ttl "$value" 2>&1) && { echo "--ttl '$value' was taken"; return 1; }
        [ "$msg" = "Error: --ttl takes a duration above 0 and up to 365d, such as 30m or 8h: $value" ] ||
            { echo "--ttl '$value': $msg"; return 1; }
        [ ! -e "$C/e" ] || { echo "--ttl '$value' left a container"; return 1; }
    done
    msg=$(lb create e --ttl 2>&1) && return 1
    echo "--ttl without a value: $msg"
    [ ! -e "$C/e" ]
}

# create draws an id for each box (ROADMAP 8.9), which .conf keeps as id= and
# inspect shows, and by which the audit log tells a box from a later one of
# its name. inspect names the audit log too.
t_box_id() {
    local one two again
    lb create a && lb create b || return 1
    one=$(sed -n 's/^id=//p' "$C/a/.conf")
    two=$(sed -n 's/^id=//p' "$C/b/.conf")
    echo "the ids of a and b: $one $two"
    printf '%s\n%s\n' "$one" "$two" | grep -Ecx '[0-9a-f]{16}' | grep -qx 2 && [ "$one" != "$two" ] ||
        { echo "not two ids of 16 hex digits"; return 1; }
    lb inspect a | grep -qx "id: $one" && lb inspect a | grep -qx "audit_path: $W/data/audit.log" ||
        { echo "inspect does not show the id and the audit log"; return 1; }
    command -v python3 >/dev/null 2>&1 && {
        lb inspect a --json | python3 -I -c 'import json, sys; c = json.load(sys.stdin)[0]; assert c["id"] == sys.argv[1] and c["audit_path"].endswith("/data/audit.log")' "$one" ||
            { echo "inspect --json does not say them"; return 1; }
    }
    lb rm a && lb create a || return 1
    again=$(sed -n 's/^id=//p' "$C/a/.conf")
    echo "a made again: $again"
    [ -n "$again" ] && [ "$again" != "$one" ]
}

# create --profile agent (ROADMAP 8.10) refuses what would undo it, each by
# its name and whichever comes first, and takes what tightens it, as far as
# asking for root, which it needs for its user namespace; nothing is made
# before that. Its agent_* settings are checked as the default_* ones are,
# and refused where a box would have needed one. What it stores is the
# lifecycle suite's to see, as root.
t_profile_option() {
    [ "$(id -u)" -ne 0 ] || return 77
    local before msg opt setting key root='Error: lightbox create --profile agent must be run as root'
    before=$(kept_sum)
    for opt in '--privileged:--privileged' '--link db:--link' '--net nat:--net nat' \
               '--seccomp deny:--seccomp deny' '--copy:--copy: its root is an overlay of its base'; do
        # shellcheck disable=SC2086     # the option and its value
        msg=$(lb create a --profile agent ${opt%%:*} 2>&1) && { echo "--profile agent took ${opt%%:*}"; return 1; }
        [ "$msg" = "Error: --profile agent refuses ${opt#*:}" ] || { echo "${opt%%:*}: $msg"; return 1; }
        # shellcheck disable=SC2086
        msg=$(lb create a ${opt%%:*} --profile agent 2>&1) && return 1
        [ "$msg" = "Error: --profile agent refuses ${opt#*:}" ] || { echo "${opt%%:*} first: $msg"; return 1; }
    done
    echo "refused, each by its name: --privileged, --link, --net nat, --seccomp deny, --copy"
    for opt in '' --read-only '--net none' '--net outside' '--net proxy:3128' '--seccomp allow' --userns \
               '--mem 512M --pids 64 --cpu 1 --ttl 1h' "--workspace $W/vol"; do
        # shellcheck disable=SC2086
        msg=$(lb create a --profile agent $opt 2>&1) && { echo "--profile agent $opt made a box"; return 1; }
        [ "$msg" = "$root" ] || { echo "--profile agent $opt: $msg"; return 1; }
    done
    msg=$(lb create a --profile other 2>&1) && return 1
    [ "$msg" = 'Error: --profile takes agent, not: other' ] || { echo "--profile other: $msg"; return 1; }
    msg=$(lb create a --profile 2>&1) && return 1
    [ "$msg" = 'Error: option --profile requires a value' ] || { echo "--profile without a value: $msg"; return 1; }
    for setting in 'agent_mem = 1Gb' 'agent_pids = lots' 'agent_cpu = 1024' 'agent_ttl = 0'; do
        printf '%s\n' "$setting" >> "$CONF"
        key=${setting%% *}
        lb ls 2>&1 >/dev/null | grep -q "^Warning: $key in lightbox.conf is not " || { echo "no warning for $setting"; return 1; }
        msg=$(lb create a --profile agent 2>&1) && return 1
        case $msg in *"Error: $key: "*) ;; *) echo "the refusal does not name $key: $msg"; return 1 ;; esac
        # given every limit and the lifetime, the box needs none of them
        msg=$(lb create a --profile agent --mem 64M --pids 5 --cpu 1 --ttl 1h 2>&1 | tail -n 1)
        [ "$msg" = "$root" ] || { echo "with all four given and $setting: $msg"; return 1; }
        sed -i '$d' "$CONF"
    done
    printf 'agent_ttl = none\n' >> "$CONF"
    msg=$(lb ls 2>&1 >/dev/null)
    sed -i '$d' "$CONF"
    [ -z "$msg" ] || { echo "agent_ttl = none: $msg"; return 1; }
    echo "agent_mem, agent_pids, agent_cpu and agent_ttl: said when wrong, and refused where needed"
    [ "$before" = "$(kept_sum)" ] || { echo "what lightbox keeps changed"; return 1; }
}

# --workspace <dir> (ROADMAP 8.10) is a volume at /workspace, where every
# exec runs: .conf has the volume and workdir=, and inspect shows it. A
# directory that is not there, a relative path, one with a colon, a second
# --workspace and a --vol at /workspace are refused, and nothing is made.
t_workspace_option() {
    local msg want
    mkdir -p "$W/vol/ws" "$W/vol/a:b"
    lb create w --workspace "$W/vol/ws" && lb create plain || return 1
    conf_has w "vol=$W/vol/ws:/workspace" && conf_has w 'workdir=/workspace' || { cat "$C/w/.conf"; return 1; }
    ! grep -q '^workdir=\|^profile=' "$C/w/.conf" "$C/plain/.conf" | grep -v 'w/.conf:workdir=' ||
        { echo "a profile, or a workdir where there is no workspace"; return 1; }
    lb inspect w | grep -qx 'workdir: /workspace' && lb inspect w | grep -qx 'profile: -' &&
        lb inspect plain | grep -qx 'workdir: -' || { echo "inspect does not show them"; return 1; }
    command -v python3 >/dev/null 2>&1 && {
        lb inspect w --json | python3 -I -c 'import json, sys; c = json.load(sys.stdin)[0]; assert c["workdir"] == "/workspace" and c["profile"] is None' ||
            { echo "inspect --json does not say them"; return 1; }
    }
    for want in "$W/vol/none:Error: --workspace takes a directory that is there: $W/vol/none" \
                "ws:Error: --workspace takes an absolute path: ws"; do
        msg=$(lb create x --workspace "${want%%:*}" 2>&1) && return 1
        [ "$msg" = "${want#*:}" ] || { echo "--workspace ${want%%:*}: $msg"; return 1; }
    done
    msg=$(lb create x --workspace "$W/vol/a:b" 2>&1) && return 1
    [ "$msg" = "Error: --workspace takes a directory whose path has no ':', as a volume's has none: $W/vol/a:b" ] ||
        { echo "a path with a colon: $msg"; return 1; }
    msg=$(lb create x --workspace "$W/vol/ws" --workspace "$W/vol/ws" 2>&1) && return 1
    [ "$msg" = 'Error: --workspace is given once: a box has one workspace' ] || { echo "two: $msg"; return 1; }
    msg=$(lb create x --vol "$W/vol/ws:/workspace" --workspace "$W/vol/ws" 2>&1) && return 1
    [ "$msg" = "Error: --workspace: $W/vol/ws: there is already a volume at that destination" ] ||
        { echo "with a --vol at /workspace: $msg"; return 1; }
    [ ! -e "$C/x" ] || { echo "a refused box is there"; return 1; }
}

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
    wait "$holder" 2>/dev/null      # gone, and not only told to go: ls looked before it was, once, on 2026-11-23
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

# create --device (ROADMAP G.1), as an ordinary user, with nodes every Linux
# has: a character device of the host's goes in .conf as host:path[:ro], at
# its own path under /dev or the one given, and inspect shows it in text and
# in JSON. Refused, each with its reason and before anything is made: a block
# device, the host's memory and log and the other devices that give the host
# away, anything that is no character device or not there, a path in the
# container outside /dev or one every container has, a spec of the wrong
# shape, a seventeenth device; and to a box of --profile agent anything that
# is no GPU's compute node. A device line of .conf that cannot be read is an
# error of the configuration.
t_create_device() {
    local bad=0 said json before blk
    no() { # what it says, create's options
        local want=$1
        shift
        said=$(lb create dev 10.0.0.4 "$@" 2>&1) && { echo "create --device $*: succeeded"; lb rm dev >/dev/null 2>&1; bad=1; return; }
        case $said in *"$want"*) ;; *) echo "create $*: $said"; bad=1 ;; esac
        [ ! -e "$C/dev" ] || { echo "create $*: the container is there"; bad=1; }
    }
    # one at its own path, read alone, as host:ro: a node most hosts have that no container has already
    local own="" d
    for d in /dev/fuse /dev/net/tun /dev/loop-control; do [ -c "$d" ] && { own=$d; break; }; done
    [ -n "$own" ] || echo "none of /dev/fuse, /dev/net/tun and /dev/loop-control here: host:ro at its own path is not tried"
    lb create web 10.0.0.2 --device /dev/null:/dev/gpu/null --device /dev/zero:/dev/zero2:ro ${own:+--device "$own:ro"} \
        >/dev/null || return 1
    want='device=/dev/null:/dev/gpu/null
device=/dev/zero:/dev/zero2:ro'
    [ -n "$own" ] && want="$want
device=$own:$own:ro"
    [ "$(grep '^device=' "$C/web/.conf")" = "$want" ] || { grep '^device=' "$C/web/.conf"; echo "the .conf does not have them"; return 1; }
    said=$(lb inspect web | grep '^device: ')
    [ "$said" = "$(printf '%s\n' "$want" | sed 's/^device=/device: /')" ] || { echo "$said"; echo "inspect does not show them"; return 1; }
    if command -v python3 >/dev/null 2>&1; then
        lb inspect web --json | python3 -I -c '
import json, sys
d = json.load(sys.stdin)[0]["devices"]
want = [{"host": "/dev/null", "path": "/dev/gpu/null", "ro": False}, {"host": "/dev/zero", "path": "/dev/zero2", "ro": True}]
if sys.argv[1]:
    want.append({"host": sys.argv[1], "path": sys.argv[1], "ro": True})
assert d == want, d
' "$own" || { echo "inspect --json does not have them"; return 1; }
    fi
    lb create db 10.0.0.3 >/dev/null && [ "$(lb inspect db | grep '^device')" = 'device: -' ] ||
        { echo "a container without devices is not shown so"; return 1; }
    [ "$(lb inspect db | grep '^gpu: ')" = 'gpu: 0' ] && ! grep -q '^gpu=' "$C/db/.conf" || { echo "a container without --gpu is said to have it"; return 1; }
    # --gpu: kept as gpu=1, the nodes found at each start and none in .conf (ROADMAP G.3)
    lb create gpu 10.0.0.5 --gpu >/dev/null || return 1
    grep -qx 'gpu=1' "$C/gpu/.conf" && ! grep -q '^device=' "$C/gpu/.conf" && [ "$(lb inspect gpu | grep '^gpu: ')" = 'gpu: 1' ] ||
        { grep -E '^(gpu|device)' "$C/gpu/.conf"; echo "--gpu is not kept as gpu=1 alone"; return 1; }
    if command -v python3 >/dev/null 2>&1; then
        lb inspect gpu --json | python3 -I -c 'import json, sys; d = json.load(sys.stdin)[0]; assert d["gpu"] is True and d["devices"] == [], d' ||
            { echo "inspect --json does not say gpu"; return 1; }
    fi
    before=$(ls "$C")
    blk=$(find /dev -maxdepth 2 -type b 2>/dev/null | head -n 1)
    [ -n "$blk" ] && no 'is a block device: no container is given one' --device "$blk:/dev/disk0"
    for refused in '/dev/mem:the host'"'"'s memory' '/dev/kmsg:the kernel'"'"'s log' '/dev/port:the host'"'"'s I/O ports' \
                   '/dev/tty0:a virtual console' '/dev/console:the host'"'"'s console' '/dev/uinput:uinput'; do
        [ -c "${refused%%:*}" ] && no "${refused%%:*} is ${refused#*:}" --device "${refused%%:*}"
    done
    mkfifo "$W/fifo"
    no 'is not a character device' --device "$W/fifo:/dev/fifo"
    no 'is not there' --device /dev/lightbox-no-such-node
    no 'needs its path in the container' --device "$W/fifo"
    no 'is under /dev' --device /dev/null:/etc/null
    no 'is under /dev' --device /dev/null:/dev
    no 'every container has that path of /dev already' --device /dev/null
    no 'every container has that path of /dev already' --device /dev/zero:/dev/pts/7
    no 'every container has that path of /dev already' --device /dev/zero:/dev/shm/x
    no 'only :ro may follow' --device /dev/null:/dev/a:rw
    no 'its paths have no colon in them' --device /dev/null:/dev/a:ro:x
    no 'must be an absolute path without ..' --device dev/null:/dev/a
    no 'must be an absolute path without ..' --device /dev/null:/dev/../etc/a
    no 'there is already a device at that path' --device /dev/null:/dev/a --device /dev/zero:/dev/a
    set -- ; for i in $(seq 1 17); do set -- "$@" --device "/dev/null:/dev/n$i"; done
    no 'the maximum of 16 devices' "$@"
    no 'is not a GPU'"'"'s compute node: a box of --profile agent is given render nodes' --profile agent --device /dev/null:/dev/gpu
    # with --userns, a node it could open (ROADMAP G.2): one that only its owner
    # may is refused, and one that only its group may, of a group other than
    # 0, is taken and ends at the root that --userns needs
    local node
    node=$(find /dev -maxdepth 2 -type c -perm 0600 -user 0 2>/dev/null | head -n 1)
    [ -n "$node" ] && no 'is read and written by its owner alone, whom no container of --userns stands for' \
        --userns --device "$node:/dev/own"
    node=$(find /dev -maxdepth 2 -type c -perm 0660 -group 0 2>/dev/null | head -n 1)
    [ -n "$node" ] && no 'which is root'"'"'s, gid 0, and that a container of --userns never holds' --userns --device "$node:/dev/grp0"
    node=$(find /dev -maxdepth 2 -type c -perm 0660 ! -group 0 2>/dev/null | head -n 1)
    [ -n "$node" ] && no 'create --userns must be run as root' --userns --device "$node:/dev/grp"
    [ "$before" = "$(ls "$C")" ] || { echo "a refused create left something in the store"; bad=1; }
    # what a .conf of the container's says, read back
    echo 'device=/dev/null' >> "$C/web/.conf"
    said=$(lb inspect web 2>&1) && { echo "inspect of a .conf with a device line that cannot be read succeeded"; bad=1; }
    case $said in *"configuration cannot be used"*"every container has that path"*) ;; *) echo "$said"; bad=1 ;; esac
    return $bad
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
# /etc/lightbox/lightbox.conf, and the built-in values where there is none.
# The place in $HOME that lightbox read before 0.6 is not read: a file that
# is there, with nothing named and none in /etc, ends the command, which
# says where the settings are looked for. A file that is named and not there
# is an error. (No case here writes /etc: the lifecycle suite has that.)
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
        for words in doctor ls 'create fromhome 10.0.0.9'; do
            # shellcheck disable=SC2086
            said=$(LIGHTBOX_CONFIG='' HOME="$W/home" "$LB" $words 2>&1) && { echo "lightbox $words went on with a file in HOME alone"; bad=1; }
            [ "$said" = "Error: $CONF is where lightbox looked for its settings before 0.6, and it is
not read. Move it to /etc/lightbox/lightbox.conf, or name it with --config or LIGHTBOX_CONFIG" ] ||
                { echo "lightbox $words, with a file in HOME alone: $said"; bad=1; }
        done
        # with no file there either, the built-in values, and nothing said
        said=$(env -u LIGHTBOX_CONFIG HOME="$W/nohome" "$LB" doctor 2>&1)
        [ "$(printf '%s\n' "$said" | bridge)" = br0 ] || { echo "no file anywhere: bridge $(printf '%s\n' "$said" | bridge)"; bad=1; }
        printf '%s\n' "$said" | grep -E '^(Error|Warning|Note): .*lightbox\.conf' && { echo "no file anywhere, and that was said"; bad=1; }
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
# DESTDIR/etc/lightbox and the manual page with the others of its section,
# and writes nothing in the home of whoever runs it. What it puts there is
# what a package holds, so run_dir, which is on a tmpfs and which setup and
# start make, is not among it. A configuration that is there already is kept.
t_make_install_stays_in_destdir() {
    src=$(dirname "$LB")
    [ -f "$src/Makefile" ] && [ -f "$src/lightbox.conf.example" ] || { echo "no source tree beside $LB"; return 77; }
    mkdir -p "$W/installer"
    inst() { env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS HOME="$W/installer" make -s -C "$src" install DESTDIR="$W/dest" >"$W/install.out" 2>&1; }
    inst || { cat "$W/install.out"; return 1; }
    find "$W/dest" -type f | sed "s#^$W/dest##" | sort
    [ -x "$W/dest/usr/local/bin/lightbox" ] && cmp -s "$W/dest/etc/lightbox/lightbox.conf" "$src/lightbox.conf.example" ||
        { echo "the binary or the configuration is not under DESTDIR"; return 1; }
    cmp -s "$W/dest/usr/local/share/man/man8/lightbox.8" "$src/lightbox.8" || { echo "the manual page is not under DESTDIR"; return 1; }
    [ "$(mode_of "$W/dest/var/lib/lightbox")" = 700 ] && [ "$(mode_of "$W/dest/var/lib/lightbox/containers")" = 700 ] ||
        { echo "lightbox_dir or container_dir is not made for its owner alone"; return 1; }
    [ ! -e "$W/dest/run" ] || { echo "run_dir is made under DESTDIR: $(find "$W/dest/run")"; return 1; }
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

# doctor --profile agent (ROADMAP 8.11): after the checks of every container,
# six of what a box of the profile needs, in text and in --json, each one
# that fails followed by its fix. An ordinary user cannot make an idmapped
# mount, and is told that whether one works is not known. Without the option
# there are none of them, and a value that is not agent, or none, is refused.
t_doctor_profile() {
    [ "$(id -u)" -ne 0 ] || { echo "run as root: what an ordinary user is told is not shown"; return 77; }
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to decode JSON with"; return 77; }
    local report names json rc said
    report=$(lb doctor --profile agent 2>&1) && { printf '%s\n' "$report"; echo "doctor exited 0 for an ordinary user"; return 1; }
    printf '%s\n' "$report" | sed -n '/^agent\./,$p'
    names=$(printf '%s\n' "$report" | sed -n 's/^\(agent\.[a-z_]*\): .*/\1/p' | paste -sd' ')
    [ "$names" = 'agent.kernel agent.userns_ranges agent.overlayfs agent.idmap agent.nft agent.cgroup_kill' ] ||
        { echo "the profile's checks: $names"; return 1; }
    printf '%s\n' "$report" | grep -Eqx 'agent\.kernel: (yes|no) \(.+; the profile needs Linux 5\.19 or later, for an overlay on an idmapped layer\)' ||
        { echo "agent.kernel does not say what it needs"; return 1; }
    [ "$(printf '%s\n' "$report" | grep -A1 '^agent\.idmap: ' | paste -sd'|')" = \
      'agent.idmap: no (not known: only root may make an idmapped mount)|  to fix: sudo lightbox doctor --profile agent' ] ||
        { echo "agent.idmap does not say that only root can tell"; return 1; }
    printf '%s\n' "$report" | grep -Eqx 'agent\.nft: (ok|missing) \(/.+/nft\)' || { echo "agent.nft does not name nft"; return 1; }
    # overlayfs as the host has it (ROADMAP R.4): listed, a module of the
    # running kernel's to load, or none, which a box cannot do without
    local mods want
    mods=/lib/modules/$(uname -r)
    [ -d "$mods" ] || mods=/usr/lib/modules/$(uname -r)
    if grep -q "$(printf '\toverlay$')" /proc/filesystems; then
        want='agent.overlayfs: yes (in /proc/filesystems)'
    elif grep -qs '/overlay\.ko' "$mods/modules.builtin" "$mods/modules.dep"; then
        want="agent.overlayfs: yes (a module of the kernel's, which the first overlay mounted loads)"
    elif [ -e "$mods/modules.builtin" ] || [ -e "$mods/modules.dep" ]; then
        want='agent.overlayfs: no (the kernel has none, built in or as a module: a box is an overlay of its base)'
    else
        want="agent.overlayfs: no (not in /proc/filesystems, and the running kernel's modules are not listed)"
    fi
    printf '%s\n' "$report" | grep -Fqx "$want" ||
        { printf '%s\n' "$report" | grep '^agent\.overlayfs: '; echo "expected: $want"; return 1; }
    printf '%s\n' "$report" | awk '/^agent\./ { on = 1 }
        on && want { if ($0 !~ /^  to fix: ./) { print "no fix after " name; bad = 1 } want = 0; next }
        on && /^agent\.[a-z_]+: (no|missing)( |$)/ { want = 1; name = $1 }
        END { if (want) { print "no fix after " name; bad = 1 } exit bad }' || return 1
    ! lb doctor 2>&1 | grep -q '^agent\.' || { echo "doctor without --profile has the profile's checks"; return 1; }
    json=$(lb doctor --json --profile agent)
    rc=$?
    printf '%s' "$json" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
names = [c["check"] for c in d["checks"] if c["check"].startswith("agent.")]
assert names == ["agent.kernel", "agent.userns_ranges", "agent.overlayfs", "agent.idmap", "agent.nft", "agent.cgroup_kill"], names
for c in d["checks"]:
    assert isinstance(c["ok"], bool) and (c["fix"] is None) == c["ok"], c
    assert c["text"].startswith(("yes", "no", "ok", "missing", "unusable")) or c["check"] == "network", c
assert d["overall"] == "degraded", d["overall"]
' || return 1
    [ "$rc" = 1 ] || { echo "doctor --json --profile agent exited $rc"; return 1; }
    said=$(lb doctor --profile 2>&1) && return 1
    [ "$said" = 'Error: option --profile requires a value' ] || { echo "--profile alone: $said"; return 1; }
    said=$(lb doctor --profile other 2>&1) && return 1
    [ "$said" = 'Error: --profile takes agent, not: other' ] || { echo "--profile other: $said"; return 1; }
}

# device_filter without root (ROADMAP R.4): a kernel without the bpf call is
# named, as anyone may ask it; on one with the call, whether the program
# loads is root's to try, and an ordinary user is told it is not known.
t_doctor_device_filter_as_a_user() {
    [ "$(id -u)" -ne 0 ] || { echo "run as root: what an ordinary user is told is not shown"; return 77; }
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to ask for the bpf call with"; return 77; }
    local want said
    if python3 -I -c '
import ctypes, platform, sys
nr = {"x86_64": 321, "aarch64": 280}[platform.machine()]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(nr, 5, None, 0)
sys.exit(0 if ctypes.get_errno() == 38 else 1)'; then
        want='device_filter: no (the kernel has no bpf system call, which loads the program)|  to fix: boot a kernel with CONFIG_CGROUP_BPF and CONFIG_BPF_SYSCALL; only a --privileged container starts without it'
    else
        want='device_filter: no (not known: only root may load the program)|  to fix: sudo lightbox doctor'
    fi
    said=$(lb doctor 2>&1 | grep -A1 '^device_filter: ' | paste -sd'|')
    printf '%s\n' "$said"
    [ "$said" = "$want" ] || { echo "expected: $want"; return 1; }
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

# What a command that was killed while it took a snapshot left, a .<id>.new
# with a base's files in it, is taken away by the next snapshot and by base
# rm, which say so (ROADMAP F.7). A name that is not such a directory's stays;
# and where there is no store, whose lock every command that takes a
# snapshot holds, nothing is taken away, as one may be being made.
t_base_unfinished() {
    B="$W/data/bases"
    mkdir -p "$B/.0123456789ab.new/rootfs/bin" "$B/.0123456789ab.newer" "$B/.0123456789AB.new" "$B/0123456789ab.new" ||
        return 1
    echo placeholder > "$B/.0123456789ab.new/rootfs/bin/placeholder"
    rmdir "$C" || return 1
    said=$(lb base add "$BASE" 2>&1)
    rc=$?
    mkdir "$C" || return 1
    [ $rc -eq 0 ] || { printf '%s\n' "$said"; return 1; }
    case $said in *Removed*) printf '%s\n' "$said"; echo "cleared without the store's lock"; return 1 ;; esac
    [ -f "$B/.0123456789ab.new/rootfs/bin/placeholder" ] || { echo "taken away without the store's lock"; return 1; }
    said=$(lb base add "$BASE") || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    printf '%s\n' "$said" |
        grep -qx "Removed an unfinished base snapshot, which a command that was killed left: $B/.0123456789ab.new" ||
        return 1
    [ ! -e "$B/.0123456789ab.new" ] || { echo "the unfinished snapshot is still there"; return 1; }
    for other in .0123456789ab.newer .0123456789AB.new 0123456789ab.new; do
        [ -d "$B/$other" ] || { echo "$other was taken away"; return 1; }
    done
    # base rm takes one away too, and removes what it was asked to
    id=$(printf '%s\n' "$said" | sed -n 's/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p')
    [ -n "$id" ] && mkdir "$B/.fedcba987654.new" || return 1
    said=$(lb base rm "$id") || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    printf '%s\n' "$said" |
        grep -qx "Removed an unfinished base snapshot, which a command that was killed left: $B/.fedcba987654.new" &&
        printf '%s\n' "$said" | grep -qx "Base $id removed" && [ ! -e "$B/.fedcba987654.new" ] && [ ! -e "$B/$id" ]
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

# logs --audit prints the lines of the audit log about one box (ROADMAP 8.9),
# and those of a box that is gone; nothing where no exec ran. The log is one
# for the host, and never read through a link.
t_logs_audit() {
    local out msg
    lb create web || return 1
    [ -z "$(lb logs web --audit)" ] && [ -z "$(lb logs --audit gone)" ] || { echo "lines where no exec ran"; return 1; }
    printf '%s\n' '{"box":"web","event":"start"}' '{"box":"web2","event":"start"}' '{"box":"gone","event":"end"}' \
        '{"box":"web","event":"end"}' > "$W/data/audit.log"
    out=$(lb logs --audit web) || return 1
    printf '%s\n' "$out"
    [ "$out" = '{"box":"web","event":"start"}
{"box":"web","event":"end"}' ] || { echo "not the lines of web"; return 1; }
    [ "$(lb logs gone --audit)" = '{"box":"gone","event":"end"}' ] || { echo "not the lines of a box that is gone"; return 1; }
    # a box that does not run has nothing to follow
    out=$(HOME="$W/home" LIGHTBOX_CONFIG="$CONF" timeout 5 "$LB" logs --audit -f web | wc -l) && [ "$out" = 2 ] ||
        { echo "logs --audit -f of a stopped box did not end by itself"; return 1; }
    msg=$(lb logs --audit 2>&1) && return 1
    [ "$msg" = 'Usage: lightbox logs <name> [-f] [--audit]' ] || { echo "without a name: $msg"; return 1; }
    msg=$(lb logs web --audit extra 2>&1) && return 1
    [ "$msg" = 'Error: unexpected argument: extra' ] || { echo "a word too many: $msg"; return 1; }
    refused lb logs --audit 'a@b' 2>/dev/null || return 1
    ln -sf "$CONF" "$W/data/audit.log"
    msg=$(lb logs --audit web 2>&1) && return 1
    echo "through a link: $msg"
    case $msg in "Error: cannot read the audit log $W/data/audit.log (errno "*) ;; *) return 1 ;; esac
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
check "run takes create's options and exec's, and refuses others first" t_run_options
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
check 'logs --audit prints the lines of one box, of one that is gone too, and never through a link' t_logs_audit
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
check '--ttl takes a duration, which is stored as given and shown'  t_ttl_option
check 'create draws an id for each box, which is stored and shown'  t_box_id
check '--profile agent refuses what would undo it by its name, and its agent_* settings are checked' t_profile_option
check '--workspace is a volume at /workspace and the workdir, and what is not a directory is refused' t_workspace_option
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
check 'create --device keeps a character device of the host'"'"'s, and refuses what gives the host away' t_create_device
check 'configuration: carriage returns are stripped'                   t_config_strips_carriage_returns
check 'configuration: inline comments are stripped'                    t_config_strips_inline_comments
check 'configuration: unknown keys and lines that are no setting are said, with the line' t_config_reports_unknown_keys
check 'configuration: --config, LIGHTBOX_CONFIG, then /etc; a file in HOME alone ends the command' t_config_lookup_order
check 'make install writes under DESTDIR only, and keeps a configuration' t_make_install_stays_in_destdir
check 'help goes to standard output with status 0, and --version names the release' t_help_exits_zero
check 'rm takes several names, and names those it did not remove'      t_rm_handles_every_argument
check 'a surplus argument is an error that names it'                    t_surplus_arguments_are_errors
check 'doctor says how to fix each thing it finds missing'              t_doctor_says_how_to_fix
check 'doctor --json: settings and checks, typed'                       t_doctor_json
check 'doctor --profile agent: what the profile needs, and its fixes'   t_doctor_profile
check 'doctor says without root that a kernel has no bpf call, and else that root may tell' t_doctor_device_filter_as_a_user
check 'update, restart, rm -f and reset check their options before anything'  t_update_restart_rm_options
check 'update writes the limits into a stopped container'"'"'s .conf'       t_update_rewrites_the_conf
check 'create --userns is root'"'"'s, and inspect and doctor show the ranges' t_userns_as_a_user_sees_it
check 'base add, ls and rm manage the snapshots of bases'              t_base_snapshots
check 'a snapshot a killed command left is cleared by the next, and by base rm' t_base_unfinished
check 'start without root is a clean error'                   t_start_without_root_is_a_clean_error

# ─── Images (ROADMAP Track I) ───────────────────────────────────────────────

# tests/image_check.py holds an image to what it says of itself, every blob
# to its digest and its size, and prints what is in it.
IMAGE_CHECK=$(cd "$(dirname "$0")" && pwd)/image_check.py
need_python() { command -v python3 >/dev/null 2>&1 || { echo "no python3 to read the image with"; return 77; }; }
annotations_of() { printf '%s\n' "$1" | sed -n 's/^annotation //p' | paste -sd' ' -; }

# export (ROADMAP I.5), as an ordinary user has it, of a container that is a
# copy of its base: the directory is an image whose every blob is what its
# descriptor says, with one layer that has the container's files, links and
# second names, and the container's limits as annotations. What a container
# may do on a host is not in it. The same container gives the same bytes, and
# nothing lightbox keeps is changed but the record of the generation the
# first export is, of the line it begins (ROADMAP I.10); a second changes
# nothing.
t_export_image() {
    need_python || return 77
    local me said out before layer config line token
    # everything lightbox keeps but that record, and the time of the directory it is made in
    kept_but_generation() { find "$W/data" "$R" ! -path "$C/web" ! -name .generation -printf '%p %y %s %T@\n' | LC_ALL=C sort; }
    me="$(id -u):$(id -g)"
    ln -s placeholder "$BASE/bin/link" && ln "$BASE/bin/placeholder" "$BASE/bin/second-name" || return 1
    lb create web 10.0.0.2 --mem 1G --swap 512M --pids 64 --cpu 0.5 --ttl 8h --privileged --read-only \
        --seccomp deny --net nat --vol "$W/vol:/data" --dns 9.9.9.9 --oom-score 100 >/dev/null || return 1
    printf 'work\n' > "$C/web/rootfs/work.txt" && chmod 640 "$C/web/rootfs/work.txt" || return 1
    before=$(kept_but_generation)
    said=$(lb export web "$W/image") || { printf '%s\n' "$said"; return 1; }
    printf '%s\n' "$said"
    [ "$before" = "$(kept_but_generation)" ] || { echo "export changed what lightbox keeps, beyond the record of the generation"; return 1; }
    grep -qxE '[0-9a-f]{16} 1 [0-9a-f]{8}' "$C/web/.generation" && [ "$(mode_of "$C/web/.generation")" = 600 ] &&
        printf '%s\n' "$said" | grep -qx "Generation 1, the first of the container's line" ||
        { echo "the first export is not on record as generation 1 of a line: $(cat "$C/web/.generation" 2>&1)"; return 1; }
    line=$(cut -d' ' -f1 "$C/web/.generation") token=$(cut -d' ' -f3 "$C/web/.generation")
    out=$(python3 -I "$IMAGE_CHECK" "$W/image") || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
    printf '%s\n' "$said" | grep -q "^Container 'web' exported: 1 layer, " &&
        printf '%s\n' "$said" | grep -qx "Image $(printf '%s\n' "$out" | sed -n 's/^manifest //p')" ||
        { echo "export does not say what it wrote"; return 1; }
    [ "$(mode_of "$W/image")" = 700 ] && [ "$(mode_of "$W/image/index.json")" = 600 ] &&
        [ -z "$(find "$W/image/blobs" -type f ! -perm 600)" ] || { echo "the image is not its owner's alone"; return 1; }

    # the limits, and nothing else of the container's configuration
    [ "$(annotations_of "$out")" = "ac.ozkr.lightbox.cpu=0.5 ac.ozkr.lightbox.generation=1 ac.ozkr.lightbox.history=$token ac.ozkr.lightbox.lineage=$line ac.ozkr.lightbox.mem=1G ac.ozkr.lightbox.name=web ac.ozkr.lightbox.pids=64 ac.ozkr.lightbox.swap=512M ac.ozkr.lightbox.ttl=8h ac.ozkr.lightbox.version=1" ] ||
        { echo "the annotations are not the container's limits and its generation: $(annotations_of "$out")"; return 1; }
    layer=$(printf '%s\n' "$out" | sed -n 's/^layer 1 \(sha256:[0-9a-f]*\) .*/\1/p')
    config=$(printf '%s\n' "$out" | sed -n 's/^config sha256://p')
    [ "$(cat "$W/image/blobs/sha256/$config")" = \
      "{\"architecture\":\"$(printf '%s\n' "$out" | sed -n 's/^architecture //p')\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"$layer\"]}}" ] ||
        { echo "the configuration says more than what the image is for and its layer: $(cat "$W/image/blobs/sha256/$config")"; return 1; }

    # the container's files, as they are
    has() { printf '%s\n' "$out" | grep -qE -- "^entry 1 $1\$" || { echo "the layer has no: $1"; return 1; }; }
    has "file 0640 $me 5 work.txt" && has "file 0[0-7]{3} $me 30 etc/passwd" && has "file 0[0-7]{3} $me 4 etc/hostname" &&
        has "dir 0[0-7]{3} $me 0 etc" && has "link 0777 $me 0 bin/link -> placeholder" &&
        has "file 0[0-7]{3} $me 12 bin/placeholder" && has "hardlink 0[0-7]{3} $me 0 bin/second-name -> bin/placeholder" || return 1

    # the same container is the same image, in a directory that was there and empty too
    before=$(kept_sum)
    mkdir -m 777 "$W/empty" && lb export web "$W/again" > "$W/again.out" && lb export web "$W/empty" >/dev/null || return 1
    diff -r "$W/image" "$W/again" && diff -r "$W/image" "$W/empty" || { echo "a second export wrote another image"; return 1; }
    [ "$before" = "$(kept_sum)" ] && grep -qx 'Generation 1, as the export before: the container was not started since' "$W/again.out" ||
        { echo "a second export of a container that was not started is another generation, or changed what lightbox keeps"; return 1; }
    [ "$(mode_of "$W/empty")" = 700 ] || { echo "a directory that was there is not its owner's alone: $(mode_of "$W/empty")"; return 1; }

    # a container that no option gave a swap or a lifetime says nothing of them
    lb create plain 10.0.0.3 >/dev/null && lb export plain "$W/plain" >/dev/null || return 1
    out=$(python3 -I "$IMAGE_CHECK" "$W/plain") || { printf '%s\n' "$out"; return 1; }
    [ "$(annotations_of "$out" | sed 's/ ac\.ozkr\.lightbox\.\(generation\|history\|lineage\)=[0-9a-f]*//g')" = 'ac.ozkr.lightbox.cpu=1 ac.ozkr.lightbox.mem=256M ac.ozkr.lightbox.name=plain ac.ozkr.lightbox.pids=128 ac.ozkr.lightbox.version=1' ] ||
        { echo "the annotations of a container with the defaults: $(annotations_of "$out")"; return 1; }

    # skopeo, where the host has it, reads the image as the one export named,
    # and copies it, which holds every blob to its digest, to the same blobs
    # when it is told to leave a layer that is not compressed as it is
    if command -v skopeo >/dev/null 2>&1; then
        out=$(python3 -I "$IMAGE_CHECK" "$W/image") || return 1
        skopeo_here inspect "oci:$W/image" > "$W/skopeo.out" 2>&1 || { cat "$W/skopeo.out"; echo "skopeo does not read the image"; return 1; }
        cat "$W/skopeo.out"
        grep -q "\"$layer\"" "$W/skopeo.out" || { echo "skopeo does not find the layer"; return 1; }
        grep -q "\"Digest\": \"$(printf '%s\n' "$out" | sed -n 's/^manifest //p')\"" "$W/skopeo.out" ||
            { echo "skopeo reads another manifest than export named"; return 1; }
        if skopeo copy --help 2>&1 | grep -q -- --dest-oci-accept-uncompressed-layers; then
            skopeo_here --insecure-policy copy --dest-oci-accept-uncompressed-layers "oci:$W/image" "oci:$W/copied" \
                > "$W/skopeo.out" 2>&1 || { cat "$W/skopeo.out"; echo "skopeo does not copy the image"; return 1; }
            diff -r "$W/image/blobs" "$W/copied/blobs" || { echo "skopeo's copy of the image has other blobs"; return 1; }
        else
            echo "this skopeo cannot be told to leave a layer as it is: the image was not copied"
        fi
    else
        echo "no skopeo here: the image was read by image_check.py alone"
    fi
}

# What is no export: a directory that is not the image's own, a container
# that is not there, is half made or runs, and a tree that is no layer. Each
# is said, and nothing of an image is left where one was to be.
t_export_refusals() {
    local bad=0 before said
    # What lightbox keeps, with every time to the nanosecond: a refused export
    # that made a directory among it and took it away again left the directory
    # above with the time of now, which a look in whole seconds saw only when
    # a second had ended in between (CI run 45177356327, on 2026-11-23).
    kept_sum() { find "$W/data" "$R" -printf '%p %y %s %T@\n' | LC_ALL=C sort; }
    lb create web 10.0.0.2 >/dev/null || return 1
    mkdir "$W/full" "$W/there" "$W/data/bases" && : > "$W/full/file" && : > "$W/afile" && ln -s "$C" "$W/link" &&
        ln -s there "$W/link-to-there" && chmod 755 "$W/full" || return 1
    before=$(kept_sum)
    no() { # what it says, the command
        local want=$1
        shift
        said=$(lb "$@" 2>&1) && { echo "lightbox $*: succeeded"; bad=1; return; }
        case $said in *"$want"*) ;; *) echo "lightbox $*: $said"; bad=1 ;; esac
    }
    no 'Usage: lightbox export <name> <dir>' export
    no 'Usage: lightbox export <name> <dir>' export web
    no 'Error: unexpected argument: more' export web "$W/x" more
    no 'Error: unknown option: --force' export --force web "$W/x"
    no 'Error: unknown option: --compress' export web "$W/x" --compress
    no 'Error: container does not exist: nosuch' export nosuch "$W/x"
    no 'Error: container name must only contain' export a/b "$W/x"
    no 'a directory of its own, and this one is not empty' export web "$W/full"
    no 'into a directory, and this is none' export web "$W/afile"
    no 'into a directory, and this is a link' export web "$W/link-to-there"
    no 'which has to be in one that is there' export web "$W/no/such/x"
    no "among lightbox's own files" export web "$C/image"
    no "among lightbox's own files" export web "$C/web/rootfs/image"
    no "among lightbox's own files" export web "$W/data/bases/image"
    no "among lightbox's own files" export web "$W/link/web/rootfs/image"
    [ "$before" = "$(kept_sum)" ] || { echo "a refused export changed what lightbox keeps"; bad=1; }
    # A tree that cannot be a layer ends it, with the entry named. What is
    # kept is looked at with the file in it, as making it is a change.
    : > "$C/web/rootfs/.wh.x"
    before=$(kept_sum)
    no ': .wh.x: has a name that begins with .wh.' export web "$W/x"
    no ': .wh.x: has a name that begins with .wh.' export web "$W/there"
    [ "$before" = "$(kept_sum)" ] || { echo "a refused export of a tree that is no layer changed what lightbox keeps"; bad=1; }
    rm "$C/web/rootfs/.wh.x"
    [ ! -e "$W/x" ] && [ ! -e "$C/image" ] && [ ! -e "$C/web/rootfs/image" ] && [ ! -e "$W/data/bases/image" ] ||
        { echo "a refused export left a directory"; bad=1; }
    [ "$(ls -A "$W/full")" = file ] && [ "$(mode_of "$W/full")" = 755 ] && [ -d "$W/there" ] && [ -z "$(ls -A "$W/there")" ] ||
        { echo "a refused export changed a directory that was there"; bad=1; }
    # one that create did not finish, and one that runs
    : > "$C/web/.creating"
    no 'was not created completely, and is not exported' export web "$W/x"
    rm "$C/web/.creating"
    record web $$ "$(awk '{ printf "%s", $22 }' /proc/$$/stat)" running
    no 'Error: container is running (stop it first): web' export web "$W/x"
    [ ! -e "$W/x" ] || { echo "a refused export left a directory"; bad=1; }
    return $bad
}

# A container that overlays a snapshot is two layers: the snapshot, and its
# own files with what it took out of its base marked as an image marks it.
# Two containers of one base have the same first layer, whose digest the
# snapshot keeps. No overlay is mounted for this: the container is one by its
# .conf, and its rootfs/ is made here as an overlay would leave it, in a user
# namespace, where the device 0:0 that marks a file as taken out can be made.
t_export_overlay() {
    need_python || return 77
    local rc out id first names
    mkdir -p "$BASE/lib" "$BASE/opt/old" && echo gone > "$BASE/lib/gone" && echo keep > "$BASE/lib/keep" &&
        echo x > "$BASE/opt/old/x" || return 1
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 C=$1/data/containers
        # copies, which the lines below make overlays by their .conf: where an
        # overlay mounts in such a namespace, as on CI, create would make one
        "$LB" create one 10.0.0.2 --copy >/dev/null && "$LB" create two 10.0.0.3 --copy >/dev/null || exit 1
        id=$("$LB" base add "$W/base" | sed -n "s/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p")
        [ -n "$id" ] || exit 1
        for name in one two; do
            echo "base=$id" >> "$C/$name/.conf"
            mv "$C/$name/rootfs" "$C/$name/copy" && mkdir -p "$C/$name/rootfs/etc" &&
                cp "$C/$name/copy/etc/hostname" "$C/$name/rootfs/etc/hostname" || exit 1
        done
        U=$C/one/rootfs
        mkdir -p "$U/lib" "$U/opt/old" "$U/srv" && echo new > "$U/srv/new" && echo y > "$U/opt/old/y" || exit 1
        mknod "$U/lib/gone" c 0 0 2>/dev/null || exit 77
        python3 -I -c "import os, sys; os.setxattr(sys.argv[1], \"user.overlay.opaque\", b\"y\")" "$U/opt/old" 2>/dev/null || exit 77
        "$LB" export one "$W/one" && "$LB" export two "$W/two" || exit 1
        echo "kept: $(cat "$W/data/bases/$id/layer")"
        echo changed > "$W/data/bases/$id/rootfs/lib/keep"
        "$LB" export two "$W/changed" 2>&1 | grep "^Warning"
    ' _ "$W" "$LB" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -ne 77 ] || { echo "no device 0:0 or no user.* attribute can be made in a user namespace here"; return 77; }
    [ $rc -eq 0 ] || return 1
    out=$(python3 -I "$IMAGE_CHECK" "$W/one") || { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
    grep -q "^Container 'one' exported: 2 layers, " "$W/ns.out" && printf '%s\n' "$out" | grep -qx 'layers 2' ||
        { echo "an overlay is not two layers"; return 1; }
    # its own files alone, and the two marks, each an empty file
    names=$(printf '%s\n' "$out" | sed -n 's/^entry 2 [a-z]* [0-7]* [0-9:]* [0-9]* //p' | paste -sd' ' -)
    [ "$names" = 'etc etc/hostname lib lib/.wh.gone opt opt/old opt/old/.wh..wh..opq opt/old/y srv srv/new' ] ||
        { echo "the second layer is not the container's own files and its marks: $names"; return 1; }
    printf '%s\n' "$out" | grep -qE '^entry 2 file 0[0-7]{3} 0:0 0 lib/\.wh\.gone$' &&
        printf '%s\n' "$out" | grep -qE '^entry 2 file 0[0-7]{3} 0:0 0 opt/old/\.wh\.\.wh\.\.opq$' ||
        { echo "a mark is not an empty file"; return 1; }
    # the first is the snapshot, with what the container took out still in it
    printf '%s\n' "$out" | grep -qE '^entry 1 file 0[0-7]{3} 0:0 5 lib/gone$' &&
        printf '%s\n' "$out" | grep -qE '^entry 1 file 0[0-7]{3} 0:0 2 opt/old/x$' &&
        ! printf '%s\n' "$out" | grep -q '^entry 1 .* srv/new$' || { echo "the first layer is not the snapshot"; return 1; }
    # which is one layer for every container on it, and kept by the snapshot
    first=$(printf '%s\n' "$out" | sed -n 's/^layer 1 //p')
    out=$(python3 -I "$IMAGE_CHECK" "$W/two") || { printf '%s\n' "$out"; return 1; }
    [ -n "$first" ] && [ "$(printf '%s\n' "$out" | sed -n 's/^layer 1 //p')" = "$first" ] ||
        { echo "two containers of one snapshot have two first layers"; return 1; }
    grep -qx "kept: $first" "$W/ns.out" || { echo "the snapshot does not keep its layer's digest and size: $first"; return 1; }
    # a snapshot that was changed under its containers is said to be another layer
    grep -q '^Warning: the base snapshot [0-9a-f]\{12\} is another layer than it was' "$W/ns.out" ||
        { echo "a changed snapshot was not said to be one"; return 1; }
    python3 -I "$IMAGE_CHECK" "$W/changed" >/dev/null || return 1
}

# import (ROADMAP I.6) reads an image whole before it makes anything, and
# before it asks for root: every blob held to the size and the SHA-256 it is
# named by, the layers to what the configuration says of them, the image to
# this machine's architecture. tests/image_edit.py changes an image that
# export wrote into one that is another, or none; each is refused with what
# is wrong, and nothing lightbox keeps is changed. What an image says of its
# container beyond its limits is said, and not taken.
IMAGE_EDIT=$(cd "$(dirname "$0")" && pwd)/image_edit.py
t_import_refusals() {
    need_python || return 77
    local bad=0 before said n=0 other
    lb create web 10.0.0.2 --mem 1G >/dev/null && lb export web "$W/image" >/dev/null && mkdir "$W/empty" || return 1
    before=$(kept_sum)
    changed() { # what import says then, the change
        local want=$1
        shift
        n=$((n + 1))
        cp -r "$W/image" "$W/changed.$n" && python3 -I "$IMAGE_EDIT" "$W/changed.$n" "$@" ||
            { echo "image_edit $*: failed"; bad=1; return; }
        said=$(lb import "$W/changed.$n" new 2>&1) && { echo "import after $*: succeeded"; bad=1; return; }
        case $said in *"$want"*) ;; *) echo "import after $*: $said"; bad=1 ;; esac
    }
    changed 'the manifest is not what it is named by: its bytes have another SHA-256' byte manifest
    changed 'the configuration is not what it is named by: its bytes have another SHA-256' byte config
    changed 'a layer is not what it is named by: its bytes have another SHA-256' byte layer
    changed 'a layer has another size than it is named with' longer layer
    changed 'the configuration has another size than it is named with' longer config
    changed 'the manifest is not among its blobs' gone manifest
    changed 'the configuration is not among its blobs' gone config
    changed 'a layer is not among its blobs' gone layer
    changed 'a layer is not among its blobs' link layer
    other=arm64
    [ "$(uname -m)" = aarch64 ] && other=amd64
    changed "is an image for linux on $other, and this lightbox runs linux on" architecture "$other"
    changed 'is an image for windows on' os windows
    changed 'a layer of a type that is not read: application/vnd.oci.image.layer.v1.tar+zstd' \
        layer-type application/vnd.oci.image.layer.v1.tar+zstd
    changed 'the manifest is of a type that is not read: application/vnd.docker.distribution.manifest.v2+json' \
        manifest-type application/vnd.docker.distribution.manifest.v2+json
    changed 'the configuration is of a type that is not read: application/x' config-type application/x
    changed 'the manifest is no image manifest of schema 2' schema 1
    changed 'oci-layout does not say that it is an image layout of version 1.0.0' layout '{}'
    changed 'oci-layout is no JSON, at 1:1: what is here is no value' layout nonsense
    changed "the configuration does not name the manifest's layers as they are unpacked" one-layer-more
    changed 'the configuration names another layer than the manifest, for one that is not compressed' other-layer
    changed 'index.json names more than one image, and import takes a directory with one' two-manifests
    changed 'index.json names no image' no-manifests
    changed 'index.json names an index of images and no image' index-of-indexes
    changed 'a name that is there twice in one object' name-twice
    changed 'the manifest has a name on the way to /layers in letters of another case' name-in-capitals
    changed 'the manifest is no JSON, at 1:' no-json
    # a text of the image's that a terminal would obey is not passed on to it
    changed 'a layer of a type that is not read: (a text with control characters)' layer-type "$(printf 'x\033[31m')"
    case $said in *"$(printf '\033')"*) echo "import printed the image's control characters"; bad=1 ;; esac

    no() { # what it says, the command
        local want=$1
        shift
        said=$(lb "$@" 2>&1) && { echo "lightbox $*: succeeded"; bad=1; return; }
        case $said in *"$want"*) ;; *) echo "lightbox $*: $said"; bad=1 ;; esac
    }
    no 'Usage: lightbox import <dir> <name> [<ip>] [options]' import
    no 'Usage: lightbox import <dir> <name> [<ip>] [options]' import "$W/image"
    no "import takes the image's directory first, and then the name" import --copy "$W/image" new
    no 'Error: container name must only contain' import "$W/image" a/b
    no 'Error: there is no directory with an image at' import "$W/none" new
    no 'it has no oci-layout' import "$W/empty" new
    no 'it has no oci-layout' import "$C/web" new

    # What an image says of its container and import does not take is said,
    # before anything is asked of the caller; a whole image is root's to unpack.
    if [ "$(id -u)" != 0 ]; then
        notes() { # what is said, the annotation
            n=$((n + 1))
            cp -r "$W/image" "$W/changed.$n" && python3 -I "$IMAGE_EDIT" "$W/changed.$n" annotation "$2" || { bad=1; return; }
            said=$(lb import "$W/changed.$n" new 2>&1) && { echo "an ordinary user imported an image"; bad=1; return; }
            case $said in *"$1"*'Error: lightbox import must be run as root') ;; *) echo "with the annotation $2: $said"; bad=1 ;; esac
        }
        notes 'Note: the image says ac.ozkr.lightbox.privileged, which import does not take' ac.ozkr.lightbox.privileged=1
        notes 'Note: the image says ac.ozkr.lightbox.vol, which import does not take' ac.ozkr.lightbox.vol=/:/host
        notes 'Note: the image says ac.ozkr.lightbox.mem with what is no such value, which is not taken' ac.ozkr.lightbox.mem=lots
        notes "Note: the image's annotations are of the version 2, and this lightbox reads 1: none of them is taken" ac.ozkr.lightbox.version=2
        said=$(lb import "$W/image" new 2>&1)
        [ "$said" = 'Error: lightbox import must be run as root' ] || { echo "a whole image, as an ordinary user: $said"; bad=1; }
    fi
    [ "$before" = "$(kept_sum)" ] && [ ! -e "$C/new" ] || { echo "a refused import changed what lightbox keeps"; bad=1; }
    return $bad
}

# An image is made a container again, in a user namespace, where this user
# is root and unpacking is allowed: the tree is the exported one but for the
# files create writes in /etc, which are the new container's, with the line
# of the old one gone from its hosts file. The limits no option gives are
# the image's, where they are no more than lightbox.conf gives a new
# container; what is more is said and not taken, and an option or the
# settings give it. An image whose layer was compressed, as skopeo compresses one,
# gives the same tree; one that unpacks to another layer than its
# configuration names, or whose gzip stream is cut or has more after its end,
# is refused, and nothing of a container or a snapshot is left. Layers of an
# image become one tree with --copy: a mark takes out what it names, and a
# device is not made. Where an overlay mounts in such a namespace the layer
# is a snapshot, and a second import takes no second one.
t_import_round_trip() {
    need_python || return 77
    local rc
    mkdir -p "$BASE/lib" "$BASE/opt/old" && ln -s placeholder "$BASE/bin/link" && ln "$BASE/bin/placeholder" "$BASE/bin/second-name" &&
        echo gone > "$BASE/lib/gone" && echo keep > "$BASE/lib/keep" && echo x > "$BASE/opt/old/x" || return 1
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 EDIT=$3 C=$1/data/containers
        fail() { echo "FAILED: $*"; exit 1; }
        # a tree but for what create writes in /etc: names, kinds, modes, owners, sizes, links and times
        listing() {
            (cd "$1" && find . -mindepth 1 ! -path ./etc ! -path ./etc/hostname ! -path ./etc/hosts ! -path ./etc/resolv.conf \
                -printf "%P %y %m %U:%G %l %n %Ts " \( -type f -printf "%s" -o -true \) -printf "\n" | LC_ALL=C sort)
        }
        # where a container has the files of its image: its rootfs/, or the snapshot under it
        tree_of() {
            base=$(sed -n "s/^base=//p" "$C/$1/.conf")
            if [ -n "$base" ]; then echo "$W/data/bases/$base/rootfs"; else echo "$C/$1/rootfs"; fi
        }
        snapshots() { ls "$W/data/bases" 2>/dev/null | wc -l; }
        conf() { grep -qx -- "$2" "$C/$1/.conf" || fail "$1 has no $2 in its .conf: $(paste -sd" " "$C/$1/.conf")"; }

        "$LB" create web 10.0.0.2 --mem 128M --pids 64 --cpu 0.5 --ttl 8h --copy > /dev/null || fail "create"
        echo work > "$C/web/rootfs/work.txt" && chmod 640 "$C/web/rootfs/work.txt" &&
            touch -d "2020-02-02 02:02:02 UTC" "$C/web/rootfs/work.txt" "$C/web/rootfs/bin" || fail "the container could not be changed"
        "$LB" export web "$W/image" > "$W/export.out" || fail "export"
        listing "$C/web/rootfs" > "$W/web.list"

        echo "--- the image, a container again"
        "$LB" import "$W/image" back 10.0.0.9 > "$W/import.out" 2>&1 || { cat "$W/import.out"; fail "import"; }
        cat "$W/import.out"
        grep -qx "Container .back. imported (ip=10.0.0.9)" "$W/import.out" || fail "import does not say what it made"
        grep -q "^$(grep "^Image sha256:" "$W/export.out")" "$W/import.out" || fail "import names another image than export wrote"
        grep -qx "Limits of the image.s: mem=128M pids=64 cpu=0.5 ttl=8h" "$W/import.out" || fail "the limits it took are not said"
        for line in mem=128M pids=64 cpu=0.5 ttl=8h; do conf back "$line"; done
        listing "$(tree_of back)" > "$W/back.list"
        diff "$W/web.list" "$W/back.list" || fail "the tree is not the exported one"
        [ "$(cat "$C/back/rootfs/etc/hostname")" = back ] || fail "its hostname is not its own"
        grep -qx "10.0.0.9	back" "$C/back/rootfs/etc/hosts" || fail "its hosts file has no line for it"
        ! grep -q "	web\$" "$C/back/rootfs/etc/hosts" || fail "its hosts file still has the line of the container it was"
        had=$(snapshots)
        if [ -n "$(sed -n "s/^base=//p" "$C/back/.conf")" ]; then
            echo "an overlay mounts here: the layer is a snapshot"
            [ "$(cd "$C/back/rootfs" && find . -type f | LC_ALL=C sort | paste -sd" ")" = "./etc/hostname ./etc/hosts ./etc/resolv.conf" ] ||
                fail "its own files are more than create writes"
            "$LB" import "$W/image" again > "$W/again.out" 2>&1 || { cat "$W/again.out"; fail "a second import"; }
            grep -q ", on the base snapshot [0-9a-f]\{12\}, which was here\$" "$W/again.out" && [ "$(snapshots)" = "$had" ] ||
                fail "a second import took a second snapshot"
        fi

        echo "--- an option is before the image, and the image before lightbox.conf"
        "$LB" import "$W/image" opt --mem 2G --ttl 1h > "$W/opt.out" 2>&1 || { cat "$W/opt.out"; fail "import with options"; }
        for line in mem=2G pids=64 cpu=0.5 ttl=1h; do conf opt "$line"; done
        grep -qx "Limits of the image.s: pids=64 cpu=0.5" "$W/opt.out" || fail "the limits it took, beside the options: $(cat "$W/opt.out")"
        said=$("$LB" import "$W/image" other --rootfs "$W/base" 2>&1) && fail "import took --rootfs"
        case $said in *"no --rootfs"*) ;; *) fail "--rootfs: $said" ;; esac
        said=$("$LB" import "$W/image" web 2>&1) && fail "import over a container that is there"
        case $said in *"container already exists: web"*) ;; *) fail "an existing name: $said" ;; esac
        [ ! -e "$C/other" ] || fail "a refused import left a container"

        echo "--- an image gives its container no more than lightbox.conf gives a new one"
        cp -r "$W/image" "$W/more" || fail "cp"
        for pair in mem=4G swap=1G pids=max cpu=8; do
            python3 -I "$EDIT" "$W/more" annotation "ac.ozkr.lightbox.$pair" || fail "image_edit"
        done
        "$LB" import "$W/more" capped > "$W/capped.out" 2>&1 || { cat "$W/capped.out"; fail "import of an image that has more"; }
        cat "$W/capped.out"
        grep -qx "Note: the image has mem=4G, which is more than lightbox.conf gives a new container, 256M: it is not taken, and --mem gives it more" "$W/capped.out" &&
            grep -qx "Note: the image has pids=max, which is more than lightbox.conf gives a new container, 128: it is not taken, and --pids gives it more" "$W/capped.out" &&
            grep -qx "Note: the image has cpu=8, which is more than lightbox.conf gives a new container, 1: it is not taken, and --cpu gives it more" "$W/capped.out" &&
            grep -qx "Note: the image has swap=1G, and a new container here has no swap: it has none, and --swap gives it some" "$W/capped.out" ||
            fail "what the image has more of is not said"
        for line in mem=256M pids=128 cpu=1 ttl=8h; do conf capped "$line"; done
        ! grep -q "^swap=" "$C/capped/.conf" || fail "the image gave its container swap"
        grep -qx "Limits of the image.s: ttl=8h" "$W/capped.out" || fail "a lifetime, which only takes away, is not the image.s: $(grep "^Limits" "$W/capped.out")"
        # the option gives it, and then nothing is said of it
        "$LB" import "$W/more" given --mem 4G --swap 1G --pids max --cpu 8 > "$W/given.out" 2>&1 || { cat "$W/given.out"; fail "import with what the image has, as options"; }
        for line in mem=4G swap=1G pids=max cpu=8; do conf given "$line"; done
        ! grep -q "^Note: the image has " "$W/given.out" || fail "a limit an option gave is held against the image.s"
        # and so does a lightbox.conf that gives a new container as much
        printf "default_mem = 4G\ndefault_pids = max\ndefault_cpu = 8\n" >> "$LIGHTBOX_CONFIG"
        "$LB" import "$W/more" roomy > "$W/roomy.out" 2>&1 || { cat "$W/roomy.out"; fail "import where lightbox.conf gives as much"; }
        for line in mem=4G pids=max cpu=8; do conf roomy "$line"; done
        grep -qx "Limits of the image.s: mem=4G pids=max cpu=8 ttl=8h" "$W/roomy.out" && ! grep -q "^swap=" "$C/roomy/.conf" ||
            fail "what lightbox.conf gives as much of is not the image.s: $(grep "^Limits\|^Note" "$W/roomy.out" | paste -sd"|")"
        sed -i "/^default_/d" "$LIGHTBOX_CONFIG"

        echo "--- what an image says beyond its limits is said and not taken"
        cp -r "$W/image" "$W/asking" && python3 -I "$EDIT" "$W/asking" annotation ac.ozkr.lightbox.privileged=1 &&
            python3 -I "$EDIT" "$W/asking" annotation ac.ozkr.lightbox.net=nat || fail "image_edit"
        "$LB" import "$W/asking" asked > "$W/asked.out" 2>&1 || { cat "$W/asked.out"; fail "import of an image that asks for more"; }
        grep -q "^Note: the image says ac.ozkr.lightbox.privileged, which import does not take" "$W/asked.out" &&
            grep -q "^Note: the image says ac.ozkr.lightbox.net, which import does not take" "$W/asked.out" || fail "what it asks for is not said"
        ! grep -q "^privileged=1" "$C/asked/.conf" && grep -qx "net=outside" "$C/asked/.conf" || fail "the image had its way: $(paste -sd" " "$C/asked/.conf")"

        echo "--- a layer that is compressed"
        cp -r "$W/image" "$W/gz" && python3 -I "$EDIT" "$W/gz" gzip || fail "image_edit gzip"
        "$LB" import "$W/gz" unpacked > "$W/gz.out" 2>&1 || { cat "$W/gz.out"; fail "import of a compressed layer"; }
        listing "$(tree_of unpacked)" > "$W/gz.list"
        diff "$W/web.list" "$W/gz.list" || fail "a compressed layer is another tree"
        # A layer that is not what the configuration names, where it is
        # unpacked: with --copy every layer is, whatever is here already. The
        # same through a snapshot is the case of base import.
        had=$(snapshots)
        for pair in "gzip-other:is, as it was unpacked, not the layer its configuration names" \
                    "gzip-cut:of the image" "gzip-more:gzip did not unpack layer 1 of the image to its end"; do
            change=${pair%%:*}
            cp -r "$W/image" "$W/$change" && python3 -I "$EDIT" "$W/$change" "$change" || fail "image_edit $change"
            said=$("$LB" import "$W/$change" broken --copy 2>&1) && fail "$change was imported"
            case $said in *"${pair#*:}"*) ;; *) fail "$change: $said" ;; esac
            [ ! -e "$C/broken" ] && [ "$(snapshots)" = "$had" ] && [ -z "$(ls -A "$W/data/bases" 2>/dev/null | grep "^\.")" ] ||
                fail "$change left a container or a snapshot"
        done
        # Where the layer the configuration names is a snapshot here already,
        # as it is where an overlay mounts, the compressed one is held to
        # that digest all the same, and refused as it is everywhere else.
        if [ -n "$(sed -n "s/^base=//p" "$C/unpacked/.conf")" ]; then
            said=$("$LB" import "$W/gzip-other" named 2>&1) && fail "an image whose layer is another than it says was taken where its snapshot is"
            case $said in *"is, as it was unpacked, not the layer its configuration names"*) ;; *) fail "gzip-other onto its snapshot: $said" ;; esac
            [ ! -e "$C/named" ] && [ "$(snapshots)" = "$had" ] || fail "a refused import onto a snapshot left a container or a snapshot"
        fi

        echo "--- two layers and three, as one tree"
        "$LB" create over --copy > /dev/null && id=$("$LB" base add "$W/base" | sed -n "s/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p") &&
            [ -n "$id" ] && echo "base=$id" >> "$C/over/.conf" && mv "$C/over/rootfs" "$C/over/copy" || fail "no container to be an overlay"
        U=$C/over/rootfs
        mkdir -p "$U/etc" "$U/lib" "$U/opt/old" "$U/srv" && cp "$C/over/copy/etc/hostname" "$U/etc/hostname" &&
            echo new > "$U/srv/new" && echo y > "$U/opt/old/y" || fail "no upper directory"
        mknod "$U/lib/gone" c 0 0 2>/dev/null || { echo "no device 0:0 can be made here"; exit 77; }
        python3 -I -c "import os, sys; os.setxattr(sys.argv[1], \"user.overlay.opaque\", b\"y\")" "$U/opt/old" 2>/dev/null ||
            { echo "no user.* attribute can be set here"; exit 77; }
        "$LB" export over "$W/two" > /dev/null || fail "export of two layers"
        "$LB" import "$W/two" flat --copy > "$W/flat.out" 2>&1 || { cat "$W/flat.out"; fail "import of two layers"; }
        cat "$W/flat.out"
        F=$C/flat/rootfs
        [ "$(cat "$F/lib/keep" "$F/srv/new" "$F/opt/old/y")" = "keep
new
y" ] && [ ! -e "$F/lib/gone" ] && [ ! -e "$F/opt/old/x" ] || fail "the second layer was not put over the first: $(cd "$F" && find lib opt srv | paste -sd" ")"
        [ -z "$(find "$F" -name ".wh.*" -o -type c)" ] || fail "a mark of a layer is in the tree"
        grep -q ": 2 layers, as a copy\$" "$W/flat.out" || fail "two layers with --copy are not said to be a copy"
        python3 -I -c "
import io, sys, tarfile
with tarfile.open(sys.argv[1], \"w\", format=tarfile.PAX_FORMAT) as t:
    d = tarfile.TarInfo(\"added\"); d.type = tarfile.DIRTYPE; d.mode = 0o755; t.addfile(d)
    f = tarfile.TarInfo(\"added/file\"); f.size = 6; f.mode = 0o600; t.addfile(f, io.BytesIO(b\"third\\n\"))
    n = tarfile.TarInfo(\"added/null\"); n.type = tarfile.CHRTYPE; n.devmajor, n.devminor = 1, 3; t.addfile(n)
    w = tarfile.TarInfo(\"srv/.wh.new\"); t.addfile(w)
" "$W/third.tar" && cp -r "$W/two" "$W/three" && python3 -I "$EDIT" "$W/three" add-layer "$W/third.tar" || fail "no third layer"
        "$LB" import "$W/three" three --copy > "$W/three.out" 2>&1 || { cat "$W/three.out"; fail "import of three layers"; }
        cat "$W/three.out"
        T=$C/three/rootfs
        [ "$(cat "$T/added/file")" = third ] && [ ! -e "$T/added/null" ] && [ ! -e "$T/srv/new" ] && [ -e "$T/lib/keep" ] ||
            fail "the third layer was not put over the two"
        grep -qx "Note: 1 device of the image.s was not made: a container.s devices are lightbox.s to give" "$W/three.out" ||
            fail "a device that was not made is not said"
    ' _ "$W" "$LB" "$IMAGE_EDIT" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -ne 77 ] || return 77
    [ $rc -eq 0 ] && ! grep -q '^FAILED: ' "$W/ns.out"
}

# To a registry and back (ROADMAP I.8). lightbox writes and reads a
# directory, and skopeo carries it: tests/registry.py is a registry for this
# case alone, on the loopback. Two containers that overlay one snapshot are
# exported and copied to it; of the second, the layer that is the snapshot is
# not sent again, which the registry's own record of what it was sent shows.
# What is copied back, into empty directories, has its layers compressed, and
# import makes of it the tree that it makes of the directory export wrote.
REGISTRY=$(cd "$(dirname "$0")" && pwd)/registry.py
t_registry() {
    need_python || return 77
    command -v skopeo >/dev/null 2>&1 || { echo "no skopeo to carry an image to a registry with"; return 77; }
    local rc pid port sent n
    mkdir -p "$BASE/lib" && echo gone > "$BASE/lib/gone" && echo keep > "$BASE/lib/keep" || return 1
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 C=$1/data/containers
        "$LB" create one --mem 128M --ttl 8h --copy > /dev/null && "$LB" create two --copy > /dev/null || exit 1
        id=$("$LB" base add "$W/base" | sed -n "s/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p")
        [ -n "$id" ] || exit 1
        for name in one two; do
            echo "base=$id" >> "$C/$name/.conf"
            mv "$C/$name/rootfs" "$C/$name/copy" && mkdir -p "$C/$name/rootfs/etc" "$C/$name/rootfs/srv" &&
                cp "$C/$name/copy/etc/hostname" "$C/$name/rootfs/etc/hostname" && echo "of $name" > "$C/$name/rootfs/srv/own" || exit 1
        done
        mkdir "$C/one/rootfs/lib" && mknod "$C/one/rootfs/lib/gone" c 0 0 2>/dev/null || exit 77
        "$LB" export one "$W/one" > /dev/null && "$LB" export two "$W/two" > /dev/null
    ' _ "$W" "$LB" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -ne 77 ] || { echo "no device 0:0 can be made in a user namespace here"; return 77; }
    [ $rc -eq 0 ] || return 1

    python3 -I "$REGISTRY" "$W/registry" "$W/port" "$W/registry.log" > "$W/registry.out" 2>&1 &
    pid=$!
    n=0
    while [ ! -s "$W/port" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    port=$(cat "$W/port" 2>/dev/null)
    carried() {
        [ -n "$port" ] && mkdir -p "$W/home/run" || { cat "$W/registry.out"; echo "the registry did not start"; return 1; }
        copy() { timeout 120 env -i PATH="$PATH" HOME="$W/home" XDG_RUNTIME_DIR="$W/home/run" XDG_CONFIG_HOME="$W/home/.config" \
                     skopeo --insecure-policy copy --dest-tls-verify=false --src-tls-verify=false "$@" 2>&1; }
        copy "oci:$W/one" "docker://127.0.0.1:$port/boxes/one:latest" || { echo "skopeo did not copy the image to the registry"; return 1; }
        sent=$(grep -c '^PATCH ' "$W/registry.log")
        copy "oci:$W/two" "docker://127.0.0.1:$port/boxes/two:latest" || { echo "skopeo did not copy the second image"; return 1; }
        sed 's/sha256:\([0-9a-f]\{12\}\)[0-9a-f]*/\1/g; s/sha256%3A\([0-9a-f]\{12\}\)[0-9a-f]*/\1/g' "$W/registry.log"
        # the first image: two layers and the configuration; the second: its own layer and its configuration
        [ "$sent" = 3 ] && [ "$(grep -c '^PATCH ' "$W/registry.log")" = 5 ] ||
            { echo "the registry was sent $sent blobs and then $(($(grep -c '^PATCH ' "$W/registry.log") - sent)), not 3 and then 2"; return 1; }
        copy "docker://127.0.0.1:$port/boxes/one:latest" "oci:$W/one-back" && copy "docker://127.0.0.1:$port/boxes/two:latest" "oci:$W/two-back" ||
            { echo "skopeo did not copy the images back"; return 1; }
        grep -q 'image.layer.v1.tar+gzip' "$W/one-back/blobs/sha256/"* || { echo "what came back has no compressed layer: is this still what a registry gives?"; return 1; }
    }
    carried
    rc=$?
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    [ $rc -eq 0 ] || return 1

    # what came back is the container that was exported
    # shellcheck disable=SC2016
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 C=$1/data/containers
        listing() {
            (cd "$1" && find . -mindepth 1 ! -path ./etc ! -path ./etc/hostname ! -path ./etc/hosts ! -path ./etc/resolv.conf \
                -printf "%P %y %m %U:%G %l %n %Ts " \( -type f -printf "%s" -o -true \) -printf "\n" | LC_ALL=C sort)
        }
        for name in one two; do
            "$LB" import "$W/$name" "$name-direct" --copy > "$W/$name-direct.out" 2>&1 || { cat "$W/$name-direct.out"; exit 1; }
            "$LB" import "$W/$name-back" "$name-carried" --copy > "$W/$name-carried.out" 2>&1 || { cat "$W/$name-carried.out"; exit 1; }
            listing "$C/$name-direct/rootfs" > "$W/direct.list" && listing "$C/$name-carried/rootfs" > "$W/carried.list" || exit 1
            diff "$W/direct.list" "$W/carried.list" || { echo "FAILED: $name came back from the registry as another tree"; exit 1; }
            [ "$(cat "$C/$name-carried/rootfs/srv/own")" = "of $name" ] && [ -e "$C/$name-carried/rootfs/lib/keep" ] ||
                { echo "FAILED: $name came back without its files"; exit 1; }
        done
        [ ! -e "$C/one-carried/rootfs/lib/gone" ] && [ -e "$C/two-carried/rootfs/lib/gone" ] ||
            { echo "FAILED: what one took out of its base is not what came back as taken out"; exit 1; }
        grep -qx "Limits of the image.s: mem=128M pids=128 cpu=1 ttl=8h" "$W/one-carried.out" && grep -qx "ttl=8h" "$C/one-carried/.conf" ||
            { echo "FAILED: the limits did not come back: $(grep "^Limits" "$W/one-carried.out")"; exit 1; }
    ' _ "$W" "$LB" > "$W/ns2.out" 2>&1
    rc=$?
    cat "$W/ns2.out"
    [ $rc -eq 0 ]
}

# A registry's image as a base (ROADMAP I.9). An image that somebody else
# built says nothing of lightbox's and has as many layers as it has; here it
# is made of an export, with its annotations taken away, a command to start
# and a second layer that adds a file, takes one out and has a device. base
# import reads it as import reads one, whole and before root is asked for,
# and unpacks all its layers into one snapshot, which a second import of
# those layers, compressed or not, finds. create --base makes a container of
# the snapshot, by its id, and a copy of it where it is to be one. A layer
# that unpacks to another than the configuration names, and a blob that is
# not what it is named by, leave no snapshot. What names a base that is none
# is refused with what would take it.
t_base_import() {
    need_python || return 77
    local bad=0 before said rc
    # exported where this user is root, so that the layer's files are root's
    # shellcheck disable=SC2016
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        "$2" create web 10.0.0.2 --copy > /dev/null && "$2" export web "$1/image" > /dev/null' _ "$W" "$LB" || return 1
    python3 -I -c '
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w", format=tarfile.PAX_FORMAT) as t:
    d = tarfile.TarInfo("added"); d.type = tarfile.DIRTYPE; d.mode = 0o755; t.addfile(d)
    f = tarfile.TarInfo("added/file"); f.size = 7; f.mode = 0o640; t.addfile(f, io.BytesIO(b"second\n"))
    n = tarfile.TarInfo("added/null"); n.type = tarfile.CHRTYPE; n.devmajor, n.devminor = 1, 3; t.addfile(n)
    w = tarfile.TarInfo("bin/.wh.placeholder"); t.addfile(w)
' "$W/second.tar" && cp -r "$W/image" "$W/foreign" && python3 -I "$IMAGE_EDIT" "$W/foreign" no-annotations &&
        python3 -I "$IMAGE_EDIT" "$W/foreign" command && python3 -I "$IMAGE_EDIT" "$W/foreign" add-layer "$W/second.tar" &&
        cp -r "$W/foreign" "$W/bad" && python3 -I "$IMAGE_EDIT" "$W/bad" byte layer || { echo "no image to import"; return 1; }

    # what is refused before anything is made, and before root is asked for
    before=$(kept_sum)
    no() { # what it says, the command
        local want=$1
        shift
        said=$(lb "$@" 2>&1) && { echo "lightbox $*: succeeded"; bad=1; return; }
        case $said in *"$want"*) ;; *) echo "lightbox $*: $said"; bad=1 ;; esac
    }
    no 'Usage: lightbox base import <dir>' base import
    no 'Error: base import takes one directory, with an image in it' base import "$W/foreign" more
    no 'Error: there is no directory with an image at' base import "$W/none"
    no 'it has no oci-layout' base import "$BASE"
    no 'a layer is not what it is named by: its bytes have another SHA-256' base import "$W/bad"
    no 'Error: --base takes the id of a base snapshot, as base ls shows it, not: latest' create new --base latest
    no 'Error: --base takes the id of a base snapshot, as base ls shows it, not: ../../etc' create new --base ../../etc
    no 'Error: there is no base snapshot 000000000000' create new --base 000000000000
    no 'Error: --base is given once: a container has one base' create new --base 000000000000 --base 000000000000
    no 'Error: --rootfs names a base and --base a snapshot of one' create new --base 000000000000 --rootfs "$BASE"
    no 'Error: --rootfs names a base and --base a snapshot of one' create new --rootfs "$BASE" --base 000000000000
    no 'Error: the base is an image and no root filesystem: ' create new --rootfs "$W/foreign"
    no 'lightbox base import <dir> a' create new --rootfs "$W/foreign"
    no 'Error: this is an image and no root filesystem, and base import <dir> makes a base of one: ' base add "$W/foreign"
    if [ "$(id -u)" != 0 ]; then
        said=$(lb base import "$W/foreign" 2>&1) && { echo "an ordinary user imported a base"; bad=1; }
        [ "$said" = 'Error: lightbox base import must be run as root' ] || { echo "a whole image, as an ordinary user: $said"; bad=1; }
    fi
    [ "$before" = "$(kept_sum)" ] && [ ! -e "$C/new" ] || { echo "a refused command changed what lightbox keeps"; bad=1; }
    [ $bad -eq 0 ] || return 1

    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 EDIT=$3 C=$1/data/containers
        fail() { echo "FAILED: $*"; exit 1; }
        snapshots() { ls -A "$W/data/bases" 2>/dev/null | wc -l; }
        only_etc() { [ "$(cd "$C/$1/rootfs" && find . -type f | LC_ALL=C sort | paste -sd" ")" = "./etc/hostname ./etc/hosts ./etc/resolv.conf" ]; }

        echo "--- every layer of the image, one snapshot"
        "$LB" base import "$W/foreign" > "$W/base.out" 2>&1 || { cat "$W/base.out"; fail "base import"; }
        cat "$W/base.out"
        id=$(sed -n "s/^Base \([0-9a-f]\{12\}\) unpacked from the image sha256:[0-9a-f]\{64\}, 2 layers\$/\1/p" "$W/base.out")
        [ -n "$id" ] || fail "base import does not say what it made"
        grep -qx "Note: 1 device of the image.s was not made: a container.s devices are lightbox.s to give" "$W/base.out" ||
            fail "a device that was not made is not said"
        grep -qx "Note: the image names a command to start, which lightbox does not read: a container starts its /init.sh, where it has one" "$W/base.out" ||
            fail "the command of the image.s, which is not read, is not said"
        grep -qx "A container of it: lightbox create <name> --base $id" "$W/base.out" || fail "what makes a container of it is not said"
        S=$W/data/bases/$id/rootfs
        [ "$(cat "$S/added/file")" = second ] && [ "$(stat -c %a "$S/added/file")" = 640 ] && [ -e "$S/etc/passwd" ] ||
            fail "the snapshot is not the two layers: $(cd "$S" && find . | paste -sd" ")"
        [ ! -e "$S/bin/placeholder" ] && [ ! -e "$S/added/null" ] && [ -z "$(find "$S" -name ".wh.*" -o -type c -o -type b)" ] ||
            fail "a mark or a device of a layer is in the snapshot"
        [ "$(grep -c "^sha256:[0-9a-f]\{64\}\$" "$W/data/bases/$id/image")" = 2 ] || fail "the snapshot does not keep the layers it is"
        "$LB" base ls | grep -q "^$id  .*  sha256:[0-9a-f]\{64\} and the layers over it  -\$" || { "$LB" base ls; fail "base ls does not show it"; }

        echo "--- the same layers again, and compressed: that snapshot"
        had=$(snapshots)
        "$LB" base import "$W/foreign" > "$W/again.out" 2>&1 || { cat "$W/again.out"; fail "a second base import"; }
        grep -q "^Base $id is the image sha256:[0-9a-f]\{64\} already, 2 layers: nothing was unpacked\$" "$W/again.out" && [ "$(snapshots)" = "$had" ] ||
            fail "a second base import took a second snapshot: $(head -n 1 "$W/again.out")"
        cp -r "$W/foreign" "$W/gz" && python3 -I "$EDIT" "$W/gz" gzip || fail "image_edit gzip"
        "$LB" base import "$W/gz" > "$W/gz.out" 2>&1 || { cat "$W/gz.out"; fail "base import of compressed layers"; }
        grep -q "^Base $id is the image sha256:[0-9a-f]\{64\} already, 2 layers: nothing was unpacked\$" "$W/gz.out" && [ "$(snapshots)" = "$had" ] ||
            fail "the layers compressed are another snapshot: $(head -n 1 "$W/gz.out")"

        echo "--- a container of the snapshot"
        "$LB" create one --base "$id" > "$W/one.out" 2>&1 || { cat "$W/one.out"; fail "create --base"; }
        if [ -n "$(sed -n "s/^base=//p" "$C/one/.conf")" ]; then
            echo "an overlay mounts here"
            grep -qx "base=$id" "$C/one/.conf" && only_etc one || fail "the container does not overlay the snapshot it was given"
            "$LB" base ls | grep -q "^$id  .*  one\$" || fail "base ls does not show the container on its snapshot"
            said=$("$LB" base rm "$id" 2>&1) && fail "a snapshot was removed under its container"
            case $said in *"is used by: one"*) ;; *) fail "base rm: $said" ;; esac
            # and an import of that image is a container on it, with nothing of its own but what create writes
            "$LB" import "$W/foreign" three > "$W/three.out" 2>&1 || { cat "$W/three.out"; fail "import of the image"; }
            grep -qx "base=$id" "$C/three/.conf" && only_etc three && grep -q ", on the base snapshot $id, which was here\$" "$W/three.out" ||
                fail "an image that is no export of lightbox.s is not all snapshot: $(cat "$W/three.out")"
        else
            echo "no overlay mounts here: a copy of the snapshot"
            [ "$(cat "$C/one/rootfs/added/file")" = second ] && [ ! -e "$C/one/rootfs/bin/placeholder" ] || fail "the container is no copy of the snapshot"
        fi
        "$LB" create two --base "$id" --copy > "$W/two.out" 2>&1 || { cat "$W/two.out"; fail "create --base --copy"; }
        ! grep -q "^base=" "$C/two/.conf" && [ "$(cat "$C/two/rootfs/added/file")" = second ] && [ "$(cat "$C/two/rootfs/etc/hostname")" = two ] &&
            [ ! -e "$C/two/rootfs/bin/placeholder" ] || fail "a copy of the snapshot is not its files, with its own in /etc"
        [ "$(cat "$S/etc/hostname")" = web ] || fail "what create writes for a container went into the snapshot: $(cat "$S/etc/hostname")"
        said=$("$LB" import "$W/foreign" other --base "$id" 2>&1) && fail "import took --base"
        case $said in *"no --base"*) ;; *) fail "import --base: $said" ;; esac

        echo "--- a layer that is another than the configuration names"
        # where the snapshot of those layers is here: held to them all the same
        cp -r "$W/foreign" "$W/foreign-other" && python3 -I "$EDIT" "$W/foreign-other" gzip-other || fail "image_edit gzip-other"
        said=$("$LB" base import "$W/foreign-other" 2>&1) && fail "a compressed layer that is another tree was taken for the snapshot that is here"
        case $said in *"layer 1 of the image is, as it was unpacked, not the layer its configuration names"*) ;; *) fail "foreign-other: $said" ;; esac
        had=$(snapshots)
        cp -r "$W/image" "$W/other" && python3 -I "$EDIT" "$W/other" gzip-other || fail "image_edit gzip-other"
        said=$("$LB" base import "$W/other" 2>&1) && fail "a layer that unpacks to another was made a base"
        case $said in *"layer 1 of the image is, as it was unpacked, not the layer its configuration names"*"no snapshot of it is kept"*) ;; *) fail "gzip-other: $said" ;; esac
        [ "$(snapshots)" = "$had" ] || fail "a refused image left a snapshot, or half of one: $(ls -A "$W/data/bases" | paste -sd" ")"
    ' _ "$W" "$LB" "$IMAGE_EDIT" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -eq 0 ] && ! grep -q '^FAILED: ' "$W/ns.out"
}

# An import takes no work away (ROADMAP I.10). A container that is exported is
# of a line and at a generation of it, which the image carries and an import
# keeps; an export of a container that was started since is the next one.
# import --replace puts an image in the place of a container that is there
# only where the image continues the generation the container is, and the
# container was not started since that was written: it then has the image's
# files and generation, and its own name, address and settings. What the two
# are to each other otherwise is said, with both generations, and both are
# left; --force replaces all the same. No start is made here: that a
# container was started is the record a start leaves, made by hand.
t_import_replace() {
    need_python || return 77
    local rc
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 EDIT=$3 C=$1/data/containers
        fail() { echo "FAILED: $*"; exit 1; }
        started() { : > "$C/$1/.changed"; }
        gen() { cat "$C/$1/.generation"; }
        # what a refused replace says, the image, the container; and that it changed nothing
        no() {
            before=$(cd "$C/$3" && find . -printf "%p %y %s %T@\n" | LC_ALL=C sort)
            said=$("$LB" import "$2" "$3" --replace 2>&1) && fail "$3 was replaced by $2: $said"
            # the first as a pattern of grep, in which a dot stands for the apostrophe this script cannot have
            printf "%s\n" "$said" | grep -q "$1" || fail "replace of $3 by $2: $said"
            case $said in *"Both are left as they are. --force puts the image in its place all the same; lightbox export $3 <dir>"*) ;;
                *) fail "replace of $3 by $2 does not say what else can be done: $said" ;; esac
            [ "$before" = "$(cd "$C/$3" && find . -printf "%p %y %s %T@\n" | LC_ALL=C sort)" ] || fail "a refused replace changed $3"
        }

        "$LB" create web 10.0.0.2 --copy --mem 128M --vol "$W/vol:/data" > /dev/null && echo one > "$C/web/rootfs/work.txt" || fail "create"
        "$LB" export web "$W/g1" > /dev/null || fail "export"
        line=$(gen web | cut -d" " -f1)
        echo "--- the next generation is of a container that was started since"
        started web && echo two >> "$C/web/rootfs/work.txt" && "$LB" export web "$W/g2" > "$W/g2.out" || fail "a second export"
        grep -qx "Generation 2: the container was started since the one before" "$W/g2.out" && [ ! -e "$C/web/.changed" ] &&
            gen web | grep -qxE "$line 2 [0-9a-f]{8},[0-9a-f]{8}" || fail "not generation 2 with the first behind it: $(gen web)"

        echo "--- an import is the generation its image is"
        "$LB" import "$W/g1" there 10.0.0.9 --copy --mem 64M > /dev/null || fail "import"
        [ "$(gen there)" = "$line 1 $(gen web | cut -d" " -f3 | cut -d, -f1)" ] && [ ! -e "$C/there/.changed" ] || fail "the import is not generation 1 of the line: $(gen there)"

        echo "--- the image that continues it takes its place"
        conf=$(grep -v "^base=" "$C/there/.conf")
        "$LB" import "$W/g2" there --replace > "$W/replace.out" 2>&1 || { cat "$W/replace.out"; fail "replace"; }
        cat "$W/replace.out"
        grep -qx "Container .there. replaced: generation 2 in the place of generation 1" "$W/replace.out" &&
            grep -qx "Its address, its limits and its settings are as they were" "$W/replace.out" || fail "replace does not say what it did"
        [ "$(cat "$C/there/rootfs/work.txt" | paste -sd" ")" = "one two" ] && [ "$(cat "$C/there/rootfs/etc/hostname")" = there ] &&
            grep -qx "10.0.0.9	there" "$C/there/rootfs/etc/hosts" && ! grep -q "	web\$" "$C/there/rootfs/etc/hosts" || fail "its files are not the image.s, with its own name"
        [ "$(gen there)" = "$(gen web)" ] && [ "$(cat "$C/there/.ip")" = 10.0.0.9 ] && [ "$conf" = "$(grep -v "^base=" "$C/there/.conf")" ] &&
            grep -qx "mem=64M" "$C/there/.conf" || fail "its generation is not the image.s, or its address and settings are not its own"
        [ -z "$(ls -A "$C/there" | grep -v -x -e .conf -e .generation -e .ip -e .resolv -e rootfs)" ] || fail "a replace left: $(ls -A "$C/there" | paste -sd" ")"
        said=$("$LB" import "$W/g2" there --replace 2>&1) || fail "the same image again: $said"
        case $said in "Container "*" is generation 2 of its line already, as the image is, and was not started since: nothing was replaced") ;;
            *) fail "the same image again: $said" ;; esac

        echo "--- what is refused, with both generations"
        no "the container is generation 2, which continues generation 1, the image.s: the container is the newer" "$W/g1" web
        started there
        no "the container was started since generation 2, which the image is: the container is the newer" "$W/g2" there
        "$LB" export there "$W/g3-there" > /dev/null && started web && "$LB" export web "$W/g3-web" > /dev/null || fail "exports of both"
        no "the container is generation 3 and the image generation 3 of one line, and neither continues the other: each has what the other has not" "$W/g3-there" web
        "$LB" import "$W/g2" behind --copy > /dev/null && started behind || fail "import"
        no "the container was started since generation 2, and the image is generation 3, which continues generation 2 too: each has what the other has not" "$W/g3-web" behind
        "$LB" create fresh --copy > /dev/null || fail "create"
        no "the container was never exported or imported, so that nothing says the image continues it" "$W/g2" fresh
        "$LB" export fresh "$W/fresh" > /dev/null || fail "export"
        no "the image is generation 1 of another container.s line than this one is of" "$W/fresh" web
        cp -r "$W/g2" "$W/foreign" && python3 -I "$EDIT" "$W/foreign" no-annotations || fail "image_edit"
        no "the image names no generation of a container.s, so that nothing says it continues this one" "$W/foreign" web
        cp -r "$W/g2" "$W/half" && python3 -I "$EDIT" "$W/half" annotation ac.ozkr.lightbox.generation=many || fail "image_edit"
        no "the image names no generation" "$W/half" web
        case $said in *"Note: the image says ac.ozkr.lightbox.generation with what is no such value, which is not taken"*) ;; *) fail "a generation that is no number is not said: $said" ;; esac

        echo "--- what goes with --replace, and what it needs"
        for words in "--force" "--replace --mem 1G" "10.0.0.7 --replace" "--replace --copy"; do
            # shellcheck disable=SC2086
            said=$("$LB" import "$W/g3-there" web $words 2>&1) && fail "import web $words was taken"
            case $said in *"--force goes with --replace"*|*"nothing goes with it but --force, and this does not: "*) ;; *) fail "import web $words: $said" ;; esac
        done
        said=$("$LB" import "$W/g2" nosuch --replace 2>&1) && fail "a container that is not there was replaced"
        case $said in *"container does not exist: nosuch"*) ;; *) fail "no such container: $said" ;; esac
        : > "$C/fresh/.creating"
        said=$("$LB" import "$W/g2" fresh --replace --force 2>&1) && fail "a half-made container was replaced"
        case $said in *"was not created completely, and no image is put in its place"*) ;; *) fail "a half-made container: $said" ;; esac
        python3 -I -c "import os, sys; os.unlink(sys.argv[1])" "$C/fresh/.creating"

        echo "--- --force replaces all the same"
        "$LB" import "$W/g3-there" web --replace --force > "$W/force.out" 2>&1 || { cat "$W/force.out"; fail "replace --force"; }
        grep -qx "Container .web. replaced: generation 3 in the place of generation 3" "$W/force.out" && [ "$(gen web)" = "$(gen there)" ] &&
            [ "$(cat "$C/web/rootfs/etc/hostname")" = web ] && grep -qx "mem=128M" "$C/web/.conf" && grep -q "^vol=" "$C/web/.conf" ||
            fail "--force did not put the image in the place of the container, with its settings kept: $(cat "$W/force.out")"
        "$LB" import "$W/foreign" fresh --replace --force > "$W/foreign.out" 2>&1 || { cat "$W/foreign.out"; fail "replace --force by an image of no line"; }
        [ ! -e "$C/fresh/.generation" ] && [ "$(cat "$C/fresh/rootfs/work.txt" | paste -sd" ")" = "one two" ] || fail "an image of no line left the container of one"

        echo "--- an image that cannot be unpacked leaves the container as it was"
        cp -r "$W/g3-web" "$W/broken" && python3 -I "$EDIT" "$W/broken" gzip-other || fail "image_edit"
        # but for the time of its directory, in which the image.s files were for a while
        before=$(cd "$C/behind" && find . -mindepth 1 -printf "%p %y %s %T@\n" | LC_ALL=C sort)
        said=$("$LB" import "$W/broken" behind --replace --force 2>&1) && fail "an image that is not what it says was put in the place of a container"
        case $said in *"not the layer its configuration names"*"the image was not unpacked, and the container is as it was: behind"*) ;; *) fail "a layer that is another: $said" ;; esac
        [ "$before" = "$(cd "$C/behind" && find . -mindepth 1 -printf "%p %y %s %T@\n" | LC_ALL=C sort)" ] || fail "a replace that failed changed the container"
    ' _ "$W" "$LB" "$IMAGE_EDIT" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -eq 0 ] && ! grep -q '^FAILED: ' "$W/ns.out"
}

# An export into the directory of the one before (ROADMAP I.13). The
# directory holds the image of an export of the container before, and
# nothing else: the new image takes its place, and is the image a new
# directory gets. The layer that is the snapshot is in the directory already
# and is not read again, which a snapshot that was changed since shows: its
# layer is the one it was, and nothing is said of the change. No blob that
# only the image before named is left. A directory with a file that is no
# part of an image, an image with a blob that is not what it is named by, one
# that export did not write so, the image of another container and a newer
# one of this container's line are refused and left as they were, to the
# time of every file; and so is the image before when the export fails.
t_export_again() {
    need_python || return 77
    local rc
    mkdir -p "$BASE/lib" && echo keep > "$BASE/lib/keep" || return 1
    # shellcheck disable=SC2016     # the script is for the shell in the namespace
    HOME="$W/home" LIGHTBOX_CONFIG="$CONF" unshare -r --mount -- bash -c '
        W=$1 LB=$2 EDIT=$3 CHECK=$4 C=$1/data/containers
        fail() { echo "FAILED: $*"; exit 1; }
        listing() { (cd "$1" && find . -printf "%p %y %s %T@\n" | LC_ALL=C sort); }
        # what a refused export says, as a pattern of grep, the container, the directory, which is left as it was
        no() {
            before=$(listing "$3")
            said=$("$LB" export "$2" "$3" 2>&1) && fail "$2 was exported into $3: $said"
            printf "%s\n" "$said" | grep -q "$1" || fail "export of $2 into $3: $said"
            [ "$before" = "$(listing "$3")" ] || fail "an export that was refused with [$1] changed $3"
        }
        # a copy, made an overlay of a snapshot by its .conf, as no overlay is mounted for this
        "$LB" create web 10.0.0.2 --copy > /dev/null && id=$("$LB" base add "$W/base" | sed -n "s/^Base \([0-9a-f]\{12\}\) taken of .*/\1/p") &&
            [ -n "$id" ] && echo "base=$id" >> "$C/web/.conf" && mv "$C/web/rootfs" "$C/web/copy" && mkdir -p "$C/web/rootfs/etc" &&
            cp "$C/web/copy/etc/hostname" "$C/web/rootfs/etc/hostname" || fail "no container that overlays a snapshot"
        "$LB" export web "$W/img" > /dev/null || fail "export"
        first=$(python3 -I "$CHECK" "$W/img" | sed -n "s/^layer 1 //p")

        echo "--- into the directory of the export before: the image a new directory gets"
        echo more > "$C/web/rootfs/more.txt" || fail "no file"
        "$LB" export web "$W/img" > "$W/again.out" 2>&1 || { cat "$W/again.out"; fail "a second export into the directory"; }
        cat "$W/again.out"
        grep -q "^In the place of the image of the export before: the layer that is the base snapshot was there, and\$" "$W/again.out" ||
            fail "the second export does not say that the snapshot was not written again"
        "$LB" export web "$W/new" > /dev/null && diff -r "$W/img" "$W/new" || fail "it is another image than a new directory gets"
        [ "$(ls -A "$W/img" | paste -sd" ")" = "blobs index.json oci-layout" ] && [ "$(ls -A "$W/img/blobs/sha256" | wc -l)" = 4 ] ||
            fail "a blob that the image does not name is left: $(ls -A "$W/img/blobs/sha256" | paste -sd" ")"

        echo "--- the snapshot is not read again"
        echo changed > "$W/data/bases/$id/rootfs/lib/keep" && echo third > "$C/web/rootfs/third.txt" || fail "no change"
        "$LB" export web "$W/img" > "$W/third.out" 2>&1 || { cat "$W/third.out"; fail "a third export into the directory"; }
        ! grep -q "^Warning" "$W/third.out" || fail "the snapshot was read: $(grep "^Warning" "$W/third.out")"
        out=$(python3 -I "$CHECK" "$W/img") || fail "the directory is no image any more: $out"
        [ "$(printf "%s\n" "$out" | sed -n "s/^layer 1 //p")" = "$first" ] && printf "%s\n" "$out" | grep -q "^entry 2 file .* third.txt\$" &&
            [ "$(ls -A "$W/img/blobs/sha256" | wc -l)" = 4 ] || fail "not the layer that was there and, over it, the files of now"
        "$LB" export web "$W/read" 2>&1 | grep -q "^Warning: the base snapshot $id is another layer than it was" ||
            fail "a new directory, for which the snapshot is read, does not say that it was changed"

        echo "--- what is refused, and left as it was"
        : > "$W/img/stray" && no "this one is not empty" web "$W/img" && python3 -I -c "import os, sys; os.unlink(sys.argv[1])" "$W/img/stray" || fail "stray"
        : > "$W/img/blobs/sha256/stray" && no "holds another image, or more than one" web "$W/img" &&
            python3 -I -c "import os, sys; os.unlink(sys.argv[1])" "$W/img/blobs/sha256/stray" || fail "stray blob"
        cp -r "$W/img" "$W/bad" && python3 -I "$EDIT" "$W/bad" byte layer || fail "image_edit"
        no "a layer is not what it is named by: its bytes have another SHA-256" web "$W/bad"
        cp -r "$W/img" "$W/gz" && python3 -I "$EDIT" "$W/gz" gzip || fail "image_edit"
        no "holds another image, or more than one" web "$W/gz"
        cp -r "$W/img" "$W/foreign" && python3 -I "$EDIT" "$W/foreign" no-annotations || fail "image_edit"
        no "holds another image, or more than one" web "$W/foreign"
        "$LB" create other --copy > /dev/null || fail "create"
        no "the directory holds the image of another container, which export does not write over" other "$W/img"
        "$LB" import "$W/img" there --copy > /dev/null && : > "$C/there/.changed" && "$LB" export there "$W/newer" > /dev/null || fail "no newer generation"
        no "an image of this container.s line that the container does not continue" web "$W/newer"
        # And an export that fails while it writes leaves the image before:
        # every file of it as it was. The layer it began was in the directory
        # of the blobs for a while, whose own time is that of now.
        : > "$C/web/rootfs/.wh.x"
        files() { (cd "$W/img" && find . -type f -printf "%p %s %T@\n" | LC_ALL=C sort); }
        before=$(files)
        said=$("$LB" export web "$W/img" 2>&1) && fail "a tree that is no layer was exported: $said"
        printf "%s\n" "$said" | grep -q ": .wh.x: has a name that begins with .wh." || fail "a tree that is no layer: $said"
        [ "$before" = "$(files)" ] && [ "$(ls -A "$W/img/blobs/sha256" | wc -l)" = 4 ] || fail "an export that failed changed the image before, or left a file"
        python3 -I -c "import os, sys; os.unlink(sys.argv[1])" "$C/web/rootfs/.wh.x"
        python3 -I "$CHECK" "$W/img" > /dev/null || fail "after an export that failed the directory is no image"

        echo "--- a copy, which is one layer"
        "$LB" export other "$W/one" > /dev/null && echo more > "$C/other/rootfs/more.txt" && "$LB" export other "$W/one" > "$W/one.out" 2>&1 ||
            { cat "$W/one.out"; fail "a second export of a copy into the directory"; }
        grep -qx "In the place of the image of the export before" "$W/one.out" && [ "$(ls -A "$W/one/blobs/sha256" | wc -l)" = 3 ] &&
            python3 -I "$CHECK" "$W/one" | grep -q "^entry 1 file .* more.txt\$" || fail "a copy was not exported in the place of its image before"
    ' _ "$W" "$LB" "$IMAGE_EDIT" "$IMAGE_CHECK" > "$W/ns.out" 2>&1
    rc=$?
    cat "$W/ns.out"
    [ $rc -eq 0 ] && ! grep -q '^FAILED: ' "$W/ns.out"
}

check 'export writes a container as an image whose every blob is what it is named by' t_export_image
check 'export refuses what would be no image, and leaves nothing of one'  t_export_refusals
check 'an overlay is exported as its snapshot and, over it, its own files and marks' t_export_overlay
check 'import refuses what is no image, or another than it is named, before anything is made' t_import_refusals
check 'import makes of an image the container that was exported, and of a compressed one too' t_import_round_trip
check 'an image goes to a registry and back with skopeo, its base sent once, and is the same container' t_registry
check "base import makes one snapshot of an image's layers, and create --base a container of it" t_base_import
check 'import --replace puts an image in the place of the container it continues, and of no other' t_import_replace
check 'export into the directory of the export before writes the new image, and no snapshot again' t_export_again

summary validation
