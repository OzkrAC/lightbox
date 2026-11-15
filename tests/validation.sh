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
sandbox() {
    W="$ROOT/$1"
    C="$W/data/containers"
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

lb() { HOME="$W/home" "$LB" "$@"; }

# Succeeds when the command fails. Output is kept for the report.
refused() { ! "$@"; }

conf_has()  { grep -qxF -- "$2" "$C/$1/.conf"; }
vol_count() { grep -c '^vol=' "$C/$1/.conf"; }
mode_of()   { stat -c %a "$1"; }
tree_sum()  { (cd "$1" && find . -print0 | sort -z | xargs -0 stat -c '%n %F %s %Y' | sha256sum); }

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
    [ "$(cat "$C/web/.ip")" = 10.0.0.2 ]
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
    refused lb create waytoolongname1 10.0.0.2 &&
    [ -z "$(ls -A "$C")" ]
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

t_cpu_must_be_whole() {
    refused lb create web 10.0.0.2 --cpu 0.5
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

t_unknown_command_prints_usage() {
    usage=$(lb frobnicate 2>&1)
    [ $? -ne 0 ] && printf '%s\n' "$usage" | grep -q '^Usage: lightbox'
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

t_addvol_refuses_a_destination_twice() {
    lb create web 10.0.0.2 --vol "$W/vol:/data" || return 1
    mkdir -p "$W/other"
    refused lb add-vol web "$W/other:/data"
}

t_duplicate_address_refused() {
    lb create a 10.0.0.9 || return 1
    refused lb create b 10.0.0.9
}
t_gateway_address_refused()   { refused lb create a 10.0.0.1; }
t_network_address_refused()   { refused lb create a 10.0.0.0; }
t_broadcast_address_refused() { refused lb create a 10.0.0.255; }

# A value is stored as given or refused, never shortened.
t_pids_value_not_cut() {
    lb create web 10.0.0.2 --pids 123456789 || return 0
    grep '^pids=' "$C/web/.conf"
    conf_has web 'pids=123456789'
}
t_cpu_value_not_cut() {
    lb create web 10.0.0.2 --cpu 1024 || return 0
    grep '^cpu=' "$C/web/.conf"
    conf_has web 'cpu=1024'
}
t_mem_must_be_a_size()         { refused lb create web 10.0.0.2 --mem not-a-size; }
t_oom_score_must_be_a_number() { refused lb create web 10.0.0.2 --oom-score abc; }
t_number_with_trailing_text_refused() { refused lb create web 10.0.0.2 --oom-score 12abc; }

t_missing_value_is_named() {
    msg=$(lb create web 10.0.0.2 --mem 2>&1) && return 1
    printf '%s\n' "$msg"
    case $msg in *'unknown option'*) return 1 ;; esac
    case $msg in *--mem*) return 0 ;; esac
    return 1
}

# A record of a process that no longer exists. Listing must not rewrite it.
stale_record() {
    lb create web 10.0.0.2 || return 1
    sleep 0 & dead=$!
    wait "$dead"
    printf '%s' "$dead" > "$C/web/.pid"
    printf '12345' > "$C/web/.pid_start"
    printf 'running\n' > "$C/web/.state"
}
t_ls_writes_nothing() {
    stale_record || return 1
    before=$(tree_sum "$C/web")
    lb ls >/dev/null
    [ -e "$C/web/.pid" ] || echo ".pid was deleted"
    echo "state is now: $(cat "$C/web/.state")"
    [ "$before" = "$(tree_sum "$C/web")" ]
}
t_inspect_writes_nothing() {
    stale_record || return 1
    before=$(tree_sum "$C/web")
    lb inspect web >/dev/null
    [ -e "$C/web/.pid" ] || echo ".pid was deleted"
    echo "state is now: $(cat "$C/web/.state")"
    [ "$before" = "$(tree_sum "$C/web")" ]
}

# PID 1 is alive and belongs to root. For an ordinary user kill(1, 0) fails
# with EPERM, which is not "no such process".
t_other_users_process_is_not_gone() {
    [ "$(id -u)" -ne 0 ] || return 77
    lb create web 10.0.0.2 || return 1
    printf '1' > "$C/web/.pid"
    awk '{ printf "%s", $22 }' /proc/1/stat > "$C/web/.pid_start"
    printf 'running\n' > "$C/web/.state"
    before=$(tree_sum "$C/web")
    json=$(lb ls --json)
    printf '%s\n' "$json"
    lb inspect web | grep -x 'running: yes' || return 1
    printf '%s' "$json" | grep -q '"status":"running"' && [ "$before" = "$(tree_sum "$C/web")" ]
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
    before=$(tree_sum "$W/data")
    bad=0
    for words in setup 'start web' 'stop web' 'exec web /bin/true'; do
        # shellcheck disable=SC2086
        msg=$(lb $words 2>&1) && { echo "lightbox $words succeeded"; bad=1; }
        echo "lightbox $words: $msg"
        [ "$msg" = "Error: lightbox ${words%% *} must be run as root" ] || bad=1
    done
    [ "$before" = "$(tree_sum "$W/data")" ] || { echo "something under $W/data changed"; bad=1; }
    [ "$(mode_of "$C")" = 755 ] || { echo "setup changed the mode of container_dir"; bad=1; }
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

# A record is a file anyone with access can damage. Whatever it holds, the
# listing stays JSON and gives the value back unchanged.
t_ls_json_escapes_values() {
    command -v python3 >/dev/null 2>&1 || { echo "no python3 to decode JSON with"; return 77; }
    lb create web 10.0.0.2 || return 1
    printf '1"2\\3\t4\001' > "$C/web/.ip"
    json=$(lb ls --json)
    printf '%s\n' "$json"
    printf '%s' "$json" | json_valid || return 1
    [ "$(printf '%s' "$json" | json_field ip | od -An -c | tr -s ' ')" = "$(printf '1"2\\3\t4\001' | od -An -c | tr -s ' ')" ]
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
    mkdir "$C/has space" "$C/far-too-long-for-a-name" "$C/.hidden"
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

t_inspect_shows_volumes_and_links() {
    lb create db 10.0.0.3 && lb create web 10.0.0.2 --vol "$W/vol:/data:ro" --link db || return 1
    report=$(lb inspect web)
    printf '%s\n' "$report"
    printf '%s\n' "$report" | grep -q '/data' && printf '%s\n' "$report" | grep -Eq 'link.*db'
}

t_config_strips_carriage_returns() {
    printf 'bridge = br9\r\n' >> "$CONF"
    lb doctor 2>/dev/null | grep -x 'bridge: br9'
}
t_config_strips_inline_comments() {
    printf 'bridge = br9 # the test bridge\n' >> "$CONF"
    lb doctor 2>/dev/null | grep -x 'bridge: br9'
}
t_config_reports_unknown_keys() {
    printf 'defualt_mem = 1G\n' >> "$CONF"
    lb doctor 2>&1 >/dev/null | grep -q 'defualt_mem'
}

t_help_exits_zero() {
    usage=$(lb --help 2>&1) || return 1
    printf '%s\n' "$usage" | grep -q '^Usage: lightbox'
}

# rm with two names removes both, or refuses and removes neither.
t_rm_handles_every_argument() {
    lb create a 10.0.0.2 && lb create b 10.0.0.3 || return 1
    if lb rm a b; then
        [ ! -e "$C/a" ] && [ ! -e "$C/b" ]
    else
        [ -e "$C/a" ] && [ -e "$C/b" ]
    fi
}

# Without root, start says so and leaves the container's state alone.
t_start_without_root_is_a_clean_error() {
    [ "$(id -u)" -ne 0 ] || return 77
    lb create web 10.0.0.2 || return 1
    before=$(cat "$C/web/.state")
    msg=$(lb start web 2>&1) && return 1
    printf '%s\n' "$msg" | head -5
    echo "state: $before -> $(cat "$C/web/.state")"
    printf '%s\n' "$msg" | grep -qi 'root' && [ "$(cat "$C/web/.state")" = "$before" ]
}

# start reads its options before it touches anything, so a mistyped one
# changes nothing, with or without root.
t_start_options_are_checked() {
    lb create web 10.0.0.2 || return 1
    before=$(tree_sum "$C/web")
    said() { msg=$(lb start web "$@" 2>&1) && { echo "start web $* succeeded"; return 1; }; echo "start web $*: $msg"; }
    said -t soon   && case $msg in *soon*) ;; *) return 1 ;; esac || return 1
    said -t 86401  && case $msg in *86401*) ;; *) return 1 ;; esac || return 1
    said -t -1     && case $msg in *'number of seconds'*) ;; *) return 1 ;; esac || return 1
    said -t        && case $msg in *'number of seconds'*) ;; *) return 1 ;; esac || return 1
    said --bogus   && case $msg in *'unknown option'*--bogus*) ;; *) return 1 ;; esac || return 1
    said another   && case $msg in *'unexpected argument'*another*) ;; *) return 1 ;; esac || return 1
    [ "$before" = "$(tree_sum "$C/web")" ] || { echo "the container's records changed"; return 1; }
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
    before=$(tree_sum "$C/web")
    said() { msg=$(lb stop web "$@" 2>&1) && { echo "stop web $* succeeded"; return 1; }; echo "stop web $*: $msg"; }
    said -t soon   && case $msg in *soon*) ;; *) return 1 ;; esac || return 1
    said -t        && case $msg in *'number of seconds'*) ;; *) return 1 ;; esac || return 1
    said --bogus   && case $msg in *'unknown option'*--bogus*) ;; *) return 1 ;; esac || return 1
    said another   && case $msg in *'unexpected argument'*another*) ;; *) return 1 ;; esac || return 1
    # with options that are fine it goes on: to who runs it, and as root to the container, which is not running
    said -t 3      && case $msg in *'must be run as root'*|*'not running'*) ;; *) return 1 ;; esac || return 1
    [ "$before" = "$(tree_sum "$C/web")" ] || { echo "the container's records changed"; return 1; }
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
    followed=$(HOME="$W/home" timeout 5 "$LB" logs web -f) || { echo "logs -f of a stopped container did not end by itself"; return 1; }
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
    printf '%s' "$holder" > "$C/web/.pid"
    awk '{ printf "%s", $22 }' "/proc/$holder/stat" > "$C/web/.pid_start"
    printf 'running\n' > "$C/web/.state"
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
    HOME="$W/home" "$LB" create web 10.0.0.2 <&- >&- 2>&- || { echo "create failed with status $?"; return 1; }
    echo "state: $(cat "$C/web/.state"), ip: $(cat "$C/web/.ip")"
    [ "$(cat "$C/web/.state")" = stopped ] && [ "$(cat "$C/web/.ip")" = 10.0.0.2 ] && conf_has web 'mem=256M' || return 1
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
    echo "modes: dir $(mode_of "$C/web"), .conf $(mode_of "$C/web/.conf"), .ip $(mode_of "$C/web/.ip"), .state $(mode_of "$C/web/.state")"
    [ "$(mode_of "$C/web")" = 700 ] && [ "$(mode_of "$C/web/.conf")" = 600 ] &&
    [ "$(mode_of "$C/web/.ip")" = 600 ] && [ "$(mode_of "$C/web/.state")" = 600 ] &&
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
check 'create refuses malformed and out-of-subnet addresses' t_create_refuses_bad_addresses
check 'volume specifications are validated'                 t_volume_spec_rules
check 'an unknown option is refused'                        t_unknown_option_refused
check '--cpu takes whole numbers only'                      t_cpu_must_be_whole
check 'ls lists containers'                                 t_ls_lists_containers
check 'ls --json prints JSON'                               t_ls_json_is_json
check 'inspect prints name, address and state'              t_inspect_basics
check 'commands fail for a container that does not exist'   t_missing_container_is_an_error
check 'add-vol appends a volume'                            t_addvol_appends
check 'rm removes the container directory'                  t_rm_removes
check 'stop and exec refuse a stopped container'            t_stopped_container_cannot_stop_or_exec
check 'an unknown command prints usage and fails'           t_unknown_command_prints_usage
check 'ls writes nothing'                                   t_ls_writes_nothing
check 'inspect writes nothing'                              t_inspect_writes_nothing
check 'a process owned by another user is not gone'         t_other_users_process_is_not_gone
check 'a dead container is shown as exited'                 t_dead_container_shown_as_exited
check 'setup, start, stop and exec ask for root first'      t_root_is_asked_for_first
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

xfail FS-addvol-checks     'add-vol refuses a destination twice'             t_addvol_refuses_a_destination_twice
xfail NET-ip-validate      'a duplicate address is refused'                  t_duplicate_address_refused
xfail NET-ip-validate      'the gateway address is refused'                  t_gateway_address_refused
xfail NET-ip-validate      'the network address is refused'                  t_network_address_refused
xfail NET-ip-validate      'the broadcast address is refused'                t_broadcast_address_refused
xfail CLI-opt-values       '--pids is stored whole or refused'               t_pids_value_not_cut
xfail CLI-opt-values       '--cpu is stored whole or refused'                t_cpu_value_not_cut
xfail CLI-opt-values       '--mem must be a size'                            t_mem_must_be_a_size
xfail CFG-parse-int        '--oom-score must be a number'                    t_oom_score_must_be_a_number
xfail CFG-parse-int        'a number with trailing text is refused'          t_number_with_trailing_text_refused
xfail CLI-missing-value    'an option without its value is named'            t_missing_value_is_named
check 'ls --json stays JSON next to an odd directory name'    t_ls_json_escapes_names
check 'ls --json escapes whatever a record holds'             t_ls_json_escapes_values
check 'ls --json gives pid as null for a stopped container'   t_ls_json_pid_is_null_when_stopped
check 'ls is sorted by name'                                  t_ls_is_sorted
check 'ls lists only directories with a container name'       t_ls_lists_only_containers
xfail CLI-inspect          'inspect shows volumes and links'                 t_inspect_shows_volumes_and_links
xfail CFG-parse            'configuration: carriage returns are stripped'    t_config_strips_carriage_returns
xfail CFG-parse            'configuration: inline comments are stripped'     t_config_strips_inline_comments
xfail CFG-parse            'configuration: unknown keys are reported'        t_config_reports_unknown_keys
xfail CLI-help             '--help exits 0'                                  t_help_exits_zero
xfail CLI-extra-args       'rm handles every argument or none'               t_rm_handles_every_argument
check 'start without root is a clean error'                   t_start_without_root_is_a_clean_error

summary validation
