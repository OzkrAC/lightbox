#!/usr/bin/env bash
# Unprivileged functional checks of lightbox's metadata/CLI paths.
# Everything is confined to the scratchpad: HOME, container dir, rootfs and cgroup root are all redirected.
set -u
S=/tmp/claude-1000/-home-c0dr-ozkr-ac-endeavor-lightbox/ee7507ce-59b0-47cb-9e8f-cde3b30f88a2/scratchpad
LB="$S/build/lightbox/lightbox"
T="$S/sandbox"
rm -rf "$T"; mkdir -p "$T/home/.config/lightbox" "$T/data/containers" "$T/base/etc" "$T/base/bin" "$T/base/dev" "$T/fakecg" "$T/vols"
echo "root:x:0:0:root:/root:/bin/sh" > "$T/base/etc/passwd"
echo "hello" > "$T/base/bin/placeholder"

cat > "$T/home/.config/lightbox/lightbox.conf" <<EOF
lightbox_dir = $T/data
rootfs = $T/base
container_dir = $T/data/containers
cgroup_root = $T/fakecg
EOF

lb() { HOME="$T/home" "$LB" "$@"; }
C="$T/data/containers"
hr() { printf '\n──────── %s ────────\n' "$*"; }

hr "T1  create with 6 moderately long volumes: is .conf complete?"
args=()
for i in 1 2 3 4 5 6; do
  src="$T/vols/application-data-directory-number-$i/with/a/reasonably/deep/nested/path/segment"
  mkdir -p "$src"
  args+=(--vol "$src:/srv/application/mounted/volume/number/$i/with/a/reasonably/deep/path:ro")
done
lb create t1 10.0.0.2 "${args[@]}"; echo "exit=$?"
echo "requested volumes: 6   vol= lines stored: $(grep -c '^vol=' "$C/t1/.conf")   .conf bytes: $(stat -c %s "$C/t1/.conf")"
echo "last line of .conf (should end in ':ro'):"; tail -c 120 "$C/t1/.conf"; echo "<EOF>"

hr "T2  IP sanity: duplicate IP, gateway IP, network and broadcast addresses"
lb create dup1 10.0.0.9 >/dev/null; echo "dup1 10.0.0.9   exit=$?"
lb create dup2 10.0.0.9 >/dev/null; echo "dup2 10.0.0.9   exit=$?  (same IP as dup1)"
lb create gwip 10.0.0.1 >/dev/null; echo "gwip 10.0.0.1   exit=$?  (the bridge/gateway address)"
lb create net0 10.0.0.0 >/dev/null; echo "net0 10.0.0.0   exit=$?  (network address)"
lb create bcast 10.0.0.255 >/dev/null; echo "bcast 10.0.0.255 exit=$? (broadcast address)"

hr "T3  option value handling"
lb create v1 10.0.0.20 --pids 123456789 --cpu 1024 --oom-score abc --mem 'not-a-size' >/dev/null; echo "exit=$?"
echo "asked: --pids 123456789 --cpu 1024 --oom-score abc --mem not-a-size ; stored:"; sed 's/^/    /' "$C/v1/.conf"
lb create v2 10.0.0.21 --mem; echo "^ '--mem' with no value, exit=$?"
lb create v3 10.0.0.22 --cpu 0.5; echo "^ fractional cpu, exit=$?"

hr "T4  add-vol growth beyond reader buffers (readers use 2048-byte buffers, add-vol 4096)"
lb create t4 10.0.0.30 >/dev/null
n=0
for i in $(seq 1 40); do
  src="$T/vols/v$i/some/host/directory/for/volume/number/$i/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  mkdir -p "$src"
  if lb add-vol t4 "$src:/mnt/volume/number/$i/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:ro" >/dev/null 2>&1; then n=$((n+1)); fi
done
echo "add-vol calls that reported success: $n (compile-time MAX_VOLS for create is 16)"
echo ".conf bytes: $(stat -c %s "$C/t4/.conf")   vol= lines actually in file: $(grep -c '^vol=' "$C/t4/.conf")"
echo "re-adding volume #30 (already added) reports:"; i=30
lb add-vol t4 "$T/vols/v$i/some/host/directory/for/volume/number/$i/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:/mnt/volume/number/$i/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:ro" 2>&1 | cut -c1-60
echo "lines not matching a complete 'vol=...:ro' entry (corruption check):"
grep '^vol=' "$C/t4/.conf" | grep -vc ':ro$'

hr "T5  read-only commands and runtime state (run as non-root)"
lb create t5 10.0.0.40 >/dev/null
# Simulate a 'running' record whose PID belongs to another user (pid 1), with its true start time.
st=$(awk '{print $22}' /proc/1/stat)
printf '1' > "$C/t5/.pid"; printf '%s' "$st" > "$C/t5/.pid_start"; printf 'running\n' > "$C/t5/.state"
echo "before ls:  .pid=$(cat "$C/t5/.pid")  .state=$(cat "$C/t5/.state")"
lb ls --json > "$T/ls.json" 2> "$T/ls.err"; echo "ls --json exit=$?"
echo "after  ls:  .pid=$( [ -e "$C/t5/.pid" ] && cat "$C/t5/.pid" || echo '<deleted>')  .state=$(cat "$C/t5/.state")"
python3 -c "import json,sys; json.load(open('$T/ls.json')); print('ls --json: valid JSON')" 2>&1 | tail -1

hr "T6  JSON escaping of names found on disk"
mkdir -p "$C/we\"ird"
lb ls --json | python3 -c "import json,sys; json.load(sys.stdin); print('valid JSON')" 2>&1 | tail -1
rmdir "$C/we\"ird"

hr "T7  rootfs configured as a symlink to the base image"
ln -s "$T/base" "$T/base-current"
lb create t7 10.0.0.50 --rootfs "$T/base-current" >/dev/null; echo "exit=$?"
echo "container rootfs is: $(stat -c '%F' "$C/t7/rootfs")  -> $(readlink "$C/t7/rootfs" 2>/dev/null)"
echo "resolv.conf written into the shared base image? $( [ -e "$T/base/etc/resolv.conf" ] && echo YES || echo no)"
rm -f "$T/base/etc/resolv.conf"

hr "T8  empty rootfs is accepted at create time"
mkdir -p "$T/empty"; lb create t8 10.0.0.51 --rootfs "$T/empty"; echo "exit=$?"

hr "T9  inspect: are volumes / links shown?"
lb create t9 10.0.0.60 --vol "$T/vols:/data:ro" --link t1 >/dev/null
lb inspect t9 | grep -ciE 'vol|link' | sed 's/^/lines mentioning vol or link: /'

hr "T10 global config parsing: CRLF, inline comment, unknown key"
cp "$T/home/.config/lightbox/lightbox.conf" "$T/conf.bak"
printf 'bridge = br9 # my bridge\r\nsubnet = 10.9.0.0/24\r\ndefualt_mem = 1G\r\n' >> "$T/home/.config/lightbox/lightbox.conf"
lb doctor 2>/dev/null | grep -E '^(bridge|subnet):' | cat -A
cp "$T/conf.bak" "$T/home/.config/lightbox/lightbox.conf"

hr "T11 help / multi-arg handling"
lb --help >/dev/null 2>&1; echo "lightbox --help         exit=$?"
lb create --help 2>&1 | head -1
lb rm dup1 dup2 >/dev/null; echo "rm dup1 dup2 -> dup2 still exists? $( [ -d "$C/dup2" ] && echo YES || echo no)"

hr "T12 start without root: what does the user see?"
lb start t5 2>&1 | head -6; echo "exit=${PIPESTATUS[0]}"
echo "state afterwards: $(cat "$C/t5/.state")"
