# lightbox

A minimal, secure Linux container runtime: one static binary of about 150 KB, with no libc, built on [lightc](https://github.com/OscarAC/lightc). It makes the Linux system calls it needs itself, a container's network among them, and runs a few host tools for the rest: `iptables` or `nft` for the firewall, and `cp` and `rm` for a container's files (see [How it works](#how-it-works)).

## Prerequisites

- **Kernel:** Linux 5.10 or later, the floor lightc sets, with namespaces and cgroup v2 offering the `cpu`, `memory` and `pids` controllers, and `io` for `--io-max`. For the network: bridge and veth; with iptables, `iptables` with the conntrack, physdev and MASQUERADE matches and targets, and `br_netfilter` with `net.bridge.bridge-nf-call-iptables=1` for containers created with `--link`; with nftables, nf_tables with NAT, masquerading, conntrack and the bridge family (`CONFIG_NF_TABLES_BRIDGE`, `nft_meta_bridge`), and no `br_netfilter`
- **Building:** GCC 13 or later, which CI builds with, make and ninja, which builds lightc
- **Host tools:** `iptables` and `iptables-restore`, or with `firewall_backend = nftables` `nft`, and `cp` and `rm`. Since 0.7 lightbox runs neither `ip` nor `nsenter`
- **Root:** `setup`, `start`, `stop`, `restart`, `reset`, `update`, `exec` and `run` run as root, and so does `create --userns`. A container's root is the host's root, unless it was created with `--userns` (see [User namespaces](#user-namespaces) and [Threat model](#threat-model))

`lightbox doctor` checks all of this on the host it runs on: root, the kernel and the system calls lightbox makes, cgroup v2 and its controllers, that the kernel loads the cgroup device program a container starts with (`CONFIG_CGROUP_BPF`), the tools, the base root filesystem, and with nftables that forwarding is on. Each check that fails is followed by what fixes it, and `doctor` then exits 1; `doctor --json` gives the same to scripts.

## Building

Depends on [lightc](https://github.com/OscarAC/lightc), a freestanding C runtime.

```sh
git clone --recursive https://github.com/OzkrAC/lightbox
cd lightbox
make

# in a clone made without --recursive
git submodule update --init

# or build against another lightc tree that is already built
make LIGHTC=/path/to/lightc
```

lightc is pinned as a git submodule in `lightc/`. `make` configures and builds it there, then produces a single statically linked `lightbox` binary.

The Makefile looks for lightc in `LIGHTC=`, then in the `lightc/` submodule, then in a sibling `../lightc/`. The submodule is the only copy it configures and builds itself. A sibling or `LIGHTC=` tree is someone else's working copy: lightbox links its `build/liblightc.a` and stops with a hint if that file is missing.

`make CC=aarch64-linux-gnu-gcc` cross-builds; lightc must be built for the same architecture.

### Checks

```sh
make check
```

runs everything that needs no root:

| Target | What it does |
| --- | --- |
| `make check-sys` | Compiles `tests/sys_check.c` and `tests/sys_check_net.c`, which compare every private syscall number, constant and structure in `lightbox_sys.h`, every number in the seccomp tables of `lightbox_seccomp.h`, and every constant and layout of the device program of `lightbox_devices.h`, with the kernel's headers, for x86_64 and aarch64 |
| `make analyze` | Compiles every file with `-fanalyzer` and a strict warning set; any diagnostic is an error |
| `make test-unit` | Runs lightbox's own helpers from the command line. The one that starts programs: exit statuses, signals, missing programs, quiet and captured output. The ones that mount, make directories and bring up loopback: in a user namespace of their own. The cgroup device program, interpreted: the verifier's rules and its verdict for every kind of device, access and a range of numbers |
| `make test-validation` | Runs the built binary as an ordinary user against a temporary directory tree |
| `make test-seccomp` | Installs each of lightbox's real seccomp profiles and probes every syscall in its deny table, every call that sets a file's mode with the setuid or setgid bit and without, and `socket` of families it takes and does not, and for the allow-list a call it does not name; runs git, Python, Node.js and a C compiler under each, where the host has them; and interprets the x86_64 and the aarch64 program of each profile for every syscall number, every bit of a mode and every family of a socket |

In the test suites an open finding from `ROADMAP.md` is an expected failure that names its ledger id. When a fix makes one pass, the suite fails until the case is changed from `xfail` to `check`.

One more suite starts real containers, so it needs root:

```sh
sudo make test-lifecycle
```

It covers `setup`, `create`, `start`, `exec`, `stop` and `rm`, volumes, limits, the init hook, the sandbox and the network between containers. It needs a kernel with bridge, veth and cgroup v2, a statically linked busybox to build the containers' root filesystem from (`busybox-static` on Debian, Ubuntu and Void), and iproute2's `ip` and util-linux's `nsenter`, which the suite looks with; for lightbox's own commands it masks both. `LIGHTBOX_TEST_ROOTFS=/path` uses a copy of a root filesystem of yours instead; `sudo tests/fetch_image.sh alpine <dir>`, or `debian <dir>`, fetches one of the two images the allow-list is fitted to, pinned by its SHA-256, and unpacks it there, as CI does. The busybox goes into every image at `/lbt/busybox` too, and the cases that look at the network from inside a container run its `nc`, `ip` and `hostname`, which images do not all have; everything else they run is the image's own. `LIGHTBOX_TEST_USERNS=overlay` makes every container of the suite with `--userns`, and `LIGHTBOX_TEST_USERNS=copy` with `--userns --copy`, but in the cases about overlays; the suite puts an `/etc/subuid` and an `/etc/subgid` of its own over the host's, in its mount namespace only. `LIGHTBOX_TEST_SECCOMP=deny` makes every container with `--seccomp deny`, but where a case chooses the profile, alone or with either of the two.

The suite works in private network, mount and PID namespaces with a configuration of its own, so your bridge, firewall rules and containers are not touched. Its cgroups live under `/sys/fs/cgroup/lightbox-test-<pid>` and are removed at the end, and the run fails if the host's virtual interfaces, firewall rules or cgroups differ afterwards. A network card that the machine itself gains or loses during the run, as a cloud VM can, is reported and does not count. Kernel modules that get loaded on the way stay loaded.

sudo drops the environment, so options go on make's command line: `sudo make test-lifecycle V=1 KEEP=1`. Build first, as yourself; the target builds nothing.

`sudo make bench` works in the same namespaces and measures the wall time of `create`, `start`, `exec`, `stop` and `rm`, the number of processes one start makes, and `create` from a base of 1 GB. CI runs it on every push and puts its numbers on the run's page: on GitHub's runners a start takes 9 to 13 ms at 0.7.0, where it took 535 to 542 before Phase 1 of the roadmap.

`.github/workflows/ci.yml` runs `make check`, the lifecycle suite in its three ways and the timing on every push to `main` and every pull request, on x86_64 and on aarch64. A run's page lists each suite's totals, the cases it skipped and why each expected failure fails, without opening a log.

## Quick start

The commands below run as root, from the directory `make` built `./lightbox` in.

### 1. Get a rootfs

lightbox needs a Linux root filesystem to use as a base image. Any distro works — Alpine's minirootfs is a good starting point (about 3 MB); on aarch64 take its `aarch64` tarball.

```sh
mkdir -p /opt/rootfs/alpine
wget https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.21.3-x86_64.tar.gz -C /opt/rootfs/alpine
```

Tell lightbox where to find it — either export the environment variable or pass `--rootfs` on each create:

```sh
export LIGHTBOX_ROOTFS=/opt/rootfs/alpine
```

What an image has to contain:

- Nothing, for a container to run: lightbox makes `/dev`, `/proc`, `/sys`, `/tmp` and `/run` and the container's network itself, and `create` writes `/etc/resolv.conf`, `/etc/hostname` and a line of `/etc/hosts`, making `/etc` where there is none. A single static binary is an image too.
- `/bin/sh`, for an `/init.sh` hook and for `exec` without a command.
- The programs that `exec` runs, found on `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, with their libraries where they are linked dynamically: nothing of the host is in a container.
- `/etc/passwd` and `/etc/group`, for `exec --user <name>` and for the groups of the user a command runs as.

An empty image is refused. A container does not copy its image: see [Storage](#storage).

### 2. Set up host networking

Run once to create the bridge and the firewall rules and to turn on forwarding. Safe to re-run (idempotent).

```sh
./lightbox setup
```

This creates:
- A `br0` bridge with the address `gw` and the prefix of `subnet`, `10.0.0.1/24` unless `lightbox.conf` sets them
- lightbox's firewall chains, reached from the top of `FORWARD` and `POSTROUTING` (see [Firewall](#firewall))
- IPv4 forwarding, if it was off, with the `FORWARD` policy set to DROP as Docker does
- cgroup v2 mounted at `cgroup_root`, if it is an empty directory

The bridge, the firewall rules and forwarding live in the kernel only, and a reboot takes them. `start` looks for them, with one process, and makes them again as `setup` does when they are not all there, saying so: after a reboot, or after a firewall service loaded its own rules over lightbox's.

A firewall's reload or flush (`firewall-cmd --reload`, `iptables -F`, a service that loads its own rules, `nft flush ruleset`) takes lightbox's rules while containers run, and with them the rules of their links. Until they are back, a container reaches nothing beyond this host, and what keeps containers apart is the bridge and the FORWARD policy only. Two containers without links still do not reach each other: their ports on the bridge are isolated, and an isolated port does not reach another. It does reach a port that is not isolated, which a linked container's is: with the policy at DROP, as `setup` leaves it when it turned forwarding on, nothing passes between them, links included; with ACCEPT, as a host that forwarded before keeps it, a linked container reaches and is reached by every container on the bridge. As with Podman, two things put them back:

- `lightbox reload` puts in again what `setup` makes and the link rules of every running container, at once. Run it after the firewall's reload; it changes nothing that is there already. It leaves a container that another lightbox command is working on to that command, and says so.
- The next `start` finds setup's rules gone, makes them again and puts back the links of the containers that run.

lightbox has no daemon to hear of a reload by itself, as Docker's does of firewalld's; a hook of the firewall's own that runs `lightbox reload` after it does the same.

To take lightbox off the host's network again, once no container runs:

```sh
./lightbox setup --teardown
```

It refuses while a container runs, and names it. Otherwise it removes lightbox's firewall rules, in iptables and in nftables, the bridge and `cgroup_base`, and clears away what containers that ended without a stop left. `LIGHTBOX-USER` goes too, unless it holds rules of the host's. Containers and their files stay, and a `setup` or a `start` makes the network again. IPv4 forwarding and the `FORWARD` policy stay as they are, as something else on the host may forward by then: when `setup` was the one that changed them, `--teardown` says so and gives the commands that put them back.

### 3. Create, start, and use containers

```sh
# Create a container; it gets the lowest free address of the subnet, 10.0.0.2 on a new host
./lightbox create mybox
# or give it one: ./lightbox create mybox 10.0.0.20

# Start it; after the teardown above this makes the host network again
./lightbox start mybox

# Get a shell inside
./lightbox exec mybox /bin/sh

# Run a single command
./lightbox exec mybox cat /etc/os-release

# See what the container's services have printed; -f keeps following
./lightbox logs mybox
# and what exec and run asked of it
./lightbox logs --audit mybox

# List all containers, and look at one
./lightbox ls
./lightbox inspect mybox

# Stop and remove
./lightbox stop mybox
./lightbox rm mybox
```

### 4. Customize containers

```sh
# Custom resource limits
./lightbox create app --mem 512M --cpu 2 --pids 256

# Half a CPU, and no limit on memory, at an address of your choosing
./lightbox create small 10.0.0.8 --cpu 0.5 --mem max

# Read-only rootfs with a data volume
mkdir -p /srv/www
./lightbox create web --read-only --vol /srv/www:/var/www:ro

# Mount a host file into the container
mkdir -p /srv/config && echo 'debug = 1' > /srv/config/app.conf
./lightbox create conf --vol /srv/config/app.conf:/etc/app.conf:ro

# Another base than LIGHTBOX_ROOTFS for this container, and a full copy of it
./lightbox create other --rootfs /opt/rootfs/alpine --copy

# Choose the name servers the container asks
./lightbox create resolver --dns 9.9.9.9 --dns 149.112.112.112

# Disable the security sandbox
./lightbox create dev --privileged

# Allow two containers to talk to each other; the one linked to comes first
./lightbox create db
./lightbox create api --link db

# Run a command as one of the container's users, with a variable set, in a directory
./lightbox start web
./lightbox exec web --user nobody --env MODE=debug --workdir /var/www -- ls -la

# Change the limits of a container, at once if it runs
./lightbox update web --mem 128M --cpu 0.5

# Add a volume to an existing container configuration, and take it out again;
# a container that runs has the change from its next start
./lightbox add-vol app /srv/config/app.conf:/etc/app.conf:ro
./lightbox rm-vol app /etc/app.conf

# Stop and start, and remove a container that runs
./lightbox restart web
./lightbox rm -f web
```

### 5. Start services with an init hook

If the image has an `/init.sh`, the container's init runs it once the container is built, and `start` returns when the script has ended:

```sh
# /init.sh in the image: start the service in the background and return
/usr/sbin/nginx &
```

What the hook gets:

- It runs as `/bin/sh /init.sh`, as root, in `/`, with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `HOME=/root` and `TERM=xterm` and nothing else of the environment `start` was given. The container is complete by then: its mounts, its `/dev`, its address and default route, its cgroup and limits, and the container is on record, so `stop` and `ls` find it.
- It has the container's sandbox: 11 capabilities, the seccomp filter and no_new_privs, the masked and read-only parts of `/proc`. A hook that mounts filesystems or configures the network needs `--privileged`. Its root is the host's root (see [Threat model](#threat-model)).
- The hook and everything it starts read from `/dev/null` and write to the container's log, not to the terminal `start` was typed on. `lightbox logs <name>` shows the log, and `logs -f` follows it until the container stops.
- A hook that exits with a status other than 0 fails the start: `start` says which status it was, and the container is stopped and cleaned up. A hook that fails after `start` has returned stops the container as well.
- `start` waits 30 seconds for the hook. If the hook is still running then, for instance because it runs its service in the foreground, `start` says so and returns; the container stays up. `start <name> -t <seconds>` or `start_timeout` in `lightbox.conf` sets the wait, and 0 does not wait at all.
- What the hook starts stays when the hook ends, as children of init, which reaps them. `lightbox stop` sends SIGTERM to every process in the container and waits until they have ended, for 10 seconds; what is left then is killed. A service that should shut down cleanly has to handle SIGTERM. `stop <name> -t <seconds>` or `stop_timeout` in `lightbox.conf` sets the time, and `-t 0` kills at once.
- Ctrl-C, or a `kill`, while `start` is working undoes the start: nothing of the container is left running, and the exit status is 128 plus the signal's number.

## Configuration

lightbox reads `/etc/lightbox/lightbox.conf` at startup, or the file that `--config <path>` or the variable `LIGHTBOX_CONFIG` names, in that order; `make install` puts the example there. All values have built-in defaults — the config file is optional. A file that `--config` or `LIGHTBOX_CONFIG` names has to be there. Without any of the three, lightbox 0.6 still reads `~/.config/lightbox/lightbox.conf`, where earlier versions looked, and warns that 0.7 will not; with `/etc/lightbox/lightbox.conf` there as well, it says that the file in `~` is not read.

A line is `<key> = <value>`, blank, or a comment that begins with `#`. A `#` after a space or a tab begins a comment too, and a carriage return at the end of a line is no part of it, as files written on Windows have one. A key lightbox does not know and a line that is no setting are reported as warnings, with the file and the line, and change nothing.

```ini
# /etc/lightbox/lightbox.conf

# Base directory for lightbox data (base rootfs and container directories)
lightbox_dir = /var/lib/lightbox

# Default rootfs to copy when creating containers
# Also overridable with LIGHTBOX_ROOTFS env var or --rootfs flag
rootfs = /var/lib/lightbox/rootfs

# Where containers are stored (each gets a subdirectory)
container_dir = /var/lib/lightbox/containers

# Records of the containers that run: one directory for each, with the PID of
# its init and its state. It belongs on a tmpfs, as /run is: a reboot ends
# every container and has to take these along
run_dir = /run/lightbox

# cgroup v2 mount point
cgroup_root = /sys/fs/cgroup

# Bridge interface and network: subnet is <address>/<bits>, with 8 to 30
# bits, and gw is the bridge's address in it
bridge = br0
subnet = 10.0.0.0/24
gw = 10.0.0.1

# Default container resource limits: what --mem, --pids, --cpu and
# --oom-score take
default_mem = 256M
default_pids = 128
default_cpu = 1
default_oom = 500

# Seconds that start waits for a container's /init.sh; 0 does not wait
start_timeout = 30

# Seconds that a container's processes get to end when it is stopped
stop_timeout = 10

# Name servers for new containers, up to three. Without this they are the ones
# this host asks, or 1.1.1.1 and 8.8.8.8 if those are of no use to a container
dns = 9.9.9.9, 149.112.112.112

# The firewall, as Docker's daemon.json has it (see Firewall below): whether
# lightbox makes its rules ("iptables"), whether setup turns IPv4 forwarding on
# ("ip-forward"), whether it then leaves the FORWARD policy instead of setting
# it to DROP ("ip-forward-no-drop"), and whether containers are masqueraded
# ("ip-masq")
firewall = true
ip_forward = true
ip_forward_no_drop = false
ip_masq = true

# iptables or nftables ("firewall-backend"), and with nftables the mark, or
# mark/mask, of packets that lightbox's rules accept before they drop anything
# ("bridge-accept-fwmark")
firewall_backend = iptables
# bridge_accept_fwmark = 0x10/0xf0
```

If `lightbox_dir` is set, `rootfs` and `container_dir` are automatically derived from it (e.g., `rootfs = <lightbox_dir>/rootfs`) unless explicitly overridden.

No setting is cut to fit. A directory may be up to 448 characters long, and one that is longer, like a bridge name or an address that is too long, ends every command with the setting named: the first part of such a value would be the name of something else. The file itself may be up to 16 KB.

`subnet` and `gw` are read as one network by `setup`, `create`, `start` and `doctor`: a `gw` that is not in `subnet`, or that is its first or its last address, ends the command with the setting named. The bridge and every container have the prefix of `subnet`. A container's address is one of `subnet` and not its first or its last address, `gw` or another container's; `create` refuses any other, and without one takes the lowest that is free. An address is written as four numbers without a zero in front of any, since programs read `10.0.0.05` differently. `start` refuses a container whose address is not in `subnet` as it is now, after a change of `subnet`. `setup` leaves a bridge that is there as it is: after changing `subnet` or `gw`, delete the bridge while no container runs, with `ip link delete br0`, and run `setup` again.

A `default_*` setting has to be a value its option would take. One that is not is reported as a warning by every command, and only stops the command that would have needed it: `create` for a container that is not given that limit as an option. No container gets a limit that nobody chose.

### Firewall

lightbox keeps its iptables rules in chains of its own, as Docker does with its iptables backend, and `setup` jumps to them from the top of the host's chains. They come before the host firewall's own rules and its policy, so a host whose firewall drops forwarded traffic, as Docker, ufw and firewalld set up, still forwards what the bridge needs:

| Chain | Reached from | What is in it |
|-------|--------------|---------------|
| `LIGHTBOX-USER` | the top of `FORWARD` | This host's rules that are to decide before lightbox's, like Docker's `DOCKER-USER`. lightbox makes it and never changes it |
| `LIGHTBOX-FORWARD` | `FORWARD`, after `LIGHTBOX-USER` | Between two ports of the bridge, what a link allows and nothing else; out of the bridge by any interface, and back what belongs to such a connection |
| `LIGHTBOX-LINKS` | `LIGHTBOX-FORWARD` | A jump to `LB-<name>` for each running container with links, whose rules name the two ports of each link |
| `LIGHTBOX-POSTROUTING` | the top of `POSTROUTING` (nat) | Masquerading of `subnet` for what leaves by any interface but the bridge |

The settings are Docker's:

- `firewall = false` (Docker's `iptables`): lightbox makes no firewall rules at all, and a container with links is not started, since nothing would keep it to its links. Without masquerading, containers do not reach beyond the host unless the host routes their subnet.
- `ip_forward = false` (`ip-forward`): `setup` leaves IPv4 forwarding as it is, and says so when it is off.
- `ip_forward_no_drop = true` (`ip-forward-no-drop`): when `setup` turns forwarding on, it leaves the `FORWARD` policy as it is. Without it the policy becomes DROP, so that the host forwards what a rule accepts and nothing else. A host that had forwarding on already keeps its policy in any case.
- `ip_masq = false` (`ip-masq`): nothing is masqueraded.

A setting that is not `true` or `false` is said, and its built-in value is kept. `setup` flushes and fills `LIGHTBOX-FORWARD` and `LIGHTBOX-POSTROUTING` for the bridge of its `lightbox.conf`, so one host has one lightbox network. On a host where lightbox 0.4 or earlier ran `setup`, the next `setup` takes out the rules that it put straight into `FORWARD` and `POSTROUTING`; a running container with links gets its link rules back when it is started again.

#### With nftables

`firewall_backend = nftables` (Docker's `firewall-backend`) puts lightbox's rules in two nftables tables of its own instead, as Docker's nftables backend does:

| Table | Chain or set | What is in it |
|-------|--------------|---------------|
| `ip lightbox` | `forward` | What comes back to the bridge for a connection from it; anything else new that would go into the bridge is dropped |
| `ip lightbox` | `postrouting` | Masquerading of `subnet` for what leaves by any interface but the bridge, when `ip_masq` is true |
| `bridge lightbox` | `forward` | Between two ports of the bridge, the pairs in `links` and nothing else |
| `bridge lightbox` | `links` | A pair of ports for each way of each link of a running container |

The bridge-family chain sees what the bridge switches without `br_netfilter`, so a container with links starts without it. `setup` makes both tables in one transaction, and a start of a container with links runs one `nft`. `setup` with nftables takes out the chains lightbox made in iptables, but for `LIGHTBOX-USER` and the jump to it, which are this host's; with iptables it takes the two tables away.

What changes with the backend, as it does for Docker:

- `setup` does not turn IPv4 forwarding on. When it is off and `ip_forward` is true, `setup` stops before it changes anything and says so: turn it on yourself, with rules of this host's against forwarding between its other interfaces, or set `ip_forward = false`. `ip_forward_no_drop` has no use, as no policy is set.
- There is no `LIGHTBOX-USER`. An nftables `accept` does not get a packet past another table, so the host's rules go in tables of its own: one that drops decides whatever lightbox's accept. To accept what lightbox's rules drop, mark it in a chain of the host's on the same hook with a lower priority (`filter - 1` or below), and set `bridge_accept_fwmark` to that mark, or mark and mask: `0x10`, or `0x10/0xf0`. Mark 0 is every unmarked packet's and is refused.
- A chain of another table whose policy drops forwarded packets drops the containers' traffic too: iptables' `FORWARD` with policy DROP, which Docker, ufw, firewalld and lightbox's own `setup` with iptables leave, among them. `setup` names every such chain it finds, and so does `doctor`, as `forward_drops`. Change their policy, with `iptables -P FORWARD ACCEPT` for iptables', or accept the bridge's traffic in them.
- A host firewall that flushes the whole ruleset when it loads, as `/etc/nftables.conf` files that begin with `flush ruleset` do, takes lightbox's tables with it. The next `start` makes them again; to have them back at once, run `lightbox setup`.

### Rootfs resolution order

1. `--rootfs <path>` flag on create (highest priority)
2. `LIGHTBOX_ROOTFS` environment variable
3. `rootfs` in `lightbox.conf`
4. `/var/lib/lightbox/rootfs` (built-in default)

## Command reference

`lightbox --help` prints this.

```
Usage: lightbox [--config <path>] <command> [args]

Commands:
  create <name> [<ip>] [options]
                                Create a new container; without <ip>, the lowest free address
         --mem  <limit>         Memory limit: <number>[K|M|G|T] or max (default: 256M)
         --swap <limit>         Swap it may use: 0, <number>[K|M|G|T] or max (default: 0)
         --pids <limit>         Max processes, or max (default: 128)
         --cpu  <num>           CPUs, such as 2 or 0.5 (default: 1)
         --io-max <limit>       I/O limit for one disk: "8:0 wbps=10485760", with rbps, wbps,
                                riops or wiops (default: none)
         --vol  <src:dst[:ro]>  Bind mount (repeatable)
         --rootfs <path>         Base rootfs to copy (default: $LIGHTBOX_ROOTFS or lightbox.conf)
         --userns               A user namespace of its own: its root is an unprivileged uid
                                on the host, from the range of /etc/subuid; as root
         --read-only            Read-only root filesystem
         --copy                 A copy of the base, and not an overlay of its snapshot
         --privileged           Disable security sandbox
         --seccomp allow|deny   The seccomp profile: the allow-list, or the deny-list
                                (default: allow)
         --oom-score <n>        OOM score adjustment (default: 500)
         --ttl <duration>       How long it may run from each start, such as 30m or 8h; then
                                it stops as stop stops it, and is expired
         --link <name>          Allow network to another container
         --dns <address>        A name server for the container (up to 3; default: the host's)
  start  <name>... [-t <seconds>]  Start stopped containers, one after the other
         -t <seconds>            How long to wait for /init.sh (default: 30, 0: do not wait)
  stop   <name>... [-t <seconds>]  Stop running containers, one after the other
         -t <seconds>            How long their processes get to end (default: 10)
  add-vol <name> <src:dst[:ro]> Add a volume to an existing container
  rm-vol <name> <dst>           Remove the volume at a destination
  restart <name>... [-t <seconds>]  Stop containers that run, as stop does, and start them
  reset  <name>... [-t <seconds>]  Make the root filesystem of containers their base's again,
                                without a copy; one that runs is stopped first. Volumes are kept
  update <name> [--mem <limit>] [--pids <limit>] [--cpu <num>]
                                Change a container's limits, live if it runs and from its next
                                start in any case
  rm     [-f] <name>...         Remove containers; -f kills one that runs first
  exec   <name> [options] [--] [cmd [args...]]  Run a command in a running container
         --user <name|uid[:gid]> Who to run it as (default: root)
         --env <KEY=VALUE>       Set a variable in its environment (repeatable)
         --workdir <dir>         The directory to run it in (default: /)
         --timeout <duration>    End it, and all it started, after this long, such as 30s,
                                 5m or 1.5h; exec then exits with 124
         exec exits with the command's status, or 128 plus the signal that ended it; with
         125 when lightbox failed, 126 when the command could not be run, 127 when not found
  run    [create options] [exec options] [--] [cmd [args...]]
                                Create a box, start it, run a command in it as exec runs it,
                                and remove it; run exits as exec does. A box whose run was
                                killed is removed by the next run
  logs   <name> [-f] [--audit]  Show what the container has printed; -f follows it. --audit
                                shows what exec and run asked of it, kept after it is removed
  inspect <name> [--json]       Show a container's configuration and state; --json as JSON
  doctor [--json]               Check what lightbox needs of this host, and say how to fix what
                                is missing; --json as JSON
  ls [--json]                   List all containers
  base ls                       List the snapshots of bases that containers overlay
  base add <dir>                Take a new snapshot of a base, for the containers made after it
  base rm <id>...               Remove snapshots that no container uses
  setup                         Setup host networking
  setup --teardown              Take lightbox's host network away, when no container runs
  reload                        Put lightbox's firewall rules and bridge in again, and the links
                                of running containers, after a firewall's reload took them

  --config <path>                              The lightbox.conf to read (default:
                                               $LIGHTBOX_CONFIG, else /etc/lightbox/lightbox.conf)
  --help, help [<command>], <command> --help   This text, or a command's part of it
  --version                                    The version of lightbox, and of lightc
```

Help that is asked for goes to standard output, and the command exits 0. A word that a command will not use is an error that names it, and the command does nothing. `start`, `stop`, `restart` and `rm` take several names, as Docker's do, and do one container after the other: one that cannot be done ends nothing for the others, the command names those it did not do at the end, and its exit status is the first that was not 0.

### Create options

A container's name is 1 to 30 characters of `a-z`, `A-Z`, `0-9`, `_` and `-`.

| Flag | Default | Description |
|------|---------|-------------|
| `--rootfs <path>` | `$LIGHTBOX_ROOTFS` | Base rootfs to copy |
| `--mem <limit>` | `256M` | Memory limit: a number of bytes, optionally with `K`, `M`, `G` or `T`, or `max` for none |
| `--swap <limit>` | `0` | Swap the container may use beyond its memory: `0`, a size as for `--mem`, or `max` |
| `--pids <limit>` | `128` | Max processes, 1 to 4194304, or `max` for no limit |
| `--cpu <num>` | `1` | CPUs, 0.01 to 512, with up to two decimals: `2`, `0.5`, `1.25` |
| `--io-max "<major>:<minor> <key>=<value>..."` | none | I/O limit for one whole disk of the host, as `io.max` takes it: `"8:0 wbps=10485760 riops=1000"`, with `rbps`, `wbps`, `riops` and `wiops`, each a number or `max` |
| `--vol <src>:<dst>[:ro]` | — | Bind mount (repeatable, up to 16, one at a destination) |
| `--userns` | off | A user namespace of its own: its root is an unprivileged uid on the host (see [User namespaces](#user-namespaces)); `create` runs as root |
| `--read-only` | off | Read-only root filesystem |
| `--copy` | off | A full copy of the base, as before 0.7, and not an overlay of its snapshot |
| `--privileged` | off | Disable security sandbox |
| `--seccomp allow\|deny` | `allow` | The seccomp profile: `allow` for the allow-list, which answers every syscall it does not name with ENOSYS, or `deny` for the deny-list (see [Security](#security)) |
| `--oom-score <n>` | `500` | OOM score adjustment, -1000 to 1000 |
| `--ttl <duration>` | none | How long the container may run from each start: a duration as `exec --timeout` takes one, from 1 ms to 365 days, such as `30m` or `8h`, counted on the clock of the time since boot, which goes on while the host is suspended. At the end init shuts the container down as `stop` does, with all it runs, the commands of `exec` among them, and writes why in its log; `ls` and `inspect` show it as `expired`, and the next `start`, `stop` or `rm` clears away what it left. Init keeps the time, in the container: no process there can send it a signal it does not handle, trace it or set its clock, but a kernel flaw past the sandbox could, so the lifetime is a guard against containers that are forgotten or run away, and not a security boundary |
| `--net nat\|outside\|none\|proxy:<port>` | `outside` | What it may reach: `outside` the internet and its name servers only, `nat` the network every container had before 0.8, with the host and its networks, `none` loopback alone, with no address, or `proxy:<port>` that TCP port of the gateway and nothing else, where a proxy of the host's listens, with no name server and no `--link` (see [Security](#security) and [contrib/proxy](contrib/proxy/README.md)) |
| `--link <name>` | — | Allow network to another container (repeatable) |
| `--dns <address>` | the host's | A name server for the container (IPv4, up to 3) |

A value that is not what its option takes ends `create` with the option named, and nothing is made: no value is shortened or stored to be found wrong at the next start. An option that is given without its value says so.

A container's memory limit is a limit: past it, a process is killed and does not go on in swap, unless `--swap` gives the container some. The kernel then ends the whole container, not only the one process, and the next `start`, `stop` or `rm` clears it away. Processes that `exec` starts have the container's `--oom-score`, as its init does.

`start` enables the `memory`, `pids`, `cpu` and `io` cgroup controllers one by one. One that the host does not give the container's cgroup stops the start only when the container has a limit that needs it: `cpu` always, `memory` for `--mem` or `--swap`, `pids` for `--pids` and `io` for `--io-max`. Otherwise `start` says it once and the container runs without it.

### Exec options

Options come before the command. A command that begins with a dash goes after `--`; without a command, `exec` runs `/bin/sh`.

| Flag | Default | Description |
|------|---------|-------------|
| `--user <name\|uid[:gid]>`, `-u` | root | Who the command runs as. A name is looked up in the container's `/etc/passwd`. A value that begins with a digit must be a uid, or a uid and a gid, and nothing else |
| `--env <KEY=VALUE>`, `-e` | — | Set a variable in the command's environment (repeatable; the later of two for one variable wins) |
| `--workdir <dir>`, `-w` | `/` | The directory the command runs in, as an absolute path in the container |
| `--timeout <duration>` | none | How long the command may run: digits, up to three more after a point, and `s`, `m`, `h` or `d`, or no unit for seconds, from 1 ms to 365 days, such as `30s`, `5m` or `1.5h`. At the deadline the command and everything it started are ended, in the background and in sessions of their own too, and `exec` exits with 124. A command that ends before it takes along what it left running. Two processes keep the time, the `exec` process and its worker, which the container cannot reach: when the `exec` process ends while the command runs, killed for one, the worker ends everything at once, and when it is held up, stopped for one, the worker does so a second past the deadline. Only root on the host, killing both, can let a command outlive its limit |

What the command gets as its standard streams depends on what `exec` itself was given, and is never a terminal of yours:

- **Typed at a terminal** (stdin and stdout are both a terminal): the command gets a terminal of its own, a pseudo-terminal of the container, as its controlling terminal. Your terminal is raw for as long as the command runs, so every key goes to the command: Ctrl-C interrupts what runs in the container, not `exec`. The window's size is passed on, also when it changes.
- **With a terminal on one side only**, as in `lightbox exec x cat file | less` or `lightbox exec x cat > notes`: the command gets a pipe in the place of the terminal, which `exec` reads or fills. Bytes arrive as they were sent.
- **Without a terminal**, as in a script or a pipeline: the three streams as they are.

In every case the command leads a session of its own and is given nothing else that was open where `exec` was run. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to `exec` are passed on to the command.

The command is found as a shell finds it: a name without a slash is looked for in the directories of `PATH`. Its environment is `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `HOME`, `USER` and `LOGNAME` for its user, and the `TERM` of the terminal `exec` was typed on; nothing else of your environment goes into the container. Its groups are the ones the container's `/etc/group` lists for its user, and none for a uid the container has no account for.

`exec` exits with the command's status, or 128 plus the number of the signal that ended it. Its own statuses are those of `env` and `timeout`, so that a program that drives a container can tell what the command did from what lightbox did: 124 when `--timeout` ended the command, 125 when lightbox failed before the command ran, such as for an option it does not take or a container that is not running, 126 when the command could not be run, as a file that is not executable or a `--workdir` that is not there, and 127 when it is not there. A command can return those numbers too; every other command of lightbox's fails with 1.

Every `exec` runs in a cgroup of its own, `exec-<pid>-<start time>` of the `exec` that made it, below the container's, whose limits hold for it. Nothing in the container can reach cgroupfs to leave it, so what a command starts is in it until it ends. Without `--timeout`, what a command left running in the background goes on in that cgroup after `exec` returns, and the cgroup is removed once it is empty, by the next `exec` or by `stop`. `--timeout` ends what is in it with `cgroup.kill`, or, on a kernel before 5.14, by killing what it lists until nothing is left.

### run

`lightbox run [create options] [exec options] [--] [cmd [args...]]` is a box for one command: it creates a container under a name of its own, `run-` and 12 hex digits, starts it, runs the command in it as `exec` runs it, and removes it, whatever the command did. Every option of `create` and of `exec` goes before the command, `--timeout` among them, which ends the command with 124 as it does for `exec`; without a command, `run` runs `/bin/sh`.

```sh
sudo ./lightbox run --net none --timeout 10m -- /bin/sh -c 'make test'
```

What `run` prints is the command's: `create`, `start` and `rm` say nothing but their errors. It exits as `exec` does, with the command's status, 124, 126 or 127, and with 125 when the box could not be made or started. SIGINT, SIGTERM and SIGHUP sent to `run` go on to the command; one that comes while the box is made stops `run` there. The box is removed once the command has ended, or when it has not within `stop_timeout`, and the removal is in a session of its own, which a terminal's keys do not reach. A `run` killed outright cannot remove its box, which runs on: the box's `.runner` names that `run`, its PID and start time, and the next `run` removes every box whose `run` is gone, and says so. A box that must not outlive a killed `run` for long gets a `--ttl`, as `--timeout` keeps its command to its time in any case.

### Audit log

Every `exec`, and so the command of every `run`, appends two lines to `<lightbox_dir>/audit.log`: one as the command is about to start, and one when it has ended. Each is one JSON object, written with one `write` on a descriptor opened to append, so that the lines of commands that run at once do not mix. `lightbox logs --audit <name>` prints the lines of a box, and still does after the box is removed; with `-f` it follows them while the box runs.

```json
{"box":"web","box_id":"8c1f0e7a5d3b2a19","time":"2026-11-21T16:39:23.123Z","event":"start","exec_id":"4242-981234","via":"exec","uid":0,"loginuid":1000,"user":null,"workdir":"/srv","timeout":"10m","env":["CI"],"argv":["make","test"]}
{"box":"web","box_id":"8c1f0e7a5d3b2a19","time":"2026-11-21T16:41:02.456Z","event":"end","exec_id":"4242-981234","status":0,"duration_ms":99333,"timed_out":false}
```

- `box_id` is the id that `create` draws for a box, kept in its `.conf` as `id=` and shown by `inspect`: it tells a box from a later one of the same name. A box created before 0.8 has none, and its lines have `null`.
- `exec_id` is the PID and start time of the `exec`, as its cgroup is named, and pairs a start with its end. `via` is `exec` or `run`.
- `uid` is the caller's, which is 0 under `sudo`, and `loginuid` that of the user who logged in, from `/proc/self/loginuid`, which `sudo` and `su` keep; `null` when no login set one.
- `user`, `workdir` and `timeout` are as given, and `null` when not given. `env` has the keys of `--env` and not their values, which are often credentials. `argv` is the command as given, or `/bin/sh`.
- `status` is what `exec` exits with, 124 to 127 among them, `duration_ms` how long it took from the moment `exec` began, and `timed_out` whether `--timeout` ended the command.
- Every string is ASCII: a character outside it as `\uXXXX`, and a byte that is not part of UTF-8 as `\udcXX`, Python's `surrogateescape`, so `json.loads(line)["argv"][0].encode("utf-8", "surrogateescape")` gives back the bytes that were given. No control sequence or reordering mark in an argument reaches a terminal that shows the log.

An `exec` whose start cannot be written in the log does not run, and exits with 125; one whose end cannot be written says so and exits as it would have. A start with no end is an `exec` whose process was killed.

The log is mode 0600 in `lightbox_dir`, mode 0700, which no box has mounted: what runs in a box can neither read it nor change it. It records what was asked of a box, not what the command then did; what left a box through a proxy is in the proxy's log. The arguments are recorded as given, so the log is as sensitive as the commands are. Root on the host can change it, and it is not rotated yet.

## Security

All security features are on by default. Pass `--privileged` to disable.

The sandbox covers everything in a container: init, the `/init.sh` hook and all it starts, and every `exec`. A hook that mounts filesystems or configures the network therefore needs `--privileged`.

| Feature | Implementation |
|---------|---------------|
| Capability dropping | The bounding, effective and permitted sets are reduced to 11 capabilities: Docker's default 14 without `NET_RAW`, `MKNOD` and `SETFCAP`. The inheritable and ambient sets are emptied |
| Seccomp | One of two BPF filters, chosen with `create --seccomp` and shown by `inspect`. Both deny 60 syscalls on x86_64 (51 on aarch64), the x32 range, `clone` with namespace flags, and a mode with the setuid or setgid bit in `chmod`, `fchmod`, `fchmodat`, `fchmodat2`, `mknod`, `mknodat`, `creat`, and `open` and `openat` that make a file; `openat2`, whose mode they cannot read, answers ENOSYS so that callers use `openat`. Both keep `socket` to `AF_UNIX`, `AF_INET`, `AF_INET6` and `AF_NETLINK`, and `socketpair` to `AF_UNIX`; another family answers EAFNOSUPPORT, as one the kernel lacks would: `AF_PACKET`, `AF_ALG`, `AF_VSOCK`, which no network namespace confines, and the families of old and rare protocols. The allow-list, the default, allows 247 other syscalls on both architectures and 34 more on x86_64 alone, Docker's list fitted to what agents run: a shell, git, Python, Node.js, a C compiler and a package manager. It answers every syscall it does not name with ENOSYS, as an older kernel would, so a program falls back: among them `mount`, `pivot_root`, `sethostname` and `syslog`, which need a capability a container does not have, `modify_ldt`, and every call newer than Linux 6.8 or than the list. The deny-list allows every other syscall; a container created before 0.8 has it |
| no_new_privs | Prevents SUID escalation |
| /proc and /sys masking | The paths Docker masks by default are covered, files with `/dev/null` and directories with an empty read-only tmpfs. A mask that cannot be made fails the start |
| /proc read-only | Remounts /proc/sys, /proc/bus, /proc/fs, /proc/irq read-only |
| Root filesystem | Mounted `nodev`, and `nosuid` unless privileged. Devices come from the `/dev` that lightbox builds |
| Devices | A cgroup device program, attached to a container's cgroup before init is in it, lets its processes open the devices of its `/dev` and no other: `null`, `zero`, `full`, `tty`, its devpts' `ptmx` and terminals, and `random` and `urandom` for reading only. A node of any other device is refused with EPERM wherever it is, and no device can be made; a privileged container has no program. `start` fails when the kernel does not load it, and `doctor` says whether it does |
| Network | `create --net` chooses what a container may reach, as rules in lightbox's chains or tables, and `inspect` shows it. `outside`, the default, reaches the internet and the name servers it was created with, on port 53, and is refused at once, TCP with a reset, which a client says as a refused connection, and the rest with an ICMP "administratively prohibited", which it says as no route to the host: the host on every address of its, which `nat` leaves to the host's own firewall; and beyond the host `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, the metadata address of the clouds among it, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15` and multicast and above. `nat` reaches the host and the outside, as before 0.8, and so does a container created before. `none` has loopback and no interface, address or rule. `proxy:<port>` reaches that TCP port of the gateway and is refused everything else at once, name servers included; its `resolv.conf` names none, so names are its proxy's to look up, and `exec` and the init hook have `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in both spellings. lightbox ships no proxy: what a container may reach through one is the proxy's configuration, and [contrib/proxy](contrib/proxy/README.md) has one for Squid that allows a list of names and looks up no other. The bridge drops what it would switch to or from a container of `proxy`, so a `--link` to it reaches nothing. The rules hold a container by its address, which one that is not privileged cannot change; a privileged container can |
| Container isolation | A container without `--link` has an isolated port on the bridge: it reaches the host and the outside, and no other container, as far as its `--net` lets it reach either. IPv6 is off inside containers. A container with `--link` shares the bridge, and is kept to its links by firewall rules that name the two ports of each link: with iptables it does not start unless `br_netfilter` lets iptables see bridged traffic, and with nftables a table of the bridge family sees it without. A link holds whichever of the two starts first, and a container's link rules go with it when it stops, is removed or is found dead |
| The terminal of whoever runs `exec` | A command never holds it. Typed at a terminal, `exec` gives the command a pseudo-terminal of the container and carries the bytes; where only one of its streams is a terminal, a pipe stands in for it |
| The binary `exec` enters with | `exec` executes itself again from a sealed copy in memory before it enters a container, so the processes it puts there are never the installed binary. Where the kernel refuses executable memfds (`vm.memfd_noexec=2`) it takes the binary through a read-only mount of its own instead. Its worker is not dumpable. `lightbox doctor` says which of the two is in use |
| User namespaces | With `--userns`: a container's root is an unprivileged uid of the host's, from a range of `lightbox`'s in `/etc/subuid` and `/etc/subgid`, and its root filesystem and its volumes idmapped mounts, a volume to its source's owner and never to host root (see [User namespaces](#user-namespaces)). Without it, a container's root is the host's root |
| OOM priority | Containers scored higher for OOM killer |

### Threat model

lightbox keeps what runs in a container away from the host and from the other containers, as far as the kernel's namespaces, the sandbox and the firewall can:

- **The host from a container's processes:** their own PID, mount, UTS, IPC and network namespaces, and with `--userns` a user namespace in which root is an unprivileged uid of the host's; 11 capabilities and a seccomp filter of Docker's kind, with no_new_privs; the paths of `/proc` and `/sys` that Docker masks, masked, and the rest of `/proc`'s system trees read-only; a root filesystem that is `nodev` and `nosuid`, and a device program that lets them open the devices of the container's `/dev` and no other; and limits on memory, swap, processes, CPU and, with `--io-max`, I/O.
- **The host from what a container leaves in a volume:** nothing in a container that is not privileged gives a file the setuid or the setgid bit or a file capability, so no program it leaves in a volume, or in its own files, runs on the host with the rights of their owner, the volume's owner or root. Inside the container they would mean nothing, as its root is `nosuid` and no_new_privs is set. A package that installs such a program, such as `passwd`, `mount` or `sudo`, or that runs `setcap`, such as `iputils-ping`, fails to install in a container: update it in the base on the host, or give the container `--privileged`.
- **Containers from each other:** each on an isolated port of the bridge, and with `--link` kept to its links by firewall rules that lightbox owns and takes away with the container.
- **The host, its networks and the clouds' metadata from a container's traffic:** with `--net outside`, the default, a container reaches the internet and its name servers and nothing of the host's, of a private network or of the metadata services; with `--net proxy:<port>`, its proxy's port and nothing else; with `--net none`, nothing.
- **The host's terminal and the installed binary from a container:** `exec` gives a command a terminal of the container's, not yours, and enters from a sealed copy of itself.

What it does not keep out, and what to do about it:

- **Without `--userns`, a container's root is the host's root.** What keeps it in is the namespaces and the sandbox; a flaw in the kernel past them would be a flaw on the host. Create a container with `--userns` (see [User namespaces](#user-namespaces)), or run as root in it only what you would run as root on the host, and the rest with `exec --user`.
- **`--privileged` turns the sandbox off.** Such a container has all capabilities, no seccomp filter and no device program; give it only to what needs that, such as a hook that mounts filesystems.
- **With `--net nat` the host itself is in reach,** as it was for every container before 0.8: services of the host that listen on the bridge's address, or on all addresses, answer such a container, and so do the host's networks. Give it `--net outside`, the default, unless it needs them, or keep the services to the addresses they are for.
- **Disk is not limited.** A container's copy of its image and its `console.log`, which is not rotated, take what the disk has, and so does the audit log.
- **Whoever runs lightbox is root.** lightbox does not decide who may use it: giving someone `sudo lightbox` is giving them root.
- **Images are trusted as files.** `create` copies an image as it is; what it contains runs in the sandbox, with the container's root.

## How it works

- **Namespaces**: `clone()` with PID, mount, UTS, IPC and network namespace flags, and with `--userns` a user namespace, whose maps `start` writes before init does anything. `start` makes the idmapped root in a mount namespace of its own, which init's is copied from, and init binds it onto itself, mounts `/proc` and `/sys` while the host's are still there, and becomes the container's root before it builds the rest
- **Filesystem**: each container lives under `<container_dir>/<name>/` with `rootfs/` for its own files, `.conf` and `.ip` for what it is configured with and `console.log` for its output. Init mounts an overlay of the base's snapshot and `rootfs/` in the container's mount namespace, or takes `rootfs/` as it is for a copy, and `pivot_root`s into it (see [Storage](#storage))
- **Runtime records**: what is known about a container while it runs is in `<run_dir>/<name>/`: `pid` and `pid_start` for its init, `state`, and `exit`, where init writes its exit status as the last thing it does. These are written without waiting for a disk, and a reboot takes them away with everything else in `/run`; a container without them is stopped. `start` makes the directory again when it is missing, for root alone
- **States**: `ls` and `inspect` show `stopped`, `running`, `starting` and `stopping` while a command is at work, `exited` for a container that ended by itself, `expired` for one whose `--ttl` ran out, `failed` for one that was killed or whose start or hook failed, and `creating` for one that `create` did not finish. A half-made container is not started: remove it and create it again
- **A container that ended without a stop**: when init is killed, or is told to stop by a signal from somewhere other than `lightbox stop`, from inside the container too, nobody is there to clear up. `ls` shows such a container as `exited` and changes nothing. The next `start`, `stop` or `rm` clears away what it left, its cgroup, its interface and the firewall rules of its links, says that it did, and records `exited` if init had ended with status 0, `expired` if its `--ttl` ended it, and `failed` otherwise
- **A container's configuration**: `.conf` is lines of `key=value` that begin with `version=1`. One piece of code reads it and one writes it; a command reads it once, and `start` hands it to init. A file with the version line is read strictly: an unknown key, a key given twice or a value that is not one is an error that names the file and the line, and a file written by a newer lightbox is refused, not guessed at. A file from before the version line is still read as it was, and is written in the new form at the next `add-vol` or `rm-vol`. `rm` does not need the file, so a container whose configuration is damaged can always be removed
- **Devices**: bind-mounted from host (`/dev/null`, `/dev/zero`, `/dev/random`, etc.)
- **Networking**: veth pair per container connected to a host bridge with NAT. The container's end is `eth0`, made in the container's namespace. lightbox makes the bridge, the pair and the port, and takes them away, with rtnetlink requests of its own, and init gives `eth0` its address and the default route from inside the container: nothing enters the container's namespace from the host, and no tool is run for any of it. The host's end is `vb-` and twelve hex digits of a hash of the container's name, the same for a name every time, with the alias `lightbox:<name>`; `inspect` shows it as `host_interface`. lightbox removes only interfaces that carry its alias, and `start` refuses a container whose name on the host is taken by an interface it did not make, which it leaves alone. The alias is given as the interface joins the bridge, a moment after it is made: one that a `start` killed in that moment left has none, is left alone the same way, and goes with `ip link delete <interface>`. `create` writes the container's `/etc/resolv.conf`, `/etc/hostname` and a line for its own name in `/etc/hosts` among the container's own files, through its overlay or into its copy, where a link in the image cannot send them anywhere else
- **Resource limits**: cgroups v2 (memory, PIDs, CPU, I/O)
- **Init**: lightbox remains PID 1 inside the container. It reaps children and handles shutdown from the moment the container is built, and runs `/init.sh`, if the rootfs has one, as one of its children: after `/tmp` and `/run` are mounted, with the sandbox on, and only once the container is on record, so `stop` and `ls` always find a container whose hook runs
- **Stopping**: `stop` sends init a SIGTERM that carries the number of seconds the container may take. Init passes SIGTERM on to every process in the container, the ones `exec` put there included, reaps them, and exits when none is left or the time is over; the kernel kills whatever remains with it. `stop` waits for init through a pidfd, so it returns as soon as the container has ended. It then kills anything still in the cgroup and in the cgroups of its execs below it, waits until the kernel reports the cgroup empty, and removes those and then it. A SIGTERM sent to init by other means has the same effect, with the `stop_timeout` that was set when the container started
- **Output**: init leads a session of its own and keeps nothing that was open in the command that started it. Its standard output and error, and those of the hook and every service, are appended to `<container_dir>/<name>/console.log`, which only root can read. The log is kept from one start to the next and is not rotated or limited yet, so a container that prints without end fills the disk it is on
- **Audit**: `exec` and `run` append what they ask of a box to `<lightbox_dir>/audit.log`, one for the host, which only root can read and no box has mounted, so that a box's record outlives the box (see [Audit log](#audit-log))
- **Starting**: `start` and init talk over two pipes. Init builds the container when `start` has set up its cgroup and network, and reports back when it is built and again when the hook has ended. If either side goes away the other notices: an init whose `start` was killed exits before it runs anything
- **External tools**: on the host, `iptables` and `iptables-restore`, or `nft`, make the firewall (a start with links runs one of them once, and every start looks at the firewall with one), and `cp` and `rm` take a snapshot or a copy of a base and remove a container. Everything else lightbox does with system calls of its own, rtnetlink for the network among them, and nothing from the image is run before `/init.sh`
- **One command at a time**: `start`, `stop`, `restart`, `reset`, `update`, `rm`, `add-vol` and `rm-vol` take a lock on the container they change, and `create` and `setup` one on the whole store, so two commands on one container do their work one after the other. A command that has to wait says so. `ls` and `inspect` never wait. `setup`, `start`, `stop`, `restart`, `reset`, `update`, `exec` and `run` need root and say so before they touch anything
- **Configuration**: optional `/etc/lightbox/lightbox.conf`, or the file `--config` or `LIGHTBOX_CONFIG` names, for all paths and defaults

## Storage

A container's root is an overlay: a snapshot of its base, which containers of that base share and nothing writes to, and the container's own files on top. As Docker keeps its images, lightbox keeps the snapshots itself, in `<lightbox_dir>/bases/<id>/`:

- The first `create` from a base takes a snapshot of it, a reflink where the filesystem has them and a copy where it has not; every `create` from that base after it uses the snapshot, and takes no time and no room of the base's size. Changing or removing the base directory afterwards changes no container.
- `<container_dir>/<name>/rootfs/` holds the container's own files: what `create` wrote in `/etc`, and what the container writes. What it takes out of the base is marked there, the way overlayfs marks it. The overlay is mounted in the container's mount namespace only; on the host, `rootfs/` shows the container's own files and nothing of the base.
- A file of the base that you change from the host has to be in `rootfs/` first: appending to `rootfs/etc/passwd` while the container has the base's makes a file of only what you appended. Change it inside the container, with `exec`, or copy it into `rootfs/` and change the copy.
- `lightbox base ls` lists the snapshots, with their base and the containers on them. `lightbox base add <dir>` takes a new snapshot of a base, for the containers made after it, as after an update of the base; the containers made before keep theirs. `lightbox base rm <id>` removes a snapshot that no container uses.
- `lightbox reset <name>` makes a container's root filesystem its base's again, as it was after `create`: what the container wrote, changed and took out is gone, and nothing is copied. Its `rootfs/` and the overlay's work directory are replaced by empty ones, and the files that `create` wrote in `/etc` are written again, the same ones, as `create` keeps what it wrote in `resolv.conf` in `.resolv` beside `.conf`. A container made before that gets the `resolv.conf` that `create` would write now, and is told so. A container that runs is stopped first, as `stop` stops it, and `-t` is `stop`'s. Its volumes, configuration, address and `console.log` are not touched. A container that is a copy of its base is refused. A reset cut short leaves the container half made, as `create` marks it: `start` refuses it, and `reset` again makes it whole.
- `--copy` makes the container a full copy of its base in `rootfs/`, as every container was before 0.7. So does every `create` where an overlay cannot be mounted, without overlayfs in the kernel or without the right to mount, and it says so; `doctor` says whether the kernel has overlayfs. Containers made before 0.7 are copies, and stay as they are.

## User namespaces

A container created with `--userns` has a user namespace of its own, and its root is not the host's: uid 0 in it is an unprivileged uid on the host, and so are its other users. Its ids are a range of 65536 uids and 65536 gids that nothing else on the host has, taken, as rootful Podman's `--userns=auto` takes its own from the name `containers`, from the ranges that `/etc/subuid` and `/etc/subgid` give the name `lightbox`. Add one to both before the first such container, as large as you like:

```bash
echo lightbox:2147483647:2147483648 >> /etc/subuid
echo lightbox:2147483647:2147483648 >> /etc/subgid
```

- `create --userns` runs as root, and gives the container the first range of 65536 of each file that no container has. Its `.conf` records it as `userns=1`, `uid_start` and `gid_start`, the host's uid and gid of its root, and `inspect` shows them. `doctor` says how many ranges the two files hold. Without a range for `lightbox`, `create --userns` says what to add, and makes nothing.
- The container's root is an idmapped mount of its base, so that the base's files, owned by host root, are its root's and keep their other ids, and nothing is chowned. That needs Linux 5.12 and a filesystem with idmapped mounts, such as ext4, xfs, btrfs or tmpfs from 6.3 on; an overlay on an idmapped snapshot needs Linux 5.19. Where the kernel or the filesystem cannot, `create --userns` says so and makes nothing: there is no fallback that chowns.
- An overlay container's own files, `rootfs/`, belong on the host to its range: what its root makes there is the first uid of the range's, and the snapshot stays host root's. A `--copy` container's files keep the base's ids on disk, root's included, as the copy is idmapped as it is; its directory is root's alone, as every container's is.
- `exec` joins the user namespace first, and its command runs as the container's user, which is a uid of the range on the host.
- A volume is an idmapped mount of its source, for the source's owner: the container's root stands for the owner and group of the source on the host, and no other id is mapped. A file the container's root makes in it belongs on the host to that owner and group, and theirs are root's in the container. Files of other ids show as owned by nobody, the container's other users make nothing in it, and its root cannot give a file another id, nor the setuid or setgid bit (see [Security](#security)).
- A volume whose source is host root's, by its uid or by its gid, is bound as it is: no container stands for root. Its files show as nobody's, and the container writes in it only where anyone on the host may.
- `start` takes the volumes itself, as host root, and init attaches them. An idmapped volume needs a filesystem with idmapped mounts, as the root does: where the source's has none, `start` says so and the container does not start.

## Volume Notes

- A volume is written `src:dst[:ro]`. Both paths are absolute and may not contain `..`, a colon or a control character such as a newline; they are stored in one spelling, without doubled slashes. The destination may not be `/` or under `/proc`, `/sys` or `/dev`.
- A container has at most 16 volumes, and one at any destination: a second one there would be mounted over the first, which would never be seen. A destination inside another volume is another destination.
- The source is a path on the host, taken when the container starts. The destination is a path in the container, looked up inside it: where the image has a link on the way, the volume lands where the link leads in the container. A destination that the image lacks is made; one that leads nowhere in the container fails the start.
- Volumes are mounted on top of everything else, so one below `/tmp` or `/run` is visible there.
- `--vol` now supports both directory and single-file bind mounts.
- `lightbox add-vol <name> <src>:<dst>[:ro]` appends a volume to an existing container's config. Adding the very same volume again does nothing.
- `lightbox rm-vol <name> <dst>` takes the volume at that destination out of the config. What is in the volume's source is not touched.
- If the container is already running, added and removed volumes take effect after a restart.
