# lightbox

A minimal, secure Linux container runtime. Single static binary, ~33KB, no libc — built on [lightc](https://github.com/OscarAC/lightc) using raw Linux syscalls.

## Prerequisites

- Linux with namespace and cgroup v2 support
- GCC and ninja (build time)
- `iproute2`, `iptables`, `util-linux` (`nsenter`) at runtime
- BusyBox `ip` is not sufficient; `lightbox start` requires the full `iproute2` `ip` binary for veth creation and bridge attachment
- For containers created with `--link`: the `br_netfilter` kernel module, with `net.bridge.bridge-nf-call-iptables=1`
- Root privileges

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
| `make check-sys` | Compiles `tests/sys_check.c` and `tests/sys_check_net.c`, which compare every private syscall number, constant and structure in `lightbox_sys.h`, and every number in the seccomp table of `lightbox_seccomp.h`, with the kernel's headers, for x86_64 and aarch64 |
| `make analyze` | Compiles every file with `-fanalyzer` and a strict warning set; any diagnostic is an error |
| `make test-unit` | Runs lightbox's own helpers from the command line. The one that starts programs: exit statuses, signals, missing programs, quiet and captured output. The ones that mount, make directories and bring up loopback: in a user namespace of their own |
| `make test-validation` | Runs the built binary as an ordinary user against a temporary directory tree |
| `make test-seccomp` | Installs lightbox's real seccomp profile and probes every syscall in its deny table; also interprets the x86_64 and the aarch64 filter program for every syscall number |

In the test suites an open finding from `ROADMAP.md` is an expected failure that names its ledger id. When a fix makes one pass, the suite fails until the case is changed from `xfail` to `check`.

One more suite starts real containers, so it needs root:

```sh
sudo make test-lifecycle
```

It covers `setup`, `create`, `start`, `exec`, `stop` and `rm`, volumes, limits, the init hook, the sandbox and the network between containers. It needs a kernel with bridge, veth and cgroup v2, and a statically linked busybox to build the containers' root filesystem from (`busybox-static` on Debian, Ubuntu and Void). `LIGHTBOX_TEST_ROOTFS=/path` uses a copy of a root filesystem of yours instead.

The suite works in private network, mount and PID namespaces with a configuration of its own, so your bridge, firewall rules and containers are not touched. Its cgroups live under `/sys/fs/cgroup/lightbox-test-<pid>` and are removed at the end, and the run fails if the host's virtual interfaces, firewall rules or cgroups differ afterwards. A network card that the machine itself gains or loses during the run, as a cloud VM can, is reported and does not count. Kernel modules that get loaded on the way stay loaded.

sudo drops the environment, so options go on make's command line: `sudo make test-lifecycle V=1 KEEP=1`. Build first, as yourself; the target builds nothing.

`sudo make bench` works in the same namespaces and measures the wall time of `create`, `start`, `exec`, `stop` and `rm`, and the number of processes one start makes.

`.github/workflows/ci.yml` runs `make check`, the lifecycle suite and the timing on every push to `main` and every pull request, on x86_64 and on aarch64. A run's page lists each suite's totals, the cases it skipped and why each expected failure fails, without opening a log.

## Quick start

### 1. Get a rootfs

lightbox needs a Linux root filesystem to use as a base image. Any distro works — Alpine minirootfs is a good starting point (~3MB). The image needs no tools of its own: lightbox mounts and configures everything itself, so a single static binary is an image too.

```sh
mkdir -p /opt/rootfs/alpine
wget https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.21.3-x86_64.tar.gz -C /opt/rootfs/alpine
```

Tell lightbox where to find it — either export the environment variable or pass `--rootfs` on each create:

```sh
export LIGHTBOX_ROOTFS=/opt/rootfs/alpine
```

### 2. Set up host networking

Run once to create the bridge, enable NAT, and mount cgroups. Safe to re-run (idempotent).

```sh
./lightbox setup
```

This creates:
- A `br0` bridge on `10.0.0.1/24`
- iptables NAT masquerade for outbound traffic
- FORWARD rules for container-to-WAN communication
- A DROP rule for inter-container traffic (isolation by default, together with isolated bridge ports)
- cgroup v2 mount at `/sys/fs/cgroup`

### 3. Create, start, and use containers

```sh
# Create a container with IP 10.0.0.2
./lightbox create mybox 10.0.0.2

# Start it
./lightbox start mybox

# Get a shell inside
./lightbox exec mybox /bin/sh

# Run a single command
./lightbox exec mybox cat /etc/os-release

# See what the container's services have printed; -f keeps following
./lightbox logs mybox

# List all containers
./lightbox ls

# Stop and remove
./lightbox stop mybox
./lightbox rm mybox
```

### 4. Customize containers

```sh
# Custom resource limits
./lightbox create app 10.0.0.2 --mem 512M --cpu 2 --pids 256

# User namespaces are planned but not supported yet
# ./lightbox create sandbox 10.0.0.3 --userns

# Read-only rootfs with a data volume
./lightbox create web 10.0.0.4 --read-only --vol /data/www:/var/www:ro

# Mount a host file into the container
./lightbox create app 10.0.0.6 --vol /srv/config/app.conf:/etc/app.conf:ro

# Use a different rootfs image
./lightbox create deb 10.0.0.5 --rootfs /opt/rootfs/debian

# Disable the security sandbox
./lightbox create dev 10.0.0.6 --privileged

# Allow two containers to talk to each other
./lightbox create api 10.0.0.10 --link db
./lightbox create db  10.0.0.11

# Add a volume to an existing container configuration
./lightbox add-vol app /srv/config/app.conf:/etc/app.conf:ro
# Restart if the container is already running
```

### 5. Start services with an init hook

If the image has an `/init.sh`, the container's init runs it with `/bin/sh` once the container is built, and `start` returns when the script has ended:

```sh
# /init.sh in the image: start the service in the background and return
/usr/sbin/nginx &
```

- The hook and everything it starts read from `/dev/null` and write to the container's log, not to the terminal `start` was typed on. `lightbox logs <name>` shows the log, and `logs -f` follows it until the container stops.
- A hook that exits with a status other than 0 fails the start: `start` says which status it was, and the container is stopped and cleaned up. A hook that fails after `start` has returned stops the container as well.
- `start` waits 30 seconds for the hook. If the hook is still running then, for instance because it runs its service in the foreground, `start` says so and returns; the container stays up. `start <name> -t <seconds>` or `start_timeout` in `lightbox.conf` sets the wait, and 0 does not wait at all.
- Ctrl-C, or a `kill`, while `start` is working undoes the start: nothing of the container is left running, and the exit status is 128 plus the signal's number.

## Configuration

lightbox reads `~/.config/lightbox/lightbox.conf` at startup. All values have built-in defaults — the config file is optional.

```ini
# ~/.config/lightbox/lightbox.conf

# Base directory for lightbox data (base rootfs and container directories)
lightbox_dir = /var/lib/lightbox

# Default rootfs to copy when creating containers
# Also overridable with LIGHTBOX_ROOTFS env var or --rootfs flag
rootfs = /var/lib/lightbox/rootfs

# Where containers are stored (each gets a subdirectory)
container_dir = /var/lib/lightbox/containers

# PID file directory
run_dir = /run/lightbox

# cgroup v2 mount point
cgroup_root = /sys/fs/cgroup

# Bridge interface and network
bridge = br0
subnet = 10.0.0.0/24
gw = 10.0.0.1

# Default container resource limits
default_mem = 256M
default_pids = 128
default_cpu = 1
default_oom = 500

# Seconds that start waits for a container's /init.sh; 0 does not wait
start_timeout = 30
```

If `lightbox_dir` is set, `rootfs` and `container_dir` are automatically derived from it (e.g., `rootfs = <lightbox_dir>/rootfs`) unless explicitly overridden.

### Rootfs resolution order

1. `--rootfs <path>` flag on create (highest priority)
2. `LIGHTBOX_ROOTFS` environment variable
3. `rootfs` in `lightbox.conf`
4. `/var/lib/lightbox/rootfs` (built-in default)

## Command reference

```
lightbox <command> [args]

  setup                         Initialize host networking
  create <name> <ip> [options]  Create a new container
  start  <name> [-t <seconds>]  Start a stopped container
  stop   <name>                 Stop a running container
  add-vol <name> <src>:<dst>[:ro]  Add a volume to an existing container
  rm     <name>                 Remove a container
  exec   <name> [cmd...]        Run a command in a container
  logs   <name> [-f]            Show what a container has printed; -f follows it
  ls                            List all containers
```

### Create options

| Flag | Default | Description |
|------|---------|-------------|
| `--rootfs <path>` | `$LIGHTBOX_ROOTFS` | Base rootfs to copy |
| `--mem <limit>` | `256M` | Memory limit |
| `--pids <limit>` | `128` | Max processes |
| `--cpu <num>` | `1` | CPU cores |
| `--vol <src>:<dst>[:ro]` | — | Bind mount (repeatable) |
| `--userns` | — | Future improvement; not supported yet |
| `--uid-start <n>` | — | Future improvement; not supported yet |
| `--read-only` | off | Read-only root filesystem |
| `--privileged` | off | Disable security sandbox |
| `--oom-score <n>` | `500` | OOM score adjustment |
| `--link <name>` | — | Allow network to another container (repeatable) |

## Security

All security features are on by default. Pass `--privileged` to disable.

The sandbox covers everything in a container: init, the `/init.sh` hook and all it starts, and every `exec`. A hook that mounts filesystems or configures the network therefore needs `--privileged`.

| Feature | Implementation |
|---------|---------------|
| Capability dropping | The bounding, effective and permitted sets are reduced to 12 capabilities: Docker's default 14 without `NET_RAW` and `MKNOD`. The inheritable and ambient sets are emptied |
| Seccomp | BPF filter denying 56 syscalls on x86_64 (47 on aarch64), the x32 range, and `clone` with namespace flags |
| no_new_privs | Prevents SUID escalation |
| /proc and /sys masking | The paths Docker masks by default are covered, files with `/dev/null` and directories with an empty read-only tmpfs. A mask that cannot be made fails the start |
| /proc read-only | Remounts /proc/sys, /proc/bus, /proc/fs, /proc/irq read-only |
| Root filesystem | Mounted `nodev`, and `nosuid` unless privileged. Devices come from the `/dev` that lightbox builds |
| Container isolation | A container without `--link` has an isolated port on the bridge: it reaches the host and the outside, and no other container. IPv6 is off inside containers. A container with `--link` shares the bridge, is kept to its links by iptables, and does not start unless `br_netfilter` lets iptables see bridged traffic |
| User namespaces | Planned future improvement |
| OOM priority | Containers scored higher for OOM killer |

## How it works

- **Namespaces**: `clone()` with PID, mount, UTS, IPC, net (and optionally user) namespace flags
- **Filesystem**: each container lives under `<container_dir>/<name>/` with `rootfs/` for the filesystem, `.conf`, `.ip`, `.pid` for metadata and `console.log` for its output. `pivot_root` into the rootfs copy
- **Devices**: bind-mounted from host (`/dev/null`, `/dev/zero`, `/dev/random`, etc.)
- **Networking**: veth pair per container connected to a host bridge with NAT
- **Resource limits**: cgroups v2 (memory, PIDs, CPU, I/O)
- **Init**: lightbox remains PID 1 inside the container. It reaps children and handles shutdown from the moment the container is built, and runs `/init.sh`, if the rootfs has one, as one of its children: after `/tmp` and `/run` are mounted, with the sandbox on, and only once the container is on record, so `stop` and `ls` always find a container whose hook runs
- **Output**: init leads a session of its own and keeps nothing that was open in the command that started it. Its standard output and error, and those of the hook and every service, are appended to `<container_dir>/<name>/console.log`, which only root can read. The log is kept from one start to the next and is not rotated or limited yet, so a container that prints without end fills the disk it is on
- **Starting**: `start` and init talk over two pipes. Init builds the container when `start` has set up its cgroup and network, and reports back when it is built and again when the hook has ended. If either side goes away the other notices: an init whose `start` was killed exits before it runs anything
- **External tools**: on the host, `ip` and `nsenter` set up a container's network, `iptables` the firewall, and `cp` and `rm` create and remove a container. Everything else is direct syscalls, and nothing from the image is run before `/init.sh`
- **Configuration**: optional `~/.config/lightbox/lightbox.conf` for all paths and defaults

## Volume Notes

- `--vol` now supports both directory and single-file bind mounts.
- `lightbox add-vol <name> <src>:<dst>[:ro]` appends a volume to an existing container's config.
- If the container is already running, added volumes take effect after a restart.
