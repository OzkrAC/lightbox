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
- A `br0` bridge with the address `gw` and the prefix of `subnet`, `10.0.0.1/24` unless `lightbox.conf` sets them
- lightbox's firewall chains, reached from the top of `FORWARD` and `POSTROUTING` (see [Firewall](#firewall))
- IPv4 forwarding, if it was off, with the `FORWARD` policy set to DROP as Docker does
- cgroup v2 mount at `/sys/fs/cgroup`

### 3. Create, start, and use containers

```sh
# Create a container; it gets the lowest free address of the subnet, 10.0.0.2 on a new host
./lightbox create mybox
# or give it one: ./lightbox create mybox 10.0.0.20

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
./lightbox create app --mem 512M --cpu 2 --pids 256

# Half a CPU, and no limit on memory, at an address of your choosing
./lightbox create small 10.0.0.8 --cpu 0.5 --mem max

# User namespaces are planned but not supported yet
# ./lightbox create sandbox --userns

# Read-only rootfs with a data volume
./lightbox create web --read-only --vol /data/www:/var/www:ro

# Mount a host file into the container
./lightbox create conf --vol /srv/config/app.conf:/etc/app.conf:ro

# Use a different rootfs image
./lightbox create deb --rootfs /opt/rootfs/debian

# Choose the name servers the container asks
./lightbox create resolver --dns 9.9.9.9 --dns 149.112.112.112

# Disable the security sandbox
./lightbox create dev --privileged

# Allow two containers to talk to each other; the one linked to comes first
./lightbox create db
./lightbox create api --link db

# Run a command as one of the container's users, with a variable set, in a directory
./lightbox exec app --user www-data --env MODE=debug --workdir /var/www -- ls -la

# Add a volume to an existing container configuration
./lightbox add-vol app /srv/config/app.conf:/etc/app.conf:ro
# Take the volume at a destination out again
./lightbox rm-vol app /etc/app.conf
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
- `lightbox stop` sends SIGTERM to every process in the container and waits until they have ended, for 10 seconds; what is left then is killed. A service that should shut down cleanly has to handle SIGTERM. `stop <name> -t <seconds>` or `stop_timeout` in `lightbox.conf` sets the time, and `-t 0` kills at once.
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

### Rootfs resolution order

1. `--rootfs <path>` flag on create (highest priority)
2. `LIGHTBOX_ROOTFS` environment variable
3. `rootfs` in `lightbox.conf`
4. `/var/lib/lightbox/rootfs` (built-in default)

## Command reference

```
lightbox <command> [args]

  setup                         Initialize host networking
  create <name> [<ip>] [options]  Create a new container; without <ip>, the lowest free address
  start  <name> [-t <seconds>]  Start a stopped container
  stop   <name> [-t <seconds>]  Stop a running container
  add-vol <name> <src>:<dst>[:ro]  Add a volume to an existing container
  rm-vol <name> <dst>           Remove the volume at a destination
  rm     <name>                 Remove a container
  exec   <name> [options] [--] [cmd [args...]]   Run a command in a container
  logs   <name> [-f]            Show what a container has printed; -f follows it
  ls                            List all containers
```

### Create options

| Flag | Default | Description |
|------|---------|-------------|
| `--rootfs <path>` | `$LIGHTBOX_ROOTFS` | Base rootfs to copy |
| `--mem <limit>` | `256M` | Memory limit: a number of bytes, optionally with `K`, `M`, `G` or `T`, or `max` for none |
| `--swap <limit>` | `0` | Swap the container may use beyond its memory: `0`, a size as for `--mem`, or `max` |
| `--pids <limit>` | `128` | Max processes, 1 to 4194304, or `max` for no limit |
| `--cpu <num>` | `1` | CPUs, 0.01 to 512, with up to two decimals: `2`, `0.5`, `1.25` |
| `--io-max "<major>:<minor> <key>=<value>..."` | none | I/O limit for one whole disk of the host, as `io.max` takes it: `"8:0 wbps=10485760 riops=1000"`, with `rbps`, `wbps`, `riops` and `wiops`, each a number or `max` |
| `--vol <src>:<dst>[:ro]` | — | Bind mount (repeatable, up to 16, one at a destination) |
| `--userns` | — | Future improvement; not supported yet |
| `--uid-start <n>` | — | Future improvement; not supported yet |
| `--read-only` | off | Read-only root filesystem |
| `--privileged` | off | Disable security sandbox |
| `--oom-score <n>` | `500` | OOM score adjustment, -1000 to 1000 |
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

What the command gets as its standard streams depends on what `exec` itself was given, and is never a terminal of yours:

- **Typed at a terminal** (stdin and stdout are both a terminal): the command gets a terminal of its own, a pseudo-terminal of the container, as its controlling terminal. Your terminal is raw for as long as the command runs, so every key goes to the command: Ctrl-C interrupts what runs in the container, not `exec`. The window's size is passed on, also when it changes.
- **With a terminal on one side only**, as in `lightbox exec x cat file | less` or `lightbox exec x cat > notes`: the command gets a pipe in the place of the terminal, which `exec` reads or fills. Bytes arrive as they were sent.
- **Without a terminal**, as in a script or a pipeline: the three streams as they are.

In every case the command leads a session of its own and is given nothing else that was open where `exec` was run. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to `exec` are passed on to the command.

The command is found as a shell finds it: a name without a slash is looked for in the directories of `PATH`. Its environment is `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, `HOME`, `USER` and `LOGNAME` for its user, and the `TERM` of the terminal `exec` was typed on; nothing else of your environment goes into the container. Its groups are the ones the container's `/etc/group` lists for its user, and none for a uid the container has no account for. `exec` exits with the command's status, with 127 when the command is not there and 126 when it cannot be run.

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
| Container isolation | A container without `--link` has an isolated port on the bridge: it reaches the host and the outside, and no other container. IPv6 is off inside containers. A container with `--link` shares the bridge, is kept to its links by iptables rules that name the two ports of each link, and does not start unless `br_netfilter` lets iptables see bridged traffic. A link holds whichever of the two starts first, and a container's link rules go with it when it stops, is removed or is found dead |
| The terminal of whoever runs `exec` | A command never holds it. Typed at a terminal, `exec` gives the command a pseudo-terminal of the container and carries the bytes; where only one of its streams is a terminal, a pipe stands in for it |
| The binary `exec` enters with | `exec` executes itself again from a sealed copy in memory before it enters a container, so the processes it puts there are never the installed binary. Where the kernel refuses executable memfds (`vm.memfd_noexec=2`) it takes the binary through a read-only mount of its own instead. Its worker is not dumpable. `lightbox doctor` says which of the two is in use |
| User namespaces | Planned future improvement |
| OOM priority | Containers scored higher for OOM killer |

## How it works

- **Namespaces**: `clone()` with PID, mount, UTS, IPC, net (and optionally user) namespace flags
- **Filesystem**: each container lives under `<container_dir>/<name>/` with `rootfs/` for the filesystem, `.conf` and `.ip` for what it is configured with and `console.log` for its output. `pivot_root` into the rootfs copy
- **Runtime records**: what is known about a container while it runs is in `<run_dir>/<name>/`: `pid` and `pid_start` for its init, `state`, and `exit`, where init writes its exit status as the last thing it does. These are written without waiting for a disk, and a reboot takes them away with everything else in `/run`; a container without them is stopped. `start` makes the directory again when it is missing, for root alone
- **States**: `ls` and `inspect` show `stopped`, `running`, `starting` and `stopping` while a command is at work, `exited` for a container that ended by itself, `failed` for one that was killed or whose start or hook failed, and `creating` for one that `create` did not finish. A half-made container is not started: remove it and create it again
- **A container that ended without a stop**: when init is killed, or is told to stop by a signal from somewhere other than `lightbox stop`, from inside the container too, nobody is there to clear up. `ls` shows such a container as `exited` and changes nothing. The next `start`, `stop` or `rm` clears away what it left, its cgroup, its interface and the firewall rules of its links, says that it did, and records `exited` if init had ended with status 0 and `failed` otherwise
- **A container's configuration**: `.conf` is lines of `key=value` that begin with `version=1`. One piece of code reads it and one writes it; a command reads it once, and `start` hands it to init. A file with the version line is read strictly: an unknown key, a key given twice or a value that is not one is an error that names the file and the line, and a file written by a newer lightbox is refused, not guessed at. A file from before the version line is still read as it was, and is written in the new form at the next `add-vol` or `rm-vol`. `rm` does not need the file, so a container whose configuration is damaged can always be removed
- **Devices**: bind-mounted from host (`/dev/null`, `/dev/zero`, `/dev/random`, etc.)
- **Networking**: veth pair per container connected to a host bridge with NAT. `create` writes the container's `/etc/resolv.conf`, `/etc/hostname` and a line for its own name in `/etc/hosts`, inside the copy of the image, where a link in the image cannot send them anywhere else
- **Resource limits**: cgroups v2 (memory, PIDs, CPU, I/O)
- **Init**: lightbox remains PID 1 inside the container. It reaps children and handles shutdown from the moment the container is built, and runs `/init.sh`, if the rootfs has one, as one of its children: after `/tmp` and `/run` are mounted, with the sandbox on, and only once the container is on record, so `stop` and `ls` always find a container whose hook runs
- **Stopping**: `stop` sends init a SIGTERM that carries the number of seconds the container may take. Init passes SIGTERM on to every process in the container, the ones `exec` put there included, reaps them, and exits when none is left or the time is over; the kernel kills whatever remains with it. `stop` waits for init through a pidfd, so it returns as soon as the container has ended. It then kills anything still in the cgroup, waits until the kernel reports the cgroup empty, and removes it. A SIGTERM sent to init by other means has the same effect, with the `stop_timeout` that was set when the container started
- **Output**: init leads a session of its own and keeps nothing that was open in the command that started it. Its standard output and error, and those of the hook and every service, are appended to `<container_dir>/<name>/console.log`, which only root can read. The log is kept from one start to the next and is not rotated or limited yet, so a container that prints without end fills the disk it is on
- **Starting**: `start` and init talk over two pipes. Init builds the container when `start` has set up its cgroup and network, and reports back when it is built and again when the hook has ended. If either side goes away the other notices: an init whose `start` was killed exits before it runs anything
- **External tools**: on the host, `ip` and `nsenter` set up a container's network, `iptables` and `iptables-restore` the firewall (a start with links runs `iptables-restore` once), and `cp` and `rm` create and remove a container. Everything else is direct syscalls, and nothing from the image is run before `/init.sh`
- **One command at a time**: `start`, `stop`, `rm`, `add-vol` and `rm-vol` take a lock on the container they change, and `create` and `setup` one on the whole store, so two commands on one container do their work one after the other. A command that has to wait says so. `ls` and `inspect` never wait. `setup`, `start`, `stop` and `exec` need root and say so before they touch anything
- **Configuration**: optional `~/.config/lightbox/lightbox.conf` for all paths and defaults

## Volume Notes

- A volume is written `src:dst[:ro]`. Both paths are absolute and may not contain `..`, a colon or a control character such as a newline; they are stored in one spelling, without doubled slashes. The destination may not be `/` or under `/proc`, `/sys` or `/dev`.
- A container has at most 16 volumes, and one at any destination: a second one there would be mounted over the first, which would never be seen. A destination inside another volume is another destination.
- The source is a path on the host, taken when the container starts. The destination is a path in the container, looked up inside it: where the image has a link on the way, the volume lands where the link leads in the container. A destination that the image lacks is made; one that leads nowhere in the container fails the start.
- Volumes are mounted on top of everything else, so one below `/tmp` or `/run` is visible there.
- `--vol` now supports both directory and single-file bind mounts.
- `lightbox add-vol <name> <src>:<dst>[:ro]` appends a volume to an existing container's config. Adding the very same volume again does nothing.
- `lightbox rm-vol <name> <dst>` takes the volume at that destination out of the config. What is in the volume's source is not touched.
- If the container is already running, added and removed volumes take effect after a restart.
