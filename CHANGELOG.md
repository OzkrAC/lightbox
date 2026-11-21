# Changelog

What changed for someone who uses lightbox, newest first. `ROADMAP.md` has the reasons and the finding each change closes.

## 0.8.0

Not tagged yet: the part of Phase 8 that is written so far.

### Changes you may have to act on

- **`create --uid-start` is gone.** It was refused before; a container created with `--userns` gets its range from `/etc/subuid` and `/etc/subgid`.
- **`inspect` has four keys more**, `userns`, `uid_start`, `gid_start` and `seccomp`, and `doctor` a setting `userns_ranges`, in text and in `--json`.
- **Nothing in a container that is not privileged gives a file the setuid or the setgid bit.** The seccomp filter refuses such a mode with EPERM in `chmod`, `fchmod`, `fchmodat`, `fchmodat2`, `mknod`, `mknodat`, `creat`, and `open` and `openat` that make a file, as systemd's `RestrictSUIDSGID=` does for a service, and `openat2`, whose mode it cannot read, answers ENOSYS so that callers use `openat`. What a container makes in a volume is on the host too, where the bits would hold: a program it left there could run with the rights of the volume's owner, or of root without `--userns`. In the container they meant nothing. A package that installs a setuid or setgid program, such as `passwd`, `mount` or `sudo`, now fails to install in a container: update it in the base on the host, or use `--privileged`.
- **A new container reaches the internet and its name servers, and not the host or its networks.** `create --net outside` is the default: the host is refused on every address of its, and so are the private ranges, link-local with the clouds' metadata services, the carriers' shared range, loopback, multicast and the rest that is no one's on the internet, at once: TCP with a reset, which a client says as a refused connection, and the rest with an ICMP "administratively prohibited", which it says as no route to the host. An ICMP error for TCP would fail a connection only a second later: it comes back while the kernel is still sending the first SYN, which takes it for a soft error. The name servers the container was created with stay in reach on port 53. A container that uses a service of the host or of the local network, such as a database, a package cache or a development server, has to be created with `--net nat`, the network every container had before; one created before keeps it. With `firewall = false` in `lightbox.conf` lightbox makes no rules, so `create` refuses `--net outside`, and the default with it: give `--net nat` or `--net none`. A start of a container of `--net outside` runs one process more, for its rules, unless it has links, which go in with them; and with `firewall_backend = iptables` every start runs one more again, the look at the jump to `LIGHTBOX-INPUT`. A container of the default starts with 6 processes with iptables, from 4.
- **A new container has the allow-list seccomp profile**, described under Added, unless it is created with `--seccomp deny`. A container created before keeps the deny-list: its `.conf` has no `seccomp=` line, which means the deny-list. A program that needs a syscall the allow-list does not name gets ENOSYS; create its container with `--seccomp deny`.
- **Under either profile, `socket` takes only `AF_UNIX`, `AF_INET`, `AF_INET6` and `AF_NETLINK`, and `socketpair` only `AF_UNIX`.** Any other family answers EAFNOSUPPORT, as a kernel without it would. `AF_VSOCK`, which no network namespace confines, and `AF_ALG` were open to a container before.
- **The deny-list refuses `pidfd_getfd`, `process_madvise` and `set_mempolicy_home_node`** with EPERM, as Docker does without `CAP_SYS_PTRACE` or `CAP_SYS_NICE`, which no container has. `pidfd_getfd` took a descriptor of another of the container's processes, which `ptrace` is refused.
- **A container opens the devices of its `/dev` and no other.** A cgroup device program, attached before init is in the container's cgroup, lets its processes open `null`, `zero`, `full`, `tty`, the `ptmx` and terminals of its devpts, and `random` and `urandom` for reading only, and refuses every other device with EPERM, wherever a node of it is and whoever made it; no device can be made. Before, only the absence of nodes kept a container from a device, and a node that host root put in its `/dev` opened. Writing to `/dev/urandom`, which its read-only mount did not prevent, is refused: a program that saves entropy there fails. `start` fails when the kernel does not load the program, which needs `CONFIG_CGROUP_BPF`, and `doctor` has a check `device_filter` that says whether it does; a privileged container has no program. A container started before keeps what it had until its next start.
- **A container no longer has `CAP_SETFCAP`**, and has 11 capabilities: Docker's 14 without `NET_RAW`, `MKNOD` and now `SETFCAP`. A file capability that a container's root wrote on a program in a volume would hold on the host, as root's for a container without `--userns`; in the container it gave nothing, as no_new_privs keeps an execve from granting it. `setcap` fails in a container, and with it a package that runs it, such as `iputils-ping`, which then tries the setuid bit and is refused that too.

### Added

- **`create --userns`** gives a container a user namespace of its own: its root is an unprivileged uid on the host, the first of a range of 65536 uids and gids that `/etc/subuid` and `/etc/subgid` give the name `lightbox`, as rootful Podman's `--userns=auto` uses `containers`. Its root filesystem is an idmapped mount, so the base's files are its root's and nothing is chowned: Linux 5.12 for a `--copy` container, 5.19 for an overlay. An overlay container's own files belong on the host to its range. Without a range, or where the kernel or the filesystem cannot idmap, `create --userns` says why and makes nothing. `exec` joins the user namespace first.
- **A volume of a `--userns` container is its source's owner's.** It is an idmapped mount, so the container's root stands for the owner and group of the source on the host and no other id is mapped: what the root makes there is the owner's on the host, and the owner's files are root's in the container. A source of host uid 0 or gid 0 is bound as it is; its files are nobody's in the container. A source on a filesystem without idmapped mounts fails the start, and says so.
- **The allow-list seccomp profile**, `create --seccomp allow` and the default: Docker's list fitted to what agents run, a shell, git, Python, Node.js, a C compiler and a package manager, with the deny-list's refusals and its rules for `clone`, for setuid and setgid modes and for the families of a socket. Any syscall it does not name answers ENOSYS, as on an older kernel, so a program falls back instead of failing: among them `mount`, `sethostname`, `syslog`, `modify_ldt` and every call newer than Linux 6.8. `--seccomp deny` gives the deny-list; the `.conf` of an allow-list container says `seccomp=allow`, and `inspect` shows `seccomp`. `make test-seccomp` runs git, Python, Node.js and a C compile and link under both profiles, and `LIGHTBOX_TEST_SECCOMP=deny` runs the lifecycle suite with every container under the deny-list, as CI does on each architecture.
- **`create --net nat|outside|none`** chooses what a container may reach, and `inspect` shows it as `net`. `none` gives it loopback and nothing else: no interface, address, route or rule, and no `--link`. The rules are lightbox's: with iptables the chains `LIGHTBOX-INPUT`, jumped to from the top of `INPUT`, `LIGHTBOX-EGRESS` and `LIGHTBOX-OUTSIDE`, and a chain `LO-<hash>` of each running container; with nftables the chains `egress` and `egress_host` and the sets `outside`, `outside_dns` and `refused` of `table ip lightbox`. `reload` puts a running container's back, as its links. The `.conf` says `net=outside` or `net=none`, and `dns=` the name servers.
- **`create --net proxy:<port>`** keeps a container to one TCP port of the gateway, where a proxy of the host's listens: everything else is refused at once, name servers included, its `resolv.conf` names none, and `exec` and the init hook have `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in both spellings, which `exec --env` can replace. It takes no `--dns` and no `--link`, `create` refuses a `--link` to such a container, and the bridge drops whatever it would switch to or from one, so a link made before reaches nothing. The rules: with iptables the container's chain `LO-<hash>` and two drops at the top of `LIGHTBOX-LINKS`; with nftables the sets `proxied` and `proxy_to` and the chain `egress_proxy` of `table ip lightbox`, and the set `sealed` of `table bridge lightbox`; on a host whose tables an earlier setup made, the next start makes them again with them. lightbox ships no proxy; **`contrib/proxy/`** has a configuration for Squid 6 that lets containers reach a list of names on ports 443 and 80, looks up no other name, and refuses a name on the list that resolves to a private range. The lifecycle suite runs it.
- **`tests/fetch_image.sh alpine|debian <dir>`** fetches Alpine's minirootfs 3.24.4 or Debian's `trixie-slim` image, each pinned by its SHA-256, and unpacks it for `LIGHTBOX_TEST_ROOTFS`. CI runs the lifecycle suite on both, on each architecture. The suite puts its static busybox in every image at `/lbt/busybox`, for the `nc`, `ip` and `hostname` its network cases run, and so needs it with `LIGHTBOX_TEST_ROOTFS` too.
- **`sudo make test-lifecycle LIGHTBOX_TEST_USERNS=overlay`**, and `=copy`, run the lifecycle suite with every container made with `--userns`, the second with `--copy` too but in the cases about overlays. CI runs the suite in both ways and as it is, on each architecture.

### Changed

- **Init mounts `/proc` and `/sys` before it lets go of the host's root**, and builds a container's `/dev` and pivots from a descriptor of its root, for every container: a user namespace requires the first, and its root cannot reach the path to the container's directory.
- **A change of a mount's flags keeps how it keeps access times**, as it kept read-only, nosuid, nodev and noexec: a user namespace may not change that of a mount it got from the host, such as one of `noatime`.

## 0.7.0

Tagged `v0.7.0`, at `1782616`, the merge of pull request 7. Phase 7 of the roadmap: performance. A new container is an overlay of a snapshot of its base, so that `create` takes as long from a base of 1 GB as from a small one; lightbox makes a container's network with rtnetlink and runs neither `ip` nor `nsenter`; and `lightbox reload` puts back what a firewall's reload took. On GitHub's runners a start takes a median of 8.8 ms on x86_64 and 12.9 ms on aarch64, and a stop 2.9 and 5.5, where before Phase 1 of the roadmap they took about 535 and 207 on the same kind of runner.

### Changes you may have to act on

- **A new container is an overlay of a snapshot of its base, not a copy of it.** The first `create` from a base takes a snapshot of it into `<lightbox_dir>/bases/`, and every container of that base shares it; `create` after the first takes no time or room of the base's size, and a change of the base directory afterwards changes no container. `<container_dir>/<name>/rootfs/` holds only the container's own files, and the base's are not there on the host: a script that reads or changes a file of the base there has to use `--copy`, or work in the container. A file of the base that is changed from the host has to be copied into `rootfs/` first. Containers made before 0.7 are copies, and stay so.
- **Where an overlay cannot be mounted**, without overlayfs or without the right to mount, `create` makes a copy, as before, and says so.
- **lightbox runs neither `ip` nor `nsenter`**, so iproute2 and util-linux are no longer needed on the host. `doctor` no longer has the checks `bin.ip` and `bin.nsenter`, in its text or in `--json`: a script that looked for them finds them gone.
- **A failure in a container's network is said with the kernel's errno** where `ip` printed its own words before, as in `Error: failed to attach the container's interface to the bridge (errno 95)` or `Error: cannot make the bridge br0 (errno 1)`.

### Changed

- **`start`, `stop`, `rm`, `setup` and `setup --teardown` make and take away the bridge, the veth pair and the bridge's port with rtnetlink requests of their own**, and the container's init gives `eth0` its address and its default route from inside the container: nothing enters the container's network namespace from the host. A start makes 4 processes instead of 12, and the only tool it runs on the host is the firewall's: one `iptables` or `nft` to look whether lightbox's rules are there, and with links the transaction that adds theirs. On GitHub's runners it takes a median of 9.0 ms on x86_64 and 11.5 ms on aarch64, where it took 22.7 and 28.5.

### Added

- **`create --copy`** makes a container a full copy of its base, as before 0.7, a reflink first where the filesystem has them.
- **`lightbox base ls`, `base add <dir>` and `base rm <id>`** list the snapshots with their bases and containers, take a new snapshot of a base for the containers made after it, and remove snapshots that no container uses.
- `inspect` shows `storage`, overlay or copy, and the `base` snapshot; `doctor` says whether the kernel has overlayfs.
- **`lightbox reload`** puts in again what a firewall's reload or flush took while containers ran, as `podman network reload` does: what `setup` makes, and the link rules of every running container. It changes nothing that is there already. A `start` that finds `setup`'s rules gone, which made them again before, now puts back the links of the running containers too.

## 0.6.0

Tagged `v0.6.0`, at `fd702e8`, the merge of pull request 6. Phase 6 of the roadmap: a command line that gives help when it is asked for and refuses what it will not use, the configuration in `/etc/lightbox`, a `doctor` that checks what `start` needs and says how to fix it, `inspect` and `doctor` in JSON, `restart`, `update` and `rm -f`, and a README whose command reference and quick start the suites check.

### Changes you may have to act on

- **Help goes to standard output and exits 0**: `lightbox --help`, `-h`, `help`, `help <command>` and `<command> --help`. It used to go to standard error, with status 1. A command line that is not one, such as an unknown command, still prints the usage on standard error and exits 1, and now says first what was wrong.
- **The configuration is `/etc/lightbox/lightbox.conf`**, or the file that `--config <path>` or `LIGHTBOX_CONFIG` names. `~/.config/lightbox/lightbox.conf`, where lightbox looked before, is still read when none of those is there, with a warning on every command: move the file to `/etc/lightbox/lightbox.conf`. lightbox 0.7 will not look in `~`. Under `sudo`, which `~` was meant depended on how `sudo` was set up.
- **`make install` puts the example configuration in `$(DESTDIR)/etc/lightbox/lightbox.conf`**, unless one is there, and writes nothing in the home of whoever runs it. It used to write `~/.config/lightbox/lightbox.conf` there, outside `DESTDIR`, which under `sudo` could be root's or the user's.
- **A key in `lightbox.conf` that lightbox does not know, and a line that is no setting, are warned about** with the file and the line; a misspelt `defualt_mem` was ignored without a word. A `#` after a space begins a comment, and a carriage return at the end of a line is dropped: `bridge = br0 # main` used to be the bridge `br0 # main`.
- **A word that a command will not use is an error that names it.** `inspect`, `doctor`, `ls`, `add-vol` and `rm-vol` ignored what came after the words they read: `inspect a b` showed `a`, and `rm a b` removed `a` and said nothing of `b`.
- **`doctor` exits 1 when an ordinary user runs it**, as `start` needs root, and on every other check that fails: it now checks the kernel, cgroup v2, `nsenter`, the base root filesystem and more. A script that ran `doctor` as a user for its exit status has to run it as root, or read its checks, as `doctor --json` gives them.
- **A container's `.conf` with `userns=1` is refused**, with its line, as user namespaces are not supported; `start` and `exec` refused such a container already. `userns=0` and `uid_start`, which earlier versions could write, are read and mean nothing. `inspect` no longer shows `userns` and `uid_start`, and `doctor` no longer looks for `chown`, which only the unsupported user namespaces used. About 190 lines of code that could not run are gone.

### Added

- **`start`, `stop` and `rm` take several names**, as Docker's do, and do one container after the other. One that cannot be done ends nothing for the others; the command names those it did not do, and exits with the first status that was not 0. `-t` for `start` and `stop` may come anywhere among the names.
- **`lightbox --version`** prints the version of lightbox and of lightc.
- **`lightbox --config <path> <command>`** reads that configuration, as `LIGHTBOX_CONFIG=<path>` does.
- **`doctor` checks what `start` needs**: that it runs as root, Linux 5.10 or later and the system calls lightbox makes, cgroup v2 at `cgroup_root` with the `cpu`, `memory` and `pids` controllers, `nsenter`, which it did not look for, an `ip` that is iproute2's and not BusyBox's, a base root filesystem with something in it, and with nftables that forwarding is on. Each check that fails is followed by a `  to fix:` line, and `doctor` exits 1, as it did for what it checked before; run as an ordinary user it now always does, since `start` needs root. It also says whether the bridge, the firewall rules and forwarding are there, which `start` makes when they are not. **`doctor --json`** gives the settings and the checks as JSON.
- **`lightbox update <name> --mem/--pids/--cpu`** changes a container's limits: in its `.conf`, so that every start has them, and at once in the cgroup of a container that runs. A limit that the running container does not take is said, and it has it from its next start. The values are held to what `create` holds them to.
- **`lightbox restart <name>... [-t <seconds>]`** stops a container that runs, as `stop` does, and starts it, and starts one that is stopped.
- **`lightbox rm -f <name>`** kills a container that runs first, as `docker rm -f` does, and removes it.
- **`inspect` shows all of a container's configuration**: a `volume:` line for each volume, as `<src>:<dst>[:ro]`, a `link:` line for each link, `-` for none, and `log_path`. **`inspect --json`** gives the same as an array of one JSON object, as `docker inspect` does, with numbers, `true` and `false`, `null` for what is not there, and arrays of volumes and links; a configuration that cannot be used is an error and prints no JSON.

### Fixed

- On a kernel before 5.8, which has no `faccessat2`, lightbox could not tell that any file was there; it asks with `faccessat` then. Such a kernel is below lightbox's floor, and `doctor` now says so.
- **The README says what the code does.** Its command reference is the usage `lightbox --help` prints, which the validation suite compares with it, and its quick start is run by the lifecycle suite as it is written. It gave the binary as about 33 KB, which is about 150; it said everything but a few tools was direct syscalls without naming `nft`, and that containers could have a user namespace. It now says what an image must contain, what the `/init.sh` hook gets and with which privileges, and what lightbox does and does not keep out, in a threat model.

## 0.5.1

Tagged `v0.5.1`, at `d0298a3`, the merge of pull request 5; no 0.5.0 was tagged. Phase 5 of the roadmap: one reader and writer for a container's configuration, strict values, locks, the clearing away of containers that died, records in `run_dir`, addresses and limits that are checked, firewall rules in chains and tables of lightbox's own with nftables as a backend to choose, interfaces that lightbox owns, and a host network that comes back after a reboot.

### Changes you may have to act on

- **`setup`, `start`, `stop` and `exec` refuse to run as an ordinary user**, with "must be run as root", before they look at anything. `start` used to go ahead, fail at its first privileged step and record the container as failed; `setup` changed the modes of the storage directories before it failed.
- **Commands wait for each other.** `start`, `stop`, `rm` and `add-vol` on the same container, and `create` and `setup` on the store, run one after the other; the one that waits prints "Waiting for another lightbox command to finish". A `stop` typed while a `start` is still waiting for the init hook waits for that `start`. `ls` and `inspect` never wait.
- **An option's value is what the option takes, or `create` refuses it** with the option named, and makes nothing. `--mem` takes a number of bytes, optionally with `K`, `M`, `G` or `T`, or `max`; `--pids` a number from 1 to 4194304, or `max`; `--cpu` a number of CPUs from 0.01 to 512; `--oom-score` a number from -1000 to 1000. Before, `--mem not-a-size` was stored and failed the start, `--oom-score abc` was stored as 0 and `--oom-score 12abc` as 12, and a long value was cut: `--pids 123456789` became 1234567 and `--cpu 1024` became 102. A number that begins with a 0, as in `--mem 0100M`, is refused too: the kernel would have read it as octal.
- **The `default_*` settings in `lightbox.conf` are held to the same.** One that is not a limit is reported as a warning by every command, and `create` refuses a container that would have needed it; give that container the option, or correct the setting.
- **A second volume at a destination is refused**, by `create` and by `add-vol`. The second one used to be mounted over the first. Adding the very same volume again still does nothing and is no error.
- **A volume path with a control character in it, such as a newline, is refused.**
- **A setting in `lightbox.conf` that does not fit is an error, not a shorter setting.** A directory may be up to 448 characters long. A `lightbox.conf` of more than 16 KB is refused as a whole; one of more than 2 KB used to be read up to that point, and the settings after it did not count.
- **The records of a running container are in `run_dir`**, `/run/lightbox` unless set otherwise, and no longer in the container's directory: `<run_dir>/<name>/pid`, `pid_start`, `state` and `exit`. Scripts that read `<container_dir>/<name>/.pid` or `.state` have to read these, or better `lightbox inspect`. A container that an older lightbox started and that is still running is found through its old records, and can be stopped as usual. If `run_dir` is set to a directory that is not on a tmpfs, the records outlast a reboot and containers show as `exited` after one until a command clears them.
- **A container that ended without `lightbox stop` is cleared away by the next `start`, `stop` or `rm`**, which prints a note saying so: its cgroup, its interface and the firewall rules of its links are removed, and its state becomes `exited` if its init ended with status 0, as it does when it is sent SIGTERM, and `failed` otherwise. Before, such a container became `failed` in every case, and its cgroup and rules stayed; `rm` left the rules for good.
- **A container that `create` did not finish is not started.** A `create` that is interrupted while it copies the root filesystem leaves a container that `ls` shows as `creating`; `start` used to run it with whatever had been copied.
- **`create` refuses an address that no container can have**: another container's, which it names, the gateway's, and the first and the last address of the subnet. It took them all; two containers on one address, or one on the bridge's, could not be reached.
- **An address with a zero in front of one of its numbers, such as `10.0.0.05`, is refused**, by `create`, `--dns` and the `dns` setting: some programs read such a number as octal and others refuse it. A container that was created with one does not start; create it again.
- **`subnet` and `gw` are checked together** by `setup`, `create` and `start`, and reported by `doctor`: `subnet` is `<address>/<bits>` with 8 to 30 bits, and `gw` is an address in it that is neither its first nor its last. Either one wrong ends the command, with the setting named, before anything is made.
- **The prefix of `subnet` is used.** `setup` gave the bridge a `/24`, and `start` gave every container one, whatever `subnet` said: on a `/16`, a container outside the gateway's `/24` did not start. A bridge that an earlier `setup` made keeps the address it was given, so with a `subnet` that is not a `/24`, delete the bridge while no container runs (`ip link delete br0`) and run `setup` again.
- **`start` refuses a container whose address is not in `subnet`**, as after a change of `subnet`. It would have started and reached nothing.
- **A container has no swap unless `--swap` gives it some**, containers made before included. Past its memory limit a process is killed instead of going on in swap, and with `memory.oom.group` the kernel ends the whole container, which the next `start`, `stop` or `rm` clears away. Give a container that needs swap `--swap`, by creating it again or by adding `swap=<size>` to its `.conf`.
- **The `io` line of a `.conf` is checked**: `<major>:<minor>` and one or more of `rbps`, `wbps`, `riops` and `wiops`, each `=<number>` or `=max`, without a zero in front of a number. One that is not is an error that names the line. It could only have come from an edit by hand.
- **lightbox's firewall rules are in chains of its own**, as Docker's are: `LIGHTBOX-FORWARD`, `LIGHTBOX-LINKS` with an `LB-<name>` chain for each running container with links, and `LIGHTBOX-POSTROUTING`, reached from the top of `FORWARD` and `POSTROUTING`. Run `setup` after the upgrade: it makes them and takes out the rules that earlier versions put straight into `FORWARD` and `POSTROUTING`. A container with links that is running through the upgrade gets its link rules back when it is started again. Scripts that looked for lightbox's rules in `FORWARD` have to look in these chains.
- **When `setup` turns IPv4 forwarding on, the `FORWARD` policy becomes DROP**, as Docker does it: the host forwards what a rule accepts and nothing else. A host that had forwarding on keeps its policy. `ip_forward_no_drop = true` in `lightbox.conf` leaves the policy in any case.
- **Rules of the host's that are to decide before lightbox's go in `LIGHTBOX-USER`**, like Docker's `DOCKER-USER`. lightbox makes the chain and never changes it.
- **Masquerading no longer names the interface of the default route.** What leaves by any interface but the bridge is masqueraded, and forwarded out of the bridge: a host whose default route moves to another interface, or that reaches some networks by another one, does not cut its containers off. `setup` no longer fails on a host without a default route.
- **`setup` fills `LIGHTBOX-FORWARD` and `LIGHTBOX-POSTROUTING` for the bridge of its `lightbox.conf`**: one host has one lightbox network. Before, a second `lightbox.conf` with another bridge added rules beside the first one's.
- **The interface in a container is `eth0`.** It was `ve-<name>`; a service that names its interface has to name `eth0`. A container started before keeps its old interface until it is started again.
- **The host's end of a container's interface is `vb-` and twelve hex digits** of a hash of the container's name, no longer `vb-<name>`, and carries the alias `lightbox:<name>`. `inspect` shows it as `host_interface`. lightbox removes only interfaces that carry its alias: `start` used to delete whatever was called `vb-<name>` or `ve-<name>`, a name systemd-nspawn uses as well, and now refuses with the interface named and leaves it alone.
- **The chain of a container's links is `LB-` and the same twelve digits.**
- **A container's `.conf` that lightbox cannot use is an error that names the file and the line**, for `start`, `exec`, `inspect`, `add-vol` and `rm-vol`. `stop` still stops such a container and clears away all it had, the firewall rules of its links among them, which it knows from their record in `run_dir`. `rm` removes it as before.

### Added

- **`--cpu` takes parts of a CPU**: `--cpu 0.5` is half of one, `--cpu 1.25` one and a quarter.
- **`--mem max` and `--pids max`** for a container without that limit.
- **`lightbox create <name>` without an address** gives the container the lowest address of the subnet that is free: not the gateway's and not another container's. Two `create` at once get two addresses.
- `doctor` shows the network that `subnet` and `gw` make, or what is wrong with them.
- **`--swap <limit>`** lets a container use swap: `0`, a size as for `--mem`, or `max`.
- **`--io-max "<major>:<minor> <key>=<value>..."`** gives a container an I/O limit for one whole disk, as `io.max` takes it. Before, only an edit of the `.conf` could. `create` refuses a device that the host does not have, and a partition, for which the kernel takes no limit.
- `inspect` shows `swap` and `io`, and `host_interface`.
- **A container's name can have 30 characters**, where it could have 12: the name is no longer part of an interface's name.
- **Four firewall settings in `lightbox.conf`, those of Docker's `daemon.json`**: `firewall` (Docker's `iptables`), `ip_forward`, `ip_forward_no_drop` and `ip_masq`, each `true` or `false`. `firewall = false` makes no rules at all, and then a container with links is not started. `doctor` shows the four.
- **`firewall_backend = nftables`**, Docker's `firewall-backend`: lightbox's rules go in two nftables tables of its own, `ip lightbox` and `bridge lightbox`, and a container's links are elements of a set there. A table of the bridge family sees what the bridge switches, so a container with links starts without `br_netfilter`, and a start runs one `nft`. As with Docker's nftables backend, `setup` does not turn IPv4 forwarding on, and stops if it is off and `ip_forward` is true; there is no `LIGHTBOX-USER`; and `setup` and `doctor` name the chains of other tables, iptables' `FORWARD` among them, whose drop policy drops the containers' traffic as well. Moving from one backend to the other, `setup` takes out what the other made. `iptables` stays the default.
- **`start` makes the host's network again when it is not all there**: the bridge, lightbox's firewall rules and, with iptables, forwarding, as `setup` makes them, after a reboot or after a firewall service loaded its own rules over lightbox's. It used to fail with "failed to attach the container's interface to the bridge" until someone ran `setup`. A start looks with one process more than before.
- **`lightbox setup --teardown`** takes lightbox's firewall rules, in either backend, the bridge and `cgroup_base` away once no container runs, and refuses while one does. Forwarding and the `FORWARD` policy stay, and it says what `setup` had changed of them.
- **`bridge_accept_fwmark`**, Docker's `bridge-accept-fwmark`: with nftables, packets that a chain of the host's gave this mark, or mark and mask, are accepted by lightbox's rules before they drop anything.
- **`lightbox rm-vol <name> <dst>`** takes the volume at a destination out of a container's configuration. Like `add-vol`, it takes effect at the next start.
- A container's `.conf` begins with `version=1`. Containers made by earlier versions keep working as they are, and get the line the next time `add-vol` or `rm-vol` writes the file.

### Fixed

- Two commands working on one container at the same time could both go ahead: two `start` could each set up an interface and a cgroup for the same container, and of two `add-vol` one could write over what the other had just added.
- `LIGHTBOX_ROOTFS` was ignored unless a `lightbox.conf` existed. With the variable set as the README's quick start has it and no file, `create` copied `/var/lib/lightbox/rootfs`, or failed because that is not there. The variable now counts either way: after `--rootfs`, before the `rootfs` setting.
- A newline in a `--vol` path, or in `--mem`, was written into the container's `.conf` as it was, where the text after it was read as further settings of the container.
- `create --mem` without a value, and the same for every other option, said "unknown option". It says that the option requires a value.
- A path or a text that did not fit where lightbox kept it was cut and used: a long `container_dir` could make lightbox work on another directory than the one configured.
- `start` read the container's `.conf` once for every setting in it, and init read it again. It is read once.
- `start` waited for the disk each time it wrote a record of the container, several times in every start. It no longer waits for any.
- After a reboot, containers that had been running were shown as `exited`, from records that were kept on disk. They are shown as `stopped`.
- `start` enabled the `memory`, `pids`, `cpu` and `io` controllers in one write, which failed as a whole when any one was missing: on a host without `io` no container started, I/O limit or not. Each is enabled on its own, and a missing one stops only a container whose limits need it.
- A command that `exec` ran had the OOM score of whoever ran `exec`, not the container's.
- A link to a container that was created after the one with the link never applied: the rule named the other's address, which it did not have yet. Link rules name the two ports on the bridge, and hold whichever of the two starts first.
- A container's link rules stayed when it ended without a stop, and `stop` left them when the container's `.conf` could not be read. They are in a chain of the container's own, which `stop`, `rm` and the clearing away of a dead container remove without reading the `.conf`.
- A start put in each link rule with two `iptables` processes, a check and an insert, for each direction of each link. It runs `iptables-restore` once.

## 0.4.0

Not tagged yet. Phase 4 of the roadmap: who `exec` runs a command as, how it finds it and what terminal it gives it, where volumes are mounted, and what `create` writes into a new container.

### Changes you may have to act on

- **`exec`'s options come before the command, and one it does not know is an error.** Anything that was not `--user` used to be taken as the start of the command. A command that begins with a dash now goes after `--`.
- **A `--user` value that begins with a digit must be numbers.** `--user 0x10` ran as uid 0, `--user 1000:` as gid 0, and `--user 12abc` as uid 12; a uid too large to be one wrapped around. All of these are refused.
- **A command no longer has the groups of whoever ran `exec`.** Its supplementary groups are the ones the container's `/etc/group` lists for its user, and none for a uid without an account. Before, a uid without an account, and root when `--user` was not given, kept the caller's groups.
- **`exec` exits with 127 for a command that is not there, and 126 for one that cannot be run.** Both were 1.
- **A command run by `exec` has a terminal of its own, or none.** Typed at a terminal, `exec` gives the command a pseudo-terminal of the container and puts your terminal into raw mode until the command ends: Ctrl-C, Ctrl-Z and Ctrl-\\ go to the command, not to `exec`. With a terminal on one side only, as in `lightbox exec x cat file | less`, the command gets a pipe there and sees no terminal, so a program that asks whether it writes to a terminal will answer no. Before, the command had your terminal itself.
- **A command run by `exec` leads a session of its own**, and is given nothing that was open where `exec` was run but its three streams. A signal sent to `exec` is passed on to it; before, SIGTERM for `exec` ended `exec` and left the command running.
- **A new container asks the name servers this host asks.** It used to get 1.1.1.1 and 8.8.8.8 whatever the host used. It still gets those two when the host's only resolver is on its own loopback, as with systemd-resolved, and the servers behind that stub cannot be found. `create --dns <address>` and the `dns` setting choose others. Existing containers keep the file they have.
- **A volume path with `..` is refused**, by `create`, by `add-vol`, and by `start` for a container that already has one. A path is stored in one spelling, so `/data//x/` becomes `/data/x`.
- **A volume whose destination leads nowhere in the container fails the start.** A destination is now looked up inside the container. Where the image has a link on the way that points to a path the container lacks, the old code followed it on the host instead.

### Fixed

- `lightbox exec x cat /etc/os-release`, as the README shows it, failed: a command without a slash was not looked for in `PATH`.
- A command got its first 31 arguments, and the rest were dropped without a word.
- A user defined beyond the first 4 KB of the container's `/etc/passwd` was not found, and neither was a group beyond the first 4 KB of `/etc/group`.
- `USER` and `LOGNAME` were cut to 12 characters.
- `exec` read the container's `/etc/passwd` and `/etc/group` through their path on the host, where a link in the container's files leads wherever it says. They are read inside the container now, and only if they are regular files.
- `exec x --user`, with the value missing, ran `--user` as a command.
- A command run by `exec` held the terminal `exec` was typed at: it could read what was typed there and write to it for as long as anything it started kept the terminal open, also after `exec` had returned.
- `exec` entered a container as the installed binary, which a process in the container can reach through `/proc` for as long as the worker runs. `exec` now executes itself again from a sealed copy in memory first, as runc does since CVE-2019-5736, and its worker is closed to other processes until the command starts. If neither a sealed copy nor a read-only mount of the binary can be had, `exec` does not run; `lightbox doctor` says which it is.
- A volume's destination was made and mounted through its path on the host, before the container had its own root. A link in the image on that path was followed on the host, so `start` could make a directory or an empty file outside the container. Volumes are now attached after the container has its own root and the host's is out of its sight.
- A volume below `/run` or `/tmp` was hidden by the tmpfs that is mounted there afterwards.
- A destination such as `//proc/x` got past the check that keeps volumes off `/proc`, `/sys` and `/dev`.
- `create` wrote `resolv.conf` through the image's own `etc`. An image whose `etc`, or whose `resolv.conf`, is a link had the file written wherever that link leads on the host. It is written inside the copy of the image now, as the container will see it.

### Added

- `exec --env KEY=VALUE`, `exec --workdir <dir>`, `--` to end the options, and `-u`, `-e` and `-w` for short.
- The command gets the `TERM` of the terminal `exec` was typed on.
- `create --dns <address>` and the `dns` setting.
- `create` writes `/etc/hostname`, and adds the container's name and address to `/etc/hosts`.

## 0.3.0

Not tagged yet. Phase 3 of the roadmap: how a container starts, where its output goes, and how it stops.

### Changes you may have to act on

- **`start` waits for `/init.sh` to end.** It returned after a fixed half second before, whatever the hook was doing. It now returns when the hook has ended, or after 30 seconds with a note that the hook is still running; the container stays up either way. A hook that runs its service in the foreground makes every start take those 30 seconds: start the service in the background, or set the wait with `start <name> -t <seconds>` or `start_timeout` in `lightbox.conf`. 0 does not wait at all.
- **A hook that fails, fails the start.** `start` exits with an error that names the hook's exit status, and the container is stopped and cleaned up. Before, this happened only when the hook failed within the first half second.
- **A container's output goes to a log, not to your terminal.** What `/init.sh` and the services print used to appear wherever `start` was run, and the container kept that terminal or pipe open for as long as it ran. It is now appended to `console.log` in the container's directory, and `lightbox logs <name>` prints it. A hook that reads from standard input gets nothing: its input is `/dev/null`.
- **Ctrl-C no longer stops a running container.** A container used to stay in the process group of the shell that started it, so Ctrl-C at that shell, or closing the terminal, ended it. It now has a session of its own; use `lightbox stop`.
- **`stop` asks before it kills.** Every process in the container gets SIGTERM and 10 seconds to end, and `stop` returns as soon as they have. Before, only lightbox's own init was asked, and everything else was killed at once. A service that does not end on SIGTERM now makes `stop` take those 10 seconds: `stop <name> -t <seconds>` or `stop_timeout` in `lightbox.conf` sets the time, and `-t 0` kills at once.
- **`stop` exits with 1 when it could not remove everything.** A cgroup or an interface that is still there afterwards is an error, with a message that names it. Before, `stop` reported success whatever was left.
- **`start` and `stop` refuse arguments they do not know.** `start web extra` was accepted, and `extra` ignored.
- **A signal undoes a start.** SIGINT, SIGTERM and SIGHUP no longer end `start` where it stands. It stops the container it was starting, removes what it had set up, and exits with 128 plus the signal's number.

### Fixed

- `out=$(lightbox start x)` and `lightbox start x | cat` never returned: the container held the pipe open.
- A container inherited every file the command that started it had open.
- A command run with standard input, output or error closed could write its messages into one of its own files.
- A `start` that was killed could leave a container running that no record named, and that `stop` and `ls` did not see. Init now exits unless the command that starts it is there, and a container is on record before anything of its image runs.
- Init did not react to a signal while its hook ran, so a container with a long-running hook could not be stopped except by force, and nothing reaped its processes meanwhile.
- A start took half a second longer than the work needed, and a stop a fifth of a second.
- `stop` could signal a process that was not in the container: it took the PIDs to kill from one read of the cgroup's list, and a list longer than that read was cut in the middle of a number. It also removed the cgroup without waiting for it to be empty, which fails while a process is still ending.
- `stop` and `start` could fail, or print an error from `ip`, when the kernel removed a stopped container's interface at the moment they looked at it.
- A `.pid_start` file left over from an earlier run made every later start fail with "unexpected stale pid starttime metadata".
- `start` and `create` could exit in the middle of their work without undoing it: a failed allocation or clone left an interface behind, and a state that could not be written left a half-made container directory.

### Added

- `lightbox logs <name> [-f]` prints a container's log; with `-f` it follows the log until the container stops.
- `start -t <seconds>` and the `start_timeout` setting.
- `stop -t <seconds>` and the `stop_timeout` setting.

## 0.2.0

Not tagged yet. Everything after commit `2320a8d`: Phases 1 and 2 of the roadmap.

### Changes you may have to act on

- **The init hook runs inside the sandbox.** `/init.sh` and everything it starts now have the container's reduced capabilities, `no_new_privs` and the seccomp profile. Before, the hook ran with full privileges and only init was confined afterwards. A hook that mounts filesystems or configures the network now fails: create such a container with `--privileged`, which keeps the old behaviour.
- **A container created with `--link` needs `br_netfilter`.** `start` refuses it unless `net.bridge.bridge-nf-call-iptables` is 1, and says how to get there. Containers without links need nothing.
- **IPv6 is off inside containers.** A container has an IPv4 address and IPv4 firewall rules; IPv6 was left on, with no rule covering it.
- **`/run` in a container is mode 0755.** It was 1777. A service that runs as another user and creates files directly in `/run` needs a directory made for it.
- **More of `/proc` and `/sys` is hidden in a sandboxed container**: `/proc/acpi`, `/proc/asound`, `/proc/interrupts`, `/proc/latency_stats`, `/proc/timer_stats`, `/proc/scsi`, `/sys/firmware` and `/sys/devices/virtual/powercap` read empty, as under Docker. A container does not start if one of them cannot be hidden.
- **Device nodes inside an image are not devices.** The container's root is mounted `nodev`, and `nosuid` unless privileged. Devices come from the `/dev` that lightbox builds.
- **Building needs lightc 0.1.1 or later.** The pinned submodule has it.

### Fixed

- Containers without links could reach each other unless the host happened to have `br_netfilter` loaded. Their ports on the bridge are now isolated from each other, whatever the firewall sees.
- Init kept every capability in its effective and permitted sets; only the bounding set was reduced. All sets are reduced now, for init and for `exec`, and the inheritable and ambient sets are emptied.
- A mount that failed while hiding paths of `/proc` was ignored.
- An image had to contain `mount` and `ip`, which init ran with full privileges. An image needs no tools now: a single static binary is one.

### Changed

- lightbox mounts, makes directories and brings up loopback itself. The host no longer needs `mount`, `umount` or `mkdir`, and `doctor` no longer lists them. A start makes 13 processes where it made 45.
- `doctor` says whether bridged traffic is filtered, and `setup` notes it when it is not.

## 0.1.1

Not tagged yet. Commit `2320a8d`: Phase 0 of the roadmap, with the fixes that landed beside it.

### Changes you may have to act on

- **`ls --json` gives `pid` as a number, or `null` for a container that is not running.** It was a string.
- **Container storage is closed to other users.** `lightbox_dir`, `containers/` and each container's directory are mode 0700 and the records in them 0600. `setup` tightens what an older installation left open.
- **`setup` stops when a firewall rule cannot be added.** It used to report success.
- **lightc is a pinned git submodule.** Clone with `--recursive`, or run `git submodule update --init`. `make` no longer configures or builds a lightc checkout beside the lightbox one.

### Fixed

- Programs that start threads failed in a sandboxed container with glibc 2.34 or later: the seccomp profile answered `clone3` with `EPERM`. It answers `ENOSYS`, and glibc falls back to `clone`.
- On aarch64 every sandboxed process was killed at its first system call: the seccomp profile held x86_64 numbers only.
- The seccomp profile did not refuse x32 system call numbers, nor `clone` with namespace flags.
- `ls` and `inspect` could delete a running container's PID record and mark it failed, when run by a user who may not signal its init. They change nothing now, and show a container whose init is gone as `exited`.
- `create` and `add-vol` could write a shortened `.conf`, losing volumes or their `:ro`. They refuse instead, and `add-vol` holds to the limit of 16 volumes.
- `ls --json` printed invalid JSON for some names and records. `ls` is sorted and lists only containers.
- A tool that was killed by a signal, or could not be started, counted as having succeeded.
- `create --rootfs` given a symbolic link made the container's root that link, and wrote into the base. An empty or missing base was accepted.
- `setup` tried to mount cgroup2 on every run. It now looks first, mounts only on an empty directory, and says why when `cgroup_root` is something else.

### Added

- `make check`: the header check, the analyzer gate and the unit, validation and seccomp suites, all without root.
- `sudo make test-lifecycle`, which starts containers in private namespaces, and `sudo make bench`.
- A CI workflow that runs all of it on x86_64 and aarch64.

## 0.1.0

Commit `9dfe420`: the tree the review of November 2026 started from.
