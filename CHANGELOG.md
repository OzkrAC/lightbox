# Changelog

What changed for someone who uses lightbox, newest first. `ROADMAP.md` has the reasons and the finding each change closes.

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
