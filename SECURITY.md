# Security

lightbox runs what you put in a container on the kernel of the host, and keeps it away from the host and from the other containers as far as namespaces, its sandbox and its firewall rules can. `docs/security.html` says under "Threat model" what it keeps apart, and under "What it does not keep out" where it stops; [README](README.md#security) has the short form. What this policy covers is the boundaries lightbox promises to hold:

- **The sandbox of a container that is not `--privileged`:** a way for a process in it to act on the host outside its volumes, to gain a capability or a device it was not given, to make a system call its seccomp filter is there to refuse, or to give a file the setuid bit.
- **What lightbox does as root for a container:** a way for a container, a base or a volume to have `create`, `start`, `exec`, `stop`, `rm` or another command read, write, mount or run something of the host's that is not the container's.
- **The network a container was given:** a way to reach what `--net outside`, `--net proxy` or `--net none` refuses, or another container without a link to it, while lightbox's firewall rules are in.
- **The agent profile:** a way around what `--profile agent` turns on, the user namespace and its ranges among it.
- **The audit log:** a way for a container to change or remove what `exec` and `run` recorded of it.
- **The files of a release:** a package or a source archive that is not what its checksum and the record of its build say.

Out of scope, as the page says where lightbox stops: a flaw in the kernel itself, though a system call that the allow-list should not let through is a report worth making; a container created with `--privileged`; the host and its networks as a container of `--net nat` reaches them; what a host's own firewall does, and the absence of rules with `firewall = false`; what someone who may run lightbox, and so is root, does with it; and a base that does harm inside its own container. lightc, the runtime lightbox is linked with, has its own repository, [github.com/OscarAC/lightc](https://github.com/OscarAC/lightc); a flaw there that shows in lightbox can be reported here.

## Reporting

Report privately through [GitHub's vulnerability reporting](https://github.com/OzkrAC/lightbox/security/advisories/new) for this repository, with `lightbox --version`, the kernel's release, what `lightbox doctor` prints, how the container was created, and the steps that show the problem. Please do not open a public issue for a security problem until a fix is released.

lightbox is maintained by one person. A report is acknowledged within a week; a confirmed problem is fixed in the next release, the fix named in `CHANGELOG.md` and in the release's notes, and the reporter credited there if they wish.

## Supported versions

The latest release receives fixes; older releases do not. A security fix may change what a container is allowed to do: such a change is listed in `CHANGELOG.md` under "Changes you may have to act on".
