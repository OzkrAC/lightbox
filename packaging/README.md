# Packages

lightbox as a `.deb`, for Debian and Ubuntu, and as an `.xbps`, for Void Linux, for x86_64 and aarch64. CI builds both on every run and keeps them as the run's artifacts, and installs each to see that it works.

| File | What it is |
| --- | --- |
| `version.sh` | The version, from `lightbox.h`, as it is and as each package format writes it |
| `build-deb.sh` | Builds the `.deb`, with `dpkg-buildpackage`, on Debian or Ubuntu |
| `debian/` | The control files of the `.deb`. The build copies them into place: the tree has no `debian/` of its own |
| `build-xbps.sh` | Builds the two `.xbps`, with `xbps-create`, on Void |
| `xbps/INSTALL` | What xbps runs when it has unpacked the package: it makes lightbox's directories |

## What a package holds

What `make install PREFIX=/usr` installs, and nothing else of lightbox's own:

| Path | What it is |
| --- | --- |
| `/usr/bin/lightbox` | The binary |
| `/usr/share/man/man8/lightbox.8` | The manual page |
| `/etc/lightbox/lightbox.conf` | The example configuration, in which every setting is a comment. A configuration file to the package manager: one that was changed is kept when the package is updated |
| `/var/lib/lightbox`, mode 0700 | `lightbox_dir`, with `containers`, mode 0700, and `rootfs`, the place of the default base, which is yours to fill |

and what each distribution asks for beside it: the licence, and in the `.deb` the changelog and the README.

A package starts nothing and changes nothing on the host: lightbox has no daemon. `lightbox setup` makes the host's network, and `lightbox doctor` says what the host lacks. `run_dir`, `/run/lightbox`, is in no package: it is on a tmpfs, and `setup` and `start` make it.

The packages depend on `iptables`, which the built-in firewall backend runs; the `.deb` takes `nftables` in its place. Neither depends on a C library: the binary is static.

## Building them

```sh
packaging/build-deb.sh          # on Debian or Ubuntu: dist/lightbox_<version>-1_<arch>.deb
packaging/build-xbps.sh         # on Void: dist/lightbox-<version>_1.<arch>.xbps, and the same for <arch>-musl
```

Both take the output directory as their one argument. The `.deb` is built from the files that git tracks, so a new file has to be added to git before it is in the package. The `.xbps` for glibc and the one for musl hold the same binary, as lightbox links no C library, and differ in the architecture they name.

To install what was built:

```sh
sudo apt install ./dist/lightbox_*.deb

xbps-rindex -a dist/lightbox-*.xbps
sudo xbps-install --repository="$PWD/dist" lightbox
```

## Versions

`lightbox.h` has the version, and `version.sh` gives it to both formats. A build between two releases, `0.9.0-dev`, is `0.9.0~dev` in a `.deb` and `0.9.0pre` in an `.xbps`: each sorts before `0.9.0` in its package manager, so the release replaces it.

## What the packages are not

- **Not in a distribution's repository.** They are files to install by hand, from a CI run or a release. Debian and Void take a package from an upstream with a release history, which lightbox does not have yet.
- **Not hardened as a distribution's own packages are.** The binary is static, not position-independent and has no stack protector, as lightc does not support either yet. The Makefile holds to that whatever flags a package build gives it.
