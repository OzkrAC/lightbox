# Packages

lightbox as a `.deb`, for Debian and Ubuntu, and as an `.xbps`, for Void Linux, for x86_64 and aarch64. CI builds both on every run, installs each to see that it works, and keeps them as the run's artifacts. A tag gives a draft release that holds them, with the source archive and their SHA-256 sums.

| File | What it is |
| --- | --- |
| `version.sh` | The version, from `lightbox.h`, as it is and as each package format writes it |
| `build-deb.sh` | Builds the `.deb`, with `dpkg-buildpackage`, on Debian or Ubuntu |
| `debian/` | The control files of the `.deb`. The build copies them into place: the tree has no `debian/` of its own |
| `build-xbps.sh` | Builds the two `.xbps`, with `xbps-create`, on Void |
| `xbps/INSTALL` | What xbps runs when it has unpacked the package: it makes lightbox's directories |
| `release-notes.sh` | The notes of a release: the changelog's section for the version, how to install the files and how to check a download |

`.github/workflows/packages.yml` is the CI: it builds each package on both architectures, installs it with its package manager, checks what was installed, and for the `.deb` runs the lifecycle suite with the installed binary. The `.deb` is built on Ubuntu 24.04 and installed there and in Debian 12 and 13; the `.xbps` is built and installed in Void's container image. It also makes the source archive of `make dist`, twice, and builds lightbox from it. `.github/workflows/release.yml` is the release: see [A release](#a-release).

## What a package holds

What `make install PREFIX=/usr` installs, and nothing else of lightbox's own:

| Path | What it is |
| --- | --- |
| `/usr/bin/lightbox` | The binary |
| `/usr/share/man/man8/lightbox.8` | The manual page |
| `/etc/lightbox/lightbox.conf` | The example configuration, in which every setting is a comment. A configuration file to the package manager: one that was changed is kept when the package is updated |
| `/var/lib/lightbox`, mode 0700 | `lightbox_dir`, with `containers`, mode 0700, and `rootfs`, the place of the default base, which is yours to fill |

and what each distribution asks for beside it: the licence, and in the `.deb` also `README.md` and `CHANGELOG.md`, the latter as `changelog.gz`, in `/usr/share/doc/lightbox`, and the answers to what lintian says of the package, `debian/lightbox.lintian-overrides`, each with its reason.

A package starts nothing and changes nothing on the host: lightbox has no daemon. `lightbox setup` makes the host's network, and `lightbox doctor` says what the host lacks. `run_dir`, `/run/lightbox`, is in no package: it is on a tmpfs, and `setup` and `start` make it.

The packages depend on `iptables`, which the built-in firewall backend runs; the `.deb` takes `nftables` in its place. Neither depends on a C library: the binary is static.

## Building them

```sh
packaging/build-deb.sh          # on Debian or Ubuntu: dist/lightbox_<version>-1_<arch>.deb
packaging/build-xbps.sh         # on Void: dist/lightbox-<version>_1.<arch>.xbps, and the same for <arch>-musl
```

Both take the output directory as their one argument, and build for the architecture of the machine they run on. What they need beside git:

```sh
sudo apt install build-essential debhelper ninja-build      # Debian, Ubuntu
sudo xbps-install gcc make ninja                            # Void
```

`build-essential` is what every Debian package build takes for granted: where it is missing, `dpkg-buildpackage` says so and stops with status 3, whatever else is installed. The `.deb` is built from the files that git tracks, so a new file has to be added to git before it is in the package. The `.xbps` for glibc and the one for musl hold the same binary, as lightbox links no C library, and differ in the architecture they name.

To install what was built:

```sh
sudo apt install ./dist/lightbox_*.deb

xbps-rindex -a dist/lightbox-*.xbps
sudo xbps-install --repository="$PWD/dist" lightbox
```

The `.deb` is compressed with xz, which every dpkg reads; Ubuntu's own default, zstd, is read by Debian from Debian 12 on only.

## Versions

`lightbox.h` has the version, and `version.sh` gives it to both formats. A build between two releases, `0.9.0-dev`, is `0.9.0~dev` in a `.deb` and `0.9.0pre` in an `.xbps`: each sorts before `0.9.0` in its package manager, so the release replaces it.

## A release

1. On `main`, with CI green: `LIGHTBOX_VERSION` in `lightbox.h` loses its `-dev`, the changelog's section for the version gets its summary, and `VERSION` in `docs/lightbox-docs.js` follows. Commit, push, and wait for CI.
2. Tag that commit and push the tag: `git tag v0.9.0 && git push origin v0.9.0`. The tag is the version of `lightbox.h` with a `v` before it; the Release workflow stops at any other, before it builds.
3. The workflow builds the packages and the source archive with the jobs CI runs, and makes a draft release that holds the two `.deb`, the four `.xbps`, `lightbox-<version>.tar.gz` and `SHA256SUMS`, with notes from the changelog. A draft is seen by the maintainer alone: look at it under Releases, and publish it.
4. `LIGHTBOX_VERSION` becomes the next version with `-dev`.

For each file GitHub keeps an attestation: a record, which it signs, of the repository, the commit and the workflow run that built the file. `gh attestation verify <file> --repo OzkrAC/lightbox` checks a download against it. No signing key is kept for this. The record is public, in GitHub's attestations for the repository and in Sigstore's public log.

Run by hand from a branch, under Actions, or by a push to `main` that changes `release.yml`, the workflow is a rehearsal: it builds, sums and records the same files and keeps them as the artifact `release-files`, and makes no release. If a run for a tag fails after the draft was made, run it again: a draft that is there gets its files again, and a release that is published is left as it is.

## What the packages are not

- **Not in a distribution's repository.** They are files to install by hand, from a CI run or a release. Debian and Void take a package from an upstream with a release history, which lightbox does not have yet.
- **Without a package of debugging symbols.** Debian files a binary's symbols under its build ID, and lightc's linker script leaves the binary without one. The binary in a package is stripped.
- **Not hardened as a distribution's own packages are.** The binary is static, not position-independent and has no stack protector, as lightc does not support either yet. The Makefile holds to that whatever flags a package build gives it.
