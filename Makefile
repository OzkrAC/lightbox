# lightbox — container runtime built on lightc
#
# lightc is found in this order:
#   1. LIGHTC=/path   given on the command line or in the environment
#   2. lightc/        the pinned git submodule (git submodule update --init)
#   3. ../lightc/     a sibling checkout
#
# Only the submodule is configured and built from here. A LIGHTC= or sibling
# tree is someone else's working copy: lightbox links its build/liblightc.a if
# that exists, and stops with a hint if it does not.

ifdef LIGHTC
  LIGHTC_KIND := external
else ifneq ($(wildcard lightc/include/lightc/syscall.h),)
  LIGHTC      := lightc
  LIGHTC_KIND := submodule
else ifneq ($(wildcard ../lightc/include/lightc/syscall.h),)
  LIGHTC      := ../lightc
  LIGHTC_KIND := external
else
  LIGHTC      := lightc
  LIGHTC_KIND := missing
endif

LIGHTC_HDR := $(LIGHTC)/include/lightc/syscall.h
LIGHTC_LIB := $(LIGHTC)/build/liblightc.a

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
MANDIR     ?= $(PREFIX)/share/man
# lightbox reads /etc/lightbox/lightbox.conf without --config or
# LIGHTBOX_CONFIG; a CONFDIR elsewhere has to be named with one of them.
CONFDIR    ?= /etc/lightbox
DATADIR    ?= /var/lib/lightbox

# The release, as lightbox.h has it and --version prints it.
VERSION := $(shell sh packaging/version.sh)

# ─── Toolchain ──────────────────────────────────────────────────────────────
# make CC=aarch64-linux-gnu-gcc cross-builds; AR and STRIP follow the prefix.

ifeq ($(origin CC),default)
  CC := gcc
endif
ifeq ($(origin AR),default)
  AR := $(if $(filter %-gcc,$(CC)),$(patsubst %-gcc,%-ar,$(CC)),ar)
endif
ifeq ($(origin STRIP),undefined)
  STRIP := $(if $(filter %-gcc,$(CC)),$(patsubst %-gcc,%-strip,$(CC)),strip)
endif

ARCH := $(firstword $(subst -, ,$(shell $(CC) -dumpmachine 2>/dev/null)))

# The flag if this compiler accepts it, nothing otherwise.
cc-option = $(shell $(CC) $(1) -x c -c /dev/null -o /dev/null >/dev/null 2>&1 && echo $(1))

# GCC 14 spells it -std=c23, older releases -std=c2x (the probe lightc uses).
CSTD := $(or $(call cc-option,-std=c23),-std=c2x)

WARN := -Wall -Wextra -Wpedantic

# Hardening that needs no runtime support. The non-executable stack marking
# comes from lightc's linker script; the stack protector needs lightc's canary
# setup and is not available yet.
HARDEN := $(call cc-option,-fstack-clash-protection) \
          $(call cc-option,-ftrivial-auto-var-init=zero)
ifeq ($(ARCH),x86_64)
  HARDEN += $(call cc-option,-fcf-protection=full)
endif
ifeq ($(ARCH),aarch64)
  ARCH_CFLAGS := -mno-outline-atomics
endif

# What whoever builds lightbox may set, on make's command line or in the
# environment, as a distribution's package build does: optimisation, debugging
# information, paths. They are added to what lightbox needs, and never stand
# in its place.
CFLAGS  ?= -O2
LDFLAGS ?=

# What lightbox is compiled and linked with. What it needs comes after CFLAGS
# and LDFLAGS, so that it holds whatever those say: a freestanding, static
# program without a C library; no stack protector, as lightc sets up no canary
# yet; and no link-time optimisation, which no suite has run.
LB_CFLAGS  = $(CSTD) -DNDEBUG $(WARN) $(HARDEN) $(ARCH_CFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) \
             -ffreestanding -nostdlib -nostartfiles -nodefaultlibs \
             -fno-stack-protector -fno-lto -I$(LIGHTC)/include
LB_LDFLAGS = $(LDFLAGS) -static -no-pie -nostdlib -nostartfiles -nodefaultlibs \
             -fno-lto -T $(LIGHTC)/lightc.ld

SRCS = lightbox.c lightbox_meta.c lightbox_state.c lightbox_container.c lightbox_net.c lightbox_config.c lightbox_util.c lightbox_base.c lightbox_netlink.c lightbox_userns.c lightbox_audit.c lightbox_sha256.c lightbox_tar.c lightbox_gpu.c lightbox_json.c lightbox_image.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

# ─── Build ──────────────────────────────────────────────────────────────────

lightbox: $(OBJS) $(LIGHTC_LIB)
	$(CC) $(LB_LDFLAGS) $(OBJS) $(LIGHTC_LIB) -o $@
	$(STRIP) $@

%.o: %.c | $(LIGHTC_HDR)
	$(CC) $(LB_CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS) tests/seccomp_profile.d tests/unit.d

ifeq ($(LIGHTC_KIND),submodule)

# lightc is built as lightc builds itself: the flags this make was given are
# lightbox's, and are kept from its configure.
$(LIGHTC_LIB):
	cd $(LIGHTC) && CFLAGS= LDFLAGS= ARCH=$(ARCH) CC=$(CC) AR=$(AR) ./configure release && ninja build/liblightc.a

else ifeq ($(LIGHTC_KIND),external)

$(LIGHTC_LIB):
	@echo "lightbox: $(LIGHTC_LIB) does not exist." >&2
	@echo "  $(LIGHTC) is not lightbox's own submodule, so lightbox will not configure or build it." >&2
	@echo "  Build it yourself:   (cd $(LIGHTC) && ./configure release && ninja build/liblightc.a)" >&2
	@echo "  or use the pinned copy:   git submodule update --init" >&2
	@false

else

$(LIGHTC_HDR) $(LIGHTC_LIB):
	@echo "lightbox: lightc was not found." >&2
	@echo "  Use the pinned copy:   git submodule update --init" >&2
	@echo "  or point at a built tree:   make LIGHTC=/path/to/lightc" >&2
	@false

endif

# ─── Checks ─────────────────────────────────────────────────────────────────

# -fanalyzer plus the strict warning set of the November 2026 review. Every
# diagnostic is an error.
ANALYZE_FLAGS = -fanalyzer -Werror -Wwrite-strings -Wcast-qual -Wcast-align=strict \
    -Wshadow -Wformat=2 -Wnull-dereference -Wuninitialized -Wmaybe-uninitialized \
    -Wstrict-overflow=2 -Wundef -Wunused-macros -Wredundant-decls \
    -Wmissing-prototypes -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
    -Wstringop-overflow=4 -Warray-bounds=2 -Walloca -Wvla

analyze: | $(LIGHTC_HDR)
	@rc=0; for f in $(SRCS); do \
	    echo "  ANALYZE $$f"; \
	    $(CC) $(LB_CFLAGS) $(ANALYZE_FLAGS) -c $$f -o /dev/null || rc=1; \
	done; exit $$rc

# lightbox_sys.h, the seccomp table of lightbox_seccomp.h and the device
# program's constants of lightbox_devices.h against the kernel's headers, for
# every compiler that is installed. Compile-only: nothing is linked or run.
# The second file holds what needs the C library's headers beside the
# kernel's.
SYS_CHECK_CCS := $(sort $(CC) $(foreach c,aarch64-linux-gnu-gcc x86_64-linux-gnu-gcc,$(shell command -v $(c) >/dev/null 2>&1 && echo $(c))))

check-sys:
	@for cc in $(SYS_CHECK_CCS); do \
	    echo "  SYSCHECK $$cc"; \
	    for f in tests/sys_check.c tests/sys_check_net.c; do \
	        $$cc -std=c11 -ffreestanding -fsyntax-only -Wall -Wextra -Werror $$f || exit 1; \
	    done; \
	done

# ─── Tests ──────────────────────────────────────────────────────────────────
# The unit, validation and seccomp suites run as an ordinary user and start no
# container; "make test" runs those three. The lifecycle suite, further down,
# starts containers and needs root. In all of them an open finding is an
# expected failure that names its ledger id in ROADMAP.md; see tests/lib.sh.

# Compiler for the one hosted test program (it needs a C library and threads).
HOSTCC ?= cc

# lightbox's own helpers, called from the command line. Like the seccomp
# harness below, it is lightbox.c itself with another main().
tests/unit: tests/unit.c lightbox.c lightbox.h lightbox_sys.h lightbox_seccomp.h lightbox_devices.h $(OBJS) $(LIGHTC_LIB)
	$(CC) $(LB_CFLAGS) -MMD -MP -c tests/unit.c -o tests/unit.o
	$(CC) $(LB_LDFLAGS) tests/unit.o $(filter-out lightbox.o,$(OBJS)) $(LIGHTC_LIB) -o $@

# The cgroup device program, interpreted (lightbox_devices.h). Hosted, as it
# reads the kernel's struct bpf_insn back; the unit suite runs it.
tests/devices_filter: tests/devices_filter.c lightbox_devices.h
	-$(HOSTCC) -O1 -Wall -Wextra $< -o $@

test-unit: tests/unit tests/devices_filter
	bash tests/unit_cases.sh tests/unit

test-validation: lightbox
	bash tests/validation.sh ./lightbox

# The seccomp harness is lightbox.c itself with another main().
tests/seccomp_profile: tests/seccomp_profile.c lightbox.c lightbox.h lightbox_sys.h lightbox_seccomp.h lightbox_devices.h $(OBJS) $(LIGHTC_LIB)
	$(CC) $(LB_CFLAGS) -MMD -MP -c tests/seccomp_profile.c -o tests/seccomp_profile.o
	$(CC) $(LB_LDFLAGS) tests/seccomp_profile.o $(filter-out lightbox.o,$(OBJS)) $(LIGHTC_LIB) -o $@

# Skipped by the suite when this host cannot build a hosted, threaded program.
tests/seccomp_thread: tests/seccomp_thread.c
	-$(HOSTCC) -O1 -pthread $< -o $@

# The seccomp program of each architecture, interpreted on this machine: the
# aarch64 program is checked on x86_64 and the other way round. Hosted too.
tests/seccomp_filter_x86_64: tests/seccomp_filter.c lightbox_seccomp.h
	-$(HOSTCC) -O1 -Wall -Wextra -DLB_SECCOMP_TARGET_X86_64 $< -o $@

tests/seccomp_filter_aarch64: tests/seccomp_filter.c lightbox_seccomp.h
	-$(HOSTCC) -O1 -Wall -Wextra -DLB_SECCOMP_TARGET_AARCH64 $< -o $@

SECCOMP_TESTS = tests/seccomp_profile tests/seccomp_thread \
                tests/seccomp_filter_x86_64 tests/seccomp_filter_aarch64

test-seccomp: $(SECCOMP_TESTS)
	bash tests/seccomp_cases.sh tests/seccomp_profile tests/seccomp_thread

test: test-unit test-validation test-seccomp

# The suite that starts containers. It needs root, a kernel with bridge, veth
# and cgroup v2, and a static busybox, and it runs in private network, mount
# and PID namespaces; tests/lifecycle.sh says what it leaves alone. sudo drops
# the environment, so its options go on make's command line:
#     sudo make test-lifecycle V=1 KEEP=1
# LIGHTBOX_TEST_USERNS=overlay makes every container with --userns, and
# LIGHTBOX_TEST_USERNS=copy with --userns --copy. LIGHTBOX_TEST_SECCOMP=deny
# makes every container with --seccomp deny, alone or with either, and
# LIGHTBOX_TEST_ROOTFS=<dir> builds them from that root filesystem, such as
# one that tests/fetch_image.sh unpacked.
# It builds nothing, so that sudo leaves no file of root's in the tree.
REQUIRE_BUILT = $(MAKE) -q --no-print-directory lightbox || { \
    echo "lightbox is missing or older than its sources: run make first, without sudo" >&2; exit 2; }

test-lifecycle:
	@$(REQUIRE_BUILT)
	bash tests/lifecycle.sh ./lightbox

# Wall time of create, start, exec, stop and rm, the processes one start makes,
# and creates from a base of 1 GB. As root, in the lifecycle suite's namespaces.
bench:
	@$(REQUIRE_BUILT)
	bash bench/bench.sh ./lightbox

check: check-sys analyze test

# ─── Install ────────────────────────────────────────────────────────────────

# With DESTDIR this is what a package holds: packaging/ builds the .deb and the
# .xbps from it. run_dir is not made here: it is on a tmpfs, which a reboot
# empties, and setup and start make it.
install: lightbox
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 lightbox $(DESTDIR)$(BINDIR)/lightbox
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 lightbox.8 $(DESTDIR)$(MANDIR)/man8/lightbox.8
	install -d -m 755 $(DESTDIR)$(CONFDIR)
	install -d -m 700 $(DESTDIR)$(DATADIR)
	install -d -m 755 $(DESTDIR)$(DATADIR)/rootfs
	install -d -m 700 $(DESTDIR)$(DATADIR)/containers
	@if [ ! -f $(DESTDIR)$(CONFDIR)/lightbox.conf ]; then \
		install -m 644 lightbox.conf.example $(DESTDIR)$(CONFDIR)/lightbox.conf; \
		echo "Installed config: $(DESTDIR)$(CONFDIR)/lightbox.conf"; \
	else \
		echo "Config already exists: $(DESTDIR)$(CONFDIR)/lightbox.conf (skipped)"; \
	fi
	@echo ""
	@echo "lightbox installed to $(DESTDIR)$(BINDIR)/lightbox"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Put a root filesystem in $(DATADIR)/rootfs/, the base new containers are made from."
	@echo "     This fetches Alpine's and checks its SHA-256 before it unpacks it:"
	@echo "       sudo tests/fetch_image.sh alpine $(DATADIR)/rootfs"
	@echo "  2. Edit $(CONFDIR)/lightbox.conf if needed"
	@echo "  3. Run: lightbox setup"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lightbox
	rm -f $(DESTDIR)$(MANDIR)/man8/lightbox.8

# ─── Source archive ─────────────────────────────────────────────────────────
# lightbox-<version>.tar.gz: every file that is committed, lightc's at the
# commit lightbox pins among them, so that the archive builds with "make" and
# no network. The archive a hosting site makes of a tag leaves a submodule out.
# The files are taken as they are in the tree, so a tree with changes that are
# not committed is refused. The same commit gives the same archive: the names
# in order, root as the owner, and the commit's time on every file.
DIST := lightbox-$(VERSION)

dist:
	@test -n "$(VERSION)" || { echo "dist: no LIGHTBOX_VERSION in lightbox.h" >&2; exit 1; }
	@test -f lightc/configure || { echo "dist: the lightc submodule is not there: git submodule update --init" >&2; exit 1; }
	@test -z "$$(git status --porcelain --untracked-files=no --ignore-submodules=none)" || \
	    { echo "dist: the tree has changes that are not committed" >&2; exit 1; }
	git ls-files -z --recurse-submodules | \
	    tar --no-recursion --sort=name --owner=0 --group=0 --numeric-owner \
	        --mode='u+rw,go+r,go-w' --mtime="@$$(git log -1 --format=%ct)" \
	        --transform='s,^,$(DIST)/,S' --null --files-from=- -cf $(DIST).tar
	gzip -n -9 -f $(DIST).tar
	@echo "$(DIST).tar.gz: lightbox $$(git rev-parse --short HEAD) with lightc $$(git -C lightc rev-parse --short HEAD)"

clean:
	rm -f lightbox $(OBJS) $(DEPS)
	rm -f $(SECCOMP_TESTS) tests/seccomp_profile.o tests/seccomp_profile.d
	rm -f tests/unit tests/unit.o tests/unit.d tests/devices_filter

.PHONY: analyze bench check check-sys clean dist install test test-lifecycle test-seccomp test-unit test-validation uninstall
