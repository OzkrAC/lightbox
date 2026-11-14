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
CONFDIR    ?= /etc/lightbox
DATADIR    ?= /var/lib/lightbox
RUNDIR     ?= /run/lightbox
HOME_CONF  ?= $(HOME)/.config/lightbox

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

CFLAGS  = $(CSTD) -O2 -DNDEBUG $(WARN) $(HARDEN) $(ARCH_CFLAGS) \
          -ffreestanding -nostdlib -nostartfiles -nodefaultlibs \
          -fno-stack-protector -I$(LIGHTC)/include $(EXTRA_CFLAGS)
LDFLAGS = -static -no-pie -nostdlib -nostartfiles -nodefaultlibs \
          -T $(LIGHTC)/lightc.ld

SRCS = lightbox.c lightbox_meta.c lightbox_state.c lightbox_net.c lightbox_config.c lightbox_util.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

# ─── Build ──────────────────────────────────────────────────────────────────

lightbox: $(OBJS) $(LIGHTC_LIB)
	$(CC) $(LDFLAGS) $(OBJS) $(LIGHTC_LIB) -o $@
	$(STRIP) $@

%.o: %.c | $(LIGHTC_HDR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS) tests/seccomp_profile.d tests/unit.d

ifeq ($(LIGHTC_KIND),submodule)

$(LIGHTC_LIB):
	cd $(LIGHTC) && ARCH=$(ARCH) CC=$(CC) AR=$(AR) ./configure release && ninja build/liblightc.a

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
	    $(CC) $(CFLAGS) $(ANALYZE_FLAGS) -c $$f -o /dev/null || rc=1; \
	done; exit $$rc

# lightbox_sys.h and the seccomp table of lightbox_seccomp.h against the
# kernel's headers, for every compiler that is installed. Compile-only: nothing
# is linked or run.
SYS_CHECK_CCS := $(sort $(CC) $(foreach c,aarch64-linux-gnu-gcc x86_64-linux-gnu-gcc,$(shell command -v $(c) >/dev/null 2>&1 && echo $(c))))

check-sys:
	@for cc in $(SYS_CHECK_CCS); do \
	    echo "  SYSCHECK $$cc"; \
	    $$cc -std=c11 -ffreestanding -fsyntax-only -Wall -Wextra -Werror tests/sys_check.c || exit 1; \
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
tests/unit: tests/unit.c lightbox.c lightbox.h lightbox_sys.h lightbox_seccomp.h $(OBJS) $(LIGHTC_LIB)
	$(CC) $(CFLAGS) -MMD -MP -c tests/unit.c -o tests/unit.o
	$(CC) $(LDFLAGS) tests/unit.o $(filter-out lightbox.o,$(OBJS)) $(LIGHTC_LIB) -o $@

test-unit: tests/unit
	bash tests/unit_cases.sh tests/unit

test-validation: lightbox
	bash tests/validation.sh ./lightbox

# The seccomp harness is lightbox.c itself with another main().
tests/seccomp_profile: tests/seccomp_profile.c lightbox.c lightbox.h lightbox_sys.h lightbox_seccomp.h $(OBJS) $(LIGHTC_LIB)
	$(CC) $(CFLAGS) -MMD -MP -c tests/seccomp_profile.c -o tests/seccomp_profile.o
	$(CC) $(LDFLAGS) tests/seccomp_profile.o $(filter-out lightbox.o,$(OBJS)) $(LIGHTC_LIB) -o $@

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
# It builds nothing, so that sudo leaves no file of root's in the tree.
REQUIRE_BUILT = $(MAKE) -q --no-print-directory lightbox || { \
    echo "lightbox is missing or older than its sources: run make first, without sudo" >&2; exit 2; }

test-lifecycle:
	@$(REQUIRE_BUILT)
	bash tests/lifecycle.sh ./lightbox

# Wall time of create, start, exec, stop and rm, and the processes one start
# makes. As root, in the lifecycle suite's namespaces. bench/baseline.txt holds
# the numbers from before Phase 1 of ROADMAP.md.
bench:
	@$(REQUIRE_BUILT)
	bash bench/bench.sh ./lightbox

check: check-sys analyze test

# ─── Install ────────────────────────────────────────────────────────────────

install: lightbox
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 lightbox $(DESTDIR)$(BINDIR)/lightbox
	install -d -m 755 $(DESTDIR)$(CONFDIR)
	install -d -m 700 $(DESTDIR)$(DATADIR)
	install -d -m 755 $(DESTDIR)$(DATADIR)/rootfs
	install -d -m 700 $(DESTDIR)$(DATADIR)/containers
	install -d -m 755 $(DESTDIR)$(RUNDIR)
	install -d -m 755 $(HOME_CONF)
	@if [ ! -f $(HOME_CONF)/lightbox.conf ]; then \
		install -m 644 lightbox.conf.example $(HOME_CONF)/lightbox.conf; \
		echo "Installed config: $(HOME_CONF)/lightbox.conf"; \
	else \
		echo "Config already exists: $(HOME_CONF)/lightbox.conf (skipped)"; \
	fi
	@echo ""
	@echo "lightbox installed to $(DESTDIR)$(BINDIR)/lightbox"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Place a rootfs in $(DATADIR)/rootfs/"
	@echo "     e.g.: wget -qO- https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz | tar -xz -C $(DATADIR)/rootfs/"
	@echo "  2. Edit $(HOME_CONF)/lightbox.conf if needed"
	@echo "  3. Run: lightbox setup"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lightbox

clean:
	rm -f lightbox $(OBJS) $(DEPS)
	rm -f $(SECCOMP_TESTS) tests/seccomp_profile.o tests/seccomp_profile.d
	rm -f tests/unit tests/unit.o tests/unit.d

.PHONY: analyze bench check check-sys clean install test test-lifecycle test-seccomp test-unit test-validation uninstall
