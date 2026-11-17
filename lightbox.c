/*
 * lightbox — a minimal, secure Linux container runtime
 *
 * Built on lightc (freestanding C, no libc). Uses raw Linux syscalls for
 * namespace isolation, cgroups v2, pivot_root, seccomp, and capability dropping.
 *
 * Usage: lightbox <command> [args]
 *   setup                         — initialize host networking
 *   create <name> [<ip>] [options] — create a container
 *   start  <name> [-t <seconds>]  — start a container
 *   stop   <name> [-t <seconds>]  — stop a container
 *   rm     <name>                 — remove a container
 *   exec   <name> [cmd...]        — run a command in a container
 *   logs   <name> [-f]            — show what a container has printed
 *   ls                            — list containers
 */

#include <lightc/syscall.h>
#include <lightc/types.h>
#include <lightc/string.h>
#include <lightc/print.h>
#include <lightc/format.h>
#include <lightc/io.h>

#include "lightbox.h"
#include "lightbox_seccomp.h"

/* ─── Compile-time limits ───────────────────────────────────────────────── */

#define MAX_PATH         512
#define USERNS_RANGE_SIZE 65536
#define USERNS_MIN_START 100000
#define MAX_DNS          3       /* as many as a resolver reads from resolv.conf */
#define CHILD_STACK_SIZE (1024 * 1024) /* 1 MiB */

/* ─── Configurable defaults ─────────────────────────────────────────────── */

/* All runtime-configurable values live here. Initialized to built-in defaults,
 * then overridden by lightbox.conf if present. */
global_config cfg_global;

/* cfg_global_init() and cfg_global_load() defined after utility functions */

/* device numbers: makedev(major, minor) */
#define MAKEDEV(ma, mi) (((uint64_t)(ma) << 8) | (mi))

/* ─── Structs ───────────────────────────────────────────────────────────── */

/* ─── Utility functions ─────────────────────────────────────────────────── */

/* Is this an address a container can ask for names: IPv4, and not this
 * host's own loopback, which in a container is the container's? */
static bool usable_name_server(const char *text) {
    uint32_t addr;
    return parse_ipv4(text, &addr) && (addr >> 24) != 127 && addr != 0;
}

/*
 * The name servers a resolv.conf lists that a container can use, in its
 * order: how many, at most MAX_DNS. A resolver on the host's loopback is
 * left out, and so is IPv6, which containers do not have.
 */
static int name_servers_of(const char *resolv_path, char out[][16]) {
    static char text[8192];
    if (read_file(resolv_path, text, sizeof(text)) <= 0)
        return 0;

    int count = 0;
    for (char *line = text; *line && count < MAX_DNS; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        bool last = *end == '\0';
        *end = '\0';

        while (*line == ' ' || *line == '\t') line++;
        if (lc_string_starts_with(line, lc_string_length(line), "nameserver", 10) &&
            (line[10] == ' ' || line[10] == '\t')) {
            char *address = line + 10;
            while (*address == ' ' || *address == '\t') address++;
            size_t len = 0;
            while (address[len] && address[len] != ' ' && address[len] != '\t' && address[len] != '\r')
                len++;
            address[len] = '\0';
            if (usable_name_server(address) && str_copy(out[count], address, 16))
                count++;
        }
        line = last ? end : end + 1;
    }
    return count;
}

/* A list of addresses as the dns setting has it, separated by commas or
 * spaces: how many, or -1 when something in it is not a usable address or
 * there are more than MAX_DNS. */
static int name_servers_listed(const char *list, char out[][16]) {
    int count = 0;
    for (const char *p = list; *p; ) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        size_t len = 0;
        while (p[len] && p[len] != ' ' && p[len] != '\t' && p[len] != ',') len++;
        if (len == 0)
            break;
        char address[16];
        if (len >= sizeof(address) || count == MAX_DNS)
            return -1;
        lc_bytes_copy(address, p, len);
        address[len] = '\0';
        if (!usable_name_server(address) || !str_copy(out[count], address, 16))
            return -1;
        count++;
        p += len;
    }
    return count;
}

static void parse_volume_spec_or_die(const char *spec, volume_spec *vol) {
    const char *wrong = parse_volume_spec(spec, vol);
    if (wrong) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, wrong);
        print_str(STDERR, ": ");
        print_str(STDERR, spec);
        lc_print_char(STDERR, '\n');
        lc_kernel_exit(1);
    }
}

static bool name_char_ok(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

/* Validate container name: [a-zA-Z0-9_-], 1 to NAME_MAX_LEN characters */
void validate_name(const char *name) {
    if (!name || !name[0]) die("Error: container name required");
    size_t len = lc_string_length(name);
    if (len > NAME_MAX_LEN) die("Error: container name must be " STRINGIFY(NAME_MAX_LEN) " characters or fewer");
    for (size_t i = 0; i < len; i++) {
        if (!name_char_ok(name[i]))
            die("Error: container name must only contain [a-zA-Z0-9_-]");
    }
}

/* The same rule as a question, for names lightbox finds instead of being given. */
bool name_is_valid(const char *name) {
    if (!name || !name[0])
        return false;
    size_t len = 0;
    for (; name[len]; len++) {
        if (len == NAME_MAX_LEN || !name_char_ok(name[len]))
            return false;
    }
    return true;
}

static bool uid_ranges_overlap(int start_a, int start_b) {
    int end_a = start_a + USERNS_RANGE_SIZE;
    int end_b = start_b + USERNS_RANGE_SIZE;
    return !(end_a <= start_b || end_b <= start_a);
}

static bool userns_range_in_use(const char *exclude_name, int uid_start) {
    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    int count = list_containers(names, MAX_LISTED, NULL);

    for (int i = 0; i < count; i++) {
        if (exclude_name && streq(names[i], exclude_name))
            continue;
        /* one whose configuration cannot be read has no range to keep clear of */
        static container_config other;
        if (container_config_load(names[i], &other) != NULL)
            continue;
        if (other.userns && other.uid_start > 0 && uid_ranges_overlap(other.uid_start, uid_start))
            return true;
    }
    return false;
}

static int allocate_uid_start(const char *exclude_name) {
    int candidate = USERNS_MIN_START;
    for (int i = 0; i < 4096; i++, candidate += USERNS_RANGE_SIZE) {
        if (!userns_range_in_use(exclude_name, candidate))
            return candidate;
    }
    return -1;
}

/* ─── Time ──────────────────────────────────────────────────────────────── */

static int64_t monotonic_ms(void) {
    lc_timespec now = { 0, 0 };
    lc_kernel_get_clock(LC_CLOCK_MONOTONIC, &now);
    return now.seconds * 1000 + now.nanoseconds / 1000000;
}

static void sleep_ms(int64_t ms) {
    lc_timespec nap = { .seconds = ms / 1000, .nanoseconds = (ms % 1000) * 1000000 };
    lc_kernel_sleep(&nap);
}

/* Wait until a descriptor has something to read, for at most ms milliseconds. */
static bool readable_within(int32_t fd, int64_t ms) {
    int64_t deadline = monotonic_ms() + ms;
    for (;;) {
        int64_t left = deadline - monotonic_ms();
        if (left < 0)
            left = 0;
        lc_timespec limit = { .seconds = left / 1000, .nanoseconds = (left % 1000) * 1000000 };
        struct lb_pollfd one = { .fd = fd, .events = LB_POLLIN, .revents = 0 };
        lc_sysret n = lb_sys_ppoll(&one, 1, &limit);
        if (n == -LB_EINTR)
            continue;
        return n > 0;
    }
}

/* ─── Cgroup management ─────────────────────────────────────────────────── */

[[nodiscard]] static bool cgroup_path(char *buf, const char *name) {
    return path_join(buf, MAX_PATH, cfg_global.cgroup_base, name);
}

/* Write one of a cgroup's files: 0, or -1. */
[[nodiscard]] static int cgroup_write(const char *cg, const char *file, const char *value) {
    char path[MAX_PATH];
    if (!path_join(path, sizeof(path), cg, file))
        return -1;
    return write_file(path, value);
}

/* The controllers a container's cgroup can have, in the order they are enabled. */
enum { CTL_MEMORY, CTL_PIDS, CTL_CPU, CTL_IO, CTL_COUNT };
static const char *const CONTROLLER_NAMES[CTL_COUNT] = { "memory", "pids", "cpu", "io" };

/* Is a controller in the text of a cgroup.controllers, names and spaces? */
static bool controller_listed(const char *list, const char *name) {
    size_t len = lc_string_length(name);
    for (const char *p = list; *p; ) {
        while (*p == ' ' || *p == '\n')
            p++;
        size_t n = 0;
        while (p[n] && p[n] != ' ' && p[n] != '\n')
            n++;
        if (n > 0 && lc_string_compare(p, n, name, len) == 0)
            return true;
        p += n;
    }
    return false;
}

/*
 * The controllers a container's limits need: memory for a memory limit, and
 * for a swap limit it was given; pids for a process limit; cpu always, since
 * every container has a CPU limit; io for an I/O limit. The swap limit of 0
 * that a container has without --swap needs none: without the controller
 * there is no limit to set, and that is said.
 */
static void controllers_needed(const container_config *c, bool need[CTL_COUNT]) {
    need[CTL_MEMORY] = !streq(c->mem, "max") || (c->swap[0] && !streq(c->swap, "max"));
    need[CTL_PIDS] = !streq(c->pids, "max");
    need[CTL_CPU] = true;
    need[CTL_IO] = c->io[0] != '\0';
}

/*
 * What a container's cgroup has of the controllers, from the text of its
 * cgroup.controllers: NULL, or why the container cannot have its limits. A
 * controller that it lacks and does not need is a warning, once, and the
 * container runs without it.
 */
static const char *controllers_check(const char *listed, const container_config *config, bool have[CTL_COUNT]) {
    static const char *const lacking[CTL_COUNT] = {
        "the container's cgroup has no memory controller, and the container has a memory or a swap limit",
        "the container's cgroup has no pids controller, and the container has a process limit",
        "the container's cgroup has no cpu controller, and every container has a CPU limit",
        "the container's cgroup has no io controller, and the container has an I/O limit",
    };
    static const char *const without[CTL_COUNT] = {
        "Warning: the container's cgroup has no memory controller: nothing keeps the container from swapping\n",
        "Warning: the container's cgroup has no pids controller; the container has no process limit that needs it\n",
        "",
        "Warning: the container's cgroup has no io controller; the container has no I/O limit that needs it\n",
    };
    bool need[CTL_COUNT];
    controllers_needed(config, need);
    for (int i = 0; i < CTL_COUNT; i++) {
        have[i] = controller_listed(listed, CONTROLLER_NAMES[i]);
        if (!have[i] && need[i])
            return lacking[i];
    }
    for (int i = 0; i < CTL_COUNT; i++) {
        if (!have[i])
            print_str(STDERR, without[i]);
    }
    return NULL;
}

/*
 * Make a container's cgroup, give it the container's limits and put init in
 * it. NULL, or what failed.
 */
static const char *cgroup_create(const char *name, int pid, const container_config *config) {
    char cg[MAX_PATH], path[MAX_PATH];
    if (!cgroup_path(cg, name) || !path_join(path, sizeof(path), cg, "cgroup.controllers"))
        return "the path of the container's cgroup is too long";

    /* The controllers one at a time, at the root and below it: one that a
     * level cannot have does not keep the others from it. What the
     * container's cgroup then lists is what it has. */
    (void)lc_kernel_mkdirat(AT_FDCWD, cfg_global.cgroup_base, 0755);
    for (int i = 0; i < CTL_COUNT; i++) {
        char plus[16] = "+";
        lc_bytes_copy(plus + 1, CONTROLLER_NAMES[i], lc_string_length(CONTROLLER_NAMES[i]) + 1);
        (void)cgroup_write(cfg_global.cgroup_root, "cgroup.subtree_control", plus);
        (void)cgroup_write(cfg_global.cgroup_base, "cgroup.subtree_control", plus);
    }
    (void)lc_kernel_mkdirat(AT_FDCWD, cg, 0755);
    char listed[256];
    if (read_file(path, listed, sizeof(listed)) < 0)
        return "failed to create the container's cgroup";

    bool have[CTL_COUNT];
    const char *lacking = controllers_check(listed, config, have);
    if (lacking)
        return lacking;

    if (have[CTL_MEMORY]) {
        if (cgroup_write(cg, "memory.max", config->mem) < 0)
            return "failed to set the memory limit";
        /* No swap unless the container was given some: past its memory
         * limit a process is killed, and does not go on in swap. */
        if (cgroup_write(cg, "memory.swap.max", config->swap[0] ? config->swap : "0") < 0) {
            char swap_path[MAX_PATH];
            if (!path_join(swap_path, sizeof(swap_path), cg, "memory.swap.max") || path_exists(swap_path))
                return "failed to set the swap limit";
            if (config->swap[0] && !streq(config->swap, "max"))
                return "this kernel does not count swap for cgroups, and the container has a swap limit";
            if (!config->swap[0])
                print_str(STDERR, "Warning: this kernel does not count swap for cgroups: nothing keeps the container from swapping\n");
        }
        /* and what the kernel kills for it is the whole container, not some
         * part of it that the rest goes on without */
        if (cgroup_write(cg, "memory.oom.group", "1") < 0)
            return "failed to set memory.oom.group";
    }
    if (have[CTL_PIDS] && cgroup_write(cg, "pids.max", config->pids) < 0)
        return "failed to set the process limit";

    /* cpu: so much of every period, on all CPUs together */
    int quota;
    char cpu_max[32];
    bool cut = false;
    if (!parse_cpu_limit(config->cpu, &quota))
        return "the container's CPU limit is not one";
    size_t len = (size_t)fmt_int(cpu_max, quota);
    str_append(cpu_max, len, " " STRINGIFY(CPU_PERIOD_US), sizeof(cpu_max), &cut);
    if (cut || cgroup_write(cg, "cpu.max", cpu_max) < 0)
        return "failed to set the CPU limit";

    if (config->io[0] && cgroup_write(cg, "io.max", config->io) < 0)
        return "failed to set the I/O limit; the kernel takes one for a disk that is there, and not for a partition";

    /* move container process into this cgroup */
    char pidbuf[16];
    fmt_int(pidbuf, pid);
    if (cgroup_write(cg, "cgroup.procs", pidbuf) < 0)
        return "failed to move init into the container's cgroup";
    return NULL;
}

/*
 * Call fn for every PID a cgroup.procs lists. The list is read to its end,
 * however long it is, and a number is put together across reads: taken from
 * a buffer that ends in the middle of one, it would be another process's.
 * How many there were, or -1 when the list could not be read.
 */
static int each_listed_pid(const char *procs_path, void (*fn)(int pid)) {
    lc_sysret fd = lc_kernel_open_file(procs_path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    char buf[4096];
    int count = 0;
    int64_t pid = 0;
    bool in_number = false;
    for (;;) {
        lc_sysret n = lc_kernel_read_retry((int32_t)fd, buf, sizeof(buf));
        if (n < 0) {
            lc_kernel_close_file((int32_t)fd);
            return -1;
        }
        /* at the end of the list a number without a newline ends too */
        for (lc_sysret i = 0; i < (n == 0 ? 1 : n); i++) {
            char c = n == 0 ? '\n' : buf[i];
            if (c >= '0' && c <= '9') {
                if (pid <= INT32_MAX)
                    pid = pid * 10 + (c - '0');
                in_number = true;
            } else {
                if (in_number && pid > 0 && pid <= INT32_MAX) {
                    fn((int)pid);
                    count++;
                }
                pid = 0;
                in_number = false;
            }
        }
        if (n == 0)
            break;
    }
    lc_kernel_close_file((int32_t)fd);
    return count;
}

static void kill_pid(int pid) {
    lc_kernel_send_signal(pid, SIGKILL);
}

/* Does the cgroup's own account say that no process is left in it? */
static bool cgroup_is_empty(const char *cg) {
    char path[MAX_PATH], events[256];
    if (!path_join(path, MAX_PATH, cg, "cgroup.events") ||
        read_file(path, events, sizeof(events)) <= 0)
        return false;
    for (const char *line = events; *line; ) {
        if (lc_string_starts_with(line, lc_string_length(line), "populated 0", 11))
            return true;
        while (*line && *line != '\n') line++;
        if (*line == '\n') line++;
    }
    return false;
}

/* How long a cgroup gets to become empty once everything in it is killed. */
#define CGROUP_EMPTY_MS 5000

/*
 * Remove a container's cgroup: kill what is left in it, wait until the
 * kernel says it is empty, and only then remove the directory. 0, or -1 with
 * the reason reported when the directory is still there.
 *
 * cgroup.kill (Linux 5.14) ends everything in the cgroup at once, including
 * what is forked while it does. Without it, what the list shows is killed,
 * again and again until the list is empty.
 */
static int cgroup_destroy(const char *name) {
    char cg[MAX_PATH], tmp[MAX_PATH];
    if (!cgroup_path(cg, name) || !path_join(tmp, MAX_PATH, cg, "cgroup.procs")) {
        print_str(STDERR, "Error: the path of the container's cgroup is too long\n");
        return -1;
    }

    if (!path_exists(cg)) return 0;

    bool at_once = cgroup_write(cg, "cgroup.kill", "1") == 0;

    int64_t deadline = monotonic_ms() + CGROUP_EMPTY_MS;
    while (!cgroup_is_empty(cg) && monotonic_ms() < deadline) {
        if (!at_once)
            (void)each_listed_pid(tmp, kill_pid);
        sleep_ms(10);
    }

    lc_sysret rc = lc_kernel_unlinkat(AT_FDCWD, cg, AT_REMOVEDIR);
    while (rc == -LB_EBUSY && monotonic_ms() < deadline) {
        /* the last process is gone and the kernel has not finished with it */
        sleep_ms(10);
        rc = lc_kernel_unlinkat(AT_FDCWD, cg, AT_REMOVEDIR);
    }
    if (rc < 0 && rc != -LB_ENOENT) {
        char digits[16];
        fmt_int(digits, (int)-rc);
        print_str(STDERR, "Error: cannot remove the cgroup ");
        print_str(STDERR, cg);
        print_str(STDERR, " (errno ");
        print_str(STDERR, digits);
        print_str(STDERR, ")\n");
        return -1;
    }
    return 0;
}

static void cgroup_join_self(const char *name) {
    char cg[MAX_PATH], pidbuf[16];
    fmt_int(pidbuf, lc_kernel_get_process_id());
    if (!cgroup_path(cg, name) || cgroup_write(cg, "cgroup.procs", pidbuf) < 0)
        die2("Error: cannot join the cgroup of container ", name);
}

/* ─── Security: capabilities ────────────────────────────────────────────── */

/* Default non-privileged container capabilities.
 * Deliberately stricter than Docker's historical default:
 * - no CAP_NET_RAW: avoid raw sockets/packet capture by default
 * - no CAP_MKNOD: device node creation is unnecessary with our fixed /dev setup
 */
static const int ALLOWED_CAPS[] = {
    LB_CAP_CHOWN, LB_CAP_DAC_OVERRIDE, LB_CAP_FOWNER, LB_CAP_FSETID,
    LB_CAP_KILL, LB_CAP_SETGID, LB_CAP_SETUID, LB_CAP_SETPCAP,
    LB_CAP_NET_BIND_SERVICE, LB_CAP_SYS_CHROOT,
    LB_CAP_AUDIT_WRITE, LB_CAP_SETFCAP,
};
#define N_ALLOWED_CAPS (sizeof(ALLOWED_CAPS) / sizeof(ALLOWED_CAPS[0]))

/*
 * Reduce every capability set of this process to the allowed capabilities.
 *
 *   bounding                 what a later execve can give back
 *   effective and permitted  what the process holds itself: init never
 *                            executes anything, so for it the bounding set
 *                            alone would change nothing
 *   inheritable and ambient  what it passes on; emptied
 *
 * Any step that fails ends the process: a container must not run with more
 * than this.
 */
static void drop_capabilities(void) {
    uint64_t allowed = 0;
    for (size_t i = 0; i < N_ALLOWED_CAPS; i++)
        allowed |= 1ULL << ALLOWED_CAPS[i];

    /* PR_CAPBSET_READ fails past the last capability this kernel knows */
    for (int cap = 0; cap < 64; cap++) {
        lc_sysret held = lc_kernel_prctl(LB_PR_CAPBSET_READ, (uint64_t)cap, 0, 0, 0);
        if (held < 0)
            break;
        if (held == 1 && !(allowed & (1ULL << cap)) &&
            lc_kernel_prctl(LB_PR_CAPBSET_DROP, (uint64_t)cap, 0, 0, 0) < 0)
            die("Error: failed to drop a capability from the bounding set");
    }

    /* never more than the process has: capset cannot add to permitted */
    struct lb_cap_header hdr = { LB_CAPABILITY_VERSION_3, 0 };
    struct lb_cap_data sets[LB_CAPABILITY_WORDS];
    if (lb_sys_capget(&hdr, sets) < 0)
        die("Error: failed to read the capability sets");
    for (int word = 0; word < LB_CAPABILITY_WORDS; word++) {
        uint32_t keep = sets[word].permitted & (uint32_t)(allowed >> (32 * word));
        sets[word].effective = keep;
        sets[word].permitted = keep;
        sets[word].inheritable = 0;
    }
    if (lb_sys_capset(&hdr, sets) < 0)
        die("Error: failed to reduce the capability sets");

    if (lc_kernel_prctl(LB_PR_CAP_AMBIENT, LB_PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
        die("Error: failed to clear the ambient capability set");
}

/* ─── Security: seccomp ─────────────────────────────────────────────────── */

/*
 * Install the profile: the deny table of lightbox_seccomp.h for this
 * architecture, a refusal of the x32 range on x86_64, and clone without
 * namespace flags. The caller has set no_new_privs or holds CAP_SYS_ADMIN.
 */
static void apply_seccomp(void) {
    struct lb_sock_filter filter[LB_SECCOMP_PROG_LEN];
    struct lb_sock_fprog prog = {
        .len = (uint16_t)lb_seccomp_build(filter),
        .filter = filter,
    };

    if (prog.len != LB_SECCOMP_PROG_LEN)
        die("Error: seccomp program has an unexpected length");
    if (lc_kernel_prctl(LB_PR_SET_SECCOMP, LB_SECCOMP_MODE_FILTER, (uint64_t)&prog, 0, 0) < 0)
        die("Error: failed to install seccomp filter");
}

/*
 * What everything in a non-privileged container runs under: the reduced
 * capability sets, no_new_privs and the seccomp profile. Init applies it
 * before its hook, so the hook and all it starts inherit it; exec applies it
 * to the command it runs. Any step that fails ends the process.
 */
static void apply_sandbox(void) {
    drop_capabilities();
    if (lc_kernel_prctl(LB_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("Error: failed to enable no_new_privs");
    apply_seccomp();
}

/* ─── Security: /proc masking ───────────────────────────────────────────── */

/* Cover a path: a directory with an empty read-only tmpfs, anything else
 * with /dev/null. What this kernel does not have is left out. */
static void mask_path(const char *path) {
    struct lb_statx stx;
    lc_sysret rc = lb_sys_statx(AT_FDCWD, path, 0, LB_STATX_TYPE, &stx);
    if (rc == -LB_ENOENT)
        return;
    if (rc < 0)
        die2("Error: cannot examine a path that must be masked: ", path);

    if ((stx.stx_mode & LB_S_IFMT) == LB_S_IFDIR)
        require_mount("tmpfs", path, "tmpfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=555");
    else
        require_mount("/dev/null", path, NULL, MS_BIND, NULL);
}

/*
 * Keep a non-privileged container away from the parts of /proc and /sys that
 * show or change the host: the paths Docker masks or makes read-only by
 * default, with sysrq-trigger masked where Docker makes it read-only. A mount
 * that fails ends the start; a container must not run with a path left open.
 */
static void mask_proc_paths(void) {
    static const char *const masked[] = {
        "/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore",
        "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi",
        "/proc/sysrq-trigger", "/proc/timer_list", "/proc/timer_stats",
        "/sys/devices/virtual/powercap", "/sys/firmware",
    };
    for (size_t i = 0; i < sizeof(masked) / sizeof(masked[0]); i++)
        mask_path(masked[i]);

    static const char *const read_only[] = {
        "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
    };
    for (size_t i = 0; i < sizeof(read_only) / sizeof(read_only[0]); i++) {
        if (!path_exists(read_only[i]))
            continue;
        require_mount(read_only[i], read_only[i], NULL, MS_BIND, NULL);
        require_mount(NULL, read_only[i], NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL);
    }
}

/* ─── Options ───────────────────────────────────────────────────────────── */

/* The value of the option at argv[*i]: the argument after it, which *i then
 * stands on. An option that is the last argument has none, and is told so. */
static const char *option_value(int argc, char **argv, int *i) {
    if (*i + 1 >= argc) {
        print_str(STDERR, "Error: option ");
        print_str(STDERR, argv[*i]);
        print_str(STDERR, " requires a value\n");
        lc_kernel_exit(1);
    }
    return argv[++*i];
}

/* "<prefix><subject> <what>" for an option or a setting, and the end. */
[[noreturn]] static void die_about(const char *prefix, const char *what, const char *subject) {
    print_str(STDERR, prefix);
    print_str(STDERR, subject);
    print_str(STDERR, ": ");
    print_str(STDERR, what);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

/* ─── cmd_create ────────────────────────────────────────────────────────── */

/* NULL when the disk an I/O limit names is one on this host, or why the
 * kernel will not take a limit for it: io.max is for whole disks. */
static const char *io_disk_problem(const char *limit) {
    char path[64] = "/sys/dev/block/";
    size_t pos = lc_string_length(path), i = 0;
    while (limit[i] && limit[i] != ' ' && pos + 1 < sizeof(path))
        path[pos++] = limit[i++];
    path[pos] = '\0';
    if (!path_exists(path))
        return "there is no block device with that number on this host";
    char partition[80];
    if (!path_join(partition, sizeof(partition), path, "partition") || path_exists(partition))
        return "that is a partition, and the kernel limits only whole disks";
    return NULL;
}

[[noreturn]] static void die_about_address(const char *address, const char *why) {
    print_str(STDERR, "Error: a container cannot have the address ");
    print_str(STDERR, address);
    print_str(STDERR, ": ");
    print_str(STDERR, why);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

/*
 * The address of a new container: the one asked for, when no container has
 * it, or with none asked for the lowest of the subnet that is free. Decided
 * with the store locked, so that no other create decides at the same time,
 * and from what every container has on record, running or not.
 */
static void choose_address(const container_network *net, const uint32_t *asked, char out[IPV4_TEXT_MAX]) {
    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    static uint32_t taken[MAX_LISTED];
    static int holder[MAX_LISTED];
    bool more = false;
    int count = list_containers(names, MAX_LISTED, &more);
    if (more)
        die("Error: there are more than " STRINGIFY(MAX_LISTED) " containers, and which addresses they have cannot be told");

    int ntaken = 0;
    for (int i = 0; i < count; i++) {
        char text[IPV4_TEXT_MAX];
        if (read_container_ip(names[i], text, sizeof(text)) == 0 && parse_ipv4(text, &taken[ntaken]))
            holder[ntaken++] = i;
    }

    if (asked) {
        format_ipv4(out, *asked);
        for (int i = 0; i < ntaken; i++) {
            if (taken[i] != *asked)
                continue;
            print_str(STDERR, "Error: a container cannot have the address ");
            print_str(STDERR, out);
            print_str(STDERR, ": it is the address of the container '");
            print_str(STDERR, names[holder[i]]);
            print_str(STDERR, "'\n");
            lc_kernel_exit(1);
        }
        return;
    }

    for (uint32_t candidate = net->network + 1; candidate < net->broadcast; candidate++) {
        if (candidate == net->gateway)
            continue;
        bool is_free = true;
        for (int i = 0; i < ntaken && is_free; i++)
            is_free = taken[i] != candidate;
        if (is_free) {
            format_ipv4(out, candidate);
            return;
        }
    }
    die2("Error: every address of the subnet has a container: ", cfg_global.subnet);
}

static void cmd_create(int argc, char **argv) {
    require_tool("cp", tool_path_cp());
    if (argc < 1) die("Usage: lightbox create <name> [<ip>] [options]");
    const char *name = argv[0];
    validate_name(name);

    /* The address, when there is one: what follows the name and is not an
     * option. Whether another container has it is looked at further down,
     * with the store locked. */
    container_network net;
    container_network_load_or_die(&net);
    bool address_given = argc >= 2 && argv[1][0] != '-';
    uint32_t asked = 0;
    if (address_given) {
        if (!parse_ipv4(argv[1], &asked))
            die2("Error: invalid IPv4 address: ", argv[1]);
        const char *why = address_unusable(&net, asked);
        if (why)
            die_about_address(argv[1], why);
    }

    /* The options. A value is what its option takes or the command ends
     * here, with the option named: none is cut to fit and none is stored to
     * be found wrong when the container is started. */
    static container_config cfg;
    container_config_init(&cfg);
    char dns[MAX_DNS][16];
    int ndns = 0;

    for (int i = address_given ? 2 : 1; i < argc; i++) {
        const char *opt = argv[i];
        if (streq(opt, "--mem")) {
            const char *value = option_value(argc, argv, &i);
            if (!mem_limit_ok(value) || !str_copy(cfg.mem, value, sizeof(cfg.mem)))
                die2("Error: --mem takes <number>[K|M|G|T] or max, not: ", value);
        } else if (streq(opt, "--swap")) {
            const char *value = option_value(argc, argv, &i);
            if (!swap_limit_ok(value) || !str_copy(cfg.swap, value, sizeof(cfg.swap)))
                die2("Error: --swap takes 0, <number>[K|M|G|T] or max, not: ", value);
        } else if (streq(opt, "--io-max")) {
            const char *value = option_value(argc, argv, &i);
            if (cfg.io[0])
                die("Error: --io-max is given once: a container has an I/O limit for one disk");
            if (!io_limit_ok(value) || !str_copy(cfg.io, value, sizeof(cfg.io)))
                die2("Error: --io-max takes \"<major>:<minor> <key>=<value> ...\", each key one of rbps, wbps, "
                     "riops and wiops and each value a number or max, not: ", value);
            const char *why = io_disk_problem(value);
            if (why)
                die_about("Error: --io-max: ", why, value);
        } else if (streq(opt, "--pids")) {
            const char *value = option_value(argc, argv, &i);
            if (!pids_limit_ok(value) || !str_copy(cfg.pids, value, sizeof(cfg.pids)))
                die2("Error: --pids takes a number from 1 to " STRINGIFY(PIDS_LIMIT_MAX) " or max, not: ", value);
        } else if (streq(opt, "--cpu")) {
            const char *value = option_value(argc, argv, &i);
            int quota;
            if (!parse_cpu_limit(value, &quota) || !str_copy(cfg.cpu, value, sizeof(cfg.cpu)))
                die2("Error: --cpu takes a number of CPUs from 0.01 to " STRINGIFY(CPU_LIMIT_MAX)
                     ", such as 2 or 0.5, not: ", value);
        } else if (streq(opt, "--userns")) {
            die("Error: --userns is not supported yet");
        } else if (streq(opt, "--uid-start")) {
            (void)option_value(argc, argv, &i);
            die("Error: --uid-start is not supported yet");
        } else if (streq(opt, "--privileged")) {
            cfg.privileged = true;
        } else if (streq(opt, "--rootfs")) {
            str_copy_or_die(cfg_global.rootfs, option_value(argc, argv, &i), MAX_PATH, "--rootfs");
        } else if (streq(opt, "--read-only")) {
            cfg.read_only = true;
        } else if (streq(opt, "--oom-score")) {
            const char *value = option_value(argc, argv, &i);
            if (!parse_oom_score(value, &cfg.oom_score))
                die2("Error: --oom-score takes a number from -1000 to 1000, not: ", value);
        } else if (streq(opt, "--vol")) {
            const char *value = option_value(argc, argv, &i);
            volume_spec vol = {0};
            parse_volume_spec_or_die(value, &vol);
            const char *wrong = config_add_volume(&cfg, &vol);
            if (wrong)
                die_about("Error: --vol: ", wrong, value);
        } else if (streq(opt, "--dns")) {
            const char *value = option_value(argc, argv, &i);
            if (ndns >= MAX_DNS) die("Error: more than " STRINGIFY(MAX_DNS) " --dns options: a resolver reads no more");
            if (!usable_name_server(value) || !str_copy(dns[ndns], value, sizeof(dns[0])))
                die2("Error: --dns takes an IPv4 address that a container can reach: ", value);
            ndns++;
        } else if (streq(opt, "--link")) {
            const char *value = option_value(argc, argv, &i);
            if (cfg.nlinks >= MAX_LINKS) die("Error: too many links");
            validate_name(value);
            str_copy_or_die(cfg.links[cfg.nlinks++], value, sizeof(cfg.links[0]), "--link");
        } else {
            die2(opt[0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", opt);
        }
    }

    /* what no option gave comes from lightbox.conf */
    {
        const char *unusable = container_config_fill_defaults(&cfg);
        if (unusable)
            die_about("Error: ", "this setting of lightbox.conf cannot be used, and no option gave the container that limit",
                      unusable);
    }

    /* check if container already exists */
    char cdir[MAX_PATH], root[MAX_PATH];
    container_dir_path(cdir, name);
    container_root(root, name);
    if (path_exists(cdir)) die2("Error: container already exists: ", name);

    /* The base must be a directory with something in it. A link to one is
     * followed. Checked before anything is created, so a refusal leaves
     * nothing behind. */
    {
        struct lb_statx stx;
        if (lb_sys_statx(AT_FDCWD, cfg_global.rootfs, 0, LB_STATX_TYPE, &stx) < 0)
            die2("Error: base rootfs does not exist: ", cfg_global.rootfs);
        if ((stx.stx_mode & LB_S_IFMT) != LB_S_IFDIR)
            die2("Error: base rootfs is not a directory: ", cfg_global.rootfs);
        int empty = dir_is_empty(cfg_global.rootfs);
        if (empty < 0)
            die2("Error: base rootfs cannot be read: ", cfg_global.rootfs);
        if (empty)
            die2("Error: base rootfs is empty: ", cfg_global.rootfs);
    }

    /* One create at a time: what one decides about names and addresses holds
     * until it is done. */
    store_lock();
    char ip[IPV4_TEXT_MAX];
    choose_address(&net, address_given ? &asked : NULL, ip);

    print_str(STDOUT,"Creating container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    const char *create_err = NULL;
    bool created_dir = false;

    /* create container directory and copy rootfs into it */
    if (lc_kernel_mkdirat(AT_FDCWD, cdir, MODE_PRIVATE_DIR) < 0) {
        create_err = "failed to create container dir";
        goto fail_create;
    }
    created_dir = true;
    /* Nobody starts or removes it while it is half made: not while this
     * command works on it, which the lock sees to, and not after this
     * command was killed half way, which the mark says for as long as the
     * directory is there. */
    container_lock(name);
    /* A container that was removed by hand, and not by rm, leaves the
     * records of its last run. They are not this container's. */
    container_forget_run(name);
    char creating[MAX_PATH];
    container_creating_path(creating, name);
    if (write_file_atomic(creating, "", MODE_PRIVATE_FILE) != 0) {
        create_err = "failed to mark the container as being created";
        goto fail_create;
    }
    {
        /* Copy what is in the base ("<base>/."), not the path itself: given a
         * link to the base, copying the path would make the container's rootfs
         * that link, and everything written to it would land in the base. */
        char base_contents[MAX_PATH + 4];
        const char *cp_argv[] = { "cp", "-a", base_contents, root, NULL };
        if (!path_join(base_contents, sizeof(base_contents), cfg_global.rootfs, ".") ||
            run_cmd(tool_path_cp(), cp_argv) != 0) {
            create_err = "failed to copy rootfs";
            goto fail_create;
        }
    }

    /* store IP */
    char ip_path[MAX_PATH];
    container_ip_path(ip_path, name);
    if (write_file_atomic(ip_path, ip, MODE_PRIVATE_FILE) < 0) {
        create_err = "failed to write IP metadata";
        goto fail_create;
    }

    /* write config */
    if (cfg.userns) {
        if (cfg.uid_start == 0) {
            cfg.uid_start = allocate_uid_start(name);
            if (cfg.uid_start <= 0) {
                create_err = "failed to allocate uid_start";
                goto fail_create;
            }
        }
        if (cfg.uid_start < USERNS_MIN_START) {
            create_err = "uid_start is below the managed userns range";
            goto fail_create;
        }
        if (userns_range_in_use(name, cfg.uid_start)) {
            create_err = "uid_start overlaps an existing container userns range";
            goto fail_create;
        }
    }
    create_err = container_config_save(name, &cfg);
    if (create_err)
        goto fail_create;

    /*
     * What the container asks for names, what it is called, and that its name
     * is its own address. These go into the copy of the image, which is the
     * image's to shape: its etc may be a link, and so may any of the three
     * files. They are written as the container will see them, with the new
     * root as the root, so a link in the image cannot put them anywhere else.
     *
     * The name servers are the ones --dns gave; or the dns setting; or the
     * ones this host asks, without its own loopback; or two public ones.
     */
    {
        if (ndns == 0 && cfg_global.dns[0]) {
            ndns = name_servers_listed(cfg_global.dns, dns);
            if (ndns <= 0) {
                create_err = "the dns setting in lightbox.conf is not a list of up to " STRINGIFY(MAX_DNS) " IPv4 addresses";
                goto fail_create;
            }
        }
        if (ndns == 0)
            ndns = name_servers_of("/etc/resolv.conf", dns);
        if (ndns == 0)      /* behind systemd-resolved's stub, the servers it asks */
            ndns = name_servers_of("/run/systemd/resolve/resolv.conf", dns);
        const char *const public_servers[] = { "1.1.1.1", "8.8.8.8" };

        char text[4096];
        bool cut = false;
        size_t pos = 0;
        text[0] = '\0';
        for (int i = 0; i < (ndns ? ndns : 2); i++) {
            pos = str_append(text, pos, "nameserver ", sizeof(text), &cut);
            pos = str_append(text, pos, ndns ? dns[i] : public_servers[i], sizeof(text), &cut);
            pos = str_append(text, pos, "\n", sizeof(text), &cut);
        }
        /* inside the container's own filesystem, so readable by its users */
        if (cut || write_file_in_root(root, "etc", "resolv.conf", text, MODE_PUBLIC_FILE) < 0) {
            create_err = "failed to write resolv.conf";
            goto fail_create;
        }

        pos = str_append(text, 0, name, sizeof(text), &cut);
        str_append(text, pos, "\n", sizeof(text), &cut);
        if (cut || write_file_in_root(root, "etc", "hostname", text, MODE_PUBLIC_FILE) < 0) {
            create_err = "failed to write the container's hostname file";
            goto fail_create;
        }

        /* the image's hosts file, with the container's name added to it */
        int had = read_file_in_root(root, "etc", "hosts", text, sizeof(text) - 64);
        if (had < 0) {
            print_str(STDERR, "Warning: the image's /etc/hosts is not a file that can be added to; it is left as it is\n");
        } else {
            pos = (size_t)had;
            if (had == 0)
                pos = str_append(text, pos, "127.0.0.1\tlocalhost\n", sizeof(text), &cut);
            else if (text[pos - 1] != '\n')
                pos = str_append(text, pos, "\n", sizeof(text), &cut);
            pos = str_append(text, pos, ip, sizeof(text), &cut);
            pos = str_append(text, pos, "\t", sizeof(text), &cut);
            pos = str_append(text, pos, name, sizeof(text), &cut);
            str_append(text, pos, "\n", sizeof(text), &cut);
            if (cut || write_file_in_root(root, "etc", "hosts", text, MODE_PUBLIC_FILE) < 0) {
                create_err = "failed to write the container's hosts file";
                goto fail_create;
            }
        }
    }

    /* shift rootfs ownership for user namespace */
    if (cfg.userns && cfg.uid_start > 0) {
        if (!tool_available(tool_path_chown())) {
            create_err = "chown is needed to shift the rootfs ownership and was not found";
            goto fail_create;
        }
        print_str(STDOUT,"Shifting rootfs ownership...\n");
        /* use chown -R via fork+exec for simplicity */
        char uid_str[32];
        size_t pos = (size_t)fmt_int(uid_str, cfg.uid_start);
        uid_str[pos++] = ':';
        fmt_int(uid_str + pos, cfg.uid_start);

        const char *chown_argv[] = { "chown", "-R", "-h", uid_str, root, NULL };
        if (run_cmd(tool_path_chown(), chown_argv) != 0) {
            create_err = "failed to shift rootfs ownership";
            goto fail_create;
        }
    }

    /* made: and with no runtime record, stopped */
    if (remove_file_durably(creating) != 0) {
        create_err = "failed to mark the container as created";
        goto fail_create;
    }
    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' created (ip=");
    print_str(STDOUT,ip);
    print_str(STDOUT,")\n");
    return;

fail_create:
    if (create_err) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, create_err);
        lc_print_char(STDERR, '\n');
    }
    if (created_dir)
        require_rm_rf(cdir);
    lc_kernel_exit(1);
}

/* ─── Starting: what the command and init say to each other ─────────────── */

/*
 * A container's init is a clone of the command that starts it, and the two
 * talk over two pipes.
 *
 *   go      command to init, one byte at a time. The first says that the
 *           cgroup and the network are in place and init may build the
 *           container. The second says that init is on record and may run
 *           the image's hook.
 *   report  init to command, one struct start_report at a time: START_READY
 *           when the container is built, START_HOOK_DONE when the hook ended.
 *
 * Each side takes the other's pipe closing as the other being gone. An init
 * that does not get its byte exits, so a command that was killed leaves
 * nothing running that no record names. A command whose pipe closes before
 * the report it waits for undoes the start.
 */
enum { START_READY = 1, START_HOOK_DONE = 2 };

struct start_report {
    int32_t what;
    int32_t status;     /* START_HOOK_DONE: the hook's exit status, as a shell gives it */
};

struct child_args {
    int32_t      go_rd, go_wr;              /* init reads the first */
    int32_t      report_rd, report_wr;      /* init writes the second */
    int32_t      starter_signals;           /* the command's signalfd, or -1 */
    int32_t      null_fd, log_fd;           /* init's standard streams once it is built; -1: the command's */
    int32_t      exit_fd;                   /* where init says how it ended; -1: nowhere */
    const char  *name;
    const container_config *config;         /* read by the command, before the clone */
    const char  *root;
    const char  *hook;                      /* the script init runs when it is ready */
    int          stop_grace;                /* seconds the container gets to end, unless a stop says otherwise */
    int          userns;
    int          privileged;
    int          read_only;
};

static uint64_t sigmask_from_signal(int signum) {
    return (signum > 0 && signum <= 64) ? (1ULL << (uint64_t)(signum - 1)) : 0;
}

/* The signals init reads from its signalfd. */
static uint64_t supervisor_signal_mask(void) {
    return sigmask_from_signal(SIGHUP) |
           sigmask_from_signal(SIGINT) |
           sigmask_from_signal(SIGQUIT) |
           sigmask_from_signal(SIGTERM) |
           sigmask_from_signal(SIGCHLD);
}

/* One byte from the command. Anything else: it is gone, or has given up. */
static bool go_received(int32_t fd) {
    char byte;
    return lc_kernel_read_retry(fd, &byte, 1) == 1;
}

static bool report_to_starter(int32_t fd, int32_t what, int32_t status) {
    struct start_report report = { .what = what, .status = status };
    return lc_kernel_write_bytes(fd, &report, sizeof(report)) == (lc_sysret)sizeof(report);
}

/*
 * Close every descriptor from 3 up but the ones listed; -1 lists none. One
 * close_range call for each stretch between them.
 */
static void close_all_but(const int32_t *keep, size_t count) {
    uint32_t from = 3;
    for (;;) {
        /* the lowest listed descriptor that is not below from */
        int32_t next = -1;
        for (size_t i = 0; i < count; i++) {
            if (keep[i] >= (int32_t)from && (next < 0 || keep[i] < next))
                next = keep[i];
        }
        uint32_t last = next < 0 ? ~0U : (uint32_t)next - 1;
        if (last >= from && lb_sys_close_range(from, last, 0) < 0) {
            /* no close_range here: one at a time, as far as descriptors
             * usually go */
            for (uint32_t fd = from; fd <= last && fd < 4096; fd++)
                lc_kernel_close_file((int32_t)fd);
        }
        if (next < 0)
            return;
        from = (uint32_t)next + 1;
    }
}

/*
 * The first thing init does.
 *
 * Its signals are blocked from here on and read from a signalfd later. The
 * kernel drops a signal sent to a namespace's init that init neither blocks
 * nor handles, and one that arrives while the container is being built, or
 * while its hook runs, has to be acted on. SIGPIPE is blocked so that writing
 * to a command that is gone is an error to act on and nothing else.
 *
 * It leaves the session and the process group of the command that started
 * it. The terminal that command runs on is then not init's: Ctrl-C there, or
 * the terminal closing, signals the command's group and not the container.
 *
 * And it closes what it inherited: every descriptor but its ends of the two
 * pipes, what becomes its standard streams, and for now the command's
 * standard streams, where it reports a container that cannot be built.
 *
 * Then init waits for the command's first byte.
 */
static void init_begin(const struct child_args *ca) {
    uint64_t blocked = supervisor_signal_mask() | sigmask_from_signal(LB_SIGPIPE);
    if (lc_kernel_set_signal_mask(LC_SIG_SETMASK, &blocked, NULL) < 0)
        die("Error: failed to block init's signals");

    /* Init holds descriptors of files on the host: its log, and the record
     * of how it ends. They are init's alone, and a process in the container
     * must not get at them by way of init. Not dumpable, init is nobody's to
     * trace or to look into under /proc but the host's root. Programs that
     * init starts are dumpable again once they are executed. */
    if (lc_kernel_prctl(LB_PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        die("Error: failed to close init to the processes it will start");

    if (lc_kernel_create_session() < 0)
        die("Error: failed to give init a session of its own");

    /* The command's ends of the pipes and its signalfd first, by name: init
     * would never see the go pipe close while it held the other end itself. */
    lc_kernel_close_file(ca->go_wr);
    lc_kernel_close_file(ca->report_rd);
    if (ca->starter_signals >= 0)
        lc_kernel_close_file(ca->starter_signals);
    const int32_t keep[] = { ca->go_rd, ca->report_wr, ca->null_fd, ca->log_fd, ca->exit_fd };
    close_all_but(keep, sizeof(keep) / sizeof(keep[0]));

    if (!go_received(ca->go_rd))
        lc_kernel_exit(1);
}

/* Reap every child that has ended. True when the hook was one of them, with
 * its wait status in *hook_status. */
static bool reap_children(int32_t hook_pid, int32_t *hook_status) {
    bool hook_ended = false;
    for (;;) {
        int32_t status;
        lc_sysret pid = lc_kernel_wait_for_child(-1, &status, WNOHANG);
        if (pid <= 0)
            break;
        if (hook_pid > 0 && pid == hook_pid) {
            hook_ended = true;
            *hook_status = status;
        }
    }
    return hook_ended;
}

static void say_with_number(const char *before, int number, const char *after) {
    char digits[16];
    fmt_int(digits, number);
    print_str(STDERR, before);
    print_str(STDERR, digits);
    print_str(STDERR, after);
}

/*
 * Run the image's hook as a child of init: its PID, or -1 once the failure
 * has been reported. Like every program lightbox starts it begins with no
 * signal blocked. Init's own descriptors are close-on-exec and do not reach
 * it.
 */
static int32_t start_hook(const char *script) {
    lc_sysret pid = lc_kernel_fork();
    if (pid < 0) {
        say_with_number("Error: cannot start the init hook (fork failed, errno ", (int)-pid, ")\n");
        return -1;
    }
    if (pid == 0) {
        uint64_t no_signals = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &no_signals, NULL);

        const char *a[] = { "/bin/sh", script, NULL };
        const char *e[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm", NULL };
        lc_sysret failed = exec_program("/bin/sh", a, e);
        say_with_number("Error: cannot execute /bin/sh for the init hook (errno ", (int)-failed, ")\n");
        lc_kernel_exit(127);
    }
    return (int32_t)pid;
}

static void cleanup_old_root_or_die(void) {
    if (lc_kernel_umount("/.old_root", MNT_DETACH) < 0)
        die("Error: failed to unmount /.old_root");
    if (lc_kernel_unlinkat(AT_FDCWD, "/.old_root", AT_REMOVEDIR) < 0)
        die("Error: failed to remove /.old_root");
    if (path_exists("/.old_root"))
        die("Error: /.old_root is still reachable after cleanup");
}

/*
 * End everything in the container, and return when it has ended or when the
 * grace period is over.
 *
 * kill(-1) reaches every process of the PID namespace but init: the services,
 * what they started, and commands that exec put there. SIGCONT goes with it,
 * so that a stopped process gets to see the SIGTERM. Then init reaps, and
 * asks with the null signal whether anyone is left: its own children end
 * with a SIGCHLD, but a command put there by exec is someone else's child,
 * so init also looks every tenth of a second.
 *
 * Whatever is left when init returns from here dies with it: the kernel kills
 * a PID namespace whose init exits.
 */
static void shut_down(int32_t sfd, int grace_seconds) {
    /* Only ever as the init of a PID namespace, where "every process" is the
     * container. Anywhere else it would be every process of the host that
     * this one may signal. */
    if (lc_kernel_get_process_id() != 1)
        return;

    lc_kernel_send_signal(-1, SIGTERM);
    lc_kernel_send_signal(-1, LB_SIGCONT);

    int64_t deadline = monotonic_ms() + (int64_t)grace_seconds * 1000;
    for (;;) {
        int32_t unused = 0;
        (void)reap_children(0, &unused);
        if (lc_kernel_send_signal(-1, 0) == -LB_ESRCH)
            return;

        int64_t left = deadline - monotonic_ms();
        if (left <= 0) {
            say_with_number("lightbox: not everything in the container ended within ", grace_seconds,
                            " s of SIGTERM; killing what is left\n");
            return;
        }
        if (readable_within(sfd, left < 100 ? left : 100)) {
            /* a child ended, or someone asks again: either way, look again */
            lc_signal_info si;
            (void)lc_kernel_read_retry(sfd, &si, sizeof(si));
        }
    }
}

/*
 * Init's life: read its signals, reap what dies, and leave when asked to.
 *
 * The hook is one child among the others. Init is here before the hook
 * starts, so a hook that takes long, or never returns, does not leave the
 * container without anyone to reap its processes or to hear a stop. When the
 * hook ends init tells the command how. A hook that fails ends the container,
 * whenever it does.
 *
 * Asked to leave, it first gives the container time to end by itself:
 * stop_grace seconds, or as many as a stop sends along with its SIGTERM.
 *
 * hook_pid is 0 when there is no hook; report_fd is then not used.
 */
static int supervisor_loop(int32_t sfd, int32_t report_fd, int32_t hook_pid, int stop_grace) {
    for (;;) {
        lc_signal_info si;
        lc_sysret n = lc_kernel_read_retry(sfd, &si, sizeof(si));
        if (n != (lc_sysret)sizeof(si))
            die("Error: failed to read signalfd");

        switch (si.signal) {
            case SIGCHLD: {
                int32_t hook_status = 0;
                if (!reap_children(hook_pid, &hook_status))
                    break;
                hook_pid = 0;

                int code = exit_code_from_status(hook_status);
                bool heard = report_to_starter(report_fd, START_HOOK_DONE, code);
                lc_kernel_close_file(report_fd);
                if (code != 0) {
                    /* the command says it when it is still there to be told */
                    if (!heard)
                        say_with_number("lightbox: the init hook failed with exit status ", code,
                                        "; the container stops\n");
                    return 1;
                }
                break;
            }
            case SIGHUP:
            case SIGINT:
            case SIGQUIT:
            case SIGTERM: {
                int grace = stop_grace;
                if (si.signal == SIGTERM && si.code == LB_SI_QUEUE &&
                    si.int_val >= 0 && si.int_val <= SECONDS_MAX)
                    grace = si.int_val;
                shut_down(sfd, grace);
                return 0;
            }
            default:
                break;
        }
    }
}

/*
 * What init does once the container is built: confine itself, tell the
 * command, wait to be put on record, run the hook, and stay as the process
 * everything else in the container descends from.
 */
static int init_main(const struct child_args *ca) {
    /* The sandbox goes on before the hook, so that the hook and everything
     * it starts run inside it. Init itself needs little after this: it runs
     * the hook, reads its signals, reaps and exits. A hook that mounts or
     * configures the network needs a privileged container. */
    if (!ca->privileged)
        apply_sandbox();

    uint64_t mask = supervisor_signal_mask();
    lc_sysret sfd = lc_kernel_create_signal_fd(-1, &mask, SFD_CLOEXEC);
    if (sfd < 0)
        die("Error: failed to create signalfd");

    /* Everything that could not be done has been said on the command's
     * stderr. From here on init, and with it the hook and every service, has
     * nothing to read and writes to the container's log: the command's
     * terminal or pipe is the command's again, and a shell that captures its
     * output gets it when the command ends, not when the container does. */
    if (ca->log_fd >= 0 && ca->null_fd >= 0) {
        if (lc_kernel_duplicate_fd(ca->null_fd, STDIN, 0) < 0 ||
            lc_kernel_duplicate_fd(ca->log_fd, STDOUT, 0) < 0 ||
            lc_kernel_duplicate_fd(ca->log_fd, STDERR, 0) < 0)
            die("Error: failed to send the container's output to its log");
        lc_kernel_close_file(ca->null_fd);
        lc_kernel_close_file(ca->log_fd);
    }

    /* Without a command to hear this, or without its answer, no record names
     * this container: it must not run anything. */
    if (!report_to_starter(ca->report_wr, START_READY, 0) || !go_received(ca->go_rd))
        lc_kernel_exit(1);
    lc_kernel_close_file(ca->go_rd);

    int32_t hook_pid = 0;
    if (ca->hook && path_exists(ca->hook)) {
        hook_pid = start_hook(ca->hook);
        if (hook_pid < 0) {
            (void)report_to_starter(ca->report_wr, START_HOOK_DONE, 126);
            return 1;
        }
    } else {
        (void)report_to_starter(ca->report_wr, START_HOOK_DONE, 0);
        lc_kernel_close_file(ca->report_wr);
    }

    return supervisor_loop((int32_t)sfd, ca->report_wr, hook_pid, ca->stop_grace);
}

static int open_target_path(int target_pid, const char *suffix) {
    char path[64];
    if (!proc_pid_path(path, sizeof(path), target_pid, suffix))
        return -1;
    return (int)lc_kernel_open_file(path, O_RDONLY | O_CLOEXEC, 0);
}

/*
 * Switch IPv6 off in the network namespace of a process, for the interfaces
 * it has and the ones it gets. A container gets an IPv4 address and IPv4
 * firewall rules; left on, IPv6 would give its interface a link-local address
 * by itself, and a way to its neighbours that none of those rules cover.
 *
 * The setting is read and written through /proc/sys of whoever asks, so a
 * child joins the namespace and writes it there. 0, or -1.
 */
static int netns_disable_ipv6(int target_pid) {
    lc_sysret child = lc_kernel_fork();
    if (child < 0)
        return -1;

    if (child == 0) {
        int fd = open_target_path(target_pid, "/ns/net");
        if (fd < 0 || lc_kernel_setns(fd, CLONE_NEWNET) < 0)
            lc_kernel_exit(1);
        if (!path_exists("/proc/sys/net/ipv6/conf"))
            lc_kernel_exit(0);      /* a kernel without IPv6 has nothing to switch off */
        if (write_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1") < 0 ||
            write_file("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1") < 0)
            lc_kernel_exit(1);
        lc_kernel_exit(0);
    }

    int32_t status;
    if (wait_child((int32_t)child, &status) < 0)
        return -1;
    return exit_code_from_status(status) == 0 ? 0 : -1;
}

static void require_setns_fd(int fd, int nstype, const char *name) {
    if (lc_kernel_setns(fd, nstype) < 0)
        die2("Error: failed to join namespace: ", name);
}

/* ─── exec: who the command runs as ─────────────────────────────────────── */

#define USER_NAME_MAX     255
#define MAX_EXEC_GROUPS   64
#define MAX_EXEC_ENV      64
/* An account file is read to its end, but not without end. */
#define ACCOUNT_FILE_MAX  (16u * 1024 * 1024)

enum exec_as { AS_ROOT, AS_NAME, AS_ID };

/* What exec was asked for. */
struct exec_request {
    enum exec_as as;
    const char  *user;                  /* AS_NAME */
    int          uid, gid;              /* AS_ID; gid is -1 when only a uid was given */
    const char  *env[MAX_EXEC_ENV];     /* --env, in the order given */
    int          nenv;
    const char  *workdir;               /* --workdir, or NULL */
    const char  *term;                  /* the caller's TERM, or NULL */
    const char *const *argv;            /* the command, NULL at its end */
};

/* Who the command runs as, once the container's own files have been asked. */
struct identity {
    int      uid, gid;
    char     name[USER_NAME_MAX + 1];   /* empty: no account has this uid */
    char     home[MAX_PATH];
    uint32_t groups[MAX_EXEC_GROUPS];
    int      ngroups;
};

/* A uid or a gid as text: digits and nothing else, and a number that a
 * process can have. "0x10" is not 0, "1000:" has no gid, and eleven nines
 * are not whatever they wrap around to. */
static bool parse_id(const char *text, size_t len, int *out) {
    if (len == 0 || len > 10)
        return false;
    int64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        value = value * 10 + (text[i] - '0');
    }
    if (value > INT32_MAX)
        return false;
    *out = (int)value;
    return true;
}

/* --user: uid, uid:gid, or a name. A value that begins with a digit is
 * numbers and must be nothing but numbers. */
static bool parse_user_spec(const char *spec, struct exec_request *req) {
    size_t len = lc_string_length(spec);
    if (len == 0)
        return false;

    if (spec[0] >= '0' && spec[0] <= '9') {
        size_t uid_len = 0;
        while (uid_len < len && spec[uid_len] != ':')
            uid_len++;
        req->gid = -1;
        if (!parse_id(spec, uid_len, &req->uid))
            return false;
        if (uid_len < len && !parse_id(spec + uid_len + 1, len - uid_len - 1, &req->gid))
            return false;
        req->as = AS_ID;
        return true;
    }

    if (len > USER_NAME_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)spec[i];
        if (c <= ' ' || c == 127 || c == ':' || c == '/')
            return false;
    }
    req->as = AS_NAME;
    req->user = spec;
    return true;
}

/* A file read a byte at a time, through a buffer. */
struct reader {
    int32_t  fd;
    size_t   len, pos;
    uint64_t total;
    char     buf[4096];
};

/*
 * Open one of a container's account files. The container decides what is at
 * that path, so only a regular file will do: a pipe would never end, and a
 * device could say anything for ever.
 */
static bool reader_open(struct reader *r, const char *path) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0)
        return false;
    struct lb_statx stx;
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE, &stx) < 0 ||
        (stx.stx_mode & LB_S_IFMT) != LB_S_IFREG) {
        lc_kernel_close_file((int32_t)fd);
        return false;
    }
    r->fd = (int32_t)fd;
    r->len = r->pos = 0;
    r->total = 0;
    return true;
}

/* The next byte, or -1 at the end of the file or of what will be read of it. */
static int reader_next(struct reader *r) {
    if (r->pos == r->len) {
        if (r->total >= ACCOUNT_FILE_MAX)
            return -1;
        lc_sysret n = lc_kernel_read_retry(r->fd, r->buf, sizeof(r->buf));
        if (n <= 0)
            return -1;
        r->len = (size_t)n;
        r->pos = 0;
        r->total += (uint64_t)n;
    }
    return (unsigned char)r->buf[r->pos++];
}

/* One field of the line being read: kept while it fits, and marked when it
 * does not, so that a field that was cut is never taken for a shorter one. */
struct field {
    char  *buf;
    size_t size, len;
    bool   cut;
};

static void field_add(struct field *f, int c) {
    if (f->len + 1 < f->size)
        f->buf[f->len++] = (char)c;
    else
        f->cut = true;
}

struct account {
    char name[USER_NAME_MAX + 1];
    int  uid, gid;
    char home[MAX_PATH];
};

/*
 * The first line of a passwd file with this name or, when want_name is NULL,
 * this uid: name:password:uid:gid:comment:home[:shell]. The file is read to
 * its end, a line of any length is one line, and a line that is short of a
 * field, or whose numbers are not numbers, is not an account.
 */
static bool find_account(const char *passwd_path, const char *want_name, int want_uid,
                         struct account *out) {
    struct reader r;
    if (!reader_open(&r, passwd_path))
        return false;

    bool found = false;
    char uid_text[12], gid_text[12];
    for (bool more = true; more && !found; ) {
        struct field name = { out->name, sizeof(out->name), 0, false };
        struct field uid  = { uid_text, sizeof(uid_text), 0, false };
        struct field gid  = { gid_text, sizeof(gid_text), 0, false };
        struct field home = { out->home, sizeof(out->home), 0, false };
        int index = 0;
        for (;;) {
            int c = reader_next(&r);
            if (c < 0) {
                more = false;
                break;
            }
            if (c == '\n')
                break;
            if (c == ':') {
                index++;
                continue;
            }
            switch (index) {
                case 0: field_add(&name, c); break;
                case 2: field_add(&uid, c); break;
                case 3: field_add(&gid, c); break;
                case 5: field_add(&home, c); break;
                default: break;
            }
        }
        if (index < 5 || name.len == 0 || name.cut || uid.cut || gid.cut || home.cut)
            continue;
        out->name[name.len] = '\0';
        out->home[home.len] = '\0';
        if (!parse_id(uid_text, uid.len, &out->uid) || !parse_id(gid_text, gid.len, &out->gid))
            continue;
        found = want_name ? streq(out->name, want_name) : out->uid == want_uid;
    }
    lc_kernel_close_file(r.fd);
    return found;
}

/*
 * The groups a group file lists this user in, other than the primary one:
 * name:password:gid:member,member,... The members are compared as they are
 * read, so a group may have any number of them. How many groups, or -1 when
 * they are more than max.
 */
static int find_groups(const char *group_path, const char *user, int primary_gid,
                       uint32_t *out, int max) {
    struct reader r;
    if (!reader_open(&r, group_path))
        return 0;

    size_t user_len = lc_string_length(user);
    int count = 0;
    char gid_text[12];
    for (bool more = true; more; ) {
        struct field gid = { gid_text, sizeof(gid_text), 0, false };
        int index = 0;
        size_t at = 0;              /* how much of the member being read has matched */
        bool differs = false, member = false;
        for (;;) {
            int c = reader_next(&r);
            if (c < 0) {
                more = false;
                break;
            }
            if (c == '\n')
                break;
            if (c == ':' && index < 3) {
                index++;
                continue;
            }
            if (index == 2) {
                field_add(&gid, c);
            } else if (index == 3) {
                if (c == ',') {
                    if (!differs && at == user_len)
                        member = true;
                    at = 0;
                    differs = false;
                } else {
                    if (at >= user_len || user[at] != (char)c)
                        differs = true;
                    at++;
                }
            }
        }
        if (index == 3 && !differs && at == user_len)
            member = true;          /* the last name on the line */

        int id;
        if (!member || gid.cut || !parse_id(gid_text, gid.len, &id) || id == primary_gid)
            continue;
        bool listed = false;
        for (int i = 0; i < count; i++) {
            if (out[i] == (uint32_t)id)
                listed = true;
        }
        if (listed)
            continue;
        if (count == max) {
            count = -1;
            break;
        }
        out[count++] = (uint32_t)id;
    }
    lc_kernel_close_file(r.fd);
    return count;
}

/*
 * Who the command runs as: the request, completed from the container's own
 * passwd and group files. Called with the container's root as this process's
 * root, so the two paths, and any link in them, stay inside the container.
 *
 * The supplementary groups are always decided here: the ones the container
 * gives the user, and none for a uid it has no account for. What groups the
 * person who typed the command is in on the host has nothing to do with it.
 */
static void resolve_identity(const struct exec_request *req, const char *passwd_path,
                             const char *group_path, struct identity *id) {
    struct account account;
    bool known = false;

    switch (req->as) {
        case AS_NAME:
            known = find_account(passwd_path, req->user, 0, &account);
            if (!known)
                die2("Error: user not found in container: ", req->user);
            id->uid = account.uid;
            id->gid = account.gid;
            break;
        case AS_ID:
            known = find_account(passwd_path, NULL, req->uid, &account);
            id->uid = req->uid;
            id->gid = req->gid >= 0 ? req->gid : (known ? account.gid : req->uid);
            break;
        case AS_ROOT:
        default:
            known = find_account(passwd_path, NULL, 0, &account);
            id->uid = 0;
            id->gid = known ? account.gid : 0;
            break;
    }

    id->name[0] = '\0';
    id->home[0] = '\0';
    id->ngroups = 0;
    if (known) {
        if (!str_copy(id->name, account.name, sizeof(id->name)) ||
            !str_copy(id->home, account.home, sizeof(id->home)))
            die("Error: the account's name or home directory is too long");
        id->ngroups = find_groups(group_path, id->name, id->gid, id->groups, MAX_EXEC_GROUPS);
        if (id->ngroups < 0)
            die2("Error: the container lists more than " STRINGIFY(MAX_EXEC_GROUPS) " groups for user ", id->name);
    }
}

/* Take the identity on: the groups first, while there is the right to. */
static void become(const struct identity *id) {
    if (lc_kernel_setgroups((size_t)id->ngroups, id->groups) < 0)
        die("Error: failed to set supplementary groups for exec");
    if (lc_kernel_setgid(id->gid) < 0)
        die("Error: failed to setgid for exec");
    if (lc_kernel_setuid(id->uid) < 0)
        die("Error: failed to setuid for exec");
}

/* ─── exec: the command and its environment ─────────────────────────────── */

/* Do two "KEY=VALUE" strings set the same variable? */
static bool same_variable(const char *a, const char *b) {
    size_t i = 0;
    while (a[i] && a[i] != '=' && a[i] == b[i])
        i++;
    return a[i] == '=' && b[i] == '=';
}

[[noreturn]] static void exec_failed(const char *before, const char *what, int exit_code) {
    print_str(STDERR, "Error: ");
    print_str(STDERR, before);
    print_str(STDERR, what);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(exit_code);
}

/*
 * Execute a command as a shell would find it: a name with a slash is a path,
 * and any other is looked for in each directory of PATH. Does not return: on
 * failure it says why and exits with what a shell exits with, 127 for a
 * command that is not there and 126 for one that cannot be run.
 */
[[noreturn]] static void exec_command(const char *const argv[], const char *const envp[]) {
    const char *command = argv[0];

    bool is_path = false;
    for (const char *p = command; *p; p++) {
        if (*p == '/')
            is_path = true;
    }
    if (is_path) {
        lc_sysret failed = exec_program(command, argv, envp);
        exec_failed(failed == -LB_ENOENT || failed == -LB_ENOTDIR ? "no such command: " : "cannot execute: ",
                    command, failed == -LB_ENOENT || failed == -LB_ENOTDIR ? 127 : 126);
    }

    const char *path = "";
    for (int i = 0; envp[i]; i++) {
        if (same_variable(envp[i], "PATH="))
            path = envp[i] + 5;
    }

    bool was_there = false;         /* found somewhere, and not allowed or not a program */
    size_t command_len = lc_string_length(command);
    for (const char *dir = path; *dir; ) {
        size_t dir_len = 0;
        while (dir[dir_len] && dir[dir_len] != ':')
            dir_len++;

        char candidate[MAX_PATH];
        /* an empty entry would mean the directory the command is run from:
         * not something to look in on a container's behalf */
        if (dir_len > 0 && dir_len + 1 + command_len < sizeof(candidate)) {
            lc_bytes_copy(candidate, dir, dir_len);
            candidate[dir_len] = '/';
            lc_bytes_copy(candidate + dir_len + 1, command, command_len + 1);
            lc_sysret failed = exec_program(candidate, argv, envp);
            if (failed != -LB_ENOENT && failed != -LB_ENOTDIR)
                was_there = true;
        }

        dir += dir_len;
        if (*dir == ':')
            dir++;
    }
    exec_failed(was_there ? "cannot execute: " : "command not found: ", command, was_there ? 126 : 127);
}

/*
 * Run the command of a request as the identity that was resolved for it: its
 * environment, its directory, and the command itself. Does not return.
 *
 * The environment is PATH, HOME, TERM, and USER and LOGNAME for a uid that
 * has a name; --env adds to it and replaces what it names, the later of two
 * for the same variable winning.
 */
[[noreturn]] static void run_command(const struct exec_request *req, const struct identity *id) {
    bool cut = false;
    char home_env[MAX_PATH + 6] = "HOME=";
    if (id->home[0])
        str_append(home_env, 5, id->home, sizeof(home_env), &cut);
    else
        str_append(home_env, 5, id->uid > 0 ? "/" : "/root", sizeof(home_env), &cut);

    char user_env[USER_NAME_MAX + 6] = "USER=";
    char logname_env[USER_NAME_MAX + 9] = "LOGNAME=";
    const char *name = id->name[0] ? id->name : (id->uid == 0 ? "root" : "");
    str_append(user_env, 5, name, sizeof(user_env), &cut);
    str_append(logname_env, 8, name, sizeof(logname_env), &cut);

    char term_env[80] = "TERM=";
    str_append(term_env, 5, req->term ? req->term : "xterm", sizeof(term_env), &cut);
    if (cut)
        die("Error: the command's environment does not fit");

    const char *base[5];
    int nbase = 0;
    base[nbase++] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
    base[nbase++] = home_env;
    base[nbase++] = term_env;
    if (name[0]) {
        base[nbase++] = user_env;
        base[nbase++] = logname_env;
    }

    const char *envp[5 + MAX_EXEC_ENV + 1];
    int n = 0;
    for (int i = 0; i < nbase; i++) {
        bool replaced = false;
        for (int j = 0; j < req->nenv; j++) {
            if (same_variable(base[i], req->env[j]))
                replaced = true;
        }
        if (!replaced)
            envp[n++] = base[i];
    }
    for (int i = 0; i < req->nenv; i++) {
        bool replaced = false;
        for (int j = i + 1; j < req->nenv; j++) {
            if (same_variable(req->env[i], req->env[j]))
                replaced = true;
        }
        if (!replaced)
            envp[n++] = req->env[i];
    }
    envp[n] = NULL;

    if (req->workdir && lc_kernel_chdir(req->workdir) < 0)
        exec_failed("cannot change to directory: ", req->workdir, 126);

    exec_command(req->argv, envp);
}

/*
 * exec's options, from argv[first] to where the command begins. Returns the
 * index of the command's first word, which is argc when there is none. Ends
 * the process on an option it does not know, a value that is missing, or one
 * that is malformed.
 */
static int parse_exec_options(int argc, char **argv, int first, struct exec_request *req) {
    int i = first;
    for (; i < argc; i++) {
        const char *arg = argv[i];
        if (streq(arg, "--"))
            return i + 1;
        if (arg[0] != '-')
            break;

        bool user = streq(arg, "--user") || streq(arg, "-u");
        bool env = streq(arg, "--env") || streq(arg, "-e");
        bool workdir = streq(arg, "--workdir") || streq(arg, "-w");
        if (!user && !env && !workdir) {
            print_str(STDERR, "Error: unknown option: ");
            print_str(STDERR, arg);
            print_str(STDERR, "\nA command that begins with a dash goes after --.\n");
            lc_kernel_exit(1);
        }
        const char *value = option_value(argc, argv, &i);

        if (user) {
            if (!parse_user_spec(value, req))
                die2("Error: --user takes a name, a uid or uid:gid, and this is none of them: ", value);
        } else if (env) {
            size_t eq = 0;
            while (value[eq] && value[eq] != '=')
                eq++;
            if (eq == 0 || value[eq] != '=')
                die2("Error: --env takes KEY=VALUE: ", value);
            if (req->nenv == MAX_EXEC_ENV)
                die("Error: more than " STRINGIFY(MAX_EXEC_ENV) " --env options");
            req->env[req->nenv++] = value;
        } else {
            if (value[0] != '/')
                die2("Error: --workdir takes an absolute path: ", value);
            req->workdir = value;
        }
    }
    return i;
}

/* A TERM worth passing into a container: a short name of ordinary characters. */
static bool term_is_plain(const char *term) {
    size_t len = lc_string_length(term);
    if (len == 0 || len > 64)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = term[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_' || c == '.' || c == '+';
        if (!ok)
            return false;
    }
    return true;
}

/* ─── exec: a binary the container cannot write to ──────────────────────── */

/*
 * A process that enters a container is, to the container, one of its own:
 * until it executes the command, it is this binary, and a file that is being
 * executed can be reached by other processes through /proc/<pid>/exe. So exec
 * does not enter a container as the installed binary. It first executes
 * itself again from a copy that nothing can write to:
 *
 *   a sealed memfd    a copy in memory, whose seals forbid writing, growing
 *                     and shrinking, and forbid taking the seals off;
 *   a read-only mount where the kernel is set to refuse executable memfds
 *                     (vm.memfd_noexec = 2): the binary itself, seen through
 *                     a mount of its own that is read-only.
 *
 * runc has done the same since CVE-2019-5736. If neither can be had, exec
 * does not run.
 */
#define SELF_SEALS (LB_F_SEAL_SEAL | LB_F_SEAL_SHRINK | LB_F_SEAL_GROW | LB_F_SEAL_WRITE)

/* what main was given: exec passes it on when it executes itself again */
static char **caller_argv;
static char **caller_env;

/* Does this process run from a file that cannot be written to? */
static bool runs_sealed(void) {
    lc_sysret fd = lc_kernel_open_file("/proc/self/exe", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return false;
    lc_sysret seals = lb_sys_fcntl((int32_t)fd, LB_F_GET_SEALS, 0);
    lc_kernel_close_file((int32_t)fd);
    if (seals >= 0 && (seals & SELF_SEALS) == SELF_SEALS)
        return true;

    /* or through a read-only mount: what the path of the running binary
     * says about its mount is what holds for anyone who reaches it there */
    struct lb_statfs fs;
    return lb_sys_statfs("/proc/self/exe", &fs) >= 0 && (fs.f_flags & LB_ST_RDONLY);
}

/* A sealed copy of this binary in memory: a descriptor to execute, or a
 * negative errno. */
static lc_sysret sealed_copy(void) {
    lc_sysret self = lc_kernel_open_file("/proc/self/exe", O_RDONLY | O_CLOEXEC, 0);
    if (self < 0)
        return self;

    lc_sysret copy = lb_sys_memfd_create("lightbox", LB_MFD_CLOEXEC | LB_MFD_ALLOW_SEALING | LB_MFD_EXEC);
    if (copy == -LB_EINVAL)     /* a kernel from before the flag */
        copy = lb_sys_memfd_create("lightbox", LB_MFD_CLOEXEC | LB_MFD_ALLOW_SEALING);

    lc_sysret rc = copy;
    while (rc >= 0) {
        static char block[65536];
        lc_sysret n = lc_kernel_read_retry((int32_t)self, block, sizeof(block));
        if (n == 0)
            break;
        rc = n < 0 ? n : lc_kernel_write_all((int32_t)copy, block, (size_t)n);
        if (rc >= 0 && rc != n)
            rc = -LB_EINVAL;
    }
    if (rc >= 0)
        rc = lb_sys_fcntl((int32_t)copy, LB_F_ADD_SEALS, SELF_SEALS);
    lc_kernel_close_file((int32_t)self);
    if (rc < 0) {
        if (copy >= 0)
            lc_kernel_close_file((int32_t)copy);
        return rc;
    }
    return copy;
}

/* This binary on a mount of its own, made read-only: a descriptor to
 * execute, or a negative errno. */
static lc_sysret readonly_clone(void) {
    lc_sysret tree = lb_sys_open_tree(AT_FDCWD, "/proc/self/exe", LB_OPEN_TREE_CLONE | LB_OPEN_TREE_CLOEXEC);
    if (tree < 0)
        return tree;
    struct lb_mount_attr attr = { .attr_set = LB_MOUNT_ATTR_RDONLY };
    lc_sysret rc = lb_sys_mount_setattr((int32_t)tree, "", LB_AT_EMPTY_PATH, &attr);
    if (rc < 0) {
        lc_kernel_close_file((int32_t)tree);
        return rc;
    }
    return tree;
}

/*
 * Would executing this descriptor be refused for what it is? A memfd that is
 * not allowed to be executed is refused at execve, not before, so the only
 * way to know without executing is to ask the setting that decides.
 */
static bool memfd_exec_refused(void) {
    char value[8];
    return read_file("/proc/sys/vm/memfd_noexec", value, sizeof(value)) > 0 && value[0] == '2';
}

seal_method exec_seal_method(void) {
    lc_sysret fd = memfd_exec_refused() ? -LB_EACCES : sealed_copy();
    if (fd >= 0) {
        lc_kernel_close_file((int32_t)fd);
        return SEAL_MEMFD;
    }
    fd = readonly_clone();
    if (fd >= 0) {
        lc_kernel_close_file((int32_t)fd);
        return SEAL_READONLY;
    }
    return SEAL_NONE;
}

/* The mark, in the environment, of a process that has executed itself once. */
#define SEALED_MARK "LIGHTBOX_EXEC_SEALED=1"

/*
 * Make sure this process runs from a file that cannot be written to, by
 * executing itself again from one if it does not. Returns in the process
 * that does; ends the process when no such file can be had.
 */
static void run_sealed(void) {
    if (runs_sealed()) {
        /* executed through a descriptor, a process is named after the
         * descriptor's number: give it its name back */
        lc_kernel_prctl(LB_PR_SET_NAME, (uint64_t)(uintptr_t)"lightbox", 0, 0, 0);
        return;
    }

    /* Once is enough: a second arrival here means that the copy was executed
     * and still does not look sealed, and trying again would not end. */
    if (env_get(caller_env, "LIGHTBOX_EXEC_SEALED"))
        die("Error: exec runs from a copy of lightbox, and cannot tell that the copy is one that cannot be written to");

    static char *env[256];
    size_t n = 0;
    for (; caller_env && caller_env[n] && n < 254; n++)
        env[n] = caller_env[n];
    static char mark[] = SEALED_MARK;
    env[n++] = mark;
    env[n] = NULL;

    lc_sysret failed = -LB_EACCES;
    if (!memfd_exec_refused()) {
        lc_sysret copy = sealed_copy();
        failed = copy;
        if (copy >= 0) {
            failed = lb_sys_execveat((int32_t)copy, "", caller_argv, env, LB_AT_EMPTY_PATH);
            lc_kernel_close_file((int32_t)copy);
        }
    }
    lc_sysret clone = readonly_clone();
    if (clone >= 0)
        failed = lb_sys_execveat((int32_t)clone, "", caller_argv, env, LB_AT_EMPTY_PATH);

    say_with_number("Error: exec enters a container only from a copy of lightbox that the container cannot\n"
                    "write to, and could not make one here (errno ", (int)-failed,
                    "). lightbox doctor says more.\n");
    lc_kernel_exit(1);
}

/* ─── exec: the command's standard streams ──────────────────────────────── */

/*
 * A command in a container does not get a terminal of the host's. Whoever
 * holds a terminal can read what is typed on it and write what is shown on
 * it, and a container's command is not to have that over the terminal of the
 * person who started it. So what the command gets depends on what lightbox
 * itself was given:
 *
 *   stdin and stdout are both a terminal
 *       a terminal of its own: a pseudo-terminal of the container's devpts,
 *       as its controlling terminal and its three streams. The caller's
 *       terminal is put into raw mode, and lightbox carries the bytes both
 *       ways and passes on the window's size when it changes.
 *   some of the three are a terminal
 *       a pipe in the place of each that is, which lightbox reads or fills;
 *       the others as they are.
 *   none is
 *       all three as they are: files, pipes, /dev/null.
 *
 * In every case the command leads a session of its own, so no signal that a
 * terminal sends to lightbox's process group reaches it by itself. lightbox
 * passes on the ones that ask a command to end.
 */

/* One direction of what lightbox carries: from a descriptor to a descriptor,
 * with what has been read and not yet written in between. */
struct channel {
    int32_t from, to;
    bool    reading;            /* from has not come to its end */
    bool    close_at_end;       /* to is a pipe of the command's: its end is the command's end of input */
    size_t  have, sent;
    char    buf[4096];
};

struct exec_streams {
    int32_t command_fd[3];      /* what the command gets as 0, 1 and 2; -1: lightbox's own */
    int32_t terminal;           /* >= 0: the command's end of the pseudo-terminal */
    int32_t master;             /* >= 0: lightbox's end of it */
    int     nchannels;
    struct channel channels[3];
};

static bool is_terminal(int32_t fd) {
    struct lb_termios modes;
    return lc_kernel_device_control(fd, LB_TCGETS, &modes) >= 0;
}

/* The modes of a terminal that passes every byte on as it is and leaves
 * every key to the other side: what cfmakeraw makes of them. */
static void make_raw(struct lb_termios *modes) {
    modes->iflag &= ~(uint32_t)(LB_IGNBRK | LB_BRKINT | LB_PARMRK | LB_ISTRIP | LB_INLCR | LB_IGNCR |
                                LB_ICRNL | LB_IXON);
    modes->oflag &= ~(uint32_t)LB_OPOST;
    modes->lflag &= ~(uint32_t)(LB_ECHO | LB_ECHONL | LB_ICANON | LB_ISIG | LB_IEXTEN);
    modes->cflag &= ~(uint32_t)(LB_CSIZE | LB_PARENB);
    modes->cflag |= LB_CS8;
    modes->cc[LB_VMIN] = 1;
    modes->cc[LB_VTIME] = 0;
}

static void copy_window_size(int32_t from, int32_t to) {
    struct lb_winsize size;
    if (lc_kernel_device_control(from, LB_TIOCGWINSZ, &size) >= 0)
        lc_kernel_device_control(to, LB_TIOCSWINSZ, &size);
}

static void set_nonblocking(int32_t fd, bool on) {
    lc_sysret flags = lb_sys_fcntl(fd, LB_F_GETFL, 0);
    if (flags >= 0)
        lb_sys_fcntl(fd, LB_F_SETFL, on ? ((uint64_t)flags | O_NONBLOCK) : ((uint64_t)flags & ~(uint64_t)O_NONBLOCK));
}

static struct channel *add_channel(struct exec_streams *st, int32_t from, int32_t to, bool close_at_end) {
    struct channel *c = &st->channels[st->nchannels++];
    c->from = from;
    c->to = to;
    c->reading = true;
    c->close_at_end = close_at_end;
    c->have = c->sent = 0;
    return c;
}

/*
 * Decide what the command gets, and make it. ptmx is the container's
 * /dev/pts/ptmx, by a path that is looked up with the container's root as
 * the root; the command's end of the pseudo-terminal is opened from the
 * descriptor of lightbox's end, by no path at all. The terminal is given to
 * the user the command runs as, the way a login gives a terminal to its user.
 */
static void prepare_streams(struct exec_streams *st, const char *ptmx, int uid, int gid) {
    st->command_fd[0] = st->command_fd[1] = st->command_fd[2] = -1;
    st->terminal = st->master = -1;
    st->nchannels = 0;

    bool tty[3] = { is_terminal(STDIN), is_terminal(STDOUT), is_terminal(STDERR) };

    if (tty[0] && tty[1]) {
        lc_sysret master = lc_kernel_open_file(ptmx, O_RDWR | LB_O_NOCTTY | O_NONBLOCK | O_CLOEXEC, 0);
        int unlocked = 0;
        if (master < 0 || lc_kernel_device_control((int32_t)master, LB_TIOCSPTLCK, &unlocked) < 0)
            die2("Error: the container has no pseudo-terminals to give the command one from: ", ptmx);
        lc_sysret terminal = lc_kernel_device_control((int32_t)master, LB_TIOCGPTPEER,
                                                      (void *)(uintptr_t)(O_RDWR | LB_O_NOCTTY | O_CLOEXEC));
        if (terminal < 0)
            die("Error: failed to open the command's terminal");
        (void)lc_kernel_fchownat((int32_t)terminal, "", (uint32_t)uid, (uint32_t)gid, LB_AT_EMPTY_PATH);
        copy_window_size(STDIN, (int32_t)master);

        st->master = (int32_t)master;
        st->terminal = (int32_t)terminal;
        st->command_fd[0] = st->command_fd[1] = st->command_fd[2] = (int32_t)terminal;
        add_channel(st, STDIN, (int32_t)master, false);
        add_channel(st, (int32_t)master, STDOUT, false);
        return;
    }

    for (int i = 0; i < 3; i++) {
        if (!tty[i])
            continue;
        int32_t ends[2];
        if (lc_kernel_create_pipe(ends, O_CLOEXEC) < 0)
            die("Error: failed to make a pipe for the command");
        if (i == STDIN) {
            /* typed on the terminal, read by the command */
            st->command_fd[i] = ends[0];
            set_nonblocking(ends[1], true);
            add_channel(st, STDIN, ends[1], true);
        } else {
            /* written by the command, shown on the terminal */
            st->command_fd[i] = ends[1];
            set_nonblocking(ends[0], true);
            add_channel(st, ends[0], i, false);
        }
    }
}

/*
 * In the command's process, before anything else: no signal held back, a
 * session of its own, the terminal if it gets one as its controlling
 * terminal, its three streams, and nothing else that was open in whoever ran
 * lightbox.
 */
static void take_streams(const struct exec_streams *st) {
    uint64_t no_signals = 0;
    lc_kernel_set_signal_mask(LC_SIG_SETMASK, &no_signals, NULL);

    if (lc_kernel_create_session() < 0)
        die("Error: failed to give the command a session of its own");
    if (st->terminal >= 0 && lc_kernel_device_control(st->terminal, LB_TIOCSCTTY, NULL) < 0)
        die("Error: failed to make the terminal the command's own");
    for (int i = 0; i < 3; i++) {
        if (st->command_fd[i] >= 0 && lc_kernel_duplicate_fd(st->command_fd[i], i, 0) < 0)
            die("Error: failed to set up the command's standard streams");
    }
    close_all_but(NULL, 0);
}

/* In lightbox, once the command has its copies: its ends are the command's
 * alone, so that each pipe ends when the command is done with it. */
static void release_command_ends(struct exec_streams *st) {
    for (int i = 0; i < 3; i++) {
        int32_t fd = st->command_fd[i];
        if (fd < 0)
            continue;
        lc_kernel_close_file(fd);
        for (int j = i; j < 3; j++) {
            if (st->command_fd[j] == fd)
                st->command_fd[j] = -1;
        }
    }
    st->terminal = -1;
}

static void channel_end_of_input(struct channel *c) {
    c->reading = false;
    if (c->close_at_end && c->to >= 0 && c->have == c->sent) {
        lc_kernel_close_file(c->to);
        c->to = -1;
    }
}

/* Read what there is. An end of file, and an error that is not "nothing yet",
 * end the direction: a pseudo-terminal says EIO when its other end is gone. */
static void channel_read(struct channel *c) {
    lc_sysret n = lc_kernel_read_bytes(c->from, c->buf, sizeof(c->buf));
    if (n > 0) {
        c->have = (size_t)n;
        c->sent = 0;
    } else if (n != -LB_EAGAIN && n != -LB_EINTR) {
        channel_end_of_input(c);
    }
}

/* Write what is waiting, or as much of it as is taken. A descriptor that can
 * no longer be written to ends the direction, and what was waiting is dropped. */
static void channel_write(struct channel *c) {
    lc_sysret n = c->to >= 0 ? lc_kernel_write_bytes(c->to, c->buf + c->sent, c->have - c->sent) : -1;
    if (n > 0) {
        c->sent += (size_t)n;
    } else if (n != -LB_EAGAIN && n != -LB_EINTR) {
        c->sent = c->have;
        c->reading = false;
        if (c->close_at_end && c->to >= 0) {
            lc_kernel_close_file(c->to);
            c->to = -1;
        }
    }
    if (c->sent == c->have) {
        c->have = c->sent = 0;
        if (!c->reading)
            channel_end_of_input(c);
    }
}

/* The signals the process that carries a command's streams reads itself. */
static uint64_t relay_signal_mask(void) {
    return sigmask_from_signal(SIGCHLD) | sigmask_from_signal(LB_SIGWINCH) |
           sigmask_from_signal(SIGINT) | sigmask_from_signal(SIGTERM) |
           sigmask_from_signal(SIGHUP) | sigmask_from_signal(SIGQUIT);
}

/*
 * Carry the command's streams until the command has ended: its wait status.
 *
 * A direction is read only when nothing of it is waiting to be written, and
 * written only when its descriptor takes something, so neither side can hold
 * up the other. A signal that asks to end is passed on to the command, and a
 * change of the window's size to its terminal. When the command has ended,
 * what it wrote last is still delivered; what something it left behind may
 * write later is not waited for.
 */
static int32_t relay_until_exit(struct exec_streams *st, int32_t command, int32_t signal_fd) {
    int32_t status = 0;
    bool ended = false;

    while (!ended) {
        struct lb_pollfd fds[4];
        struct channel *of[4];
        bool writing[4];
        uint64_t count = 0;

        fds[count] = (struct lb_pollfd){ .fd = signal_fd, .events = LB_POLLIN, .revents = 0 };
        of[count++] = NULL;
        for (int i = 0; i < st->nchannels; i++) {
            struct channel *c = &st->channels[i];
            if (c->have > c->sent && c->to >= 0) {
                fds[count] = (struct lb_pollfd){ .fd = c->to, .events = LB_POLLOUT, .revents = 0 };
                writing[count] = true;
                of[count++] = c;
            } else if (c->reading) {
                fds[count] = (struct lb_pollfd){ .fd = c->from, .events = LB_POLLIN, .revents = 0 };
                writing[count] = false;
                of[count++] = c;
            }
        }

        lc_sysret ready = lb_sys_ppoll(fds, count, NULL);
        if (ready < 0 && ready != -LB_EINTR)
            die("Error: failed to wait on the command's streams");
        if (ready <= 0)
            continue;

        if (fds[0].revents & LB_POLLIN) {
            lc_signal_info si;
            if (lc_kernel_read_retry(signal_fd, &si, sizeof(si)) == (lc_sysret)sizeof(si)) {
                if (si.signal == SIGCHLD) {
                    if (lc_kernel_wait_for_child(command, &status, WNOHANG) == command)
                        ended = true;
                } else if (si.signal == LB_SIGWINCH) {
                    if (st->master >= 0)
                        copy_window_size(STDIN, st->master);
                } else {
                    lc_kernel_send_signal(command, (int32_t)si.signal);
                }
            }
        }
        for (uint64_t i = 1; i < count; i++) {
            if (!fds[i].revents)
                continue;
            if (writing[i])
                channel_write(of[i]);
            else
                channel_read(of[i]);
        }
    }

    /* what the command wrote before it ended */
    for (int i = 0; i < st->nchannels; i++) {
        struct channel *c = &st->channels[i];
        if (c->to != STDOUT && c->to != STDERR)
            continue;
        for (int rounds = 0; rounds < 256; rounds++) {
            if (c->have > c->sent)
                (void)lc_kernel_write_all(c->to, c->buf + c->sent, c->have - c->sent);
            c->have = c->sent = 0;
            lc_sysret n = lc_kernel_read_bytes(c->from, c->buf, sizeof(c->buf));
            if (n <= 0)
                break;
            c->have = (size_t)n;
        }
    }
    return status;
}

/*
 * In lightbox, with the command started: carry its streams until it ends.
 * With a terminal for the command, the caller's terminal is raw for that
 * time, and gets its modes back at the end; the process that ran exec keeps
 * them too and puts them back once more, in case this one is killed.
 */
static int32_t serve_command(struct exec_streams *st, int32_t command, int32_t signal_fd) {
    release_command_ends(st);

    struct lb_termios saved, raw;
    bool restore = st->master >= 0 && lc_kernel_device_control(STDIN, LB_TCGETS, &saved) >= 0;
    if (restore) {
        raw = saved;
        make_raw(&raw);
        lc_kernel_device_control(STDIN, LB_TCSETS, &raw);
    }

    int32_t status = relay_until_exit(st, command, signal_fd);

    if (restore)
        lc_kernel_device_control(STDIN, LB_TCSETS, &saved);
    return status;
}

/* Hold back the signals that a command's streams are carried around, and
 * the two that would otherwise end or stop the carrier at a bad moment: a
 * descriptor to read the first from, or -1. */
static int32_t hold_relay_signals(void) {
    uint64_t read_here = relay_signal_mask();
    uint64_t blocked = read_here | sigmask_from_signal(LB_SIGPIPE) | sigmask_from_signal(LB_SIGTTOU);
    if (lc_kernel_set_signal_mask(LC_SIG_BLOCK, &blocked, NULL) < 0)
        return -1;
    lc_sysret fd = lc_kernel_create_signal_fd(-1, &read_here, SFD_CLOEXEC);
    return fd < 0 ? -1 : (int32_t)fd;
}

/*
 * In the process that ran exec: wait for the worker, and pass on what asks
 * it to end. A signal that the terminal sent has reached the worker by
 * itself, since both are in the terminal's foreground, so only the ones a
 * process sent are passed on. The worker's wait status.
 */
static int32_t attend_worker(int32_t worker, int32_t signal_fd) {
    int32_t status = 0;
    for (;;) {
        struct lb_pollfd one = { .fd = signal_fd, .events = LB_POLLIN, .revents = 0 };
        lc_sysret ready = lb_sys_ppoll(&one, 1, NULL);
        if (ready < 0 && ready != -LB_EINTR)
            die("Error: failed to wait for the exec worker");
        if (ready <= 0)
            continue;
        lc_signal_info si;
        if (lc_kernel_read_retry(signal_fd, &si, sizeof(si)) != (lc_sysret)sizeof(si))
            continue;
        if (si.signal == SIGCHLD) {
            if (lc_kernel_wait_for_child(worker, &status, WNOHANG) == worker)
                return status;
        } else if (si.signal != LB_SIGWINCH && si.code <= 0) {
            lc_kernel_send_signal(worker, (int32_t)si.signal);
        }
    }
}

/*
 * The rest of what the process that ran exec does: attend to the worker, put
 * the terminal's modes back as they were before the worker touched them, and
 * give the exit status to end with. modes is NULL when stdin is no terminal.
 */
static int finish_exec(int32_t worker, int32_t signal_fd, const struct lb_termios *modes) {
    int32_t status = attend_worker(worker, signal_fd);
    if (modes) {
        struct lb_termios back = *modes;
        lc_kernel_device_control(STDIN, LB_TCSETS, &back);
    }
    return exit_code_from_status(status);
}

/* ─── exec: entering the container ──────────────────────────────────────── */

static int exec_inside_container(const char *name, int target_pid, int userns,
                                 int privileged, int oom_score, const struct exec_request *req) {
    /* From here to the command's execve this process, and the child it
     * forks, are lightbox inside a container. Not dumpable, their memory and
     * their descriptors are closed to the container's processes, whatever
     * uid those have. */
    if (lc_kernel_prctl(LB_PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        die("Error: failed to close the exec worker to other processes");

    int rootfd = open_target_path(target_pid, "/root");
    if (rootfd < 0)
        die("Error: failed to open target root");

    int userfd = -1;
    if (userns) {
        userfd = open_target_path(target_pid, "/ns/user");
        if (userfd < 0)
            die("Error: failed to open target user namespace");
    }

    int mntfd = open_target_path(target_pid, "/ns/mnt");
    int utsfd = open_target_path(target_pid, "/ns/uts");
    int ipcfd = open_target_path(target_pid, "/ns/ipc");
    int netfd = open_target_path(target_pid, "/ns/net");
    int pidfd = open_target_path(target_pid, "/ns/pid");
    if (mntfd < 0 || utsfd < 0 || ipcfd < 0 || netfd < 0 || pidfd < 0)
        die("Error: failed to open target namespace fd");

    if (userns)
        require_setns_fd(userfd, CLONE_NEWUSER, "user");

    /* Join the host-side container cgroup before switching mount namespaces. */
    cgroup_join_self(name);
    /* and when memory runs short, be what the container's processes are to
     * the kernel, not what the caller of exec was */
    {
        char score[16];
        fmt_int(score, oom_score);
        if (write_file("/proc/self/oom_score_adj", score) < 0)
            die("Error: failed to give the command the container's OOM score");
    }

    require_setns_fd(mntfd, CLONE_NEWNS, "mount");
    require_setns_fd(utsfd, CLONE_NEWUTS, "uts");
    require_setns_fd(ipcfd, CLONE_NEWIPC, "ipc");
    require_setns_fd(netfd, CLONE_NEWNET, "net");

    if (lb_sys_fchdir(rootfd) < 0)
        die("Error: failed to chdir to target root");
    if (lb_sys_chroot(".") < 0)
        die("Error: failed to chroot into target root");
    if (lc_kernel_chdir("/") < 0)
        die("Error: failed to chdir to container root");

    /* The container's root is this process's root now: its account files
     * are read here, where no path in them leads out of the container. */
    struct identity id;
    resolve_identity(req, "/etc/passwd", "/etc/group", &id);

    /* What the command gets in the place of a terminal of the caller's: made
     * here, where /dev/pts is the container's. */
    static struct exec_streams streams;
    prepare_streams(&streams, "/dev/pts/ptmx", id.uid, id.gid);

    require_setns_fd(pidfd, CLONE_NEWPID, "pid");

    /* held back before the fork, so that the command's end is never missed */
    int32_t signal_fd = hold_relay_signals();
    if (signal_fd < 0)
        die("Error: failed to take over the signals of an exec");

    lc_sysret child = lc_kernel_fork();
    if (child < 0)
        die("Error: exec helper fork failed");

    if (child == 0) {
        take_streams(&streams);

        if (!privileged)
            apply_sandbox();
        become(&id);
        run_command(req, &id);
    }

    return serve_command(&streams, (int32_t)child, signal_fd);
}

/* ─── Starting: the command's side ──────────────────────────────────────── */

/* How long init may take to build a container, in seconds. It mounts and
 * pivots and runs nothing, so this is only ever reached by something stuck. */
#define START_SETUP_SECONDS 30

/* What the command holds of the init it cloned. */
struct init_link {
    int32_t pid;            /* -1: no init, or one that has been reaped */
    int32_t go_wr;          /* -1: closed */
    int32_t report_rd;      /* -1: closed */
    void   *stack;          /* MAP_FAILED: none */
};
#define INIT_LINK_NONE { -1, -1, -1, MAP_FAILED }

/*
 * While a container is being started, SIGINT, SIGTERM and SIGHUP do not end
 * the command where it stands, which would leave an interface, a cgroup and
 * perhaps an init behind. They are held back and read from the descriptor
 * this returns, and the command then undoes the start. SIGPIPE is held back
 * as well: writing to an init that has died is an error to handle, not an end.
 * -1 when the signals could not be taken over.
 */
static int32_t hold_signals(void) {
    uint64_t read_here = sigmask_from_signal(SIGINT) | sigmask_from_signal(SIGTERM) |
                         sigmask_from_signal(SIGHUP);
    uint64_t blocked = read_here | sigmask_from_signal(LB_SIGPIPE);

    if (lc_kernel_set_signal_mask(LC_SIG_BLOCK, &blocked, NULL) < 0)
        return -1;
    lc_sysret fd = lc_kernel_create_signal_fd(-1, &read_here, SFD_CLOEXEC);
    return fd < 0 ? -1 : (int32_t)fd;
}

/*
 * Open what becomes a container's standard streams: /dev/null to read from,
 * and its log to append to. Both are close-on-exec here; init puts copies on
 * 0, 1 and 2 that are not. The log is never followed through a link. True, or
 * false with neither open.
 */
static bool open_container_streams(const char *log_path, int32_t *null_fd, int32_t *log_fd) {
    lc_sysret null = lc_kernel_open_file("/dev/null", O_RDONLY | O_CLOEXEC, 0);
    if (null < 0)
        return false;
    lc_sysret log = lc_kernel_open_file(log_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                                        MODE_PRIVATE_FILE);
    if (log < 0) {
        lc_kernel_close_file((int32_t)null);
        return false;
    }
    *null_fd = (int32_t)null;
    *log_fd = (int32_t)log;
    return true;
}

/* The record init writes its exit status into: empty until it does. The
 * descriptor, or -1. */
static int32_t open_exit_record(const char *path) {
    lc_sysret fd = lc_kernel_open_file(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                                       MODE_PRIVATE_FILE);
    return fd < 0 ? -1 : (int32_t)fd;
}

static void close_container_streams(int32_t *null_fd, int32_t *log_fd) {
    if (*null_fd >= 0) {
        lc_kernel_close_file(*null_fd);
        *null_fd = -1;
    }
    if (*log_fd >= 0) {
        lc_kernel_close_file(*log_fd);
        *log_fd = -1;
    }
}

/*
 * Make the two pipes and clone init, which runs fn(ca) on a stack of its own
 * in the namespaces that flags names. The pipe ends in ca are filled in here.
 * NULL, or what failed; link then holds whatever exists, for init_abandon.
 */
static const char *init_spawn(struct init_link *link, struct child_args *ca,
                              int flags, int (*fn)(void *)) {
    int32_t go[2], report[2];

    if (lc_kernel_create_pipe(go, O_CLOEXEC) < 0)
        return "failed to create the pipe to the container's init";
    if (lc_kernel_create_pipe(report, O_CLOEXEC) < 0) {
        lc_kernel_close_file(go[0]);
        lc_kernel_close_file(go[1]);
        return "failed to create the pipe from the container's init";
    }
    link->go_wr = go[1];
    link->report_rd = report[0];
    ca->go_rd = go[0];
    ca->go_wr = go[1];
    ca->report_rd = report[0];
    ca->report_wr = report[1];

    const char *failed = NULL;
    link->stack = lc_kernel_map_memory(NULL, CHILD_STACK_SIZE, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (link->stack == MAP_FAILED) {
        failed = "failed to allocate the stack of the container's init";
    } else {
        /* lc_kernel_clone puts fn and ca on the child's stack before the
         * syscall, so the child never touches this stack frame */
        lc_sysret pid = lc_kernel_clone(flags | SIGCHLD, (char *)link->stack + CHILD_STACK_SIZE, fn, ca);
        if (pid < 0)
            failed = "clone failed";
        else
            link->pid = (int32_t)pid;
    }

    /* init's ends are init's alone now; without an init nobody needs them */
    lc_kernel_close_file(go[0]);
    lc_kernel_close_file(report[1]);
    return failed;
}

/* One byte for init to go on with. */
static bool init_go(const struct init_link *link) {
    return lc_kernel_write_bytes(link->go_wr, "x", 1) == 1;
}

/* Close the command's ends of the pipes and free the stack init was cloned
 * on. Each is marked, so this can be called at any point, and again. */
static void init_link_close(struct init_link *link) {
    if (link->go_wr >= 0) {
        lc_kernel_close_file(link->go_wr);
        link->go_wr = -1;
    }
    if (link->report_rd >= 0) {
        lc_kernel_close_file(link->report_rd);
        link->report_rd = -1;
    }
    if (link->stack != MAP_FAILED) {
        lc_kernel_unmap_memory(link->stack, CHILD_STACK_SIZE);
        link->stack = MAP_FAILED;
    }
}

/*
 * Undo a start from the command's side. Init is killed first, which takes
 * every process of its PID namespace with it, and waited for; the pipes are
 * closed only then, so init never sees them close and reads that as a reason
 * to go on.
 */
static void init_abandon(struct init_link *link) {
    if (link->pid > 0) {
        int32_t status;
        lc_kernel_send_signal(link->pid, SIGKILL);
        (void)wait_child(link->pid, &status);
        link->pid = -1;
    }
    init_link_close(link);
}

enum await_result {
    AWAIT_REPORT,       /* *report is filled in */
    AWAIT_CLOSED,       /* init closed its end: it is gone, or going */
    AWAIT_TIMEOUT,
    AWAIT_SIGNAL,       /* a held-back signal arrived; *signal is its number */
    AWAIT_FAILED,       /* the waiting itself failed */
};

/*
 * Wait for init's next report, for at most the given seconds. A signal that
 * hold_signals holds back ends the wait, and comes first when both are there:
 * someone asked for the start to stop. report_fd or signal_fd may be -1, and
 * is then not waited on.
 */
static enum await_result await_report(int32_t report_fd, int32_t signal_fd, int seconds,
                                      struct start_report *report, int *signal) {
    int64_t deadline = monotonic_ms() + (int64_t)seconds * 1000;

    for (;;) {
        int64_t left = deadline - monotonic_ms();
        if (left < 0)
            left = 0;
        lc_timespec limit = { .seconds = left / 1000, .nanoseconds = (left % 1000) * 1000000 };
        struct lb_pollfd fds[2] = {
            { .fd = signal_fd, .events = LB_POLLIN, .revents = 0 },
            { .fd = report_fd, .events = LB_POLLIN, .revents = 0 },
        };

        lc_sysret n = lb_sys_ppoll(fds, 2, &limit);
        if (n == -LB_EINTR)
            continue;
        if (n < 0)
            return AWAIT_FAILED;
        if (n == 0)
            return AWAIT_TIMEOUT;

        if (fds[0].revents & LB_POLLIN) {
            lc_signal_info si;
            if (lc_kernel_read_retry(signal_fd, &si, sizeof(si)) != (lc_sysret)sizeof(si))
                return AWAIT_FAILED;
            *signal = (int)si.signal;
            return AWAIT_SIGNAL;
        }
        if (fds[1].revents & (LB_POLLIN | LB_POLLHUP)) {
            lc_sysret got = lc_kernel_read_retry(report_fd, report, sizeof(*report));
            return got == (lc_sysret)sizeof(*report) ? AWAIT_REPORT : AWAIT_CLOSED;
        }
        return AWAIT_FAILED;    /* a descriptor in a state this does not know */
    }
}

/* What a start that failed leaves behind, removed. Init is gone by now. */
static void cleanup_start_failure(const char *name, const char *port, bool port_made) {
    /* One this start made goes, whatever its alias: the kernel does not take
     * an alias with an interface's creation, and a start that failed before
     * it gave the interface one has left it without. */
    if (port_made) {
        const char *del[] = { "ip", "link", "delete", port, NULL };
        (void)run_cmd_quiet(tool_path_ip(), del);   /* clean-up: best effort */
    } else if (port && port[0])
        (void)remove_own_port(port, name);          /* clean-up: best effort */

    (void)cgroup_destroy(name);     /* it has said so if it could not */
    (void)firewall_remove_links(name);

    container_forget_pid(name);
    (void)record_container_state(name, "failed\n");
}

/*
 * Take away what a container whose init has ended still has on the host:
 * whatever is left in its cgroup and the cgroup itself, the firewall rules
 * of its links, and the host's end of its interface. True when all of it is
 * gone; otherwise what is left has been said.
 */
static bool release_container(const char *name) {
    bool clean = true;

    if (cgroup_destroy(name) != 0)
        clean = false;

    /* its link rules: what the record of them names, whatever its
     * configuration says or whether it can be read */
    if (firewall_remove_links(name) != 0)
        clean = false;

    /* the host's end of the container's interface, if the kernel has not
     * removed it with the container's network namespace already */
    {
        char port[IFNAME_TEXT_MAX];
        host_port_name(name, port);
        if (remove_own_port(port, name) < 0) {
            print_str(STDERR, "Error: cannot remove the interface ");
            print_str(STDERR, port);
            lc_print_char(STDERR, '\n');
            clean = false;
        }
    }
    return clean;
}

/*
 * A container that ended without a stop: cleared away, and its end put on
 * record. Called with the container's lock held, by the commands that change
 * a container, before they do anything else.
 *
 * Such a container is one whose init is on record and gone, because it was
 * killed, or told to stop by something other than lightbox, or because its
 * hook failed after the start had returned. It is also one whose record
 * says that a command was in the middle of starting or stopping it: with the
 * lock held no command is, so that command died there.
 *
 * What it left is taken away as a stop takes it away. Its state becomes
 * "exited" when init said that it ended with status 0, which is what it does
 * when it is asked to stop, and "failed" when it said anything else or
 * nothing at all. True when there was something to clear away.
 */
static bool reconcile(const char *name) {
    container_liveness live = container_probe(name);
    if (live == CONTAINER_RUNNING)
        return false;

    char state[32];
    get_container_state(name, state, sizeof(state));
    bool cut_short = streq(state, "starting") || streq(state, "running") || streq(state, "stopping");
    if (live != CONTAINER_DEAD && !cut_short)
        return false;

    int status = 0;
    bool ended_well = container_exit_report(name, &status) && status == 0;

    (void)release_container(name);      /* it has said what it could not remove */
    container_forget_pid(name);
    (void)record_container_state(name, ended_well ? "exited\n" : "failed\n");

    print_str(STDERR, "Note: container '");
    print_str(STDERR, name);
    print_str(STDERR, ended_well ? "' had stopped by itself; what it left has been cleared away\n"
                                 : "' had ended without a stop; what it left has been cleared away\n");
    return true;
}

static void enter_user_namespace_root(void) {
    struct lb_cap_header hdr = { LB_CAPABILITY_VERSION_3, 0 };
    struct lb_cap_data data[LB_CAPABILITY_WORDS];

    if (lc_kernel_prctl(LB_PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
        die("Error: failed to enable keepcaps for userns");
    if (lc_kernel_setgid(0) < 0)
        die("Error: failed to setgid(0) in userns");
    if (lc_kernel_setuid(0) < 0)
        die("Error: failed to setuid(0) in userns");

    if (lb_sys_capget(&hdr, data) < 0)
        die("Error: capget failed in userns");

    data[0].effective = data[0].permitted;
    data[1].effective = data[1].permitted;

    if (lb_sys_capset(&hdr, data) < 0)
        die("Error: capset failed in userns");
}

/* A volume on its way into a container. */
struct volume_mount {
    int32_t tree;               /* a clone of the source's mount, attached nowhere yet */
    bool    is_dir;
    bool    ro;
    const char *dst;            /* where it goes, in the configuration it is from */
};

/*
 * Clone the mount of a volume's source: a copy of it that hangs nowhere, and
 * that stays good when the host's filesystems are taken out of the
 * container's sight. Ends the process when the volume cannot be had.
 */
static void open_volume(const volume_spec *vol, struct volume_mount *out) {
    lc_sysret tree = lb_sys_open_tree(AT_FDCWD, vol->src, LB_OPEN_TREE_CLONE | LB_OPEN_TREE_CLOEXEC);
    if (tree == -LB_ENOENT)
        die2("Error: volume source does not exist: ", vol->src);
    struct lb_statx stx;
    if (tree < 0 || lb_sys_statx((int32_t)tree, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE, &stx) < 0) {
        say_with_number("Error: cannot take the volume's source (errno ", (int)(tree < 0 ? -tree : 0), "): ");
        print_str(STDERR, vol->src);
        lc_print_char(STDERR, '\n');
        lc_kernel_exit(1);
    }

    out->tree = (int32_t)tree;
    out->is_dir = (stx.stx_mode & LB_S_IFMT) == LB_S_IFDIR;
    out->ro = vol->ro;
    out->dst = vol->dst;
}

/* The volumes a container is configured with, cloned: how many. */
static int open_volumes(const container_config *config, struct volume_mount *out) {
    for (int i = 0; i < config->nvols; i++)
        open_volume(&config->vols[i], &out[i]);
    return config->nvols;
}

/*
 * Attach the cloned volumes, in the container.
 *
 * This runs after the pivot and after the host's root has been taken away, so
 * every destination is looked up with the container's root as the root: a
 * link in the image leads where the container sees it lead, and nothing made
 * here, directory or file, can be anywhere but in the container. It also
 * runs after /tmp and /run have been mounted, so a volume below them is on
 * top of them and not hidden beneath.
 */
static void attach_volumes(const struct volume_mount *vols, int count) {
    for (int i = 0; i < count; i++) {
        const char *dst = vols[i].dst;

        /* something to mount on, of the kind the source is */
        if (vols[i].is_dir) {
            if (make_dirs(dst) != 0)
                lc_kernel_exit(1);
        } else {
            char parent[MAX_PATH];
            if (!parent_dir(parent, sizeof(parent), dst))
                die2("Error: invalid path: ", dst);
            if (make_dirs(parent) != 0)
                lc_kernel_exit(1);
            lc_sysret fd = lc_kernel_open_file(dst, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
            if (fd < 0)
                die2("Error: failed to create volume target file: ", dst);
            lc_kernel_close_file((int32_t)fd);
        }

        lc_sysret rc = lb_sys_move_mount(vols[i].tree, "", AT_FDCWD, dst,
                                         LB_MOVE_MOUNT_F_EMPTY_PATH | LB_MOVE_MOUNT_T_SYMLINKS);
        if (rc < 0) {
            say_with_number("Error: cannot mount the volume (errno ", (int)-rc, ") at ");
            print_str(STDERR, dst);
            lc_print_char(STDERR, '\n');
            lc_kernel_exit(1);
        }
        lc_kernel_close_file(vols[i].tree);

        uint64_t flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV;
        if (vols[i].ro)
            flags |= MS_RDONLY;
        require_mount(NULL, dst, NULL, flags, NULL);
    }
}

/*
 * Build the container around init: its volumes, its /dev, its own root, and
 * the filesystems that go into it. Every step that fails ends the process
 * with the reason on stderr; the command then sees init's pipe close.
 */
static void build_container(const struct child_args *ca) {
    if (ca->userns)
        enter_user_namespace_root();

    /* make all mounts private — prevents host mount events (including
     * the host's /proc) from propagating into the container */
    require_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

    /* set hostname */
    lc_kernel_sethostname(ca->name, lc_string_length(ca->name));

    /* The volumes: taken now, while the host's paths mean what they mean on
     * the host, and attached later, when the container's paths mean what
     * they mean in the container. */
    struct volume_mount volumes[MAX_VOLS];
    int nvolumes = open_volumes(ca->config, volumes);

    /* set up /dev via bind mounts (works in both userns and non-userns) */
    {
        char dev_path[MAX_PATH];
        path_join_or_die(dev_path, MAX_PATH, ca->root, "dev");
        lc_kernel_mkdirat(AT_FDCWD, dev_path, 0755);   /* a minimal image may not have it */
        require_mount("tmpfs", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755");

        struct { const char *name; uint64_t dev; int mode; } devs[] = {
            { "null",    MAKEDEV(1, 3), 0666 },
            { "zero",    MAKEDEV(1, 5), 0666 },
            { "full",    MAKEDEV(1, 7), 0666 },
            { "random",  MAKEDEV(1, 8), 0444 },
            { "urandom", MAKEDEV(1, 9), 0444 },
            { "tty",     MAKEDEV(5, 0), 0666 },
        };

        for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
            char host_dev[32], cont_dev[MAX_PATH];
            path_join_or_die(host_dev, sizeof(host_dev), "/dev", devs[i].name);
            path_join_or_die(cont_dev, MAX_PATH, dev_path, devs[i].name);
            /* create empty file as mount point */
            lc_sysret fd = lc_kernel_open_file(cont_dev, O_WRONLY | O_CREAT, devs[i].mode);
            if (fd >= 0) lc_kernel_close_file((int32_t)fd);
            require_mount(host_dev, cont_dev, NULL, MS_BIND, NULL);
            if (!ca->privileged) {
                uint64_t dev_flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NOEXEC;
                if (streq(devs[i].name, "random") || streq(devs[i].name, "urandom"))
                    dev_flags |= MS_RDONLY;
                require_mount(NULL, cont_dev, NULL, dev_flags, NULL);
            }
        }

        /* pts and shm */
        char pts[MAX_PATH], shm[MAX_PATH];
        path_join_or_die(pts, MAX_PATH, dev_path, "pts");
        path_join_or_die(shm, MAX_PATH, dev_path, "shm");
        lc_kernel_mkdirat(AT_FDCWD, pts, 0755);
        lc_kernel_mkdirat(AT_FDCWD, shm, 0755);
    }

    /* pivot_root */
    require_mount(ca->root, ca->root, NULL, MS_BIND | MS_REC, NULL);
    /* A device node inside the image is not a device here: the devices a
     * container may use are the ones bound into its /dev, which is a mount of
     * its own. Without privileges, setuid bits in the image mean nothing
     * either, as no_new_privs already has it. */
    require_mount(NULL, ca->root, NULL,
                  MS_REMOUNT | MS_BIND | MS_NODEV | (ca->privileged ? 0 : MS_NOSUID), NULL);
    if (lc_kernel_chdir(ca->root) < 0)
        die2("Error: chdir to rootfs failed: ", ca->root);
    lc_kernel_mkdirat(AT_FDCWD, ".old_root", 0755);
    if (lc_kernel_pivot_root(".", ".old_root") < 0)
        die("Error: pivot_root failed");
    cleanup_old_root_or_die();
    lc_kernel_chdir("/");

    /* Ensure standard mountpoints exist inside the container rootfs. */
    lc_kernel_mkdirat(AT_FDCWD, "/proc", 0555);
    lc_kernel_mkdirat(AT_FDCWD, "/sys", 0555);
    lc_kernel_mkdirat(AT_FDCWD, "/tmp", 01777);
    lc_kernel_mkdirat(AT_FDCWD, "/run", 0755);
    lc_kernel_mkdirat(AT_FDCWD, "/var", 0755);
    lc_kernel_mkdirat(AT_FDCWD, "/var/tmp", 01777);

    /* mount proc, sys */
    require_mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

    /*
     * sysfs mounting is typically not permitted inside an unprivileged user
     * namespace. Leave /sys as the rootfs directory in that mode.
     */
    if (!ca->userns)
        require_mount("sysfs", "/sys", "sysfs", MS_RDONLY, NULL);

    /* devpts and shm inside container */
    require_mount("devpts", "/dev/pts", "devpts",
                  MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666");
    require_mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

    /* symlinks in /dev */
    lc_kernel_symlinkat("/proc/self/fd", AT_FDCWD, "/dev/fd");
    lc_kernel_symlinkat("/proc/self/fd/0", AT_FDCWD, "/dev/stdin");
    lc_kernel_symlinkat("/proc/self/fd/1", AT_FDCWD, "/dev/stdout");
    lc_kernel_symlinkat("/proc/self/fd/2", AT_FDCWD, "/dev/stderr");
    lc_kernel_symlinkat("pts/ptmx", AT_FDCWD, "/dev/ptmx");

    /* tmpfs for /tmp and /run, so that the hook and its services find them
     * as they stay. /tmp is for everyone; /run is for root's services to
     * share with them. */
    require_mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
    require_mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755");
    if (ca->read_only)
        require_mount("tmpfs", "/var/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);

    /* the volumes, on top of all of the above and before the root may close */
    attach_volumes(volumes, nvolumes);

    /* mask sensitive /proc paths (unless privileged) */
    if (!ca->privileged) {
        mask_proc_paths();
    }

    /* read-only rootfs */
    if (ca->read_only) {
        require_mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
    }

    /* Bring up loopback. From the pivot to the hook nothing of the image is
     * run: its tools are not needed, and not trusted with what init may do. */
    if (loopback_up() != 0)
        lc_kernel_exit(1);
}

/* What the clone that becomes a container's init runs. */
/*
 * The last thing init does: say how it ends. Its exit status goes into the
 * record that was opened for it before the container was built, where the
 * next command that changes this container finds it: 0 after it was asked
 * to stop, by lightbox or by a signal from anywhere, and something else
 * after the hook failed. An init that is killed says nothing, and that is
 * told from this.
 */
static int init_ends(const struct child_args *ca, int status) {
    if (ca->exit_fd >= 0) {
        char text[16];
        size_t len = (size_t)fmt_int(text, status);
        text[len++] = '\n';
        (void)lc_kernel_write_all(ca->exit_fd, text, len);
    }
    return status;
}

static int container_child(void *arg) {
    const struct child_args *ca = (const struct child_args *)arg;

    init_begin(ca);
    build_container(ca);
    return init_ends(ca, init_main(ca));
}

/* ─── cmd_start ─────────────────────────────────────────────────────────── */

/* "<before><number><after>" in buf, for a message that names a number. */
static const char *text_with_number(char *buf, size_t bufsz, const char *before, int number,
                                    const char *after) {
    char digits[16];
    bool cut = false;       /* a message that lost its end is still the message */
    fmt_int(digits, number);
    size_t pos = str_append(buf, 0, before, bufsz, &cut);
    pos = str_append(buf, pos, digits, bufsz, &cut);
    str_append(buf, pos, after, bufsz, &cut);
    return buf;
}

/* ─── Several containers at once ────────────────────────────────────────── */

/*
 * The names among a command's arguments, moved to its front, and -t or
 * --timeout with its seconds wherever it is, when the command takes one.
 * Anything else is an error, named. How many names there are.
 */
static int names_and_seconds(int argc, char **argv, int *seconds) {
    int count = 0;
    for (int i = 0; i < argc; i++) {
        if (seconds && (streq(argv[i], "-t") || streq(argv[i], "--timeout"))) {
            if (i + 1 >= argc)
                die2("Error: option needs a number of seconds: ", argv[i]);
            if (!parse_seconds(argv[++i], seconds))
                die2("Error: not a number of seconds from 0 to " STRINGIFY(SECONDS_MAX) ": ", argv[i]);
        } else if (argv[i][0] == '-') {
            die2("Error: unknown option: ", argv[i]);
        } else {
            argv[count++] = argv[i];
        }
    }
    for (int i = 0; i < count; i++)
        validate_name(argv[i]);
    return count;
}

typedef void (*per_container)(const char *name, int seconds);

/*
 * start, stop and rm of several containers, as Docker's: each in a process
 * of its own, one after the other, so that what ends the command for one
 * ends it for that one only. The exit status is the first that was not 0,
 * and the ones that were not done are named at the end.
 */
[[noreturn]] static void each_container(const char *not_done, int count, char **names, per_container one, int seconds) {
    if (count == 1) {
        one(names[0], seconds);
        lc_kernel_exit(0);
    }
    int first = 0;
    static char failed[4096];
    size_t pos = 0;
    bool cut = false;
    for (int i = 0; i < count; i++) {
        lc_sysret pid = lc_kernel_fork();
        if (pid < 0)
            die("Error: cannot make a process for the next container");
        if (pid == 0) {
            one(names[i], seconds);
            lc_kernel_exit(0);
        }
        int32_t status = 0;
        lc_sysret got;
        do {
            got = lc_kernel_wait_for_child((int32_t)pid, &status, 0);
        } while (got == -LB_EINTR);
        int code = got == pid ? exit_code_from_status(status) : 1;
        if (code != 0) {
            if (!first)
                first = code;
            pos = str_append(failed, pos, pos ? ", " : "", sizeof(failed), &cut);
            pos = str_append(failed, pos, names[i], sizeof(failed), &cut);
        }
    }
    if (first) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, not_done);
        print_str(STDERR, ": ");
        print_str(STDERR, failed);
        print_str(STDERR, cut ? " and more\n" : "\n");
    }
    lc_kernel_exit(first);
}

static void start_one(const char *name, int hook_wait) {
    require_root("start");
    require_tool("ip", tool_path_ip());
    require_tool("nsenter", tool_path_nsenter());

    /* from here to the end, no other command works on this container */
    container_lock(name);

    /* a create that was killed half way left it with half a root filesystem,
     * or with none */
    {
        char creating[MAX_PATH];
        container_creating_path(creating, name);
        if (path_exists(creating))
            die2("Error: the container was not created completely; remove it and create it again: ", name);
    }

    char root[MAX_PATH];
    container_root(root, name);
    if (!path_exists(root)) die2("Error: container does not exist: ", name);

    if (is_running(name)) die2("Error: container is already running: ", name);
    (void)reconcile(name);          /* an earlier run that ended without a stop */
    container_forget_pid(name);     /* and whatever else one left on record */

    /* The bridge, the firewall rules and forwarding, made again when a
     * reboot took them. What makes them takes the store's lock; teardown,
     * which holds that, never waits for a container's. */
    ensure_host_network();

    /* The container's address, which has to be one of the network as it is
     * set now: with another subnet since the container was created, it would
     * start and reach nothing. */
    char ip[IPV4_TEXT_MAX], ip_cidr[CIDR_TEXT_MAX];
    {
        container_network net;
        container_network_load_or_die(&net);
        uint32_t addr;
        if (read_container_ip(name, ip, sizeof(ip)) < 0 || !parse_ipv4(ip, &addr))
            die2("Error: the container has no address on record; remove it and create it again: ", name);
        const char *why = address_unusable(&net, addr);
        if (why)
            die_about_address(ip, why);
        address_with_prefix(ip_cidr, addr, &net);
    }

    /* What the container is configured with: read here, once, for the whole
     * start. Init gets it with the memory it is cloned with. */
    static container_config config;
    container_config_load_or_die(name, &config);
    bool userns = config.userns;
    int uid_start = config.uid_start;
    bool privileged = config.privileged;
    bool read_only = config.read_only;
    int oom_score = config.oom_score;

    if (userns)
        die("Error: containers configured with user namespaces are not supported yet");

    /* A container without links gets an isolated port on the bridge: it
     * reaches the host and, through it, the outside, and no other container.
     * One with links has to share the bridge with the containers it is linked
     * to, and then the firewall is all that keeps it to those. iptables sees
     * what the bridge switches only with br_netfilter, so without that such a
     * container is not started; nftables sees it at the bridge itself.
     * Decided before anything is set up. */
    bool linked = config.nlinks > 0;
    if (linked && !cfg_global.firewall) {
        print_str(STDERR, "Error: container '");
        print_str(STDERR, name);
        print_str(STDERR, "' has links, and firewall = false in lightbox.conf. A linked container\n"
                          "shares the bridge with the others, and only lightbox's rules keep it to its\n"
                          "links, so it is not started without them\n");
        lc_kernel_exit(1);
    }
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;
    if (linked && nftables)
        require_tool("nft", tool_path_nft());
    else if (linked)
        require_tool("iptables-restore", tool_path_iptables_restore());
    if (linked && !nftables && !bridge_traffic_is_filtered()) {
        print_str(STDERR, "Error: container '");
        print_str(STDERR, name);
        print_str(STDERR,
            "' has links, and on this host bridged traffic does not pass\n"
            "through iptables. A linked container shares the bridge with the others, and\n"
            "only the firewall keeps it to its links. Let the firewall see that traffic,\n"
            "then start the container again:\n"
            "  modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1\n"
            "or set firewall_backend = nftables in lightbox.conf, which needs no br_netfilter\n");
        lc_kernel_exit(1);
    }

    int32_t signal_fd = hold_signals();
    if (signal_fd < 0)
        die("Error: failed to take over the signals that would interrupt the start");

    print_str(STDOUT,"Starting container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");
    set_container_state(name, "starting\n");

    /*
     * From here to the end of this function nothing ends the process where it
     * stands: every failure goes to fail_start, which undoes what was done.
     * tests/unit_cases.sh reads this function to see that it stays that way.
     */
    const char *start_err = NULL;
    char err_buf[96];
    int exit_code = 1;
    bool hook_failed = false;
    int32_t null_fd = -1, log_fd = -1, exit_fd = -1;
    struct init_link init = INIT_LINK_NONE;
    struct start_report report = { 0, 0 };
    int stop_signal = 0;

    /* The end of the container's interface on the host, by a name made from
     * its own. One that is there already is cleared away when lightbox made
     * it for this container; when not, it is left alone and the start ends. */
    char port[IFNAME_TEXT_MAX], port_err[128];
    bool port_made = false;
    host_port_name(name, port);
    {
        port_owner owner = host_port_owner(port, name);
        if (owner == PORT_FOREIGN) {
            bool cut = false;
            size_t pos = str_append(port_err, 0, "this host has an interface ", sizeof(port_err), &cut);
            pos = str_append(port_err, pos, port, sizeof(port_err), &cut);
            str_append(port_err, pos, " that lightbox did not make for this container; it is left alone",
                       sizeof(port_err), &cut);
            start_err = port_err;
            port[0] = '\0';         /* and nothing goes on to remove it */
            goto fail_start;
        }
        if (owner == PORT_OURS && remove_own_port(port, name) != 0) {
            start_err = "failed to remove what an earlier run left of the container's interface";
            goto fail_start;
        }
    }

    /* what the container reads from and writes to, once it is built */
    char log_path[MAX_PATH];
    container_log_path(log_path, name);
    if (!open_container_streams(log_path, &null_fd, &log_fd)) {
        start_err = "failed to open the container's log";
        goto fail_start;
    }
    /* and where init says how it ended, for the command that comes after */
    {
        char exit_path[MAX_PATH];
        container_exit_path(exit_path, name);
        exit_fd = open_exit_record(exit_path);
        if (exit_fd < 0) {
            start_err = "failed to open the record of how the container ends";
            goto fail_start;
        }
    }

    /* clone init; it waits for its first byte */
    struct child_args ca = {
        .starter_signals = signal_fd,
        .null_fd = null_fd,
        .log_fd = log_fd,
        .exit_fd = exit_fd,
        .name = name,
        .config = &config,
        .root = root,
        .hook = "/init.sh",
        .stop_grace = cfg_global.stop_timeout,
        .userns = userns,
        .privileged = privileged,
        .read_only = read_only,
    };
    int clone_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET;
    if (userns) clone_flags |= CLONE_NEWUSER;

    start_err = init_spawn(&init, &ca, clone_flags, container_child);
    close_container_streams(&null_fd, &log_fd);     /* init has its own copies */
    lc_kernel_close_file(exit_fd);
    exit_fd = -1;
    if (start_err)
        goto fail_start;
    int child_pid = (int)init.pid;

    /* write uid/gid maps if userns */
    if (userns) {
        char proc_path[64], map_buf[32];
        bool cut = false;

        /* deny setgroups */
        if (!proc_pid_path(proc_path, sizeof(proc_path), child_pid, "/setgroups") ||
            write_file(proc_path, "deny") < 0) { start_err = "failed to write setgroups"; goto fail_start; }

        /* uid_map and gid_map: the same range for both */
        {
            char first[16]; fmt_int(first, uid_start);
            size_t mp = str_append(map_buf, 0, "0 ", sizeof(map_buf), &cut);
            mp = str_append(map_buf, mp, first, sizeof(map_buf), &cut);
            str_append(map_buf, mp, " 65536", sizeof(map_buf), &cut);
        }
        if (cut || !proc_pid_path(proc_path, sizeof(proc_path), child_pid, "/uid_map") ||
            write_file(proc_path, map_buf) < 0) { start_err = "failed to write uid_map"; goto fail_start; }
        if (!proc_pid_path(proc_path, sizeof(proc_path), child_pid, "/gid_map") ||
            write_file(proc_path, map_buf) < 0) { start_err = "failed to write gid_map"; goto fail_start; }
    }

    /*
     * Set up cgroup, networking, and OOM score before init gets its first
     * byte. While it waits for that byte it is certainly there, so everything
     * that names its PID or its network namespace has something to name.
     */

    /* set up cgroup */
    start_err = cgroup_create(name, child_pid, &config);
    if (start_err)
        goto fail_start;

    /* before the namespace has an interface that could come up with it */
    if (netns_disable_ipv6(child_pid) != 0) {
        start_err = "failed to switch IPv6 off in the container";
        goto fail_start;
    }

    /* The pair: the host's end, on the bridge with lightbox's alias; and the
     * container's, made in the container's namespace as eth0, so that no end
     * of it is on the host under a name of the container's. The kernel takes
     * no alias with the pair, so the host's end gets it as it joins the
     * bridge, and until then only this start knows the interface is its own. */
    {
        char nsbuf[16];
        fmt_int(nsbuf, child_pid);
        const char *add[] = { "ip", "link", "add", port, "type", "veth",
                              "peer", "name", CONTAINER_IFNAME, "netns", nsbuf, NULL };
        if (run_cmd(tool_path_ip(), add) != 0) { start_err = "failed to create the container's interface"; goto fail_start; }
        port_made = true;
    }
    {
        char alias[64];
        bool cut = false;
        str_append(alias, str_append(alias, 0, "lightbox:", sizeof(alias), &cut), name, sizeof(alias), &cut);
        const char *a[] = { "ip", "link", "set", "dev", port, "alias", alias, "master", cfg_global.bridge, NULL };
        if (cut || run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to attach the container's interface to the bridge"; goto fail_start; }
    }
    if (!linked) {
        /* isolated ports do not reach each other, whatever the firewall does */
        const char *a[] = { "ip", "link", "set", "dev", port, "type", "bridge_slave", "isolated", "on", NULL };
        if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to isolate the container's port on the bridge"; goto fail_start; }
    }
    { const char *a[] = { "ip", "link", "set", port, "up", NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to bring the container's interface up on the host"; goto fail_start; } }

    /* configure networking inside the container */
    {
        char nsbuf[16]; fmt_int(nsbuf, child_pid);

        const char *a1[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "link", "set", CONTAINER_IFNAME, "up", NULL };
        if (run_cmd(tool_path_nsenter(), a1) != 0) { start_err = "failed to bring container veth up"; goto fail_start; }
        const char *a2[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "addr", "add", ip_cidr, "dev", CONTAINER_IFNAME, NULL };
        if (run_cmd(tool_path_nsenter(), a2) != 0) { start_err = "failed to assign container IP"; goto fail_start; }
        const char *a3[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "route", "add", "default", "via", cfg_global.gw, NULL };
        if (run_cmd(tool_path_nsenter(), a3) != 0) { start_err = "failed to install default route"; goto fail_start; }
    }

    /* set OOM score */
    {
        char oom_path[64], oom_buf[16];
        fmt_int(oom_buf, oom_score);
        if (!proc_pid_path(oom_path, sizeof(oom_path), child_pid, "/oom_score_adj") ||
            write_file(oom_path, oom_buf) < 0) { start_err = "failed to set oom_score_adj"; goto fail_start; }
    }

    /* First byte: init builds the container, and says when it is built. */
    if (!init_go(&init)) {
        start_err = "the container's init is gone";
        goto fail_start;
    }
    switch (await_report(init.report_rd, signal_fd, START_SETUP_SECONDS, &report, &stop_signal)) {
        case AWAIT_REPORT:
            if (report.what == START_READY)
                break;
            start_err = "the container's init sent a report that makes no sense";
            goto fail_start;
        case AWAIT_CLOSED:
            start_err = "the container's init gave up while it was setting up";
            goto fail_start;
        case AWAIT_TIMEOUT:
            start_err = "the container was not set up within " STRINGIFY(START_SETUP_SECONDS) " seconds";
            goto fail_start;
        case AWAIT_SIGNAL:
            goto interrupted;
        case AWAIT_FAILED:
        default:
            start_err = "failed to wait for the container's init";
            goto fail_start;
    }

    /* The container is built and nothing of the image has run. Init goes on
     * record before it runs the hook, so that there is no moment at which
     * the image's programs run in a container that stop and ls cannot find. */
    if (container_record_pid(name, child_pid) != 0) {
        start_err = "failed to record the container's init";
        goto fail_start;
    }
    if (firewall_add_links(name, &config) != 0) {
        start_err = "failed to put in the firewall rules of the container's links";
        goto fail_start;
    }

    /* Second byte: init runs the hook, and says how it ended. */
    if (!init_go(&init)) {
        start_err = "the container's init is gone";
        goto fail_start;
    }
    bool hook_still_running = false;
    if (hook_wait > 0) {
        switch (await_report(init.report_rd, signal_fd, hook_wait, &report, &stop_signal)) {
            case AWAIT_REPORT:
                if (report.what != START_HOOK_DONE) {
                    start_err = "the container's init sent a report that makes no sense";
                    goto fail_start;
                }
                if (report.status != 0) {
                    start_err = text_with_number(err_buf, sizeof(err_buf),
                                                 "the init hook /init.sh failed with exit status ",
                                                 report.status, "");
                    hook_failed = true;
                    goto fail_start;
                }
                break;
            case AWAIT_CLOSED:
                /* No stop did this: a stop waits for this command to be done
                 * with the container. Init was ended from somewhere else. */
                start_err = "the container stopped while its init hook was running";
                goto fail_start;
            case AWAIT_TIMEOUT:
                hook_still_running = true;
                break;
            case AWAIT_SIGNAL:
                goto interrupted;
            case AWAIT_FAILED:
            default:
                start_err = "failed to wait for the container's init";
                goto fail_start;
        }
    }

    if (record_container_state(name, "running\n") != 0) {
        start_err = "failed to record the container as running";
        goto fail_start;
    }
    init_link_close(&init);

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' started (pid=");
    lc_print_unsigned(STDOUT, (uint64_t)child_pid);
    print_str(STDOUT,", ip=");
    print_str(STDOUT,ip);
    print_str(STDOUT,")\n");
    print_str(STDOUT,"Attach with: lightbox exec ");
    print_str(STDOUT,name);
    print_str(STDOUT," /bin/sh\n");
    if (hook_still_running)
        say_with_number("Note: /init.sh is still running after ", hook_wait,
                        " s. The container is started, and this command no\n"
                        "longer waits for the hook. start -t <seconds> sets how long it waits; 0 does not\n"
                        "wait at all.\n");
    return;

interrupted:
    start_err = text_with_number(err_buf, sizeof(err_buf), "interrupted by signal ", stop_signal,
                                 "; the start was undone");
    exit_code = 128 + stop_signal;

fail_start:
    init_abandon(&init);
    close_container_streams(&null_fd, &log_fd);
    if (exit_fd >= 0)
        lc_kernel_close_file(exit_fd);
    if (start_err) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, start_err);
        lc_print_char(STDERR, '\n');
    }
    if (hook_failed) {
        print_str(STDERR, "What the hook printed is in the container's log: lightbox logs ");
        print_str(STDERR, name);
        lc_print_char(STDERR, '\n');
    }
    cleanup_start_failure(name, port, port_made);
    lc_kernel_exit(exit_code);
}

static void cmd_start(int argc, char **argv) {
    /* how long each waits for the init hook */
    int hook_wait = cfg_global.start_timeout;
    int count = names_and_seconds(argc, argv, &hook_wait);
    if (count == 0)
        die("Usage: lightbox start <name>... [-t <seconds>]");
    require_root("start");
    each_container("not started", count, argv, start_one, hook_wait);
}

/* ─── cmd_stop ──────────────────────────────────────────────────────────── */

/* What init gets beyond its own limit before stop ends it by force. */
#define STOP_MARGIN_MS 2000

/*
 * Ask a container's init to stop: SIGTERM through its pidfd, with the seconds
 * it may take sent along as the signal's value. False when init is gone.
 */
static bool ask_init_to_stop(int32_t pidfd, int seconds) {
    struct lb_siginfo_queue info = {
        .signo = SIGTERM,
        .code = LB_SI_QUEUE,
        .pid = lc_kernel_get_process_id(),
        .uid = (uint32_t)lc_kernel_getuid(),
        .value = seconds,
    };
    lc_sysret rc = lb_sys_pidfd_send_signal(pidfd, SIGTERM, &info, 0);
    if (rc < 0 && rc != -LB_ESRCH)
        rc = lb_sys_pidfd_send_signal(pidfd, SIGTERM, NULL, 0);   /* without the value, then */
    return rc >= 0;
}

static void stop_one(const char *name, int seconds) {
    require_root("stop");
    container_lock(name);

    if (!is_running(name)) {
        (void)reconcile(name);      /* one that ended without a stop is cleared away here */
        die2("Error: container is not running: ", name);
    }

    /* A descriptor for init, taken before looking once more whether the
     * record is init's: from here on it is that process and no other,
     * whatever becomes of the number. It reads as ready when init has ended. */
    int pid = get_container_pid(name);
    lc_sysret pidfd = lb_sys_pidfd_open(pid, 0);
    if (pidfd < 0 || !is_running(name)) {
        if (pidfd >= 0)
            lc_kernel_close_file((int32_t)pidfd);
        (void)reconcile(name);
        die2("Error: container is not running: ", name);
    }

    print_str(STDOUT,"Stopping container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");
    set_container_state(name, "stopping\n");

    /* Init passes the SIGTERM on to everything in the container and exits
     * when it has all ended, or after the seconds it was given. Only if it
     * is still there after that, and a margin, is it killed. */
    bool ended = !ask_init_to_stop((int32_t)pidfd, seconds) ||
                 readable_within((int32_t)pidfd, (int64_t)seconds * 1000 + STOP_MARGIN_MS);
    if (!ended) {
        print_str(STDERR, "Warning: the container's init did not stop when asked; killing it\n");
        lb_sys_pidfd_send_signal((int32_t)pidfd, SIGKILL, NULL, 0);
        ended = readable_within((int32_t)pidfd, CGROUP_EMPTY_MS);
    }
    lc_kernel_close_file((int32_t)pidfd);

    bool clean = ended;
    if (!ended)
        print_str(STDERR, "Error: the container's init is still there\n");

    /* what is still in its cgroup, the cgroup, its rules and its interface */
    if (!release_container(name))
        clean = false;

    /* with no runtime record it is stopped */
    container_forget_run(name);

    if (!clean) {
        print_str(STDERR, "Error: container '");
        print_str(STDERR, name);
        print_str(STDERR, "' is stopped, but not everything of it could be removed\n");
        lc_kernel_exit(1);
    }
    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' stopped\n");
}

static void cmd_stop(int argc, char **argv) {
    /* how long each container gets to end by itself */
    int seconds = cfg_global.stop_timeout;
    int count = names_and_seconds(argc, argv, &seconds);
    if (count == 0)
        die("Usage: lightbox stop <name>... [-t <seconds>]");
    require_root("stop");
    each_container("not stopped", count, argv, stop_one, seconds);
}

static void cmd_add_vol(int argc, char **argv) {
    if (argc < 2) die("Usage: lightbox add-vol <name> <src:dst[:ro]>");
    if (argc > 2) die2("Error: unexpected argument: ", argv[2]);
    const char *name = argv[0];
    validate_name(name);

    volume_spec vol = {0};
    parse_volume_spec_or_die(argv[1], &vol);

    /* read, add and write back as one step: a second add-vol waits for it */
    container_lock(name);

    if (!path_exists(vol.src))
        die2("Error: volume source does not exist: ", vol.src);

    static container_config config;
    container_config_load_or_die(name, &config);

    /* the same volume again is nothing to do, and no error */
    int at = config_volume_at(&config, vol.dst);
    if (at >= 0 && streq(config.vols[at].src, vol.src) && config.vols[at].ro == vol.ro) {
        print_str(STDOUT, "Volume already present for container '");
        print_str(STDOUT, name);
        print_str(STDOUT, "'\n");
        return;
    }

    const char *wrong = config_add_volume(&config, &vol);
    if (!wrong)
        wrong = container_config_save(name, &config);
    if (wrong)
        die_about("Error: container ", wrong, name);

    print_str(STDOUT, "Added volume to container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "': ");
    print_str(STDOUT, vol.src);
    print_str(STDOUT, " -> ");
    print_str(STDOUT, vol.dst);
    if (vol.ro)
        print_str(STDOUT, " (ro)");
    lc_print_char(STDOUT, '\n');

    if (is_running(name)) {
        print_str(STDOUT, "Restart the container for the new volume to take effect\n");
    }
}

/*
 * rm-vol <name> <dst>: take the volume at a destination out of a container's
 * configuration. The destination is given as it is in the container, and is
 * read as a volume's destination is, so /data/ and /data are the same place.
 */
static void cmd_rm_vol(int argc, char **argv) {
    if (argc < 2) die("Usage: lightbox rm-vol <name> <dst>");
    if (argc > 2) die2("Error: unexpected argument: ", argv[2]);
    const char *name = argv[0];
    validate_name(name);

    char dst[MAX_PATH];
    const char *wrong = parse_volume_destination(argv[1], dst);
    if (wrong)
        die_about("Error: ", wrong, argv[1]);

    container_lock(name);

    static container_config config;
    container_config_load_or_die(name, &config);
    if (config_remove_volumes_at(&config, dst) == 0)
        die_about("Error: container ", "has no volume at that destination", name);

    wrong = container_config_save(name, &config);
    if (wrong)
        die_about("Error: container ", wrong, name);

    print_str(STDOUT, "Removed the volume at ");
    print_str(STDOUT, dst);
    print_str(STDOUT, " from container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "'\n");

    if (is_running(name))
        print_str(STDOUT, "It stays mounted until the container is restarted\n");
}

/* ─── cmd_rm ────────────────────────────────────────────────────────────── */

static void rm_one(const char *name, int unused) {
    (void)unused;
    container_lock(name);

    if (is_running(name)) die2("Error: container is running (stop it first): ", name);

    /* one that ended without a stop still has a cgroup and firewall rules:
     * cleared away, and the rules of a command that was cut short with them */
    (void)reconcile(name);
    if (firewall_remove_links(name) != 0)
        die2("Error: the container is not removed while the firewall rules of its links are there: ", name);

    char cdir[MAX_PATH];
    container_dir_path(cdir, name);

    print_str(STDOUT,"Removing container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    (void)cgroup_destroy(name);

    /* remove entire container directory (rootfs + metadata) */
    require_rm_rf(cdir);
    container_forget_run(name);

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' removed\n");
}

static void cmd_rm(int argc, char **argv) {
    require_tool("rm", tool_path_rm());
    int count = names_and_seconds(argc, argv, NULL);
    if (count == 0)
        die("Usage: lightbox rm <name>...");
    each_container("not removed", count, argv, rm_one, 0);
}

/* ─── cmd_exec ──────────────────────────────────────────────────────────── */

/* The caller's TERM goes with the command, when it is a plain name. */
static void request_term(struct exec_request *req) {
    const char *term = env_get(caller_env, "TERM");
    if (term && term_is_plain(term))
        req->term = term;
}

static void cmd_exec(int argc, char **argv) {
    if (argc < 1)
        die("Usage: lightbox exec <name> [--user <name|uid[:gid]>] [--env KEY=VALUE]... [--workdir <dir>] [--] [cmd [args...]]");
    const char *name = argv[0];
    validate_name(name);

    run_sealed();

    static const char *const shell[] = { "/bin/sh", NULL };
    struct exec_request req = { .as = AS_ROOT, .gid = -1 };
    int command = parse_exec_options(argc, argv, 1, &req);
    /* the kernel ends argv with a NULL, so the command's words are passed on
     * as they are, however many */
    req.argv = command < argc ? (const char *const *)(uintptr_t)(argv + command) : shell;
    request_term(&req);

    require_root("exec");

    if (!is_running(name)) die2("Error: container is not running: ", name);

    /* what the command may do in the container is what the container may:
     * without its configuration, nothing is run in it */
    static container_config config;
    container_config_load_or_die(name, &config);
    int pid = get_container_pid(name);
    bool userns = config.userns;
    bool privileged = config.privileged;

    if (userns)
        die("Error: exec into userns containers is not supported yet");

    /* The terminal's modes as they are now. The worker makes the terminal
     * raw while a command has a terminal of its own, and puts the modes back;
     * this process puts them back as well, because the worker is in the
     * container's cgroup and ends without a word when the container is
     * stopped. */
    struct lb_termios modes;
    bool restore = lc_kernel_device_control(STDIN, LB_TCGETS, &modes) >= 0;

    int32_t signal_fd = hold_relay_signals();
    if (signal_fd < 0)
        die("Error: failed to take over the signals of an exec");

    lc_sysret worker = lc_kernel_fork();
    if (worker < 0)
        die("Error: failed to fork exec worker");

    if (worker == 0) {
        lc_kernel_close_file(signal_fd);
        int status = exec_inside_container(name, pid, userns, privileged, config.oom_score, &req);
        lc_kernel_exit(exit_code_from_status(status));
    }

    lc_kernel_exit(finish_exec((int32_t)worker, signal_fd, restore ? &modes : NULL));
}

/* ─── cmd_ls ────────────────────────────────────────────────────────────── */

/* ─── setup --teardown ──────────────────────────────────────────────────── */

/*
 * setup --teardown: what setup made taken away, once no container runs.
 * With the store's lock nothing is created, set up or made again by a start
 * meanwhile; a container that a command is working on, or that runs, ends
 * it. What a container that ended without a stop left is cleared away first.
 */
static void cmd_teardown(void) {
    require_root("setup --teardown");
    require_tool("ip", tool_path_ip());
    (void)store_lock();

    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    bool more = false;
    int count = list_containers(names, MAX_LISTED, &more);
    if (more)
        die("Error: there are more containers than setup --teardown can look at");
    int busy = 0;
    for (int i = 0; i < count; i++) {
        int32_t lock = container_lock_try(names[i]);
        bool running = lock < 0 || is_running(names[i]);
        if (running) {
            print_str(STDERR, lock < 0 ? "Error: a lightbox command is working on container '"
                                       : "Error: container '");
            print_str(STDERR, names[i]);
            print_str(STDERR, lock < 0 ? "'\n" : "' is running\n");
            busy++;
        } else {
            (void)reconcile(names[i]);
        }
        if (lock >= 0)
            lc_kernel_close_file(lock);
    }
    if (busy)
        die("Error: setup --teardown takes lightbox's host network away only when no container runs");
    teardown_host();
    lc_kernel_exit(0);
}

/* ─── Usage ─────────────────────────────────────────────────────────────── */

/* Each command's lines of the usage, as `lightbox <command> --help` prints them. */
static const struct { const char *name; const char *text; } command_help[] = {
    { "create",
        "  create <name> [<ip>] [options]\n"
        "                                Create a new container; without <ip>, the lowest free address\n"
        "         --mem  <limit>         Memory limit: <number>[K|M|G|T] or max (default: 256M)\n"
        "         --swap <limit>         Swap it may use: 0, <number>[K|M|G|T] or max (default: 0)\n"
        "         --pids <limit>         Max processes, or max (default: 128)\n"
        "         --cpu  <num>           CPUs, such as 2 or 0.5 (default: 1)\n"
        "         --io-max <limit>       I/O limit for one disk: \"8:0 wbps=10485760\", with rbps, wbps,\n"
        "                                riops or wiops (default: none)\n"
        "         --vol  <src:dst[:ro]>  Bind mount (repeatable)\n"
        "         --rootfs <path>         Base rootfs to copy (default: $LIGHTBOX_ROOTFS or lightbox.conf)\n"
        "         --userns               Future improvement; not supported yet\n"
        "         --uid-start <n>        Future improvement; not supported yet\n"
        "         --read-only            Read-only root filesystem\n"
        "         --privileged           Disable security sandbox\n"
        "         --oom-score <n>        OOM score adjustment (default: 500)\n"
        "         --link <name>          Allow network to another container\n"
        "         --dns <address>        A name server for the container (up to 3; default: the host's)\n" },
    { "start",
        "  start  <name>... [-t <seconds>]  Start stopped containers, one after the other\n"
        "         -t <seconds>            How long to wait for /init.sh (default: 30, 0: do not wait)\n" },
    { "stop",
        "  stop   <name>... [-t <seconds>]  Stop running containers, one after the other\n"
        "         -t <seconds>            How long their processes get to end (default: 10)\n" },
    { "add-vol",
        "  add-vol <name> <src:dst[:ro]> Add a volume to an existing container\n" },
    { "rm-vol",
        "  rm-vol <name> <dst>           Remove the volume at a destination\n" },
    { "rm",
        "  rm     <name>...              Remove containers (they must be stopped)\n" },
    { "exec",
        "  exec   <name> [options] [--] [cmd [args...]]  Run a command in a running container\n"
        "         --user <name|uid[:gid]> Who to run it as (default: root)\n"
        "         --env <KEY=VALUE>       Set a variable in its environment (repeatable)\n"
        "         --workdir <dir>         The directory to run it in (default: /)\n" },
    { "logs",
        "  logs   <name> [-f]            Show what the container has printed; -f follows it\n" },
    { "inspect",
        "  inspect <name>                Show container metadata and runtime state\n" },
    { "doctor",
        "  doctor                        Show host/runtime dependency status\n" },
    { "ls",
        "  ls [--json]                   List all containers\n" },
    { "setup",
        "  setup                         Setup host networking\n"
        "  setup --teardown              Take lightbox's host network away, when no container runs\n" },
};
#define COMMANDS (sizeof(command_help) / sizeof(command_help[0]))

static const char *help_of(const char *command) {
    for (size_t i = 0; i < COMMANDS; i++)
        if (streq(command_help[i].name, command))
            return command_help[i].text;
    return NULL;
}

static bool asks_for_help(const char *arg) {
    return streq(arg, "--help") || streq(arg, "-h");
}

/* The usage: of one command, or of all of them. */
static void print_usage(int32_t fd, const char *command) {
    print_str(fd, "Usage: lightbox [--config <path>] <command> [args]\n\n");
    if (command) {
        print_str(fd, help_of(command));
        return;
    }
    print_str(fd, "Commands:\n");
    for (size_t i = 0; i < COMMANDS; i++)
        print_str(fd, command_help[i].text);
    print_str(fd,
        "\n"
        "  --config <path>                              The lightbox.conf to read (default:\n"
        "                                               $LIGHTBOX_CONFIG, else " CONFIG_ETC_FILE ")\n"
        "  --help, help [<command>], <command> --help   This text, or a command's part of it\n"
        "  --version                                    The version of lightbox, and of lightc\n");
}

/* Help that was asked for: on standard output, and no error. */
[[noreturn]] static void help(const char *command) {
    print_usage(STDOUT, command);
    lc_kernel_exit(0);
}

/* A command line that is not one: the usage on standard error, and an error. */
[[noreturn]] static void usage(void) {
    print_usage(STDERR, NULL);
    lc_kernel_exit(1);
}

[[noreturn]] static void version(void) {
    char number[16];
    print_str(STDOUT, "lightbox " LIGHTBOX_VERSION " (lightc ");
    fmt_int(number, LC_VERSION_MAJOR);
    print_str(STDOUT, number);
    lc_print_char(STDOUT, '.');
    fmt_int(number, LC_VERSION_MINOR);
    print_str(STDOUT, number);
    lc_print_char(STDOUT, '.');
    fmt_int(number, LC_VERSION_PATCH);
    print_str(STDOUT, number);
    print_str(STDOUT, ")\n");
    lc_kernel_exit(0);
}

/* ─── main ──────────────────────────────────────────────────────────────── */

/*
 * A descriptor that lightbox opens must never be 0, 1 or 2: a message would
 * be written into whatever file that was, and a container would get it as a
 * standard stream. A caller can leave any of the three closed, so fill what
 * is missing with /dev/null before anything else is opened.
 */
static void reserve_standard_streams(void) {
    for (;;) {
        lc_sysret fd = lc_kernel_open_file("/dev/null", O_RDWR, 0);
        if (fd < 0)
            return;
        if (fd > STDERR) {
            lc_kernel_close_file((int32_t)fd);
            return;
        }
    }
}

int main(int argc, char **argv, char **envp) {
    reserve_standard_streams();
    caller_argv = argv;
    caller_env = envp;

    /* lightbox [--config <path>] <command> [args] */
    const char *config = NULL;
    int first = 1;
    if (argc > 1 && streq(argv[1], "--config")) {
        if (argc < 3 || !argv[2][0])
            die("Error: --config needs the path of a lightbox.conf");
        config = argv[2];
        first = 3;
    }
    if (argc <= first) usage();
    char **args = argv + first;
    int nargs = argc - first;

    /* help and the version need no configuration, and get none of its warnings */
    if (asks_for_help(args[0]) || streq(args[0], "help")) {
        if (nargs == 1)
            help(NULL);
        if (nargs == 2 && help_of(args[1]))
            help(args[1]);
        die2(nargs == 2 ? "Error: there is no such command: " : "Error: unexpected argument: ", args[nargs == 2 ? 1 : 2]);
    }
    if (streq(args[0], "--version")) {
        if (nargs > 1)
            die2("Error: unexpected argument: ", args[1]);
        version();
    }
    if (nargs > 1 && asks_for_help(args[1]) && help_of(args[0]))
        help(args[0]);

    /* load configuration: built-in defaults → lightbox.conf → env vars */
    cfg_global_init();
    cfg_global_load(envp, config);

    const char *cmd = args[0];
    int sub_argc = nargs - 1;
    char **sub_argv = args + 1;

    if (streq(cmd, "setup")) {
        if (sub_argc == 0)
            cmd_setup();
        else if (sub_argc == 1 && streq(sub_argv[0], "--teardown"))
            cmd_teardown();
        else
            die("Usage: lightbox setup [--teardown]");
    }
    else if (streq(cmd, "create")) cmd_create(sub_argc, sub_argv);
    else if (streq(cmd, "start"))  cmd_start(sub_argc, sub_argv);
    else if (streq(cmd, "stop"))   cmd_stop(sub_argc, sub_argv);
    else if (streq(cmd, "add-vol")) cmd_add_vol(sub_argc, sub_argv);
    else if (streq(cmd, "rm-vol")) cmd_rm_vol(sub_argc, sub_argv);
    else if (streq(cmd, "rm"))     cmd_rm(sub_argc, sub_argv);
    else if (streq(cmd, "exec"))   cmd_exec(sub_argc, sub_argv);
    else if (streq(cmd, "logs"))   cmd_logs(sub_argc, sub_argv);
    else if (streq(cmd, "inspect")) cmd_inspect(sub_argc, sub_argv);
    else if (streq(cmd, "doctor")) {
        if (sub_argc > 0)
            die2(sub_argv[0][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", sub_argv[0]);
        cmd_doctor();
    }
    else if (streq(cmd, "ls"))     cmd_ls(sub_argc, sub_argv);
    else {
        print_str(STDERR, "Error: unknown command: ");
        print_str(STDERR, cmd);
        print_str(STDERR, "\n\n");
        usage();
    }

    return 0;
}
