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
#include "lightbox_devices.h"

/* ─── Compile-time limits ───────────────────────────────────────────────── */

#define MAX_PATH         512
#define CHILD_STACK_SIZE (1024 * 1024) /* 1 MiB */

/* ─── Configurable defaults ─────────────────────────────────────────────── */

/* All runtime-configurable values live here. Initialized to built-in defaults,
 * then overridden by lightbox.conf if present. */
global_config cfg_global;

/* cfg_global_init() and cfg_global_load() defined after utility functions */

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
        lc_kernel_exit(failure_status);
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
/* What cpu.max is given for a CPU limit: "<quota> <period>". */
static bool cpu_max_text(const char *cpu, char *out, size_t max) {
    int quota;
    bool cut = false;
    if (!parse_cpu_limit(cpu, &quota))
        return false;
    size_t len = (size_t)fmt_int(out, quota);
    str_append(out, len, " " STRINGIFY(CPU_PERIOD_US), max, &cut);
    return !cut;
}

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

/*
 * The device program of lightbox_devices.h, attached to a container's cgroup
 * before init is in it (ROADMAP 8.4). Its processes then open the devices of
 * its /dev and no other, wherever a node of another is, and make none. A
 * program attached so is the cgroup's until the cgroup is removed, and no
 * cgroup below it may have another. NULL, or what failed: a container that
 * is not privileged does not start without it.
 */
static const char *device_filter_attach(const char *cg) {
    static char err[200], log[4096];
    lc_sysret prog = device_program_load(log, sizeof(log));
    if (prog < 0) {
        if (log[0]) {
            print_str(STDERR, "The kernel's verifier said of the device program:\n");
            print_str(STDERR, log);
        }
        return text_with_number(err, sizeof(err), "the kernel did not load the device program (errno ",
                                (int)-prog, "); doctor says whether it can");
    }
    lc_sysret cgfd = lc_kernel_open_file(cg, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (cgfd < 0) {
        lc_kernel_close_file((int32_t)prog);
        return text_with_number(err, sizeof(err), "cannot open the container's cgroup for its device program (errno ",
                                (int)-cgfd, ")");
    }
    struct lb_bpf_prog_attach attach = {
        .target_fd = (uint32_t)cgfd,
        .attach_bpf_fd = (uint32_t)prog,
        .attach_type = LB_BPF_CGROUP_DEVICE,
        .attach_flags = 0,
    };
    lc_sysret rc = lb_sys_bpf(LB_BPF_PROG_ATTACH, &attach, sizeof(attach));
    lc_kernel_close_file((int32_t)cgfd);
    lc_kernel_close_file((int32_t)prog);
    if (rc < 0)
        return text_with_number(err, sizeof(err),
                                "the kernel did not attach the device program to the container's cgroup (errno ",
                                (int)-rc, ")");
    return NULL;
}

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
    char cpu_max[32];
    if (!cpu_max_text(config->cpu, cpu_max, sizeof(cpu_max)))
        return "the container's CPU limit is not one";
    if (cgroup_write(cg, "cpu.max", cpu_max) < 0)
        return "failed to set the CPU limit";

    if (config->io[0] && cgroup_write(cg, "io.max", config->io) < 0)
        return "failed to set the I/O limit; the kernel takes one for a disk that is there, and not for a partition";

    /* the devices it may open, before anything of it runs in the cgroup */
    if (!config->privileged) {
        const char *failed = device_filter_attach(cg);
        if (failed)
            return failed;
    }

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
static int each_listed_pid_in(int32_t fd, void (*fn)(int pid));

static int each_listed_pid(const char *procs_path, void (*fn)(int pid)) {
    lc_sysret fd = lc_kernel_open_file(procs_path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int count = each_listed_pid_in((int32_t)fd, fn);
    lc_kernel_close_file((int32_t)fd);
    return count;
}

/* The same, from the start of a cgroup.procs that is open: read again from
 * its beginning every time. The descriptor stays open. */
static int each_listed_pid_in(int32_t fd, void (*fn)(int pid)) {
    if (lc_kernel_seek_position(fd, 0, SEEK_SET) < 0)
        return -1;

    char buf[4096];
    int count = 0;
    int64_t pid = 0;
    bool in_number = false;
    for (;;) {
        lc_sysret n = lc_kernel_read_retry(fd, buf, sizeof(buf));
        if (n < 0)
            return -1;
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
 * How deep below a container's cgroup there are cgroups to take away. Its
 * processes cannot reach cgroupfs, so there are only those of its execs, one
 * level down; a privileged container could make more of its own.
 */
#define CGROUP_DEPTH_MAX 4

/* struct linux_dirent64, as getdents64 fills a buffer with it */
#define CG_DIRENT_RECLEN 16     /* uint16_t */
#define CG_DIRENT_TYPE   18     /* uint8_t; cgroupfs always gives it */
#define CG_DIRENT_NAME   19
#define CG_DIRENT_DIR    4      /* DT_DIR */

/*
 * fn(path, entry) for every cgroup below cg, to depth levels, each after the
 * ones below it, and not for cg itself.
 */
static void each_cgroup_below(const char *cg, int depth, void (*fn)(const char *path, const char *entry)) {
    if (depth <= 0)
        return;
    lc_sysret fd = lc_kernel_open_file(cg, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return;
    char buf[1024];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        for (lc_sysret pos = 0; pos < n; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + CG_DIRENT_RECLEN, sizeof(reclen));
            if (reclen == 0)
                break;
            uint8_t type = (uint8_t)buf[pos + CG_DIRENT_TYPE];
            const char *entry = buf + pos + CG_DIRENT_NAME;
            pos += reclen;
            bool dot = entry[0] == '.' && (entry[1] == '\0' || (entry[1] == '.' && entry[2] == '\0'));
            char path[MAX_PATH];
            if (dot || type != CG_DIRENT_DIR || !path_join(path, sizeof(path), cg, entry))
                continue;
            each_cgroup_below(path, depth - 1, fn);
            fn(path, entry);
        }
    }
    lc_kernel_close_file((int32_t)fd);
}

static void kill_listed_in(const char *path, const char *entry) {
    (void)entry;
    char procs[MAX_PATH];
    if (path_join(procs, sizeof(procs), path, "cgroup.procs"))
        (void)each_listed_pid(procs, kill_pid);
}

static void remove_cgroup_dir(const char *path, const char *entry) {
    (void)entry;
    (void)lc_kernel_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

/*
 * End everything in a cgroup and the cgroups below it once: cgroup.kill
 * (Linux 5.14) ends it all at once, including what is forked while it does,
 * and without it, what the lists show is killed. True when cgroup.kill did.
 */
static bool cgroup_kill_all(const char *cg) {
    if (cgroup_write(cg, "cgroup.kill", "1") == 0)
        return true;
    char procs[MAX_PATH];
    if (path_join(procs, sizeof(procs), cg, "cgroup.procs"))
        (void)each_listed_pid(procs, kill_pid);
    each_cgroup_below(cg, CGROUP_DEPTH_MAX, kill_listed_in);
    return false;
}

/*
 * End everything in a cgroup and below it, and wait until the kernel says
 * that nothing is left, or until the deadline. Without cgroup.kill the lists
 * are killed again and again until they are empty. True when it is empty.
 */
static bool cgroup_end_all(const char *cg, int64_t deadline) {
    bool at_once = cgroup_kill_all(cg);
    while (!cgroup_is_empty(cg) && monotonic_ms() < deadline) {
        sleep_ms(10);
        if (!at_once)
            (void)cgroup_kill_all(cg);
    }
    return cgroup_is_empty(cg);
}

/*
 * Remove an empty cgroup with the cgroups below it, those first: the result
 * of the last rmdir. EBUSY is retried until the deadline: the last process
 * can be gone before the kernel has finished with it, and an exec that began
 * as the container was being stopped can have made a cgroup meanwhile.
 */
static lc_sysret cgroup_remove_all(const char *cg, int64_t deadline) {
    for (;;) {
        each_cgroup_below(cg, CGROUP_DEPTH_MAX, remove_cgroup_dir);
        lc_sysret rc = lc_kernel_unlinkat(AT_FDCWD, cg, AT_REMOVEDIR);
        if (rc != -LB_EBUSY || monotonic_ms() >= deadline)
            return rc;
        sleep_ms(10);
        if (!cgroup_is_empty(cg))
            (void)cgroup_kill_all(cg);
    }
}

/*
 * Remove a container's cgroup: kill what is left in it and in the cgroups of
 * its execs, wait until the kernel says it is empty, and only then remove
 * the directories, theirs first. 0, or -1 with the reason reported when the
 * container's is still there.
 */
static int cgroup_destroy(const char *name) {
    char cg[MAX_PATH];
    if (!cgroup_path(cg, name)) {
        print_str(STDERR, "Error: the path of the container's cgroup is too long\n");
        return -1;
    }

    if (!path_exists(cg)) return 0;

    int64_t deadline = monotonic_ms() + CGROUP_EMPTY_MS;
    (void)cgroup_end_all(cg, deadline);
    lc_sysret rc = cgroup_remove_all(cg, deadline);
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

/*
 * Every exec runs in a cgroup of its own below the container's (ROADMAP 8.7),
 * made by the process that ran exec: "exec-<pid>-<start time>" of that
 * process, a name no other process has had since boot. The container's
 * limits hold for it, as they hold for everything below, and the container
 * cannot reach cgroupfs to leave it: what the command starts, in the
 * background or in a session of its own, is in it until it ends.
 */
#define EXEC_CGROUP_PREFIX "exec-"

/* Is entry the cgroup of an exec: the PID and the start time of its own? */
static bool exec_cgroup_owner(const char *entry, int *pid, const char **started) {
    size_t prefix = lc_string_length(EXEC_CGROUP_PREFIX);
    if (!lc_string_starts_with(entry, lc_string_length(entry), EXEC_CGROUP_PREFIX, prefix))
        return false;
    const char *p = entry + prefix;
    int64_t value = 0;
    size_t digits = 0;
    for (; p[digits] >= '0' && p[digits] <= '9'; digits++) {
        value = value * 10 + (p[digits] - '0');
        if (value > INT32_MAX)
            return false;
    }
    if (digits == 0 || value == 0 || p[digits] != '-' || p[digits + 1] == '\0')
        return false;
    for (const char *t = p + digits + 1; *t; t++)
        if (*t < '0' || *t > '9')
            return false;
    *pid = (int)value;
    *started = p + digits + 1;
    return true;
}

/* An exec's cgroup that is left when its exec is over: removed when nothing
 * is in it. One whose exec is still running is left alone, as it can be
 * there before anything has joined it. */
static void remove_exec_cgroup_left(const char *path, const char *entry) {
    int pid;
    const char *started;
    if (!exec_cgroup_owner(entry, &pid, &started))
        return;
    char now[32];
    if (proc_starttime(pid, now, sizeof(now)) == 0 && streq(now, started))
        return;
    (void)lc_kernel_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);     /* EBUSY while something is in it */
}

/* Make this process's exec cgroup below the container's: its path in cg. */
static void exec_cgroup_make(const char *name, char cg[MAX_PATH]) {
    char container_cg[MAX_PATH], self[16], started[32], entry[64];
    int pid = lc_kernel_get_process_id();
    fmt_int(self, pid);
    if (proc_starttime(pid, started, sizeof(started)) < 0)
        die("Error: cannot read the start time of this process for the cgroup of the exec");
    bool cut = false;
    size_t at = str_append(entry, 0, EXEC_CGROUP_PREFIX, sizeof(entry), &cut);
    at = str_append(entry, at, self, sizeof(entry), &cut);
    at = str_append(entry, at, "-", sizeof(entry), &cut);
    (void)str_append(entry, at, started, sizeof(entry), &cut);
    if (cut || !cgroup_path(container_cg, name) || !path_join(cg, MAX_PATH, container_cg, entry))
        die("Error: the path of the exec's cgroup is too long");
    lc_sysret rc = lc_kernel_mkdirat(AT_FDCWD, cg, 0755);
    if (rc < 0) {
        char digits[16];
        fmt_int(digits, (int)-rc);
        print_str(STDERR, "Error: cannot make the cgroup of the exec (errno ");
        print_str(STDERR, digits);
        die(")");
    }
}

/*
 * The end of an exec's cgroup, in the process that ran exec once its worker
 * is gone. With a time limit nothing the command started outlives it: what
 * is left is ended. Without one it goes on, and the cgroup stays until it
 * has ended too; it is removed then by a later exec, or by stop. The cgroups
 * that earlier execs left and that are empty now go as well.
 */
static void exec_cgroup_end(const char *name, const char *cg, bool limited) {
    if (limited)
        (void)cgroup_end_all(cg, monotonic_ms() + CGROUP_EMPTY_MS);
    if (cgroup_is_empty(cg))
        (void)cgroup_remove_all(cg, monotonic_ms() + 1000);
    char container_cg[MAX_PATH];
    if (cgroup_path(container_cg, name))
        each_cgroup_below(container_cg, 1, remove_exec_cgroup_left);
}

/* Move this process into a cgroup, the one of its exec. */
static void cgroup_join_self(const char *cg) {
    char pidbuf[16];
    fmt_int(pidbuf, lc_kernel_get_process_id());
    if (cgroup_write(cg, "cgroup.procs", pidbuf) < 0)
        die2("Error: cannot join the cgroup of the exec: ", cg);
}

/* ─── Security: capabilities ────────────────────────────────────────────── */

/* Default non-privileged container capabilities.
 * Deliberately stricter than Docker's historical default:
 * - no CAP_NET_RAW: avoid raw sockets/packet capture by default
 * - no CAP_MKNOD: device node creation is unnecessary with our fixed /dev setup
 * - no CAP_SETFCAP (ROADMAP 8.2): a file capability that a container's root
 *   wrote on a program in a volume would hold on the host, as root's without
 *   --userns, for whoever runs it there. In the container it would give
 *   nothing, as no_new_privs keeps an execve from granting it.
 */
static const int ALLOWED_CAPS[] = {
    LB_CAP_CHOWN, LB_CAP_DAC_OVERRIDE, LB_CAP_FOWNER, LB_CAP_FSETID,
    LB_CAP_KILL, LB_CAP_SETGID, LB_CAP_SETUID, LB_CAP_SETPCAP,
    LB_CAP_NET_BIND_SERVICE, LB_CAP_SYS_CHROOT,
    LB_CAP_AUDIT_WRITE,
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
 * Install a profile of lightbox_seccomp.h for this architecture: the
 * deny-list, or with allow the allow-list (ROADMAP 8.3). Both refuse the x32
 * range on x86_64, clone with namespace flags and a mode with the setuid or
 * setgid bit. The caller has set no_new_privs or holds CAP_SYS_ADMIN.
 */
static void apply_seccomp(bool allow) {
    struct lb_sock_filter filter[LB_SECCOMP_PROG_MAX];
    struct lb_sock_fprog prog = {
        .len = (uint16_t)(allow ? lb_seccomp_build_allow(filter) : lb_seccomp_build(filter)),
        .filter = filter,
    };

    if (prog.len != (allow ? LB_SECCOMP_ALLOW_PROG_LEN : LB_SECCOMP_PROG_LEN))
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
static void apply_sandbox(bool allow_list) {
    drop_capabilities();
    if (lc_kernel_prctl(LB_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("Error: failed to enable no_new_privs");
    apply_seccomp(allow_list);
}

/*
 * What a host tool runs under that is given bytes from somewhere else to
 * read, as gzip is a layer of an image (ROADMAP I.6): a fault in it that
 * such bytes reach is then a fault in a process that can do little.
 *
 *   - a network and an IPC namespace of its own, with nothing in them;
 *   - nobody's uid and gid and no supplementary group, so that no file of
 *     root's is its own;
 *   - no capability, in any set, and none to be had: the bounding set is
 *     emptied and no_new_privs is set;
 *   - the allow-list, as a container has it.
 *
 * In a user namespace that maps no id for nobody, as one that an ordinary
 * user made for a test has none, the ids stay: its root is that user, and
 * the rest is done all the same. Any step that fails ends the process.
 */
#define NOBODY_ID 65534u

void sandbox_host_tool(void) {
    if (lc_kernel_unshare(CLONE_NEWNET | CLONE_NEWIPC) < 0)
        die("Error: cannot give a host tool a network of its own, with nothing in it");
    for (int cap = 0; cap < 64; cap++) {
        lc_sysret held = lc_kernel_prctl(LB_PR_CAPBSET_READ, (uint64_t)cap, 0, 0, 0);
        if (held < 0)
            break;
        if (held == 1 && lc_kernel_prctl(LB_PR_CAPBSET_DROP, (uint64_t)cap, 0, 0, 0) < 0)
            die("Error: failed to drop a capability from a host tool's bounding set");
    }
    /* setgroups is refused in a user namespace that an ordinary user made;
     * the groups there are that user's own */
    lc_sysret rc = lc_kernel_setgroups(0, NULL);
    if (rc < 0 && rc != -LB_EPERM)
        die("Error: failed to drop a host tool's groups");
    rc = lc_kernel_setgid(NOBODY_ID);
    if (rc < 0 && rc != -LB_EINVAL)
        die("Error: failed to make a host tool's group nobody's");
    rc = lc_kernel_setuid(NOBODY_ID);
    if (rc < 0 && rc != -LB_EINVAL)
        die("Error: failed to make a host tool's user nobody");

    struct lb_cap_header hdr = { LB_CAPABILITY_VERSION_3, 0 };
    struct lb_cap_data sets[LB_CAPABILITY_WORDS] = { 0 };
    if (lb_sys_capset(&hdr, sets) < 0)
        die("Error: failed to empty a host tool's capability sets");
    if (lc_kernel_prctl(LB_PR_CAP_AMBIENT, LB_PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
        die("Error: failed to clear a host tool's ambient capability set");
    if (lc_kernel_prctl(LB_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("Error: failed to enable no_new_privs for a host tool");
    apply_seccomp(true);
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
        lc_kernel_exit(failure_status);
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
    lc_kernel_exit(failure_status);
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
    lc_kernel_exit(failure_status);
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
            lc_kernel_exit(failure_status);
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

/*
 * --mem, --pids and --cpu, as create and update take them: the value checked
 * and put in the configuration, or the option named with what it takes.
 * False for any other option.
 */
static bool limit_option(int argc, char **argv, int *i, container_config *cfg) {
    const char *opt = argv[*i];
    if (streq(opt, "--mem")) {
        const char *value = option_value(argc, argv, i);
        if (!mem_limit_ok(value) || !str_copy(cfg->mem, value, sizeof(cfg->mem)))
            die2("Error: --mem takes <number>[K|M|G|T] or max, not: ", value);
    } else if (streq(opt, "--pids")) {
        const char *value = option_value(argc, argv, i);
        if (!pids_limit_ok(value) || !str_copy(cfg->pids, value, sizeof(cfg->pids)))
            die2("Error: --pids takes a number from 1 to " STRINGIFY(PIDS_LIMIT_MAX) " or max, not: ", value);
    } else if (streq(opt, "--cpu")) {
        const char *value = option_value(argc, argv, i);
        int quota;
        if (!parse_cpu_limit(value, &quota) || !str_copy(cfg->cpu, value, sizeof(cfg->cpu)))
            die2("Error: --cpu takes a number of CPUs from 0.01 to " STRINGIFY(CPU_LIMIT_MAX)
                 ", such as 2 or 0.5, not: ", value);
    } else {
        return false;
    }
    return true;
}

/*
 * The container's name and how it finds names: resolv.conf, its hostname,
 * and its own name added to the image's hosts. These go into the image as
 * the container will see it, with root as its root, so a link in the image,
 * of etc or of any of the three files, cannot put them anywhere else. NULL,
 * or what failed.
 */
/* A hosts file's text without the lines create wrote for a container of one
 * of two names, "<address>\t<name>": its new length. */
static size_t without_own_lines(char *text, size_t len, const char *name, const char *former) {
    size_t kept = 0;
    for (size_t at = 0; at < len; ) {
        size_t end = at;
        while (end < len && text[end] != '\n')
            end++;
        size_t next = end < len ? end + 1 : end;
        /* the line as two fields with one tab between them */
        char address[IPV4_TEXT_MAX], who[NAME_MAX_LEN + 1];
        size_t tab = at;
        while (tab < end && text[tab] != '\t')
            tab++;
        uint32_t parsed;
        bool own = false;
        if (tab < end && tab - at < sizeof(address) && end - tab - 1 < sizeof(who)) {
            lc_bytes_copy(address, text + at, tab - at);
            address[tab - at] = '\0';
            lc_bytes_copy(who, text + tab + 1, end - tab - 1);
            who[end - tab - 1] = '\0';
            own = parse_ipv4(address, &parsed) && (streq(who, name) || (former[0] && streq(who, former)));
        }
        if (!own) {
            lc_bytes_move(text + kept, text + at, next - at);
            kept += next - at;
        }
        at = next;
    }
    text[kept] = '\0';
    return kept;
}

/* former: with import, what the container was called where its image was
 * made, or "" for an image that does not say; the lines create wrote there
 * for that name and for this one are not kept beside the new one. NULL:
 * the hosts file is the base's, and is added to as it is. */
static const char *write_etc_files(const char *root, const char *name, const char *ip, const char *resolv,
                                   const char *former) {
    char text[4096];
    bool cut = false;
    /* inside the container's own filesystem, so readable by its users */
    if (write_file_in_root(root, "etc", "resolv.conf", resolv, MODE_PUBLIC_FILE) < 0)
        return "failed to write resolv.conf";
    size_t pos = str_append(text, 0, name, sizeof(text), &cut);
    str_append(text, pos, "\n", sizeof(text), &cut);
    if (cut || write_file_in_root(root, "etc", "hostname", text, MODE_PUBLIC_FILE) < 0)
        return "failed to write the container's hostname file";

    /* the image's hosts file, with the container's name added to it */
    int had = read_file_in_root(root, "etc", "hosts", text, sizeof(text) - 64);
    if (had < 0) {
        print_str(STDERR, "Warning: the image's /etc/hosts is not a file that can be added to; it is left as it is\n");
        return NULL;
    }
    pos = (size_t)had;
    if (former)
        pos = without_own_lines(text, pos, name, former);
    if (pos == 0)
        pos = str_append(text, pos, "127.0.0.1\tlocalhost\n", sizeof(text), &cut);
    else if (text[pos - 1] != '\n')
        pos = str_append(text, pos, "\n", sizeof(text), &cut);
    /* a container of --net none has no address: its name is a loopback one */
    pos = str_append(text, pos, ip[0] ? ip : "127.0.1.1", sizeof(text), &cut);
    pos = str_append(text, pos, "\t", sizeof(text), &cut);
    pos = str_append(text, pos, name, sizeof(text), &cut);
    str_append(text, pos, "\n", sizeof(text), &cut);
    if (cut || write_file_in_root(root, "etc", "hosts", text, MODE_PUBLIC_FILE) < 0)
        return "failed to write the container's hosts file";
    return NULL;
}

/* <container_dir>/<name>/.work and .merged: the overlay's work directory,
 * and where it is mounted in the container's mount namespace */
static bool overlay_dirs(const char *name, char work[MAX_PATH], char merged[MAX_PATH]) {
    char cdir[MAX_PATH];
    container_dir_path(cdir, name);
    return path_join(work, MAX_PATH, cdir, ".work") && path_join(merged, MAX_PATH, cdir, ".merged");
}

#define OVERLAY_CANNOT_MOUNT 3

static void say_with_number(const char *before, int number, const char *after);

/* What in_overlay does: the overlay of these options mounted at merged; for
 * a container with --userns, its lower layer first replaced by an idmapped
 * mount of itself, and the files written as the container's root on the
 * host; then what write_etc_files writes, unless name is NULL. */
struct overlay_job {
    const char *merged;
    const char *options;
    const char *lower;                  /* the layer to idmap; NULL: none */
    uint32_t    uid_start, gid_start;
    const char *name, *ip, *resolv;
    const char *former;                 /* as write_etc_files takes it */
};

/* In a child, with a mount namespace of its own. 0, OVERLAY_CANNOT_MOUNT as
 * said, or 1 as said: a container with --userns has no copy to fall back on. */
static int in_overlay(const struct overlay_job *job);

/* "Error: <before><step>, errno <n><after>" */
static void say_failed_step(const char *before, const char *step, int rc, const char *after) {
    char digits[16];
    fmt_int(digits, -rc);
    print_str(STDERR, "Error: ");
    print_str(STDERR, before);
    print_str(STDERR, step);
    print_str(STDERR, ", errno ");
    print_str(STDERR, digits);
    print_str(STDERR, after);
}

/* An idmapped copy of the mount at path put over path itself, in this
 * process's mount namespace, with the ids of a container's range. 0, or -1
 * as said. */
static int idmap_in_place(const char *path, uint32_t uid_start, uint32_t gid_start, bool privileged) {
    int ns = userns_fd_with(uid_start, gid_start);
    if (ns < 0) {
        say_failed_step("cannot make a user namespace for the container's ids (", "unshare", ns, ")\n");
        return -1;
    }
    const char *step = "";
    int tree = idmapped_tree(path, ns, privileged, &step);
    lc_kernel_close_file(ns);
    int rc = tree < 0 ? tree : attach_tree(tree, path);
    if (tree >= 0)
        lc_kernel_close_file(tree);
    if (rc < 0) {
        say_failed_step("the kernel or the filesystem cannot make an idmapped mount here (", tree < 0 ? step : "move_mount", rc,
                        "): --userns needs Linux 5.12 and a filesystem with idmapped mounts\n");
        print_str(STDERR, "  of: ");
        print_str(STDERR, path);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    return 0;
}

/*
 * Can an overlay with its upper layer where a container's would be be
 * mounted here at all? Tried before a snapshot is taken, with empty layers
 * beside the container's, so that a host without overlayfs, or a command
 * without the right to mount, does not copy the base twice.
 */
static int in_overlay(const struct overlay_job *job) {
    lc_sysret child = lc_kernel_fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        lc_sysret rc = lc_kernel_unshare(CLONE_NEWNS);
        if (rc == 0)
            rc = lc_kernel_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        if (rc == 0 && job->lower && idmap_in_place(job->lower, job->uid_start, job->gid_start, false) != 0)
            lc_kernel_exit(failure_status);
        if (rc == 0)
            rc = lc_kernel_mount("overlay", job->merged, "overlay", MS_NODEV | MS_NOSUID, job->options);
        if (rc < 0 && job->lower) {
            say_with_number("Error: an overlay cannot be put on an idmapped layer here (errno ", (int)-rc,
                            "): that needs Linux 5.19; --copy makes a container with --userns that needs 5.12\n");
            lc_kernel_exit(failure_status);
        }
        if (rc < 0) {
            say_with_number("Note: an overlay cannot be mounted here (errno ", (int)-rc,
                            "): the container is a copy of its base; lightbox doctor says why\n");
            lc_kernel_exit(OVERLAY_CANNOT_MOUNT);
        }
        /* The files of a container with --userns are its root's on the host:
         * written as that uid, which cannot pass the directories of
         * lightbox's above the overlay, so from inside it. */
        if (job->name && lc_kernel_chdir(job->merged) < 0) {
            print_str(STDERR, "Error: cannot enter the container's overlay\n");
            lc_kernel_exit(failure_status);
        }
        if (job->name && job->lower &&
            (lc_kernel_setgroups(0, NULL) < 0 || lc_kernel_setgid(job->gid_start) < 0 || lc_kernel_setuid(job->uid_start) < 0)) {
            print_str(STDERR, "Error: cannot write the container's files as its root\n");
            lc_kernel_exit(failure_status);
        }
        const char *wrong = job->name ? write_etc_files(".", job->name, job->ip, job->resolv, job->former) : NULL;
        if (wrong) {
            print_str(STDERR, "Error: ");
            print_str(STDERR, wrong);
            lc_print_char(STDERR, '\n');
            lc_kernel_exit(failure_status);
        }
        lc_kernel_exit(0);
    }
    int32_t status = 0;
    lc_sysret got;
    do {
        got = lc_kernel_wait_for_child((int32_t)child, &status, 0);
    } while (got == -LB_EINTR);
    return got == child ? exit_code_from_status(status) : 1;
}

static bool overlay_mounts_here(const char *name, const container_config *userns) {
    char cdir[MAX_PATH], lower[MAX_PATH], upper[MAX_PATH], work[MAX_PATH], merged[MAX_PATH], options[4 * MAX_PATH];
    container_dir_path(cdir, name);
    if (!path_join(lower, sizeof(lower), cdir, ".try-lower") || !path_join(upper, sizeof(upper), cdir, ".try-upper") ||
        !path_join(work, sizeof(work), cdir, ".try-work") || !path_join(merged, sizeof(merged), cdir, ".try-root"))
        return false;
    const char *dirs[] = { lower, upper, work, merged };
    bool made = true;
    for (size_t i = 0; i < 4; i++)
        made = made && lc_kernel_mkdirat(AT_FDCWD, dirs[i], MODE_PRIVATE_DIR) == 0;
    bool cut = false;
    size_t pos = str_append(options, 0, "lowerdir=", sizeof(options), &cut);
    pos = str_append(options, pos, lower, sizeof(options), &cut);
    pos = str_append(options, pos, ",upperdir=", sizeof(options), &cut);
    pos = str_append(options, pos, upper, sizeof(options), &cut);
    pos = str_append(options, pos, ",workdir=", sizeof(options), &cut);
    str_append(options, pos, work, sizeof(options), &cut);
    struct overlay_job job = {
        .merged = merged, .options = options,
        .lower = userns ? lower : NULL,
        .uid_start = userns ? userns->uid_start : 0, .gid_start = userns ? userns->gid_start : 0,
    };
    bool mounts = made && !cut && in_overlay(&job) == 0;
    for (size_t i = 0; i < 4; i++)
        if (path_exists(dirs[i]))
            require_rm_rf(dirs[i]);
    return mounts;
}


/*
 * The /etc files of a container that overlays a snapshot, written through
 * the overlay as the container will see it, in a mount namespace of a child
 * of this command's: the kernel copies up what they change, and a link in
 * the image leads where it leads in the container. 0; OVERLAY_CANNOT_MOUNT
 * where no overlay can be mounted here, as said; anything else when the
 * files could not be written, as said.
 */
static int overlay_etc(const char *name, const container_config *cfg, const char *ip, const char *resolv,
                       const char *former) {
    const char *base = cfg->base;
    char upper[MAX_PATH], work[MAX_PATH], merged[MAX_PATH], options[3 * MAX_PATH + 48], lower[MAX_PATH];
    container_root(upper, name);
    if (!overlay_dirs(name, work, merged) || !base_rootfs_path(lower, base))
        return 1;
    /* the upper layer is there already when import unpacked a layer into it */
    lc_sysret made = lc_kernel_mkdirat(AT_FDCWD, upper, 0755);
    if ((made < 0 && !(former && made == -LB_EEXIST)) || lc_kernel_mkdirat(AT_FDCWD, work, MODE_PRIVATE_DIR) < 0 ||
        lc_kernel_mkdirat(AT_FDCWD, merged, MODE_PRIVATE_DIR) < 0)
        return 1;
    /* the root of the merged tree is the upper layer's: the container's root's */
    if (cfg->userns && lc_kernel_fchownat(AT_FDCWD, upper, cfg->uid_start, cfg->gid_start, 0) < 0)
        return 1;
    if (!overlay_options(options, sizeof(options), base, upper, work)) {
        print_str(STDERR, "Note: a path of lightbox's has a comma, a colon or a backslash, which an overlay's\n"
                          "options cannot carry: the container is a copy of its base\n");
        return OVERLAY_CANNOT_MOUNT;
    }
    struct overlay_job job = {
        .merged = merged, .options = options,
        .lower = cfg->userns ? lower : NULL, .uid_start = cfg->uid_start, .gid_start = cfg->gid_start,
        .name = name, .ip = ip, .resolv = resolv, .former = former,
    };
    int code = in_overlay(&job);
    if (code == OVERLAY_CANNOT_MOUNT) {
        /* nothing was written: the copy goes where the upper layer was */
        (void)lc_kernel_unlinkat(AT_FDCWD, merged, AT_REMOVEDIR);
        if (path_exists(work))
            require_rm_rf(work);
    }
    return code;
}

/*
 * What a container asks for names, as create writes it in its resolv.conf:
 * for --net proxy none, as its proxy looks names up; otherwise the ones
 * --dns gave (dns, ndns); or with none given, the ones on record in cfg,
 * which --net outside keeps; or the dns setting; or the ones this host asks,
 * without its own loopback; or two public ones. For --net outside what it
 * asks goes on record in cfg. NULL, or what failed.
 */
#define RESOLV_TEXT_MAX 4096
static const char *make_resolv(container_config *cfg, char dns[MAX_DNS][16], int ndns, char resolv[RESOLV_TEXT_MAX]) {
    if (cfg->net == NET_PROXY) {
        /* none: a lookup of its own could carry data out */
        static const char proxy_resolv[] = "# --net proxy: the proxy looks up names\n";
        lc_bytes_copy(resolv, proxy_resolv, sizeof(proxy_resolv));
        return NULL;
    }
    if (ndns == 0 && cfg->ndns > 0) {
        for (int i = 0; i < cfg->ndns && i < MAX_DNS; i++)
            lc_bytes_copy(dns[i], cfg->dns[i], sizeof(cfg->dns[0]));
        ndns = cfg->ndns < MAX_DNS ? cfg->ndns : MAX_DNS;
    }
    if (ndns == 0 && cfg_global.dns[0]) {
        ndns = name_servers_listed(cfg_global.dns, dns);
        if (ndns <= 0)
            return "the dns setting in lightbox.conf is not a list of up to " STRINGIFY(MAX_DNS) " IPv4 addresses";
    }
    if (ndns == 0)
        ndns = name_servers_of("/etc/resolv.conf", dns);
    if (ndns == 0)      /* behind systemd-resolved's stub, the servers it asks */
        ndns = name_servers_of("/run/systemd/resolve/resolv.conf", dns);
    const char *const public_servers[] = { "1.1.1.1", "8.8.8.8" };
    bool cut = false;
    size_t pos = 0;
    resolv[0] = '\0';
    for (int i = 0; i < (ndns ? ndns : 2); i++) {
        pos = str_append(resolv, pos, "nameserver ", RESOLV_TEXT_MAX, &cut);
        pos = str_append(resolv, pos, ndns ? dns[i] : public_servers[i], RESOLV_TEXT_MAX, &cut);
        pos = str_append(resolv, pos, "\n", RESOLV_TEXT_MAX, &cut);
    }
    if (cut)
        return "the name servers do not fit in resolv.conf";
    /* --net outside lets it ask them, and only them of the addresses it may
     * not reach: on record, as the container may write its own resolv.conf */
    if (cfg->net == NET_OUTSIDE) {
        cfg->ndns = ndns ? ndns : 2;
        for (int i = 0; i < cfg->ndns; i++)
            if (!str_copy(cfg->dns[i], ndns ? dns[i] : public_servers[i], sizeof(cfg->dns[0])))
                return "a name server is too long to be one";
    }
    return NULL;
}

/*
 * create's options that take a value and those that take none, for run,
 * which has to tell them from its command (ROADMAP 8.8). Kept in step with
 * cmd_create's loop: validation gives run every option create --help names.
 */
static const char *const create_value_options[] = {
    "--mem", "--swap", "--pids", "--cpu", "--io-max", "--vol", "--rootfs", "--seccomp", "--net",
    "--oom-score", "--ttl", "--link", "--dns", "--profile", "--workspace",
};
static const char *const create_flag_options[] = { "--userns", "--read-only", "--copy", "--privileged" };

/*
 * --profile agent (ROADMAP 8.10): what this phase built, with one switch. A
 * user namespace, the allow-list filter, an overlay root, and --net none
 * unless --net outside or proxy:<port> is given; the limits and the lifetime
 * that no option gives, from the agent_* settings. What would undo it is
 * refused, by its name; what tightens it further, such as --read-only, is
 * taken. Each setting goes in .conf under its own key, beside profile=agent.
 */
static void agent_profile(container_config *cfg, bool net_given, bool full_copy) {
    if (cfg->privileged)
        die("Error: --profile agent refuses --privileged");
    if (cfg->nlinks > 0)
        die("Error: --profile agent refuses --link");
    if (net_given && cfg->net == NET_NAT)
        die("Error: --profile agent refuses --net nat");
    if (!cfg->seccomp_allow)
        die("Error: --profile agent refuses --seccomp deny");
    if (full_copy)
        die("Error: --profile agent refuses --copy: its root is an overlay of its base");
    cfg->profile = PROFILE_AGENT;
    cfg->userns = true;
    if (!net_given)
        cfg->net = NET_NONE;

    static const char *const why = "this setting of lightbox.conf cannot be used, and no option gave the box of --profile agent that limit";
    struct { char *field; size_t size; const char *value; const char *key; } limits[] = {
        { cfg->mem,  sizeof(cfg->mem),  cfg_global.agent_mem,  "agent_mem" },
        { cfg->pids, sizeof(cfg->pids), cfg_global.agent_pids, "agent_pids" },
        { cfg->cpu,  sizeof(cfg->cpu),  cfg_global.agent_cpu,  "agent_cpu" },
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        if (limits[i].field[0])
            continue;
        if (!limits[i].value[0] || !str_copy(limits[i].field, limits[i].value, limits[i].size))
            die_about("Error: ", why, limits[i].key);
    }
    if (!cfg->ttl[0]) {
        if (!cfg_global.agent_ttl_ok)
            die_about("Error: ", "this setting of lightbox.conf cannot be used, and no --ttl gave the box of --profile agent a lifetime",
                      "agent_ttl");
        if (!streq(cfg_global.agent_ttl, "none") &&
            (!parse_duration_ms(cfg_global.agent_ttl, &cfg->ttl_ms) ||
             !str_copy(cfg->ttl, cfg_global.agent_ttl, sizeof(cfg->ttl))))
            die_about("Error: ", "this setting of lightbox.conf cannot be used", "agent_ttl");
    }
}

/* --workspace <dir>: the directory at /workspace, as a volume, which with
 * --userns is its owner's (ROADMAP 8.2), and where every exec runs. */
static void add_workspace(container_config *cfg, const char *dir) {
    if (dir[0] != '/')
        die2("Error: --workspace takes an absolute path: ", dir);
    for (const char *c = dir; *c; c++) {
        if (*c == ':')
            die2("Error: --workspace takes a directory whose path has no ':', as a volume's has none: ", dir);
    }
    if (!path_is_directory(dir))
        die2("Error: --workspace takes a directory that is there: ", dir);
    char spec[MAX_PATH + sizeof(WORKSPACE_DIR) + 1];
    size_t at = 0;
    bool cut = false;
    at = str_append(spec, at, dir, sizeof(spec), &cut);
    at = str_append(spec, at, ":", sizeof(spec), &cut);
    (void)str_append(spec, at, WORKSPACE_DIR, sizeof(spec), &cut);
    if (cut)
        die2("Error: --workspace takes a directory whose path is shorter: ", dir);
    volume_spec vol = {0};
    parse_volume_spec_or_die(spec, &vol);
    const char *wrong = config_add_volume(cfg, &vol);
    if (wrong)
        die_about("Error: --workspace: ", wrong, dir);
    str_copy_or_die(cfg->workdir, WORKSPACE_DIR, sizeof(cfg->workdir), "--workspace");
}

/* Set by run: what create writes in the box's .runner, right after its mark,
 * so that no box of run is ever without it once it can be started. */
static char create_runner[48];

/* "<before><count><after>" on standard output */
static void say_count(const char *before, uint64_t count, const char *after) {
    char digits[24];
    int at = (int)sizeof(digits);
    digits[--at] = '\0';
    do { digits[--at] = (char)('0' + count % 10); count /= 10; } while (count);
    print_str(STDOUT, before);
    print_str(STDOUT, digits + at);
    print_str(STDOUT, after);
}

/* What an import made a container of, and what of the image it left out. */
static void say_imported(const image *img, const container_config *cfg, const image_unpacked *unpacked, const char *taken_base) {
    print_str(STDOUT, "Image sha256:");
    print_str(STDOUT, img->manifest);
    say_count(": ", (uint64_t)img->nlayers, img->nlayers == 1 ? " layer" : " layers");
    if (cfg->base[0]) {
        print_str(STDOUT, taken_base[0] ? ", on the new base snapshot " : ", on the base snapshot ");
        print_str(STDOUT, cfg->base);
        print_str(STDOUT, taken_base[0] ? "\n" : ", which was here\n");
    } else {
        print_str(STDOUT, ", as a copy\n");
    }
    const struct { const char *key, *value, *given; } limits[] = {
        { "mem", img->mem, cfg->mem }, { "swap", img->swap, cfg->swap }, { "pids", img->pids, cfg->pids },
        { "cpu", img->cpu, cfg->cpu }, { "ttl", img->ttl, cfg->ttl },
    };
    bool any = false;
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        if (!limits[i].value[0] || !streq(limits[i].value, limits[i].given))
            continue;
        print_str(STDOUT, any ? " " : "Limits of the image's: ");
        print_str(STDOUT, limits[i].key);
        print_str(STDOUT, "=");
        print_str(STDOUT, limits[i].value);
        any = true;
    }
    if (any)
        lc_print_char(STDOUT, '\n');
    if (unpacked->devices)
        say_count("Note: ", unpacked->devices, unpacked->devices == 1
                      ? " device of the image's was not made: a container's devices are lightbox's to give\n"
                      : " devices of the image's were not made: a container's devices are lightbox's to give\n");
    if (unpacked->attributes_left)
        say_count("Note: ", unpacked->attributes_left, unpacked->attributes_left == 1
                      ? " extended attribute of the image's was not set\n"
                      : " extended attributes of the image's were not set\n");
}

/*
 * Set by import (ROADMAP I.6): the image create makes the container of, in
 * the place of a base. Everything else is create's: the name, the address,
 * the options and what they may be, the store's lock, the mark while the
 * container is half made, and what is taken away when it cannot be made.
 */
static const image *create_image;

/* The limits no option gave, and no profile, are the image's, where it
 * carries them; lightbox.conf's come after. */
static void take_image_limits(const image *img, container_config *cfg) {
    struct { char *field; size_t size; const char *value; } limits[] = {
        { cfg->mem,  sizeof(cfg->mem),  img->mem },
        { cfg->swap, sizeof(cfg->swap), img->swap },
        { cfg->pids, sizeof(cfg->pids), img->pids },
        { cfg->cpu,  sizeof(cfg->cpu),  img->cpu },
    };
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++)
        if (!limits[i].field[0] && limits[i].value[0])
            str_copy_or_die(limits[i].field, limits[i].value, limits[i].size, "a limit of the image's");
    if (!cfg->ttl[0] && img->ttl[0] && parse_duration_ms(img->ttl, &cfg->ttl_ms))
        str_copy_or_die(cfg->ttl, img->ttl, sizeof(cfg->ttl), "the lifetime of the image's");
}

static void cmd_create(int argc, char **argv) {
    bool full_copy = false;     /* --copy: the container is a copy of its base, not an overlay */
    if (!create_image)
        require_tool("cp", tool_path_cp());
    if (argc < 1)
        die(create_image ? "Usage: lightbox import <dir> <name> [<ip>] [options]"
                         : "Usage: lightbox create <name> [<ip>] [options]");
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
    /* A new container has the allow-list unless it asks for the deny-list
     * (ROADMAP 8.3). A .conf without the line is a container made before
     * 0.8, which keeps the deny-list it was made with. */
    cfg.seccomp_allow = true;
    /* and reaches the internet and its name servers only, unless it asks
     * for more or for nothing (ROADMAP 8.5); a .conf without the line is of
     * a container made before 0.8, which has today's network */
    cfg.net = NET_OUTSIDE;
    char dns[MAX_DNS][16];
    int ndns = 0;
    bool net_given = false, agent = false;
    const char *workspace = NULL;

    for (int i = address_given ? 2 : 1; i < argc; i++) {
        const char *opt = argv[i];
        if (limit_option(argc, argv, &i, &cfg)) {
            /* --mem, --pids or --cpu */
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
        } else if (streq(opt, "--userns")) {
            cfg.userns = true;
        } else if (streq(opt, "--privileged")) {
            cfg.privileged = true;
        } else if (streq(opt, "--seccomp")) {
            const char *value = option_value(argc, argv, &i);
            if (!parse_seccomp_profile(value, &cfg.seccomp_allow))
                die2("Error: --seccomp takes allow or deny, not: ", value);
        } else if (streq(opt, "--net")) {
            const char *value = option_value(argc, argv, &i);
            if (!parse_net_mode(value, &cfg.net, &cfg.proxy_port))
                die2("Error: --net takes nat, outside, none or proxy:<port>, not: ", value);
            net_given = true;
        } else if (streq(opt, "--profile")) {
            const char *value = option_value(argc, argv, &i);
            if (!streq(value, "agent"))
                die2("Error: --profile takes agent, not: ", value);
            agent = true;
        } else if (streq(opt, "--workspace")) {
            const char *value = option_value(argc, argv, &i);
            if (workspace)
                die("Error: --workspace is given once: a box has one workspace");
            workspace = value;
        } else if (streq(opt, "--rootfs")) {
            if (create_image)
                die("Error: import makes a container of an image, which is all the base it has: no --rootfs");
            str_copy_or_die(cfg_global.rootfs, option_value(argc, argv, &i), MAX_PATH, "--rootfs");
        } else if (streq(opt, "--copy")) {
            full_copy = true;
        } else if (streq(opt, "--read-only")) {
            cfg.read_only = true;
        } else if (streq(opt, "--oom-score")) {
            const char *value = option_value(argc, argv, &i);
            if (!parse_oom_score(value, &cfg.oom_score))
                die2("Error: --oom-score takes a number from -1000 to 1000, not: ", value);
        } else if (streq(opt, "--ttl")) {
            const char *value = option_value(argc, argv, &i);
            if (!parse_duration_ms(value, &cfg.ttl_ms) || !str_copy(cfg.ttl, value, sizeof(cfg.ttl)))
                die2("Error: --ttl takes a duration above 0 and up to 365d, such as 30m or 8h: ", value);
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

    if (agent)
        agent_profile(&cfg, net_given, full_copy);
    if (workspace)
        add_workspace(&cfg, workspace);
    if (create_image)
        take_image_limits(create_image, &cfg);

    /* what no option gave comes from lightbox.conf */
    {
        const char *unusable = container_config_fill_defaults(&cfg);
        if (unusable)
            die_about("Error: ", "this setting of lightbox.conf cannot be used, and no option gave the container that limit",
                      unusable);
    }

    /* its own ids, and the right to give them out, which only root has */
    if (cfg.userns)
        require_root(agent ? "create --profile agent" : "create --userns");

    /* --net none: loopback, and no address, link or rule to have */
    if (cfg.net == NET_NONE) {
        if (address_given)
            die2("Error: a container with --net none has no address: ", argv[1]);
        if (cfg.nlinks > 0)
            die("Error: a container with --net none has no network for --link");
    }
    /* --net proxy: one port of the gateway, and no link or name server to
     * reach besides; its names are the proxy's to look up (ROADMAP 8.6) */
    if (cfg.net == NET_PROXY) {
        if (cfg.nlinks > 0)
            die("Error: a container with --net proxy reaches its proxy and nothing else: no --link");
        if (ndns > 0)
            die("Error: a container with --net proxy has its proxy look up names: no --dns");
    }
    /* --net outside and proxy are lightbox's firewall rules: without them
     * each would be nat */
    if (cfg.net == NET_OUTSIDE && !cfg_global.firewall)
        die("Error: --net outside, the default, needs lightbox's firewall rules, and lightbox.conf has\n"
            "firewall = false; create the container with --net nat or --net none");
    if (cfg.net == NET_PROXY && !cfg_global.firewall)
        die("Error: --net proxy needs lightbox's firewall rules, and lightbox.conf has firewall = false");

    /* check if container already exists */
    char cdir[MAX_PATH], root[MAX_PATH];
    container_dir_path(cdir, name);
    container_root(root, name);
    if (path_exists(cdir)) die2("Error: container already exists: ", name);

    /* The base must be a directory with something in it. A link to one is
     * followed. Checked before anything is created, so a refusal leaves
     * nothing behind. An image has been read whole by now. */
    if (!create_image) {
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
    /* A link to a container of --net proxy would be a way out of it. The
     * firewall drops what the bridge would switch to or from one, whatever
     * links name it; one that is there already is refused here. */
    for (int i = 0; i < cfg.nlinks; i++) {
        static container_config peer;
        char peer_dir[MAX_PATH];
        container_dir_path(peer_dir, cfg.links[i]);
        if (path_exists(peer_dir) && container_config_load(cfg.links[i], &peer) == NULL && peer.net == NET_PROXY)
            die2("Error: --link names a container of --net proxy, which reaches its proxy and nothing else: ",
                 cfg.links[i]);
    }
    char ip[IPV4_TEXT_MAX] = "";
    if (cfg.net != NET_NONE)
        choose_address(&net, address_given ? &asked : NULL, ip);
    if (cfg.userns) {
        const char *why = userns_allocate(&cfg.uid_start, &cfg.gid_start);
        if (why) {
            print_str(STDERR, "Error: no range of host ids for the container's user namespace: ");
            print_str(STDERR, why);
            print_str(STDERR, "\nAdd one of at least 65536 ids for " USERNS_OWNER " to both " SUBUID_FILE " and " SUBGID_FILE
                              ", such as:\n  " USERNS_OWNER ":2147483647:2147483648\n");
            lc_kernel_exit(failure_status);
        }
    }

    print_str(STDOUT, create_image ? "Importing container '" : "Creating container '");
    print_str(STDOUT,name);
    if (create_image) {
        print_str(STDOUT, "' from ");
        print_str(STDOUT, create_image->dir);
        print_str(STDOUT, "...\n");
    } else {
        print_str(STDOUT,"'...\n");
    }

    const char *create_err = NULL;
    bool created_dir = false;
    /* with import: what the image's layers were unpacked to, and the
     * snapshot this command took for them, if it took one */
    image_unpacked unpacked = { 0 };
    char taken_base[BASE_ID_TEXT] = "";
    const char *former = create_image ? create_image->name : NULL;

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
    if (create_runner[0]) {
        char runner[MAX_PATH];
        container_runner_path(runner, name);
        if (write_file_atomic(runner, create_runner, MODE_PRIVATE_FILE) != 0) {
            create_err = "failed to write which run the box is of";
            goto fail_create;
        }
    }
    static char resolv[RESOLV_TEXT_MAX];
    create_err = make_resolv(&cfg, dns, ndns, resolv);
    if (create_err)
        goto fail_create;

    /*
     * The container's root. An overlay of a snapshot of the base: the
     * container's own files are its rootfs/, the upper layer, and the
     * snapshot is shared by every container of that base. Where an overlay
     * cannot be mounted, and with --copy, a copy of the base.
     */
    bool overlay_here = !full_copy && overlay_mounts_here(name, cfg.userns ? &cfg : NULL);
    if (!full_copy && cfg.userns && !overlay_here)
        goto fail_create;           /* said: nothing falls back to a copy */
    if (overlay_here && create_image) {
        /*
         * An image of two layers is a container as export writes one: the
         * first is its snapshot, and the second its own files, with the
         * marks of what it took out of the first. Any other image is all
         * snapshot. The snapshot is one that is here already, where one is
         * those layers; otherwise the layers are unpacked into a new one,
         * which is put in place when it is whole.
         */
        int own = create_image->nlayers == 2 ? 1 : 0;
        int under = create_image->nlayers - own;
        bool took = false;
        if (image_base(create_image, under, cfg.base, &took, &unpacked) != 0) {
            create_err = "the image's base was not unpacked, and no snapshot of it is kept";
            goto fail_create;
        }
        if (took)
            lc_bytes_copy(taken_base, cfg.base, sizeof(taken_base));
        /* its own files are its root's on the host, as the overlay has them */
        if (own && (lc_kernel_mkdirat(AT_FDCWD, root, 0755) < 0 ||
                    (cfg.userns && lc_kernel_fchownat(AT_FDCWD, root, cfg.uid_start, cfg.gid_start, 0) < 0) ||
                    image_unpack(create_image, under, own, root, TAR_INTO_UPPER, cfg.userns ? cfg.uid_start : 0,
                                 cfg.userns ? cfg.gid_start : 0, &unpacked) != 0)) {
            create_err = "the container's own files were not unpacked";
            goto fail_create;
        }
        int written = overlay_etc(name, &cfg, ip, resolv, former);
        if (written == OVERLAY_CANNOT_MOUNT) {
            /* a copy after all, as said: of the image, with no snapshot */
            cfg.base[0] = '\0';
            unpacked = (image_unpacked){ 0 };
            if (taken_base[0])
                base_discard(taken_base);
            taken_base[0] = '\0';
        } else if (written != 0) {
            create_err = "failed to write the container's files in /etc";
            goto fail_create;
        }
    } else if (overlay_here) {
        bool took = false;
        if (base_snapshot_for(cfg_global.rootfs, cfg.base, &took) != 0) {
            create_err = "failed to take a snapshot of the base";
            goto fail_create;
        }
        int written = overlay_etc(name, &cfg, ip, resolv, NULL);
        if (written == OVERLAY_CANNOT_MOUNT) {
            cfg.base[0] = '\0';
        } else if (written != 0) {
            create_err = "failed to write the container's files in /etc";
            goto fail_create;
        }
    }
    if (!cfg.base[0]) {
        /* Copy what is in the base ("<base>/."), not the path itself: given a
         * link to the base, copying the path would make the container's rootfs
         * that link, and everything written to it would land in the base. A
         * reflink where the filesystem has them. */
        char base_contents[MAX_PATH + 4];
        if (!path_join(base_contents, sizeof(base_contents), cfg_global.rootfs, ".")) {
            create_err = "the path of the base is too long";
            goto fail_create;
        }
        if (path_exists(root))
            require_rm_rf(root);
        /* a copy for a container with --userns is idmapped when it starts:
         * the filesystem has to have idmapped mounts, which is looked at
         * before anything is copied */
        if (cfg.userns) {
            lc_sysret pid = lc_kernel_fork();
            if (pid == 0)
                lc_kernel_exit(lc_kernel_unshare(CLONE_NEWNS) == 0 &&
                               lc_kernel_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 &&
                               idmap_in_place(cdir, cfg.uid_start, cfg.gid_start, false) == 0 ? 0 : 1);
            int32_t status = 1;
            if (pid < 0 || wait_child((int32_t)pid, &status) < 0 || exit_code_from_status(status) != 0)
                goto fail_create;   /* said */
        }
        const char *reflink[] = { "cp", "-a", "--reflink=auto", base_contents, root, NULL };
        const char *plain[] = { "cp", "-a", base_contents, root, NULL };
        if (create_image) {
            /* every layer into one tree, one over the other: a mark takes
             * out what it names. The ids are the image's, from 0, as a copy
             * of a base has them. */
            if (lc_kernel_mkdirat(AT_FDCWD, root, 0755) < 0 ||
                image_unpack(create_image, 0, create_image->nlayers, root, TAR_INTO_TREE, 0, 0, &unpacked) != 0) {
                create_err = "the image was not unpacked";
                goto fail_create;
            }
        } else if (run_cmd_quiet(tool_path_cp(), reflink) != 0) {
            if (path_exists(root))
                require_rm_rf(root);
            if (run_cmd(tool_path_cp(), plain) != 0) {
                create_err = "failed to copy rootfs";
                goto fail_create;
            }
        }
        create_err = write_etc_files(root, name, ip, resolv, former);
        if (create_err)
            goto fail_create;
    }

    /* store IP: none for --net none */
    char ip_path[MAX_PATH];
    container_ip_path(ip_path, name);
    if (ip[0] && write_file_atomic(ip_path, ip, MODE_PRIVATE_FILE) < 0) {
        create_err = "failed to write IP metadata";
        goto fail_create;
    }

    /* what it was given to ask for names, for reset to write again */
    char resolv_path[MAX_PATH];
    container_resolv_path(resolv_path, name);
    if (write_file_atomic(resolv_path, resolv, MODE_PRIVATE_FILE) < 0) {
        create_err = "failed to keep what the container's resolv.conf says";
        goto fail_create;
    }

    /* write config, with the id the audit log knows the box by */
    if (!random_hex(cfg.id, BOX_ID_LEN / 2)) {
        create_err = "cannot draw an id for the container";
        goto fail_create;
    }
    create_err = container_config_save(name, &cfg);
    if (create_err)
        goto fail_create;

    /* made: and with no runtime record, stopped */
    if (remove_file_durably(creating) != 0) {
        create_err = "failed to mark the container as created";
        goto fail_create;
    }
    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT, create_image ? "' imported" : "' created");
    if (ip[0]) {
        print_str(STDOUT, " (ip=");
        print_str(STDOUT, ip);
        print_str(STDOUT, ")\n");
    } else {
        print_str(STDOUT, " (no network)\n");
    }
    if (create_image)
        say_imported(create_image, &cfg, &unpacked, taken_base);
    return;

fail_create:
    if (create_err) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, create_err);
        lc_print_char(STDERR, '\n');
    }
    if (created_dir)
        require_rm_rf(cdir);
    /* a snapshot this import took is nobody's: no container was made on it */
    if (taken_base[0])
        base_discard(taken_base);
    lc_kernel_exit(failure_status);
}

/*
 * import <dir> <name> [<ip>] [options] (ROADMAP I.6): a container made of an
 * image, as create makes one of a base, with create's options. The image is
 * read first, all of it, and held to the digests it names itself by: what is
 * no image ends the command before anything is made, and before it asks for
 * root, so that anyone can ask whether a directory is one. Unpacking is
 * root's: the process that does it makes the directory it fills its root.
 */
static void cmd_import(int argc, char **argv) {
    static image img;
    if (argc < 2 || argv[0][0] == '-')
        die(argc > 0 && argv[0][0] == '-' ? "Error: import takes the image's directory first, and then the name"
                                          : "Usage: lightbox import <dir> <name> [<ip>] [options]");
    validate_name(argv[1]);
    image_open(argv[0], &img);
    require_root("import");
    for (int i = 0; i < img.nlayers; i++)
        if (img.layers[i].gzip) {
            require_tool("gzip", tool_path_gzip());
            break;
        }
    create_image = &img;
    cmd_create(argc - 1, argv + 1);
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

/* A volume on its way into a container. */
struct volume_mount {
    int32_t tree;               /* a clone of the source's mount, attached nowhere yet */
    bool    is_dir;
    bool    ro;
    const char *dst;            /* where it goes, in the configuration it is from */
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
    const char  *overlay;                   /* the options of the overlay init mounts; NULL: none */
    bool         userns;                    /* in a user namespace of its own, whose maps the command writes */
    const struct volume_mount *volumes;     /* taken by the command, nvolumes of them; NULL: init takes them */
    int          nvolumes;
    const char  *hook;                      /* the script init runs when it is ready */
    uint32_t     address;                   /* eth0's, on the network of prefix bits */
    int          prefix;
    uint32_t     gateway;                   /* the bridge's, eth0's default route */
    int          stop_grace;                /* seconds the container gets to end, unless a stop says otherwise */
    int          privileged;
    int          read_only;
    bool         seccomp_allow;             /* the allow-list profile; false: the deny-list */
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
    /* and the volumes the command took, which build_container attaches */
    int32_t keep[5 + MAX_VOLS] = { ca->go_rd, ca->report_wr, ca->null_fd, ca->log_fd, ca->exit_fd };
    size_t nkeep = 5;
    for (int i = 0; ca->volumes && i < ca->nvolumes; i++)
        keep[nkeep++] = ca->volumes[i].tree;
    close_all_but(keep, nkeep);

    if (!go_received(ca->go_rd))
        lc_kernel_exit(failure_status);
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
 * --net proxy (ROADMAP 8.6): where its proxy is, for the programs of the
 * init hook and of exec, as HTTP_PROXY, HTTPS_PROXY and NO_PROXY in both
 * spellings, as programs read one or the other. How many it wrote in vars:
 * PROXY_ENV_COUNT, or 0 for another --net. Only where they connect to is
 * the firewall's to keep them to; the variables tell them where that is.
 */
#define PROXY_ENV_COUNT 6
#define PROXY_VAR_MAX   48      /* "HTTPS_PROXY=http://255.255.255.255:65535" and its NUL */
static int proxy_environment(const container_config *config, uint32_t gateway,
                             char vars[PROXY_ENV_COUNT][PROXY_VAR_MAX]) {
    if (!config || config->net != NET_PROXY)
        return 0;
    char url[32] = "http://", address[IPV4_TEXT_MAX], port[8];
    bool cut = false;
    format_ipv4(address, gateway);
    fmt_int(port, config->proxy_port);
    size_t pos = str_append(url, 7, address, sizeof(url), &cut);
    pos = str_append(url, pos, ":", sizeof(url), &cut);
    str_append(url, pos, port, sizeof(url), &cut);
    static const char *const names[PROXY_ENV_COUNT] = {
        "HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy=", "NO_PROXY=", "no_proxy=",
    };
    for (int i = 0; i < PROXY_ENV_COUNT; i++) {
        pos = str_append(vars[i], 0, names[i], PROXY_VAR_MAX, &cut);
        str_append(vars[i], pos, i < 4 ? url : "localhost,127.0.0.1,::1", PROXY_VAR_MAX, &cut);
    }
    return cut ? 0 : PROXY_ENV_COUNT;
}

/*
 * Run the image's hook as a child of init: its PID, or -1 once the failure
 * has been reported. Like every program lightbox starts it begins with no
 * signal blocked. Init's own descriptors are close-on-exec and do not reach
 * it. Its environment is PATH, HOME and TERM, and where the proxy of a
 * container of --net proxy is.
 */
static int32_t start_hook(const char *script, const container_config *config, uint32_t gateway) {
    lc_sysret pid = lc_kernel_fork();
    if (pid < 0) {
        say_with_number("Error: cannot start the init hook (fork failed, errno ", (int)-pid, ")\n");
        return -1;
    }
    if (pid == 0) {
        uint64_t no_signals = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &no_signals, NULL);

        const char *a[] = { "/bin/sh", script, NULL };
        static char proxy[PROXY_ENV_COUNT][PROXY_VAR_MAX];
        const char *e[3 + PROXY_ENV_COUNT + 1] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/root", "TERM=xterm" };
        int n = proxy_environment(config, gateway, proxy);
        for (int i = 0; i < n; i++)
            e[3 + i] = proxy[i];
        e[3 + n] = NULL;
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
/* Milliseconds since boot, suspended time included: what --ttl counts. */
static int64_t boottime_ms(void) {
    lc_timespec now = { 0, 0 };
    lc_kernel_get_clock(LB_CLOCK_BOOTTIME, &now);
    return now.seconds * 1000 + now.nanoseconds / 1000000;
}

/*
 * Init's loop: reap, see the hook end, and shut down when asked or, with
 * --ttl, at the deadline (0: none), when it returns INIT_EXPIRED. Init is
 * what keeps the lifetime: no process of the container can send it a signal
 * it does not handle, trace it or set the clock it reads. It is in the
 * container all the same, and only the host could keep a lifetime from it.
 */
static int supervisor_loop(int32_t sfd, int32_t report_fd, int32_t hook_pid, int stop_grace, int64_t deadline) {
    for (;;) {
        if (deadline) {
            int64_t left = deadline - boottime_ms();
            if (left <= 0) {
                print_str(STDERR, "lightbox: the container's --ttl is over; it stops\n");
                shut_down(sfd, stop_grace);
                return INIT_EXPIRED;
            }
            struct lb_pollfd one = { .fd = sfd, .events = LB_POLLIN, .revents = 0 };
            lc_timespec wait = { .seconds = left / 1000, .nanoseconds = (left % 1000) * 1000000 };
            lc_sysret ready = lb_sys_ppoll(&one, 1, &wait);
            if (ready < 0 && ready != -LB_EINTR)
                die("Error: failed to wait for init's signals");
            if (ready <= 0)
                continue;
        }
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
        apply_sandbox(ca->seccomp_allow);
    /* a lifetime counts from the moment the container is built */
    int64_t deadline = ca->config && ca->config->ttl_ms ? boottime_ms() + ca->config->ttl_ms : 0;

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
        lc_kernel_exit(failure_status);
    lc_kernel_close_file(ca->go_rd);

    int32_t hook_pid = 0;
    if (ca->hook && path_exists(ca->hook)) {
        hook_pid = start_hook(ca->hook, ca->config, ca->gateway);
        if (hook_pid < 0) {
            (void)report_to_starter(ca->report_wr, START_HOOK_DONE, 126);
            return 1;
        }
    } else {
        (void)report_to_starter(ca->report_wr, START_HOOK_DONE, 0);
        lc_kernel_close_file(ca->report_wr);
    }

    return supervisor_loop((int32_t)sfd, ca->report_wr, hook_pid, ca->stop_grace, deadline);
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
            lc_kernel_exit(failure_status);
        if (!path_exists("/proc/sys/net/ipv6/conf"))
            lc_kernel_exit(0);      /* a kernel without IPv6 has nothing to switch off */
        if (write_file("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1") < 0 ||
            write_file("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1") < 0)
            lc_kernel_exit(failure_status);
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
    const char  *user_text;             /* --user as given, or NULL */
    int          uid, gid;              /* AS_ID; gid is -1 when only a uid was given */
    const char  *env[MAX_EXEC_ENV];     /* --env, in the order given */
    int          nenv;
    const char  *workdir;               /* --workdir, the box's workdir=, or NULL */
    const char  *workdir_text;          /* --workdir as given, or NULL */
    int64_t      timeout_ms;            /* --timeout, or 0 */
    const char  *timeout_text;          /* as it was given */
    int64_t      keeper_deadline;       /* with --timeout: when the worker ends it, the caller failing */
    int32_t      caller_fd;             /* with --timeout: a pidfd of the process that ran exec */
    const char  *term;                  /* the caller's TERM, or NULL */
    const char  *proxy[PROXY_ENV_COUNT];    /* --net proxy: where its proxy is */
    int          nproxy;
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
 * has a name, and with --net proxy where its proxy is; --env adds to it and
 * replaces what it names, the later of two for the same variable winning.
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

    const char *base[5 + PROXY_ENV_COUNT];
    int nbase = 0;
    base[nbase++] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
    base[nbase++] = home_env;
    base[nbase++] = term_env;
    if (name[0]) {
        base[nbase++] = user_env;
        base[nbase++] = logname_env;
    }
    for (int i = 0; i < req->nproxy; i++)
        base[nbase++] = req->proxy[i];

    const char *envp[5 + PROXY_ENV_COUNT + MAX_EXEC_ENV + 1];
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
        bool timeout = streq(arg, "--timeout");
        if (!user && !env && !workdir && !timeout) {
            print_str(STDERR, "Error: unknown option: ");
            print_str(STDERR, arg);
            print_str(STDERR, "\nA command that begins with a dash goes after --.\n");
            lc_kernel_exit(failure_status);
        }
        const char *value = option_value(argc, argv, &i);

        if (timeout) {
            if (!parse_duration_ms(value, &req->timeout_ms))
                die2("Error: --timeout takes a duration above 0 and up to 365d, such as 30s, 5m or 1.5h: ", value);
            req->timeout_text = value;
        } else if (user) {
            if (!parse_user_spec(value, req))
                die2("Error: --user takes a name, a uid or uid:gid, and this is none of them: ", value);
            req->user_text = value;
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
            req->workdir_text = value;
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
    lc_kernel_exit(failure_status);
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
/*
 * exec --timeout is kept by two processes. The one that ran exec ends the
 * exec's cgroup at the deadline; its worker, which the container cannot
 * reach, keeps watch too, should that one not: when the process that ran
 * exec ends, killed or otherwise, while the command runs, the worker ends
 * everything in the cgroup at once, itself with it, and when that process
 * is held up, stopped for one, the worker does so EXEC_KEEPER_MARGIN_MS past
 * the deadline. Only root on the host, by killing both, can let a command
 * outlive its limit.
 */
#define EXEC_KEEPER_MARGIN_MS 1000

struct exec_keeper {
    int32_t kill_fd;        /* the exec's cgroup.kill, or -1 before Linux 5.14 */
    int32_t procs_fd;       /* its cgroup.procs */
    int32_t caller_fd;      /* a pidfd of the process that ran exec */
    int64_t deadline;       /* monotonic ms */
};

/* In the worker, on the host still: what it needs to end the exec's cgroup
 * with from inside the container. Ends the process when it cannot. */
static void keeper_open(struct exec_keeper *k, const char *cg, const struct exec_request *req) {
    char path[MAX_PATH];
    k->caller_fd = req->caller_fd;
    k->deadline = req->keeper_deadline;
    k->kill_fd = -1;
    if (path_join(path, sizeof(path), cg, "cgroup.kill")) {
        lc_sysret fd = lc_kernel_open_file(path, O_WRONLY | O_CLOEXEC, 0);
        if (fd >= 0)
            k->kill_fd = (int32_t)fd;
    }
    lc_sysret procs = path_join(path, sizeof(path), cg, "cgroup.procs")
                          ? lc_kernel_open_file(path, O_RDONLY | O_CLOEXEC, 0) : -1;
    if (procs < 0)
        die("Error: cannot open the cgroup.procs of the exec, to keep its --timeout with");
    k->procs_fd = (int32_t)procs;
}

static int keeper_self;

static void kill_unless_keeper(int pid) {
    if (pid != keeper_self)
        lc_kernel_send_signal(pid, SIGKILL);
}

/* End everything in the exec's cgroup, this worker last. */
[[noreturn]] static void keeper_end(const struct exec_keeper *k) {
    if (k->kill_fd >= 0)
        (void)lc_kernel_write_bytes(k->kill_fd, "1", 1);   /* this process with the rest */
    keeper_self = lc_kernel_get_process_id();
    int64_t until = monotonic_ms() + CGROUP_EMPTY_MS;
    while (each_listed_pid_in(k->procs_fd, kill_unless_keeper) > 1 && monotonic_ms() < until)
        sleep_ms(10);
    lc_kernel_send_signal(keeper_self, SIGKILL);
    lc_kernel_exit(EXEC_TIMED_OUT);
}

static int32_t relay_until_exit(struct exec_streams *st, int32_t command, int32_t signal_fd,
                                const struct exec_keeper *keeper) {
    int32_t status = 0;
    bool ended = false;

    while (!ended) {
        struct lb_pollfd fds[5];
        struct channel *of[5];
        bool writing[5];
        uint64_t count = 0;

        fds[count] = (struct lb_pollfd){ .fd = signal_fd, .events = LB_POLLIN, .revents = 0 };
        of[count++] = NULL;
        /* the process that ran exec: readable once it has ended */
        lc_timespec left, *wait = NULL;
        if (keeper) {
            fds[count] = (struct lb_pollfd){ .fd = keeper->caller_fd, .events = LB_POLLIN, .revents = 0 };
            writing[count] = false;
            of[count++] = NULL;
            int64_t ms = keeper->deadline - monotonic_ms();
            if (ms <= 0)
                keeper_end(keeper);
            left.seconds = ms / 1000;
            left.nanoseconds = (ms % 1000) * 1000000;
            wait = &left;
        }
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

        lc_sysret ready = lb_sys_ppoll(fds, count, wait);
        if (ready < 0 && ready != -LB_EINTR)
            die("Error: failed to wait on the command's streams");
        if (ready <= 0)
            continue;
        if (keeper && fds[1].revents)
            keeper_end(keeper);

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
        for (uint64_t i = keeper ? 2 : 1; i < count; i++) {
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
static int32_t serve_command(struct exec_streams *st, int32_t command, int32_t signal_fd,
                             const struct exec_keeper *keeper) {
    release_command_ends(st);

    struct lb_termios saved, raw;
    bool restore = st->master >= 0 && lc_kernel_device_control(STDIN, LB_TCGETS, &saved) >= 0;
    if (restore) {
        raw = saved;
        make_raw(&raw);
        lc_kernel_device_control(STDIN, LB_TCSETS, &raw);
    }

    int32_t status = relay_until_exit(st, command, signal_fd, keeper);

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
 * A worker killed past the deadline was ended for its time limit, by its own
 * keeper when this process was held up: *timed_out says so.
 */
static int32_t worker_status(int32_t status, int64_t deadline, bool *timed_out) {
    if (deadline && (status & 0x7f) == SIGKILL && monotonic_ms() >= deadline)
        *timed_out = true;
    return status;
}

/*
 * In the process that ran exec: wait for the worker, and pass on what asks
 * it to end. A signal that the terminal sent has reached the worker by
 * itself, since both are in the terminal's foreground, so only the ones a
 * process sent are passed on. At the deadline, when there is one, everything
 * in the exec's cgroup is ended, the worker with it, and *timed_out is set.
 * The worker's wait status.
 */
static int32_t attend_worker(int32_t worker, int32_t signal_fd, const char *cg, int64_t deadline,
                             bool *timed_out) {
    int32_t status = 0;
    for (;;) {
        lc_timespec left, *wait = NULL;
        if (deadline && !*timed_out) {
            int64_t ms = deadline - monotonic_ms();
            if (ms <= 0) {
                /* a command that ended just now has its own status */
                if (lc_kernel_wait_for_child(worker, &status, WNOHANG) == worker)
                    return worker_status(status, deadline, timed_out);
                *timed_out = true;
                if (cg)
                    (void)cgroup_kill_all(cg);
                lc_kernel_send_signal(worker, SIGKILL);     /* whatever the cgroup's lists said */
                continue;
            }
            left.seconds = ms / 1000;
            left.nanoseconds = (ms % 1000) * 1000000;
            wait = &left;
        }
        struct lb_pollfd one = { .fd = signal_fd, .events = LB_POLLIN, .revents = 0 };
        lc_sysret ready = lb_sys_ppoll(&one, 1, wait);
        if (ready < 0 && ready != -LB_EINTR)
            die("Error: failed to wait for the exec worker");
        if (ready <= 0)
            continue;
        lc_signal_info si;
        if (lc_kernel_read_retry(signal_fd, &si, sizeof(si)) != (lc_sysret)sizeof(si))
            continue;
        if (si.signal == SIGCHLD) {
            if (lc_kernel_wait_for_child(worker, &status, WNOHANG) == worker)
                return worker_status(status, deadline, timed_out);
        } else if (si.signal != LB_SIGWINCH && si.code <= 0) {
            lc_kernel_send_signal(worker, (int32_t)si.signal);
        }
    }
}

/*
 * The rest of what the process that ran exec does with its worker: attend to
 * it until the deadline, when there is one (0: none), put the terminal's
 * modes back as they were before the worker touched them, and give the exit
 * status the worker had. modes is NULL when stdin is no terminal; cg is the
 * exec's cgroup, or NULL for none.
 */
static int finish_exec(int32_t worker, int32_t signal_fd, const struct lb_termios *modes,
                       const char *cg, int64_t deadline, bool *timed_out) {
    *timed_out = false;
    int32_t status = attend_worker(worker, signal_fd, cg, deadline, timed_out);
    if (modes) {
        struct lb_termios back = *modes;
        lc_kernel_device_control(STDIN, LB_TCSETS, &back);
    }
    return exit_code_from_status(status);
}

/* ─── exec: entering the container ──────────────────────────────────────── */

static int exec_inside_container(const char *cg, int target_pid, int privileged, bool userns,
                                 bool seccomp_allow, int oom_score, const struct exec_request *req) {
    /* From here to the command's execve this process, and the child it
     * forks, are lightbox inside a container. Not dumpable, their memory and
     * their descriptors are closed to the container's processes, whatever
     * uid those have. */
    if (lc_kernel_prctl(LB_PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        die("Error: failed to close the exec worker to other processes");

    int rootfd = open_target_path(target_pid, "/root");
    if (rootfd < 0)
        die("Error: failed to open target root");

    int userfd = userns ? open_target_path(target_pid, "/ns/user") : -1;
    if (userns && userfd < 0)
        die("Error: failed to open the container's user namespace");
    int mntfd = open_target_path(target_pid, "/ns/mnt");
    int utsfd = open_target_path(target_pid, "/ns/uts");
    int ipcfd = open_target_path(target_pid, "/ns/ipc");
    int netfd = open_target_path(target_pid, "/ns/net");
    int pidfd = open_target_path(target_pid, "/ns/pid");
    if (mntfd < 0 || utsfd < 0 || ipcfd < 0 || netfd < 0 || pidfd < 0)
        die("Error: failed to open target namespace fd");

    /* Join the exec's cgroup, below the container's, before switching mount
     * namespaces: what is forked from here on is in it. */
    cgroup_join_self(cg);
    /* and with --timeout, what keeps the limit should the process that ran
     * exec not, opened here on the host */
    static struct exec_keeper keeper;
    if (req->timeout_ms)
        keeper_open(&keeper, cg, req);
    /* and when memory runs short, be what the container's processes are to
     * the kernel, not what the caller of exec was */
    {
        char score[16];
        fmt_int(score, oom_score);
        if (write_file("/proc/self/oom_score_adj", score) < 0)
            die("Error: failed to give the command the container's OOM score");
    }

    /* The user namespace first, whose root then joins the others, which it
     * owns, as the container's root: what it makes there is the container's,
     * and the ids of its user are the container's ids. */
    if (userns) {
        require_setns_fd(userfd, CLONE_NEWUSER, "user");
        if (lc_kernel_setgroups(0, NULL) < 0 || lc_kernel_setgid(0) < 0 || lc_kernel_setuid(0) < 0)
            die("Error: failed to become the root of the container's user namespace");
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
            apply_sandbox(seccomp_allow);
        become(&id);
        run_command(req, &id);
    }

    return serve_command(&streams, (int32_t)child, signal_fd, req->timeout_ms ? &keeper : NULL);
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
        rtnl nl;
        if (rtnl_open(&nl) == 0) {
            (void)rtnl_link_delete(&nl, port);      /* clean-up: best effort */
            rtnl_close(&nl);
        }
    } else if (port && port[0])
        (void)remove_own_port(port, name);          /* clean-up: best effort */

    (void)cgroup_destroy(name);     /* it has said so if it could not */
    (void)firewall_remove_links(name);
    (void)firewall_remove_egress(name);

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
    if (firewall_remove_egress(name) != 0)
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
    bool reported = container_exit_report(name, &status);
    bool ended_well = reported && status == 0;
    bool expired = reported && status == INIT_EXPIRED;

    (void)release_container(name);      /* it has said what it could not remove */
    container_forget_pid(name);
    (void)record_container_state(name, expired ? "expired\n" : ended_well ? "exited\n" : "failed\n");

    print_str(STDERR, "Note: container '");
    print_str(STDERR, name);
    print_str(STDERR, expired ? "' came to the end of its --ttl; what it left has been cleared away\n"
                      : ended_well ? "' had stopped by itself; what it left has been cleared away\n"
                                   : "' had ended without a stop; what it left has been cleared away\n");
    return true;
}

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
        lc_kernel_exit(failure_status);
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

/* "<before><errno><after><path>", for start_err */
static const char *volume_failure(const char *before, int rc, const char *after, const char *path) {
    static char text[MAX_PATH + 160];
    char digits[16];
    fmt_int(digits, rc < 0 ? -rc : rc);
    bool cut = false;
    size_t pos = str_append(text, 0, before, sizeof(text), &cut);
    pos = str_append(text, pos, digits, sizeof(text), &cut);
    pos = str_append(text, pos, after, sizeof(text), &cut);
    str_append(text, pos, path, sizeof(text), &cut);
    return text;
}

/*
 * A volume of a container with --userns, taken by the command, as host root
 * and before init is cloned: init could not make it, as an idmapped mount
 * needs CAP_SYS_ADMIN over the source's filesystem, which a user namespace
 * never has. The clone of the source's mount is idmapped to the source's
 * owner and group, which the container's root then stands for, and no other
 * id is mapped (ROADMAP 8.2). A source of host root's, uid 0 or gid 0, is
 * cloned as it is: its files are nobody's to the container, which makes
 * nothing there that is root's on the host. NULL, or why not.
 */
static const char *open_userns_volume(const volume_spec *vol, uint32_t uid_start, uint32_t gid_start,
                                      struct volume_mount *out) {
    lc_sysret tree = lb_sys_open_tree(AT_FDCWD, vol->src, LB_OPEN_TREE_CLONE | LB_OPEN_TREE_CLOEXEC);
    if (tree == -LB_ENOENT) {
        static char missing[MAX_PATH + 48];
        bool cut = false;
        str_append(missing, str_append(missing, 0, "volume source does not exist: ", sizeof(missing), &cut),
                   vol->src, sizeof(missing), &cut);
        return missing;
    }
    struct lb_statx stx = {0};
    lc_sysret rc = tree < 0 ? tree
                 : lb_sys_statx((int32_t)tree, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE | LB_STATX_UID | LB_STATX_GID, &stx);
    if (rc < 0 || (stx.stx_mask & (LB_STATX_TYPE | LB_STATX_UID | LB_STATX_GID)) != (LB_STATX_TYPE | LB_STATX_UID | LB_STATX_GID)) {
        if (tree >= 0)
            lc_kernel_close_file((int32_t)tree);
        return volume_failure("cannot take the volume's source (errno ", (int)rc, "): ", vol->src);
    }

    id_map uids, gids;
    if (volume_maps(stx.stx_uid, stx.stx_gid, uid_start, gid_start, &uids, &gids)) {
        int ns = userns_fd_mapped(&uids, &gids);
        if (ns < 0) {
            lc_kernel_close_file((int32_t)tree);
            return volume_failure("cannot make a user namespace for the volume's owner (errno ", ns, "): ", vol->src);
        }
        struct lb_mount_attr attr = {
            .attr_set = LB_MOUNT_ATTR_IDMAP | LB_MOUNT_ATTR_NODEV | LB_MOUNT_ATTR_NOSUID,
            .userns_fd = (uint64_t)ns,
        };
        rc = lb_sys_mount_setattr((int32_t)tree, "", LB_AT_EMPTY_PATH, &attr);
        lc_kernel_close_file(ns);
        if (rc < 0) {
            lc_kernel_close_file((int32_t)tree);
            return volume_failure("the kernel or the filesystem cannot idmap the volume (mount_setattr, errno ", (int)rc,
                                  "); a volume of a container with --userns needs a filesystem with idmapped mounts: ",
                                  vol->src);
        }
    }

    out->tree = (int32_t)tree;
    out->is_dir = (stx.stx_mode & LB_S_IFMT) == LB_S_IFDIR;
    out->ro = vol->ro;
    out->dst = vol->dst;
    return NULL;
}

static void close_volumes(const struct volume_mount *vols, int count) {
    for (int i = 0; i < count; i++)
        lc_kernel_close_file(vols[i].tree);
}

/* Every volume of a container with --userns, so, config->nvols of them; on a
 * failure none is left open. NULL, or why not. */
static const char *open_userns_volumes(const container_config *config, struct volume_mount *out) {
    for (int i = 0; i < config->nvols; i++) {
        const char *wrong = open_userns_volume(&config->vols[i], config->uid_start, config->gid_start, &out[i]);
        if (wrong) {
            close_volumes(out, i);
            return wrong;
        }
    }
    return NULL;
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
                lc_kernel_exit(failure_status);
        } else {
            char parent[MAX_PATH];
            if (!parent_dir(parent, sizeof(parent), dst))
                die2("Error: invalid path: ", dst);
            if (make_dirs(parent) != 0)
                lc_kernel_exit(failure_status);
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
            lc_kernel_exit(failure_status);
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
    /* make all mounts private — prevents host mount events (including
     * the host's /proc) from propagating into the container */
    require_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

    /* the root: an overlay of the base's snapshot and the container's own
     * files, in this mount namespace only */
    if (ca->overlay)
        require_mount("overlay", ca->root, "overlay", MS_NODEV | (ca->privileged ? 0 : MS_NOSUID), ca->overlay);

    /* set hostname */
    lc_kernel_sethostname(ca->name, lc_string_length(ca->name));

    /* The volumes: taken now, while the host's paths mean what they mean on
     * the host, and attached later, when the container's paths mean what
     * they mean in the container. With --userns the command took them, as
     * host root, and init has its copies of them. */
    struct volume_mount own_volumes[MAX_VOLS];
    const struct volume_mount *volumes = ca->volumes;
    int nvolumes = ca->nvolumes;
    if (!volumes) {
        nvolumes = open_volumes(ca->config, own_volumes);
        volumes = own_volumes;
    }

    /* The root, bound onto itself: a mount of this namespace's own, which
     * pivot_root takes, where one that a user namespace got with its copy of
     * the host's mounts is locked to its place and is not. A device node
     * inside the image is not a device here: the devices a container may use
     * are the ones bound into its /dev, which is a mount of its own. Without
     * privileges, setuid bits in the image mean nothing either, as
     * no_new_privs already has it. From here on the root is a descriptor,
     * and the paths below are of it: the path to it may be closed to the
     * container's root. */
    require_mount(ca->root, ca->root, NULL, MS_BIND | MS_REC, NULL);
    require_mount(NULL, ca->root, NULL,
                  MS_REMOUNT | MS_BIND | MS_NODEV | (ca->privileged ? 0 : MS_NOSUID), NULL);
    lc_sysret rootfd = lc_kernel_open_file(ca->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (rootfd < 0)
        die2("Error: cannot open the container's root: ", ca->root);

    /* In a user namespace of its own, init is the container's root from
     * here on, uid and gid 0 there and the first of its range on the host,
     * and what it makes is the container's root's. */
    if (ca->userns && (lc_kernel_setgroups(0, NULL) < 0 || lc_kernel_setgid(0) < 0 || lc_kernel_setuid(0) < 0))
        die("Error: failed to become the root of the container's user namespace");
    if (lb_sys_fchdir((int32_t)rootfd) < 0)
        die2("Error: chdir to rootfs failed: ", ca->root);
    lc_kernel_close_file((int32_t)rootfd);

    /* /dev: the host's devices, bound one by one onto empty files */
    {
        const char *dev_path = "dev";
        lc_kernel_mkdirat(AT_FDCWD, dev_path, 0755);   /* a minimal image may not have it */
        require_mount("tmpfs", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755");

        /* the nodes of LB_DEV_BOUND, which the device program lets a
         * container open as they are bound here */
#define LB_DEV_BIND(name, major, minor, mode, access) { #name, mode, (access) == LB_DEV_R },
        static const struct { const char *name; int mode; bool read_only; } devs[] = {
            LB_DEV_BOUND(LB_DEV_BIND)
        };
#undef LB_DEV_BIND

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
                if (devs[i].read_only)
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

    /* pivot_root, into the root this process is in */
    lc_kernel_mkdirat(AT_FDCWD, ".old_root", 0755);
    if (lc_kernel_pivot_root(".", ".old_root") < 0)
        die("Error: pivot_root failed");
    lc_kernel_chdir("/");

    /* Ensure standard mountpoints exist inside the container rootfs. */
    lc_kernel_mkdirat(AT_FDCWD, "/proc", 0555);
    lc_kernel_mkdirat(AT_FDCWD, "/sys", 0555);
    lc_kernel_mkdirat(AT_FDCWD, "/tmp", 01777);
    lc_kernel_mkdirat(AT_FDCWD, "/run", 0755);
    lc_kernel_mkdirat(AT_FDCWD, "/var", 0755);
    lc_kernel_mkdirat(AT_FDCWD, "/var/tmp", 01777);

    /* proc and sys, while the host's are there under /.old_root: in a user
     * namespace the kernel mounts them only where the host's are seen */
    require_mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);

    require_mount("sysfs", "/sys", "sysfs", MS_RDONLY, NULL);
    cleanup_old_root_or_die();

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

    /* Bring up loopback, and eth0, which the start put here: nothing enters
     * the namespace from the host for it. From the pivot to the hook nothing
     * of the image is run: its tools are not needed, and not trusted with
     * what init may do. */
    if (loopback_up() != 0 ||
        (ca->address && container_interface_up(ca->address, ca->prefix, ca->gateway) != 0))
        lc_kernel_exit(failure_status);
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

/* ─── Several containers at once ────────────────────────────────────────── */

/*
 * The names among a command's arguments, moved to its front, and -t or
 * --timeout with its seconds wherever it is, when the command takes one.
 * Anything else is an error, named. How many names there are.
 */
static int names_and_seconds(int argc, char **argv, int *seconds, bool *force) {
    int count = 0;
    for (int i = 0; i < argc; i++) {
        if (force && (streq(argv[i], "-f") || streq(argv[i], "--force"))) {
            *force = true;
        } else if (seconds && (streq(argv[i], "-t") || streq(argv[i], "--timeout"))) {
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

    /* What the container is configured with: read here, once, for the whole
     * start. Init gets it with the memory it is cloned with. */
    static container_config config;
    container_config_load_or_die(name, &config);
    bool privileged = config.privileged;
    /* --net none: loopback, and no address, interface or rule (ROADMAP 8.5) */
    bool networked = config.net != NET_NONE;

    /* The bridge, the firewall rules and forwarding, made again when a
     * reboot took them. What makes them takes the store's lock; teardown,
     * which holds that, never waits for a container's. */
    if (networked)
        ensure_host_network(name);

    /* The container's address, which has to be one of the network as it is
     * set now: with another subnet since the container was created, it would
     * start and reach nothing. */
    char ip[IPV4_TEXT_MAX] = "";
    container_network net = {0};
    uint32_t addr = 0;
    if (networked) {
        container_network_load_or_die(&net);
        if (read_container_ip(name, ip, sizeof(ip)) < 0 || !parse_ipv4(ip, &addr))
            die2("Error: the container has no address on record; remove it and create it again: ", name);
        const char *why = address_unusable(&net, addr);
        if (why)
            die_about_address(ip, why);
    }

    /* --net outside and proxy are lightbox's firewall rules, which it is not
     * started without */
    if (net_has_rules(config.net) && !cfg_global.firewall) {
        char mode[NET_MODE_TEXT_MAX];
        net_mode_text(mode, config.net, config.proxy_port);
        print_str(STDERR, "Error: container '");
        print_str(STDERR, name);
        print_str(STDERR, "' has --net ");
        print_str(STDERR, mode);
        print_str(STDERR, ", and firewall = false in lightbox.conf. Only\n");
        print_str(STDERR, config.net == NET_PROXY ? "lightbox's rules keep it to its proxy, so it is not started without them\n"
                                                  : "lightbox's rules keep it to the internet and its name servers, so it is not\n"
                                                    "started without them\n");
        lc_kernel_exit(failure_status);
    }
    bool read_only = config.read_only;
    int oom_score = config.oom_score;

    /* One that overlays a snapshot has its root where init mounts the
     * overlay; the snapshot has to be there. */
    static char overlay[3 * MAX_PATH + 48];
    char merged[MAX_PATH];
    const char *start_root = root;
    if (config.base[0]) {
        char lower[MAX_PATH], work[MAX_PATH];
        if (!base_rootfs_path(lower, config.base) || !path_is_directory(lower))
            die2("Error: the base snapshot that the container overlays is not there: ", config.base);
        if (!overlay_dirs(name, work, merged) || !overlay_options(overlay, sizeof(overlay), config.base, root, work))
            die2("Error: the paths of the container's overlay cannot go into its options: ", name);
        start_root = merged;
    }

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
        lc_kernel_exit(failure_status);
    }
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;
    bool ruled = linked || net_has_rules(config.net);
    if (ruled && nftables)
        require_tool("nft", tool_path_nft());
    else if (ruled)
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
        lc_kernel_exit(failure_status);
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
    char port[IFNAME_TEXT_MAX] = "", port_err[128];
    bool port_made = false;
    if (networked) {
        host_port_name(name, port);
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
        if (owner == PORT_UNKNOWN) {
            start_err = "failed to look for what an earlier run left of the container's interface";
            port[0] = '\0';
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

    /* With --userns the root is made here, in a mount namespace of this
     * command's own, which init's is copied from: the snapshot, or the copy,
     * idmapped to the container's ids, which host root alone can do, and the
     * overlay on it. Init finds it mounted; nothing changes on the host. */
    if (config.userns) {
        char lower[MAX_PATH];
        if (lc_kernel_unshare(CLONE_NEWNS) < 0 || lc_kernel_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
            start_err = "failed to give the start a mount namespace of its own";
            goto fail_start;
        }
        if (config.base[0] && !base_rootfs_path(lower, config.base)) {
            start_err = "the path of the container's base snapshot is too long";
            goto fail_start;
        }
        if (idmap_in_place(config.base[0] ? lower : root, config.uid_start, config.gid_start, privileged) != 0) {
            start_err = "failed to idmap the container's root to its ids";
            goto fail_start;
        }
        if (config.base[0] &&
            do_mount("overlay", merged, "overlay", MS_NODEV | (privileged ? 0 : MS_NOSUID), overlay) != 0) {
            start_err = "failed to mount the container's overlay on its idmapped snapshot";
            goto fail_start;
        }
    }

    /* and its volumes, each idmapped to its source's owner; init has copies
     * of them when it is cloned, and these go then */
    static struct volume_mount userns_volumes[MAX_VOLS];
    int nuserns_volumes = 0;
    if (config.userns) {
        start_err = open_userns_volumes(&config, userns_volumes);
        if (start_err)
            goto fail_start;
        nuserns_volumes = config.nvols;
    }

    /* clone init; it waits for its first byte */
    struct child_args ca = {
        .starter_signals = signal_fd,
        .null_fd = null_fd,
        .log_fd = log_fd,
        .exit_fd = exit_fd,
        .name = name,
        .config = &config,
        .root = start_root,
        .overlay = config.base[0] && !config.userns ? overlay : NULL,
        .userns = config.userns,
        .volumes = config.userns ? userns_volumes : NULL,
        .nvolumes = nuserns_volumes,
        .hook = "/init.sh",
        .address = addr,
        .prefix = net.prefix,
        .gateway = net.gateway,
        .stop_grace = cfg_global.stop_timeout,
        .privileged = privileged,
        .read_only = read_only,
        .seccomp_allow = config.seccomp_allow,
    };
    int clone_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET |
                      (config.userns ? CLONE_NEWUSER : 0);

    start_err = init_spawn(&init, &ca, clone_flags, container_child);
    close_container_streams(&null_fd, &log_fd);     /* init has its own copies */
    close_volumes(userns_volumes, nuserns_volumes);
    lc_kernel_close_file(exit_fd);
    exit_fd = -1;
    if (start_err)
        goto fail_start;
    int child_pid = (int)init.pid;

    /*
     * Set up cgroup, networking, and OOM score before init gets its first
     * byte. While it waits for that byte it is certainly there, so everything
     * that names its PID or its network namespace has something to name.
     */

    /* its ids: uid and gid 0 there are the first of its range here */
    if (config.userns && userns_write_maps(child_pid, config.uid_start, config.gid_start) != 0) {
        start_err = "failed to write the maps of the container's user namespace";
        goto fail_start;
    }

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
     * bridge, and until then only this start knows the interface is its own.
     * Init brings eth0 up and gives it its address once it has its first
     * byte. A container of --net none has none. */
    if (networked) {
        rtnl nl;
        int rc = rtnl_open(&nl);
        if (rc < 0) {
            start_err = text_with_number(err_buf, sizeof(err_buf),
                                         "no netlink socket for the container's interface (errno ", -rc, ")");
            goto fail_start;
        }
        const char *failed = NULL;
        char alias[64];
        bool cut = false;
        str_append(alias, str_append(alias, 0, "lightbox:", sizeof(alias), &cut), name, sizeof(alias), &cut);
        int bridge = rtnl_link_get(&nl, cfg_global.bridge, NULL, 0);
        if (bridge < 0) {
            rc = bridge;
            failed = "failed to find the bridge (errno ";
        } else if ((rc = rtnl_veth_add(&nl, port, CONTAINER_IFNAME, child_pid)) < 0) {
            failed = "failed to create the container's interface (errno ";
        } else {
            port_made = true;
            if (cut)
                rc = -LB_EINVAL;
            else
                rc = rtnl_link_attach(&nl, port, alias, bridge);
            if (rc < 0) {
                failed = "failed to attach the container's interface to the bridge (errno ";
            } else if (!linked && (rc = rtnl_port_isolate(&nl, port)) < 0) {
                /* isolated ports do not reach each other, whatever the firewall does */
                failed = "failed to isolate the container's port on the bridge (errno ";
            } else if ((rc = rtnl_link_up(&nl, port)) < 0) {
                failed = "failed to bring the container's interface up on the host (errno ";
            }
        }
        rtnl_close(&nl);
        if (failed) {
            start_err = text_with_number(err_buf, sizeof(err_buf), failed, -rc, ")");
            goto fail_start;
        }
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
    if (firewall_add_rules(name, ip, &config) != 0) {
        start_err = "failed to put in the firewall rules of the container's links or --net";
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
    int count = names_and_seconds(argc, argv, &hook_wait, NULL);
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
        lc_kernel_exit(failure_status);
    }
    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' stopped\n");
}

static void cmd_stop(int argc, char **argv) {
    /* how long each container gets to end by itself */
    int seconds = cfg_global.stop_timeout;
    int count = names_and_seconds(argc, argv, &seconds, NULL);
    if (count == 0)
        die("Usage: lightbox stop <name>... [-t <seconds>]");
    require_root("stop");
    each_container("not stopped", count, argv, stop_one, seconds);
}

/* A container that runs, stopped in a process of its own, as stop does it:
 * true when it does not run afterwards. */
static bool stop_if_running(const char *name, int seconds) {
    if (!is_running(name))
        return true;
    lc_sysret pid = lc_kernel_fork();
    if (pid < 0)
        die("Error: cannot make a process to stop the container in");
    if (pid == 0) {
        stop_one(name, seconds);
        lc_kernel_exit(0);
    }
    int32_t status = 0;
    lc_sysret got;
    do {
        got = lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    } while (got == -LB_EINTR);
    return got == pid && exit_code_from_status(status) == 0;
}

/* restart: stopped, with -t as stop has it, if it runs, and started. */
static void restart_one(const char *name, int seconds) {
    require_root("restart");
    if (!stop_if_running(name, seconds))
        lc_kernel_exit(failure_status);
    start_one(name, cfg_global.start_timeout);
}

static void cmd_restart(int argc, char **argv) {
    int seconds = cfg_global.stop_timeout;
    int count = names_and_seconds(argc, argv, &seconds, NULL);
    if (count == 0)
        die("Usage: lightbox restart <name>... [-t <seconds>]");
    require_root("restart");
    each_container("not restarted", count, argv, restart_one, seconds);
}

/* ─── reset ─────────────────────────────────────────────────────────────── */

/*
 * reset <name>... [-t <seconds>] (ROADMAP 8.8): the root filesystem of a
 * container that overlays a snapshot made its base's again, without a copy:
 * its upper layer, rootfs/, and the overlay's work directory are replaced by
 * empty ones, and the /etc files that create wrote are written through the
 * overlay again. Its volumes, configuration, address and log are not
 * touched. One that runs is stopped first, as stop stops it. A container
 * that is a copy of its base has nothing to be reset to and is refused.
 *
 * While its layer is replaced the container is marked as one that create has
 * not finished: a reset cut short leaves it half made, not started by start,
 * and a reset again makes it whole, or rm removes it.
 */
static void reset_one(const char *name, int seconds) {
    require_root("reset");
    static container_config cfg;
    container_config_load_or_die(name, &cfg);
    if (!cfg.base[0])
        die2("Error: the container is a copy of its base, and not an overlay of a snapshot, so it has\n"
             "nothing to be reset to; remove it and create it again: ", name);
    if (!stop_if_running(name, seconds))
        lc_kernel_exit(failure_status);

    container_lock(name);
    if (is_running(name))
        die2("Error: the container was started again before it could be reset: ", name);
    (void)reconcile(name);      /* one that ended without a stop is cleared away first */
    container_config_load_or_die(name, &cfg);
    if (!cfg.base[0])
        die2("Error: the container is a copy of its base, and has nothing to be reset to: ", name);
    char lower[MAX_PATH];
    if (!base_rootfs_path(lower, cfg.base) || !path_is_directory(lower))
        die2("Error: the base snapshot that the container overlays is not there: ", cfg.base);
    /* nothing is taken away before an overlay is known to mount */
    if (!overlay_mounts_here(name, cfg.userns ? &cfg : NULL))
        die2("Error: no overlay can be mounted here, and the container is left as it was: ", name);

    char ip[IPV4_TEXT_MAX] = "";
    if (cfg.net != NET_NONE && read_container_ip(name, ip, sizeof(ip)) < 0)
        die2("Error: the container's address is not on record: ", name);
    static char resolv[RESOLV_TEXT_MAX];
    char resolv_path[MAX_PATH];
    container_resolv_path(resolv_path, name);
    if (read_file(resolv_path, resolv, sizeof(resolv)) <= 0) {
        /* made before create kept it: what create would write now, with
         * the name servers of --net outside as they are on record */
        static container_config again;
        again = cfg;
        char dns[MAX_DNS][16];
        const char *failed = make_resolv(&again, dns, 0, resolv);
        if (failed)
            die2("Error: ", failed);
        print_str(STDERR, "Note: the container was made before lightbox kept its resolv.conf: it gets the one\n"
                          "create would write now\n");
    }

    char creating[MAX_PATH], root[MAX_PATH], work[MAX_PATH], merged[MAX_PATH];
    container_creating_path(creating, name);
    container_root(root, name);
    if (!overlay_dirs(name, work, merged))
        die2("Error: the paths of the container's overlay are too long: ", name);
    print_str(STDOUT, "Resetting container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "'...\n");
    if (write_file_atomic(creating, "", MODE_PRIVATE_FILE) != 0)
        die("Error: failed to mark the container as being reset");
    const char *dirs[] = { root, work, merged };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        if (path_exists(dirs[i]))
            require_rm_rf(dirs[i]);
    if (overlay_etc(name, &cfg, ip, resolv, NULL) != 0)
        die2("Error: failed to write the container's files in /etc; it is left half made, and reset\n"
             "makes it whole: ", name);
    container_forget_run(name);
    if (remove_file_durably(creating) != 0)
        die("Error: failed to mark the container as reset");
    print_str(STDOUT, "Container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "' reset: its root filesystem is its base's again\n");
}

static void cmd_reset(int argc, char **argv) {
    int seconds = cfg_global.stop_timeout;
    int count = names_and_seconds(argc, argv, &seconds, NULL);
    if (count == 0)
        die("Usage: lightbox reset <name>... [-t <seconds>]");
    require_root("reset");
    each_container("not reset", count, argv, reset_one, seconds);
}

/* ─── cmd_update ────────────────────────────────────────────────────────── */

/*
 * update <name> --mem/--pids/--cpu: the limits in the container's
 * configuration, which every start reads, and in the cgroup of a container
 * that runs. The configuration is changed first; a running container that
 * does not take a limit has it from its next start, and that is said.
 */
static void cmd_update(int argc, char **argv) {
    static container_config given;
    container_config_init(&given);
    given.mem[0] = given.pids[0] = given.cpu[0] = '\0';
    const char *name = NULL;
    for (int i = 0; i < argc; i++) {
        if (limit_option(argc, argv, &i, &given))
            continue;
        if (argv[i][0] == '-')
            die2("Error: unknown option: ", argv[i]);
        if (name)
            die2("Error: unexpected argument: ", argv[i]);
        name = argv[i];
    }
    if (!name || (!given.mem[0] && !given.pids[0] && !given.cpu[0]))
        die("Usage: lightbox update <name> [--mem <limit>] [--pids <limit>] [--cpu <num>]");
    validate_name(name);
    require_root("update");
    container_lock(name);

    static container_config config;
    container_config_load_or_die(name, &config);
    if (given.mem[0])  lc_bytes_copy(config.mem, given.mem, sizeof(config.mem));
    if (given.pids[0]) lc_bytes_copy(config.pids, given.pids, sizeof(config.pids));
    if (given.cpu[0])  lc_bytes_copy(config.cpu, given.cpu, sizeof(config.cpu));
    const char *wrong = container_config_save(name, &config);
    if (wrong)
        die_about("Error: container ", wrong, name);
    print_str(STDOUT, "Container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "' updated\n");
    if (!is_running(name)) {
        print_str(STDOUT, "It is not running: it has them from its next start\n");
        return;
    }

    char cg[MAX_PATH], cpu_max[32];
    if (!cgroup_path(cg, name))
        die("Error: the path of the container's cgroup is too long");
    const struct { const char *file, *value, *what; } live[] = {
        { "memory.max", given.mem, "memory limit" },
        { "pids.max", given.pids, "process limit" },
        { "cpu.max", given.cpu[0] && cpu_max_text(given.cpu, cpu_max, sizeof(cpu_max)) ? cpu_max : "", "CPU limit" },
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(live) / sizeof(live[0]); i++) {
        if (!live[i].value[0])
            continue;
        if (cgroup_write(cg, live[i].file, live[i].value) < 0) {
            print_str(STDERR, "Error: the running container did not take the new ");
            print_str(STDERR, live[i].what);
            print_str(STDERR, " (");
            print_str(STDERR, live[i].file);
            print_str(STDERR, "); it has it from its next start\n");
            failed++;
        }
    }
    if (failed)
        lc_kernel_exit(failure_status);
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

static void rm_one(const char *name, int force) {
    /* with --force, one that runs is killed first, as docker rm -f does */
    if (force && !stop_if_running(name, 0))
        lc_kernel_exit(failure_status);
    container_lock(name);

    if (is_running(name)) die2("Error: container is running (stop it first): ", name);

    /* one that ended without a stop still has a cgroup and firewall rules:
     * cleared away, and the rules of a command that was cut short with them */
    (void)reconcile(name);
    if (firewall_remove_links(name) != 0)
        die2("Error: the container is not removed while the firewall rules of its links are there: ", name);
    if (firewall_remove_egress(name) != 0)
        die2("Error: the container is not removed while the firewall rules of its --net are there: ", name);

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
    bool force = false;
    int count = names_and_seconds(argc, argv, NULL, &force);
    if (count == 0)
        die("Usage: lightbox rm [-f] <name>...");
    each_container("not removed", count, argv, rm_one, force);
}

/* ─── cmd_exec ──────────────────────────────────────────────────────────── */

/* The caller's TERM goes with the command, when it is a plain name. */
static void request_term(struct exec_request *req) {
    const char *term = env_get(caller_env, "TERM");
    if (term && term_is_plain(term))
        req->term = term;
}

/*
 * The audit log (ROADMAP 8.9, lightbox_audit.c): a line as the command is
 * about to start, and one when it has ended, which a failure in between
 * writes too. An exec whose start cannot be recorded does not run; one whose
 * end cannot be says so and exits as it would have.
 */
static const char *exec_via = "exec";       /* "run" in the exec of a run */
static struct audit_end exec_audit;
static int64_t exec_audit_started;

static void audit_failed(const char *what, int rc) {
    char path[MAX_PATH], digits[16];
    audit_log_path(path);
    fmt_int(digits, -rc);
    print_str(STDERR, what);
    print_str(STDERR, path);
    print_str(STDERR, " (errno ");
    print_str(STDERR, digits);
    print_str(STDERR, ")");
}

static void exec_audit_end(int status, bool timed_out) {
    on_failure(NULL);
    exec_audit.status = status;
    exec_audit.duration_ms = monotonic_ms() - exec_audit_started;
    exec_audit.timed_out = timed_out;
    int rc = audit_record_end(&exec_audit);
    if (rc < 0) {
        audit_failed("Warning: the end of this exec is not in the audit log ", rc);
        lc_print_char(STDERR, '\n');
    }
}

static void exec_audit_failed(void) {
    exec_audit_end(failure_status, false);
}

/* The start, and from then on a failure records an end: false if the start
 * is not in the log. */
static bool exec_audit_start(const char *name, const container_config *config, const char *cg,
                             const struct exec_request *req, int64_t started) {
    /* the exec's cgroup is EXEC_CGROUP_PREFIX<pid>-<start time> */
    const char *exec_id = cg;
    for (const char *c = cg; *c; c++) {
        if (*c == '/')
            exec_id = c + 1;
    }
    exec_id += lc_string_length(EXEC_CGROUP_PREFIX);

    struct audit_start a = {
        .box = name, .box_id = config->id, .exec_id = exec_id, .via = exec_via,
        .uid = (int64_t)(uint32_t)lb_sys_getuid(), .loginuid = audit_loginuid(),
        .user = req->user_text, .workdir = req->workdir_text, .timeout = req->timeout_text,
        .env = req->env, .nenv = req->nenv, .argv = req->argv,
    };
    int rc = audit_record_start(&a);
    if (rc < 0) {
        audit_failed("Error: cannot write to the audit log ", rc);
        print_str(STDERR, ", and an exec that it does not record is not run\n");
        return false;
    }
    exec_audit = (struct audit_end){ .box = name, .box_id = config->id, .exec_id = exec_id };
    exec_audit_started = started;
    on_failure(exec_audit_failed);
    return true;
}

static void cmd_exec(int argc, char **argv) {
    /* from the first moment the time limit can be counted from */
    int64_t started = monotonic_ms();
    if (argc < 1)
        die("Usage: lightbox exec <name> [--user <name|uid[:gid]>] [--env KEY=VALUE]... [--workdir <dir>] [--timeout <duration>] [--] [cmd [args...]]");
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
    /* a box with a workspace runs every command there that names no other
     * (ROADMAP 8.10) */
    if (!req.workdir && config.workdir[0])
        req.workdir = config.workdir;
    int pid = get_container_pid(name);
    bool privileged = config.privileged;
    /* where its proxy is: the gateway that it started with, as lightbox.conf
     * has it, which start sees to */
    static char proxy[PROXY_ENV_COUNT][PROXY_VAR_MAX];
    if (config.net == NET_PROXY) {
        container_network net;
        container_network_load_or_die(&net);
        req.nproxy = proxy_environment(&config, net.gateway, proxy);
        for (int i = 0; i < req.nproxy; i++)
            req.proxy[i] = proxy[i];
    }

    /* The terminal's modes as they are now. The worker makes the terminal
     * raw while a command has a terminal of its own, and puts the modes back;
     * this process puts them back as well, because the worker is in the
     * container's cgroup and ends without a word when the container is
     * stopped. */
    struct lb_termios modes;
    bool restore = lc_kernel_device_control(STDIN, LB_TCGETS, &modes) >= 0;

    static char cg[MAX_PATH];
    exec_cgroup_make(name, cg);
    if (req.timeout_ms) {
        lc_sysret self = lb_sys_pidfd_open(lc_kernel_get_process_id(), 0);
        if (self < 0) {
            exec_cgroup_end(name, cg, false);
            die("Error: --timeout needs a pidfd (Linux 5.3), for the worker to keep the limit with");
        }
        req.caller_fd = (int32_t)self;
        req.keeper_deadline = started + req.timeout_ms + EXEC_KEEPER_MARGIN_MS;
    }

    int32_t signal_fd = hold_relay_signals();
    if (signal_fd < 0) {
        exec_cgroup_end(name, cg, false);
        die("Error: failed to take over the signals of an exec");
    }

    if (!exec_audit_start(name, &config, cg, &req, started)) {
        exec_cgroup_end(name, cg, false);
        lc_kernel_exit(failure_status);
    }

    lc_sysret worker = lc_kernel_fork();
    if (worker < 0) {
        exec_cgroup_end(name, cg, false);
        die("Error: failed to fork exec worker");
    }

    if (worker == 0) {
        /* the end of the exec is the caller's to record, never the worker's,
         * whose PID in the container's namespace says nothing */
        on_failure(NULL);
        lc_kernel_close_file(signal_fd);
        int status = exec_inside_container(cg, pid, privileged, config.userns, config.seccomp_allow,
                                           config.oom_score, &req);
        lc_kernel_exit(exit_code_from_status(status));
    }

    bool timed_out;
    int code = finish_exec((int32_t)worker, signal_fd, restore ? &modes : NULL, cg,
                           req.timeout_ms ? started + req.timeout_ms : 0, &timed_out);
    exec_cgroup_end(name, cg, req.timeout_ms != 0);
    if (timed_out) {
        print_str(STDERR, "Error: the command ran past its time limit, --timeout ");
        print_str(STDERR, req.timeout_text);
        print_str(STDERR, ", and it and all it started were ended\n");
        code = EXEC_TIMED_OUT;
    }
    exec_audit_end(code, timed_out);
    lc_kernel_exit(code);
}

/* ─── run ───────────────────────────────────────────────────────────────── */

/*
 * run [create options] [exec options] [--] [cmd [args...]] (ROADMAP 8.8): a
 * box for one command. It is created under a name of its own, run- and 12
 * hex digits, started, the command run in it as exec runs it, and removed,
 * and run exits as exec does: with the command's status, or 124 to 127.
 * Each step is a child of run's, so that one that ends its process when it
 * fails does not keep the box from being removed, and what the steps print
 * but their errors is put away: what run prints is the command's.
 *
 * SIGINT, SIGTERM and SIGHUP for run go on to the command as exec passes
 * them on, and to a start, which undoes itself; a create is let finish. The
 * box is then removed: once the command has ended, or when it has not within
 * stop_timeout. The removal has a session of its own, so that a terminal's
 * keys do not cut it short. A box whose run was killed outright stays: its
 * .runner has that run's PID and start time, and the next run removes it.
 */
#define RUN_NAME_PREFIX "run-"
#define RUN_ARGV_MAX    65536

enum run_step { RUN_CREATE, RUN_START, RUN_EXEC, RUN_REMOVE };
enum run_pass { PASS_NONE, PASS_ALL, PASS_SENT };

struct run_box {
    char   name[NAME_MAX_LEN + 1];
    char **create_argv;
    int    create_argc;
    char **exec_argv;
    int    exec_argc;
    int32_t sfd;
};

static bool in_list(const char *arg, const char *const *list, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (streq(arg, list[i]))
            return true;
    return false;
}

/*
 * run's arguments as create's, which go into create_argv after the name, and
 * exec's, which go into exec_argv after it with "--" and the command. Ends
 * the process on an option that neither takes and on a value that is missing.
 */
static void run_split(int argc, char **argv, struct run_box *box) {
    static char *create_argv[2 * (sizeof(create_value_options) / sizeof(create_value_options[0]) +
                                  sizeof(create_flag_options) / sizeof(create_flag_options[0])) + RUN_ARGV_MAX];
    static char *exec_argv[RUN_ARGV_MAX + 8];
    static char dashdash[] = "--";
    int c = 1, e = 1, i = 0;
    for (; i < argc; i++) {
        char *arg = argv[i];
        if (streq(arg, "--")) {
            i++;
            break;
        }
        if (arg[0] != '-')
            break;
        bool for_exec = streq(arg, "--user") || streq(arg, "-u") || streq(arg, "--env") || streq(arg, "-e") ||
                        streq(arg, "--workdir") || streq(arg, "-w") || streq(arg, "--timeout");
        bool takes_value = for_exec || in_list(arg, create_value_options,
                                               sizeof(create_value_options) / sizeof(create_value_options[0]));
        if (!takes_value && !in_list(arg, create_flag_options, sizeof(create_flag_options) / sizeof(create_flag_options[0]))) {
            print_str(STDERR, "Error: unknown option: ");
            print_str(STDERR, arg);
            print_str(STDERR, "\nA command that begins with a dash goes after --.\n");
            lc_kernel_exit(failure_status);
        }
        if (c >= RUN_ARGV_MAX || e >= RUN_ARGV_MAX)
            die("Error: run takes no more than " STRINGIFY(RUN_ARGV_MAX) " words");
        char **into = for_exec ? exec_argv : create_argv;
        int *at = for_exec ? &e : &c;
        into[(*at)++] = arg;
        if (takes_value)
            into[(*at)++] = (char *)(uintptr_t)option_value(argc, argv, &i);
    }
    exec_argv[e++] = dashdash;
    for (; i < argc; i++) {
        if (e >= RUN_ARGV_MAX)
            die("Error: run takes no more than " STRINGIFY(RUN_ARGV_MAX) " words");
        exec_argv[e++] = argv[i];
    }
    create_argv[c] = NULL;
    exec_argv[e] = NULL;
    box->create_argv = create_argv;
    box->create_argc = c;
    box->exec_argv = exec_argv;
    box->exec_argc = e;
}

/* A name no container has had: run- and 12 hex digits from the kernel. */
static void run_name(char out[NAME_MAX_LEN + 1]) {
    size_t at = lc_string_length(RUN_NAME_PREFIX);
    lc_bytes_copy(out, RUN_NAME_PREFIX, at);
    if (!random_hex(out + at, 6))
        die("Error: cannot draw a name for the box");
}

/* One step of run, in a child: the child's PID. All but exec's have /dev/null
 * for stdin and stdout; the removal has a session of its own. */
static lc_sysret run_fork(enum run_step step, const struct run_box *box, const char *name) {
    lc_sysret pid = lc_kernel_fork();
    if (pid != 0)
        return pid;
    lc_kernel_close_file(box->sfd);
    if (step != RUN_EXEC) {
        lc_sysret null = lc_kernel_open_file("/dev/null", O_RDWR | O_CLOEXEC, 0);
        if (null < 0 || lc_kernel_duplicate_fd((int32_t)null, STDIN, 0) < 0 ||
            lc_kernel_duplicate_fd((int32_t)null, STDOUT, 0) < 0)
            die("Error: cannot put away what a step of run prints");
    }
    if (step == RUN_REMOVE || step == RUN_CREATE)
        (void)lc_kernel_create_session();
    switch (step) {
        case RUN_CREATE:
            cmd_create(box->create_argc, box->create_argv);
            break;
        case RUN_START:
            start_one(name, cfg_global.start_timeout);
            break;
        case RUN_EXEC:
            exec_via = "run";
            cmd_exec(box->exec_argc, box->exec_argv);
            break;
        case RUN_REMOVE:
            rm_one(name, 1);
            break;
    }
    lc_kernel_exit(0);
}

/*
 * Wait for a step's child: its exit status. A signal for run is noted in
 * *asked, the first, and passed on as pass says: to all of them, or to those
 * a process sent, as one from the terminal has reached the child by itself.
 * With give_up, -1 once stop_timeout has passed since the first, the child
 * still there.
 */
static int run_wait(lc_sysret child, int32_t sfd, enum run_pass pass, int *asked, bool give_up) {
    int64_t deadline = 0;
    for (;;) {
        int32_t status = 0;
        if (lc_kernel_wait_for_child((int32_t)child, &status, WNOHANG) == child)
            return exit_code_from_status(status);
        lc_timespec left, *wait = NULL;
        if (deadline) {
            int64_t ms = deadline - monotonic_ms();
            if (ms <= 0)
                return -1;
            left.seconds = ms / 1000;
            left.nanoseconds = (ms % 1000) * 1000000;
            wait = &left;
        }
        struct lb_pollfd one = { .fd = sfd, .events = LB_POLLIN, .revents = 0 };
        lc_sysret ready = lb_sys_ppoll(&one, 1, wait);
        if (ready < 0 && ready != -LB_EINTR)
            die("Error: failed to wait for a step of run");
        if (ready <= 0)
            continue;
        lc_signal_info si;
        if (lc_kernel_read_retry(sfd, &si, sizeof(si)) != (lc_sysret)sizeof(si) || si.signal == SIGCHLD)
            continue;
        if (!*asked)
            *asked = (int)si.signal;
        if (pass == PASS_ALL || (pass == PASS_SENT && si.code <= 0))
            lc_kernel_send_signal((int32_t)child, (int32_t)si.signal);
        if (give_up && !deadline)
            deadline = monotonic_ms() + (int64_t)cfg_global.stop_timeout * 1000;
    }
}

/* Remove a box, saying so when it could not be: true when it is gone. */
static bool run_remove(const struct run_box *box, const char *name) {
    int ignored = 0;
    lc_sysret pid = run_fork(RUN_REMOVE, box, name);
    int code = pid < 0 ? -1 : run_wait(pid, box->sfd, PASS_NONE, &ignored, false);
    char cdir[MAX_PATH];
    container_dir_path(cdir, name);
    if (code == 0 && !path_exists(cdir))
        return true;
    print_str(STDERR, "Error: the box '");
    print_str(STDERR, name);
    print_str(STDERR, "' could not be removed; the next run removes it, or lightbox rm -f does\n");
    return false;
}

/* Is the run that .runner names still there: its PID, with that start time? */
static bool runner_alive(const char *text) {
    int64_t pid = 0;
    size_t i = 0;
    for (; text[i] >= '0' && text[i] <= '9'; i++) {
        pid = pid * 10 + (text[i] - '0');
        if (pid > INT32_MAX)
            return false;
    }
    if (i == 0 || pid == 0 || text[i] != ' ')
        return false;
    char started[32], now[32];
    size_t n = 0;
    for (i++; text[i] >= '0' && text[i] <= '9' && n + 1 < sizeof(started); i++)
        started[n++] = text[i];
    started[n] = '\0';
    return n > 0 && proc_starttime((int)pid, now, sizeof(now)) == 0 && streq(now, started);
}

/* The boxes of runs that are gone, removed. */
static void run_sweep(const struct run_box *box) {
    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    bool more = false;
    int count = list_containers(names, MAX_LISTED, &more);
    for (int i = 0; i < count; i++) {
        char path[MAX_PATH], text[48];
        container_runner_path(path, names[i]);
        if (read_file(path, text, sizeof(text)) <= 0 || runner_alive(text))
            continue;
        print_str(STDERR, "Note: removing the box '");
        print_str(STDERR, names[i]);
        print_str(STDERR, "', whose run is gone\n");
        (void)run_remove(box, names[i]);
    }
}

static void cmd_run(int argc, char **argv) {
    /* the whole of it from a sealed copy, which its exec then is */
    run_sealed();

    static struct run_box box;
    run_split(argc, argv, &box);
    /* exec's options looked at before anything is made: the name is put in
     * its place later */
    {
        static char placeholder[] = "run-";
        struct exec_request req = { .as = AS_ROOT, .gid = -1 };
        box.exec_argv[0] = placeholder;
        (void)parse_exec_options(box.exec_argc, box.exec_argv, 1, &req);
    }
    require_root("run");

    uint64_t asked_set = sigmask_from_signal(SIGINT) | sigmask_from_signal(SIGTERM) | sigmask_from_signal(SIGHUP);
    uint64_t held = asked_set | sigmask_from_signal(SIGCHLD);
    if (lc_kernel_set_signal_mask(LC_SIG_BLOCK, &held, NULL) < 0)
        die("Error: failed to take over run's signals");
    lc_sysret sfd = lc_kernel_create_signal_fd(-1, &held, SFD_CLOEXEC);
    if (sfd < 0)
        die("Error: failed to take over run's signals");
    box.sfd = (int32_t)sfd;

    run_sweep(&box);

    run_name(box.name);
    box.create_argv[0] = box.name;
    box.exec_argv[0] = box.name;
    {
        char self[16], started[32];
        int pid = lc_kernel_get_process_id();
        fmt_int(self, pid);
        if (proc_starttime(pid, started, sizeof(started)) < 0)
            die("Error: cannot read the start time of run, for its box");
        bool cut = false;
        size_t at = str_append(create_runner, 0, self, sizeof(create_runner), &cut);
        at = str_append(create_runner, at, " ", sizeof(create_runner), &cut);
        at = str_append(create_runner, at, started, sizeof(create_runner), &cut);
        (void)str_append(create_runner, at, "\n", sizeof(create_runner), &cut);
        if (cut)
            die("Error: the record of run does not fit");
    }

    int asked = 0;
    char cdir[MAX_PATH];
    container_dir_path(cdir, box.name);
    lc_sysret step = run_fork(RUN_CREATE, &box, box.name);
    int code = step < 0 ? -1 : run_wait(step, box.sfd, PASS_NONE, &asked, false);
    if (code != 0) {
        if (path_exists(cdir))
            (void)run_remove(&box, box.name);
        lc_kernel_exit(asked ? 128 + asked : EXEC_FAILED);
    }
    if (!asked) {
        step = run_fork(RUN_START, &box, box.name);
        code = step < 0 ? -1 : run_wait(step, box.sfd, PASS_ALL, &asked, false);
    }
    if (code != 0 || asked) {
        (void)run_remove(&box, box.name);
        lc_kernel_exit(asked ? 128 + asked : EXEC_FAILED);
    }

    step = run_fork(RUN_EXEC, &box, box.name);
    if (step < 0) {
        (void)run_remove(&box, box.name);
        die("Error: cannot make a process for the command of run");
    }
    code = run_wait(step, box.sfd, PASS_SENT, &asked, true);
    if (code < 0) {
        /* asked to end, and the command has not: the box goes with it */
        (void)run_remove(&box, box.name);
        int32_t status = 0;
        lc_sysret got;
        do {
            got = lc_kernel_wait_for_child((int32_t)step, &status, 0);
        } while (got == -LB_EINTR);
        code = got == step ? exit_code_from_status(status) : 128 + asked;
    } else {
        (void)run_remove(&box, box.name);
    }
    lc_kernel_exit(code);
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
        "         --rootfs <path>        The base it is made from (default: $LIGHTBOX_ROOTFS or lightbox.conf)\n"
        "         --userns               A user namespace of its own: its root is an unprivileged uid\n"
        "                                on the host, from the range of /etc/subuid; as root\n"
        "         --read-only            Read-only root filesystem\n"
        "         --copy                 A copy of the base, and not an overlay of its snapshot\n"
        "         --privileged           Disable security sandbox\n"
        "         --seccomp allow|deny   The seccomp profile: the allow-list, or the deny-list\n"
        "                                (default: allow)\n"
        "         --net <mode>           What it may reach: outside, the internet and its name servers\n"
        "                                only (the default); nat, the network as before 0.8; none,\n"
        "                                nothing; proxy:<port>, that port of the gateway, where a\n"
        "                                proxy listens, and nothing else\n"
        "         --oom-score <n>        OOM score adjustment (default: 500)\n"
        "         --ttl <duration>       How long it may run from each start, such as 30m or 8h; then\n"
        "                                it stops as stop stops it, and is expired\n"
        "         --link <name>          Allow network to another container\n"
        "         --dns <address>        A name server for the container (up to 3; default: the host's)\n"
        "         --profile <name>       agent: a user namespace, the allow-list, an overlay, and the\n"
        "                                network of --net none unless --net outside or proxy:<port> is\n"
        "                                given, with the limits and lifetime of the agent_* settings. As\n"
        "                                root; it refuses --privileged, --link, --net nat, --seccomp deny\n"
        "                                and --copy\n"
        "         --workspace <dir>      The directory at /workspace, where every exec runs\n" },
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
    { "restart",
        "  restart <name>... [-t <seconds>]  Stop containers that run, as stop does, and start them\n" },
    { "reset",
        "  reset  <name>... [-t <seconds>]  Make the root filesystem of containers their base's again,\n"
        "                                without a copy; one that runs is stopped first. Volumes are kept\n" },
    { "update",
        "  update <name> [--mem <limit>] [--pids <limit>] [--cpu <num>]\n"
        "                                Change a container's limits, live if it runs and from its next\n"
        "                                start in any case\n" },
    { "rm",
        "  rm     [-f] <name>...         Remove containers; -f kills one that runs first\n" },
    { "exec",
        "  exec   <name> [options] [--] [cmd [args...]]  Run a command in a running container\n"
        "         --user <name|uid[:gid]> Who to run it as (default: root)\n"
        "         --env <KEY=VALUE>       Set a variable in its environment (repeatable)\n"
        "         --workdir <dir>         The directory to run it in (default: /)\n"
        "         --timeout <duration>    End it, and all it started, after this long, such as 30s,\n"
        "                                 5m or 1.5h; exec then exits with 124\n"
        "         exec exits with the command's status, or 128 plus the signal that ended it; with\n"
        "         125 when lightbox failed, 126 when the command could not be run, 127 when not found\n" },
    { "run",
        "  run    [create options] [exec options] [--] [cmd [args...]]\n"
        "                                Create a box, start it, run a command in it as exec runs it,\n"
        "                                and remove it; run exits as exec does. A box whose run was\n"
        "                                killed is removed by the next run\n" },
    { "logs",
        "  logs   <name> [-f] [--audit]  Show what the container has printed; -f follows it. --audit\n"
        "                                shows what exec and run asked of it, kept after it is removed\n" },
    { "inspect",
        "  inspect <name> [--json]       Show a container's configuration and state; --json as JSON\n" },
    { "doctor",
        "  doctor [--json] [--profile agent]\n"
        "                                Check what lightbox needs of this host, and say how to fix what\n"
        "                                is missing; --json as JSON. --profile agent checks what a box of\n"
        "                                that profile needs too\n" },
    { "ls",
        "  ls [--json]                   List all containers\n" },
    { "export",
        "  export <name> <dir>           Write a container that is not running as an image in <dir>,\n"
        "                                which is made: an OCI image layout, as skopeo and oras carry\n"
        "                                one to a registry\n" },
    { "import",
        "  import <dir> <name> [<ip>] [options]\n"
        "                                Make a container of the image in <dir>, an OCI image layout, with\n"
        "                                the options of create but --rootfs. Every blob is held to the\n"
        "                                digest it is named by first; the limits no option gives are the\n"
        "                                image's; as root\n" },
    { "base",
        "  base ls                       List the snapshots of bases that containers overlay\n"
        "  base add <dir>                Take a new snapshot of a base, for the containers made after it\n"
        "  base rm <id>...               Remove snapshots that no container uses\n" },
    { "setup",
        "  setup                         Setup host networking\n"
        "  setup --teardown              Take lightbox's host network away, when no container runs\n" },
    { "reload",
        "  reload                        Put lightbox's firewall rules and bridge in again, and the links\n"
        "                                of running containers, after a firewall's reload took them\n" },
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
    lc_kernel_exit(failure_status);
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
    /* exec's status is its command's, and lightbox's own failures have
     * one of their own there, from here on */
    if (streq(args[0], "exec") || streq(args[0], "run"))
        failure_status = EXEC_FAILED;

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
    else if (streq(cmd, "restart")) cmd_restart(sub_argc, sub_argv);
    else if (streq(cmd, "reset"))  cmd_reset(sub_argc, sub_argv);
    else if (streq(cmd, "update")) cmd_update(sub_argc, sub_argv);
    else if (streq(cmd, "add-vol")) cmd_add_vol(sub_argc, sub_argv);
    else if (streq(cmd, "rm-vol")) cmd_rm_vol(sub_argc, sub_argv);
    else if (streq(cmd, "rm"))     cmd_rm(sub_argc, sub_argv);
    else if (streq(cmd, "exec"))   cmd_exec(sub_argc, sub_argv);
    else if (streq(cmd, "run"))    cmd_run(sub_argc, sub_argv);
    else if (streq(cmd, "logs"))   cmd_logs(sub_argc, sub_argv);
    else if (streq(cmd, "inspect")) cmd_inspect(sub_argc, sub_argv);
    else if (streq(cmd, "doctor")) cmd_doctor(sub_argc, sub_argv);
    else if (streq(cmd, "ls"))     cmd_ls(sub_argc, sub_argv);
    else if (streq(cmd, "export")) cmd_export(sub_argc, sub_argv);
    else if (streq(cmd, "import")) cmd_import(sub_argc, sub_argv);
    else if (streq(cmd, "base"))   cmd_base(sub_argc, sub_argv);
    else if (streq(cmd, "reload")) cmd_reload(sub_argc, sub_argv);
    else {
        print_str(STDERR, "Error: unknown command: ");
        print_str(STDERR, cmd);
        print_str(STDERR, "\n\n");
        usage();
    }

    return 0;
}
