/*
 * lightbox — a minimal, secure Linux container runtime
 *
 * Built on lightc (freestanding C, no libc). Uses raw Linux syscalls for
 * namespace isolation, cgroups v2, pivot_root, seccomp, and capability dropping.
 *
 * Usage: lightbox <command> [args]
 *   setup                         — initialize host networking
 *   create <name> <ip> [options]  — create a container
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
#define NAME_MAX_LEN     12
#define USERNS_RANGE_SIZE 65536
#define USERNS_MIN_START 100000
#define CHILD_STACK_SIZE (1024 * 1024) /* 1 MiB */

/* ─── Configurable defaults ─────────────────────────────────────────────── */

/* All runtime-configurable values live here. Initialized to built-in defaults,
 * then overridden by lightbox.conf if present. */
global_config cfg_global;

/* cfg_global_init() and cfg_global_load() defined after utility functions */

/* device numbers: makedev(major, minor) */
#define MAKEDEV(ma, mi) (((uint64_t)(ma) << 8) | (mi))

/* ─── Structs ───────────────────────────────────────────────────────────── */

typedef struct {
    char name[NAME_MAX_LEN + 1];
    char ip[16];
    char mem[16];
    char pids[8];
    char cpu[4];
    int  userns;
    int  uid_start;
    int  privileged;
    int  read_only;
    int  oom_score;
    int  nvols;
    char vol_src[MAX_VOLS][MAX_PATH];
    char vol_dst[MAX_VOLS][MAX_PATH];
    int  vol_ro[MAX_VOLS];
    int  nlinks;
    char links[MAX_LINKS][NAME_MAX_LEN + 1];
} container_config;

typedef struct {
    char src[MAX_PATH];
    char dst[MAX_PATH];
    int ro;
} volume_spec;

/* ─── Utility functions ─────────────────────────────────────────────────── */

static bool parse_u32_strict(const char *s, uint32_t *out) {
    uint32_t val = 0;
    if (!s || !s[0]) return false;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c < '0' || c > '9') return false;
        val = val * 10u + (uint32_t)(c - '0');
    }
    *out = val;
    return true;
}

static bool parse_ipv4(const char *s, uint8_t out[4]) {
    uint32_t cur = 0;
    int octet = 0;
    bool have_digit = false;
    if (!s || !s[0]) return false;

    for (size_t i = 0;; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            have_digit = true;
            cur = cur * 10u + (uint32_t)(c - '0');
            if (cur > 255u) return false;
        } else if (c == '.' || c == '\0') {
            if (!have_digit || octet >= 4) return false;
            out[octet++] = (uint8_t)cur;
            cur = 0;
            have_digit = false;
            if (c == '\0') break;
        } else {
            return false;
        }
    }

    return octet == 4;
}

static uint32_t ipv4_to_u32(const uint8_t ip[4]) {
    return ((uint32_t)ip[0] << 24) |
           ((uint32_t)ip[1] << 16) |
           ((uint32_t)ip[2] << 8) |
           (uint32_t)ip[3];
}

static bool parse_cidr_ipv4(const char *cidr, uint8_t net[4], uint32_t *prefix) {
    const char *slash = NULL;
    for (const char *p = cidr; *p; p++) {
        if (*p == '/') { slash = p; break; }
    }
    if (!slash) return false;

    char ip_part[20];
    size_t ip_len = (size_t)(slash - cidr);
    if (ip_len == 0 || ip_len >= sizeof(ip_part)) return false;
    lc_bytes_copy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    if (!parse_ipv4(ip_part, net)) return false;
    if (!parse_u32_strict(slash + 1, prefix)) return false;
    return *prefix <= 32u;
}

static void validate_ipv4_address(const char *ip) {
    uint8_t tmp[4];
    if (!parse_ipv4(ip, tmp))
        die2("Error: invalid IPv4 address: ", ip);
}

static void validate_ip_in_subnet(const char *ip, const char *cidr) {
    uint8_t ip_octets[4], net_octets[4];
    uint32_t prefix = 0;
    if (!parse_ipv4(ip, ip_octets))
        die2("Error: invalid IPv4 address: ", ip);
    if (!parse_cidr_ipv4(cidr, net_octets, &prefix))
        die2("Error: invalid subnet in config: ", cidr);

    uint32_t mask = (prefix == 0) ? 0u : (0xffffffffu << (32u - prefix));
    if ((ipv4_to_u32(ip_octets) & mask) != (ipv4_to_u32(net_octets) & mask))
        die2("Error: IP is outside configured subnet: ", ip);
}

static void validate_positive_integer_option(const char *label, const char *value) {
    uint32_t parsed;
    if (!parse_u32_strict(value, &parsed) || parsed == 0)
        die2(label, value);
}

static void validate_oom_score(int oom_score) {
    if (oom_score < -1000 || oom_score > 1000)
        die("Error: oom-score must be between -1000 and 1000");
}

static void validate_volume_paths(const char *src, const char *dst) {
    if (!src[0]) die("Error: volume source must not be empty");
    if (src[0] != '/') die2("Error: volume source must be an absolute path: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/proc", 5) &&
        (src[5] == '\0' || src[5] == '/'))
        die2("Error: volume source under /proc is not allowed: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/sys", 4) &&
        (src[4] == '\0' || src[4] == '/'))
        die2("Error: volume source under /sys is not allowed: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/dev", 4) &&
        (src[4] == '\0' || src[4] == '/'))
        die2("Error: volume source under /dev is not allowed: ", src);
    if (lc_string_starts_with(src, lc_string_length(src), "/.old_root", 10))
        die2("Error: reserved volume source: ", src);
    if (!dst[0]) die("Error: volume destination must not be empty");
    if (dst[0] != '/') die2("Error: volume destination must be an absolute container path: ", dst);
    if (streq(dst, "/")) die("Error: mounting over / is not allowed");
    if (lc_string_starts_with(dst, lc_string_length(dst), "/proc", 5) &&
        (dst[5] == '\0' || dst[5] == '/'))
        die2("Error: volume destination under /proc is not allowed: ", dst);
    if (lc_string_starts_with(dst, lc_string_length(dst), "/sys", 4) &&
        (dst[4] == '\0' || dst[4] == '/'))
        die2("Error: volume destination under /sys is not allowed: ", dst);
    if (lc_string_starts_with(dst, lc_string_length(dst), "/dev", 4) &&
        (dst[4] == '\0' || dst[4] == '/'))
        die2("Error: volume destination under /dev is not allowed: ", dst);
    if (lc_string_starts_with(dst, lc_string_length(dst), "/.old_root", 10))
        die2("Error: reserved volume destination: ", dst);
}

static void parse_volume_spec_or_die(const char *spec, volume_spec *vol) {
    const char *colon1 = NULL, *colon2 = NULL;
    for (size_t i = 0; spec[i]; i++) {
        if (spec[i] != ':') continue;
        if (!colon1) colon1 = spec + i;
        else if (!colon2) colon2 = spec + i;
    }
    if (!colon1) die("Error: volume format is src:dst[:ro]");

    size_t slen = (size_t)(colon1 - spec);
    if (slen == 0 || slen >= sizeof(vol->src))
        die2("Error: invalid volume source in spec: ", spec);
    lc_bytes_copy(vol->src, spec, slen);
    vol->src[slen] = '\0';

    const char *dst_start = colon1 + 1;
    const char *dst_end = colon2 ? colon2 : spec + lc_string_length(spec);
    size_t dlen = (size_t)(dst_end - dst_start);
    if (dlen == 0 || dlen >= sizeof(vol->dst))
        die2("Error: invalid volume destination in spec: ", spec);
    lc_bytes_copy(vol->dst, dst_start, dlen);
    vol->dst[dlen] = '\0';

    vol->ro = 0;
    if (colon2) {
        if (colon2[1] == 'r' && colon2[2] == 'o' && colon2[3] == '\0')
            vol->ro = 1;
        else
            die2("Error: invalid volume mode in spec: ", spec);
    }

    validate_volume_paths(vol->src, vol->dst);
}

static void mkdir_p_or_die(const char *path) {
    if (make_dirs(path) != 0)
        lc_kernel_exit(1);      /* make_dirs has said what failed */
}

static void parent_dir(char *buf, size_t bufsz, const char *path) {
    size_t len = lc_string_length(path);
    if (len == 0 || len >= bufsz)
        die2("Error: invalid path: ", path);

    str_copy(buf, path, bufsz);
    while (len > 0 && buf[len - 1] != '/')
        len--;

    if (len == 0) {
        str_copy(buf, ".", bufsz);
    } else if (len == 1) {
        buf[1] = '\0';
    } else {
        buf[len - 1] = '\0';
    }
}

static bool container_has_volume(const char *name, const volume_spec *needle) {
    char conf_buf[CONF_MAX];
    if (container_conf_read(name, conf_buf) <= 0)
        return false;

    char *p = conf_buf;
    while (*p) {
        if (p[0] == 'v' && p[1] == 'o' && p[2] == 'l' && p[3] == '=') {
            char line[MAX_PATH * 2 + 4];
            char *end = p + 4;
            while (*end && *end != '\n') end++;
            size_t len = (size_t)(end - (p + 4));
            if (len < sizeof(line)) {
                lc_bytes_copy(line, p + 4, len);
                line[len] = '\0';
                volume_spec existing = {0};
                parse_volume_spec_or_die(line, &existing);
                if (streq(existing.src, needle->src) &&
                    streq(existing.dst, needle->dst) &&
                    existing.ro == needle->ro)
                    return true;
            }
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }

    return false;
}


static void append_container_volume(const char *name, const volume_spec *vol) {
    char conf_path[MAX_PATH], conf_buf[CONF_MAX], new_buf[CONF_MAX];
    container_conf_path(conf_path, name);
    int n = container_conf_read(name, conf_buf);
    if (n < 0)
        die2("Error: failed to read container config: ", conf_path);

    int nvols = 0;
    for (size_t i = 0; conf_buf[i]; ) {
        if (conf_buf[i] == 'v' && conf_buf[i + 1] == 'o' && conf_buf[i + 2] == 'l' && conf_buf[i + 3] == '=')
            nvols++;
        while (conf_buf[i] && conf_buf[i] != '\n') i++;
        if (conf_buf[i] == '\n') i++;
    }
    if (nvols >= MAX_VOLS)
        die2("Error: container already has the maximum of " STRINGIFY(MAX_VOLS) " volumes: ", name);

    bool overflow = false;
    size_t pos = 0;
    new_buf[0] = '\0';
    if (n > 0)
        pos = str_append_whole(new_buf, pos, conf_buf, sizeof(new_buf), &overflow);
    if (pos > 0 && new_buf[pos - 1] != '\n')
        pos = str_append_whole(new_buf, pos, "\n", sizeof(new_buf), &overflow);

    pos = str_append_whole(new_buf, pos, "vol=", sizeof(new_buf), &overflow);
    pos = str_append_whole(new_buf, pos, vol->src, sizeof(new_buf), &overflow);
    pos = str_append_whole(new_buf, pos, ":", sizeof(new_buf), &overflow);
    pos = str_append_whole(new_buf, pos, vol->dst, sizeof(new_buf), &overflow);
    if (vol->ro)
        pos = str_append_whole(new_buf, pos, ":ro", sizeof(new_buf), &overflow);
    str_append_whole(new_buf, pos, "\n", sizeof(new_buf), &overflow);

    /* Never write a config that lost part of itself. */
    if (overflow)
        die2("Error: container config would exceed its size limit: ", conf_path);

    require_write_file_atomic(conf_path, new_buf);
}

static bool name_char_ok(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

/* Validate container name: [a-zA-Z0-9_-], max 12 chars */
void validate_name(const char *name) {
    if (!name || !name[0]) die("Error: container name required");
    size_t len = lc_string_length(name);
    if (len > NAME_MAX_LEN) die("Error: container name must be 12 characters or fewer");
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
        if (conf_get_int(names[i], "userns", 0)) {
            int existing = conf_get_int(names[i], "uid_start", 0);
            if (existing > 0 && uid_ranges_overlap(existing, uid_start))
                return true;
        }
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

static void cgroup_path(char *buf, const char *name) {
    path_join(buf, MAX_PATH, cfg_global.cgroup_base, name);
}

static int cgroup_create(const char *name, int pid) {
    char cg[MAX_PATH], tmp[MAX_PATH];
    cgroup_path(cg, name);

    /* ensure parent exists and has controllers */
    lc_kernel_mkdirat(AT_FDCWD, cfg_global.cgroup_base, 0755);

    path_join(tmp, MAX_PATH, cfg_global.cgroup_root, "cgroup.subtree_control");
    if (write_file(tmp, "+memory +pids +cpu +io") < 0) return -1;
    path_join(tmp, MAX_PATH, cfg_global.cgroup_base, "cgroup.subtree_control");
    if (write_file(tmp, "+memory +pids +cpu +io") < 0) return -1;

    lc_kernel_mkdirat(AT_FDCWD, cg, 0755);

    /* read limits from config */
    char mem[16], pids[8], cpu[4];
    conf_get(name, "mem", mem, sizeof(mem), cfg_global.default_mem);
    conf_get(name, "pids", pids, sizeof(pids), cfg_global.default_pids);
    conf_get(name, "cpu", cpu, sizeof(cpu), cfg_global.default_cpu);

    path_join(tmp, MAX_PATH, cg, "memory.max");
    if (write_file(tmp, mem) < 0) return -1;

    path_join(tmp, MAX_PATH, cg, "pids.max");
    if (write_file(tmp, pids) < 0) return -1;

    /* cpu: convert cores to quota */
    int cores = parse_int(cpu);
    if (cores < 1) cores = 1;
    char cpu_max[32];
    int quota = cores * 100000;
    int len = fmt_int(cpu_max, quota);
    str_append(cpu_max, (size_t)len, " 100000", sizeof(cpu_max));
    path_join(tmp, MAX_PATH, cg, "cpu.max");
    if (write_file(tmp, cpu_max) < 0) return -1;

    /* io limits */
    char io_spec[128];
    if (conf_get(name, "io", io_spec, sizeof(io_spec), "") && io_spec[0]) {
        path_join(tmp, MAX_PATH, cg, "io.max");
        if (write_file(tmp, io_spec) < 0) return -1;
    }

    /* move container process into this cgroup */
    char pidbuf[16];
    fmt_int(pidbuf, pid);
    path_join(tmp, MAX_PATH, cg, "cgroup.procs");
    if (write_file(tmp, pidbuf) < 0) return -1;
    return 0;
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
    path_join(path, MAX_PATH, cg, "cgroup.events");
    if (read_file(path, events, sizeof(events)) <= 0)
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
    cgroup_path(cg, name);

    if (!path_exists(cg)) return 0;

    path_join(tmp, MAX_PATH, cg, "cgroup.kill");
    bool at_once = write_file(tmp, "1") == 0;
    path_join(tmp, MAX_PATH, cg, "cgroup.procs");

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
    char cg[MAX_PATH], procs_path[MAX_PATH], pidbuf[16];
    cgroup_path(cg, name);
    path_join(procs_path, MAX_PATH, cg, "cgroup.procs");
    fmt_int(pidbuf, lc_kernel_get_process_id());
    require_write_file(procs_path, pidbuf);
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

/* ─── cmd_create ────────────────────────────────────────────────────────── */

static void cmd_create(int argc, char **argv) {
    require_tool("cp", tool_path_cp());
    if (argc < 2) die("Usage: lightbox create <name> <ip> [options]");
    const char *name = argv[0];
    const char *ip = argv[1];
    validate_name(name);
    validate_ipv4_address(ip);
    validate_ip_in_subnet(ip, cfg_global.subnet);

    /* parse options */
    container_config cfg = {0};
    str_copy(cfg.name, name, sizeof(cfg.name));
    str_copy(cfg.ip, ip, sizeof(cfg.ip));
    str_copy(cfg.mem, cfg_global.default_mem, sizeof(cfg.mem));
    str_copy(cfg.pids, cfg_global.default_pids, sizeof(cfg.pids));
    str_copy(cfg.cpu, cfg_global.default_cpu, sizeof(cfg.cpu));
    cfg.oom_score = cfg_global.default_oom;

    for (int i = 2; i < argc; i++) {
        if (streq(argv[i], "--mem") && i + 1 < argc) {
            str_copy(cfg.mem, argv[++i], sizeof(cfg.mem));
        } else if (streq(argv[i], "--pids") && i + 1 < argc) {
            str_copy(cfg.pids, argv[++i], sizeof(cfg.pids));
            validate_positive_integer_option("Error: pids must be a positive integer: ", cfg.pids);
        } else if (streq(argv[i], "--cpu") && i + 1 < argc) {
            str_copy(cfg.cpu, argv[++i], sizeof(cfg.cpu));
            validate_positive_integer_option("Error: cpu must be a positive integer: ", cfg.cpu);
        } else if (streq(argv[i], "--userns")) {
            die("Error: --userns is not supported yet");
        } else if (streq(argv[i], "--uid-start") && i + 1 < argc) {
            (void)argv[++i];
            die("Error: --uid-start is not supported yet");
        } else if (streq(argv[i], "--privileged")) {
            cfg.privileged = 1;
        } else if (streq(argv[i], "--rootfs") && i + 1 < argc) {
            str_copy(cfg_global.rootfs, argv[++i], MAX_PATH);
        } else if (streq(argv[i], "--read-only")) {
            cfg.read_only = 1;
        } else if (streq(argv[i], "--oom-score") && i + 1 < argc) {
            cfg.oom_score = parse_int(argv[++i]);
            validate_oom_score(cfg.oom_score);
        } else if (streq(argv[i], "--vol") && i + 1 < argc) {
            if (cfg.nvols >= MAX_VOLS) die("Error: too many volumes");
            volume_spec vol = {0};
            parse_volume_spec_or_die(argv[++i], &vol);
            str_copy(cfg.vol_src[cfg.nvols], vol.src, sizeof(cfg.vol_src[cfg.nvols]));
            str_copy(cfg.vol_dst[cfg.nvols], vol.dst, sizeof(cfg.vol_dst[cfg.nvols]));
            cfg.vol_ro[cfg.nvols] = vol.ro;
            cfg.nvols++;
        } else if (streq(argv[i], "--link") && i + 1 < argc) {
            if (cfg.nlinks >= MAX_LINKS) die("Error: too many links");
            validate_name(argv[i + 1]);
            str_copy(cfg.links[cfg.nlinks++], argv[++i], NAME_MAX_LEN + 1);
        } else {
            die2("Error: unknown option: ", argv[i]);
        }
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
    if (record_container_state(name, "creating\n") != 0) {
        create_err = "failed to record the container's state";
        goto fail_create;
    }
    {
        /* Copy what is in the base ("<base>/."), not the path itself: given a
         * link to the base, copying the path would make the container's rootfs
         * that link, and everything written to it would land in the base. */
        char base_contents[MAX_PATH + 4];
        path_join(base_contents, sizeof(base_contents), cfg_global.rootfs, ".");
        const char *cp_argv[] = { "cp", "-a", base_contents, root, NULL };
        if (run_cmd(tool_path_cp(), cp_argv) != 0) {
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
    char conf_path[MAX_PATH], conf_buf[CONF_MAX];
    bool conf_overflow = false;
    container_conf_path(conf_path, name);
    size_t cpos = 0;
    cpos = str_append_whole(conf_buf, cpos, "mem=", sizeof(conf_buf), &conf_overflow);
    cpos = str_append_whole(conf_buf, cpos, cfg.mem, sizeof(conf_buf), &conf_overflow);
    cpos = str_append_whole(conf_buf, cpos, "\npids=", sizeof(conf_buf), &conf_overflow);
    cpos = str_append_whole(conf_buf, cpos, cfg.pids, sizeof(conf_buf), &conf_overflow);
    cpos = str_append_whole(conf_buf, cpos, "\ncpu=", sizeof(conf_buf), &conf_overflow);
    cpos = str_append_whole(conf_buf, cpos, cfg.cpu, sizeof(conf_buf), &conf_overflow);
    cpos = str_append_whole(conf_buf, cpos, "\n", sizeof(conf_buf), &conf_overflow);

    if (cfg.privileged) cpos = str_append_whole(conf_buf, cpos, "privileged=1\n", sizeof(conf_buf), &conf_overflow);
    if (cfg.read_only) cpos = str_append_whole(conf_buf, cpos, "readonly=1\n", sizeof(conf_buf), &conf_overflow);
    if (cfg.userns) {
        cpos = str_append_whole(conf_buf, cpos, "userns=1\n", sizeof(conf_buf), &conf_overflow);
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
        char uid_buf[16]; fmt_int(uid_buf, cfg.uid_start);
        cpos = str_append_whole(conf_buf, cpos, "uid_start=", sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, uid_buf, sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, "\n", sizeof(conf_buf), &conf_overflow);
    }
    {
        char oom_buf[16]; fmt_int(oom_buf, cfg.oom_score);
        cpos = str_append_whole(conf_buf, cpos, "oom_score=", sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, oom_buf, sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, "\n", sizeof(conf_buf), &conf_overflow);
    }
    for (int i = 0; i < cfg.nvols; i++) {
        cpos = str_append_whole(conf_buf, cpos, "vol=", sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, cfg.vol_src[i], sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, ":", sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, cfg.vol_dst[i], sizeof(conf_buf), &conf_overflow);
        if (cfg.vol_ro[i]) cpos = str_append_whole(conf_buf, cpos, ":ro", sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, "\n", sizeof(conf_buf), &conf_overflow);
    }
    for (int i = 0; i < cfg.nlinks; i++) {
        cpos = str_append_whole(conf_buf, cpos, "link=", sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, cfg.links[i], sizeof(conf_buf), &conf_overflow);
        cpos = str_append_whole(conf_buf, cpos, "\n", sizeof(conf_buf), &conf_overflow);
    }
    /* Never write a config that lost part of itself. */
    if (conf_overflow) {
        create_err = "container config exceeds its size limit";
        goto fail_create;
    }
    if (write_file_atomic(conf_path, conf_buf, MODE_PRIVATE_FILE) < 0) {
        create_err = "failed to write container config";
        goto fail_create;
    }

    /* write resolv.conf */
    char resolv[MAX_PATH];
    char etc_dir[MAX_PATH];
    path_join(etc_dir, MAX_PATH, root, "etc");
    lc_kernel_mkdirat(AT_FDCWD, etc_dir, 0755);
    path_join(resolv, MAX_PATH, root, "etc/resolv.conf");
    /* inside the container's own filesystem, so readable by its users */
    if (write_file_atomic(resolv, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n", MODE_PUBLIC_FILE) < 0) {
        create_err = "failed to write resolv.conf";
        goto fail_create;
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
        int len = fmt_int(uid_str, cfg.uid_start);
        str_append(uid_str, (size_t)len, ":", sizeof(uid_str));
        size_t pos = lc_string_length(uid_str);
        fmt_int(uid_str + pos, cfg.uid_start);

        const char *chown_argv[] = { "chown", "-R", "-h", uid_str, root, NULL };
        if (run_cmd(tool_path_chown(), chown_argv) != 0) {
            create_err = "failed to shift rootfs ownership";
            goto fail_create;
        }
    }

    if (record_container_state(name, "stopped\n") != 0) {
        create_err = "failed to record the container's state";
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
    const char  *name;
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

    if (lc_kernel_create_session() < 0)
        die("Error: failed to give init a session of its own");

    /* The command's ends of the pipes and its signalfd first, by name: init
     * would never see the go pipe close while it held the other end itself. */
    lc_kernel_close_file(ca->go_wr);
    lc_kernel_close_file(ca->report_rd);
    if (ca->starter_signals >= 0)
        lc_kernel_close_file(ca->starter_signals);
    const int32_t keep[] = { ca->go_rd, ca->report_wr, ca->null_fd, ca->log_fd };
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

static void build_proc_pid_path(char *buf, size_t bufsz, int pid, const char *suffix) {
    char pidbuf[16];
    fmt_int(pidbuf, pid);
    size_t pos = str_copy(buf, "/proc/", bufsz);
    pos = str_append(buf, pos, pidbuf, bufsz);
    if (suffix && suffix[0])
        str_append(buf, pos, suffix, bufsz);
}

static int open_target_path(int target_pid, const char *suffix) {
    char path[64];
    build_proc_pid_path(path, sizeof(path), target_pid, suffix);
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

static int exec_inside_container(const char *name, int target_pid, int userns,
                                 int privileged, int uid, int gid,
                                 const char *home, const char *user_name,
                                 int ngroups, const uint32_t *groups,
                                 const char *const cmd_argv[]) {
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

    require_setns_fd(pidfd, CLONE_NEWPID, "pid");

    lc_sysret child = lc_kernel_fork();
    if (child < 0)
        die("Error: exec helper fork failed");

    if (child == 0) {
        uint64_t empty_mask = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &empty_mask, NULL);

        if (!privileged)
            apply_sandbox();

        if (ngroups >= 0) {
            if (lc_kernel_setgroups((size_t)ngroups, groups) < 0)
                die("Error: failed to set supplementary groups for exec");
        }
        if (gid >= 0) {
            if (lc_kernel_setgid(gid) < 0)
                die("Error: failed to setgid for exec");
        }
        if (uid >= 0) {
            if (lc_kernel_setuid(uid) < 0)
                die("Error: failed to setuid for exec");
        }

        char home_env[MAX_PATH + 6] = "HOME=";
        if (home && home[0])
            str_append(home_env, 5, home, sizeof(home_env));
        else if (uid > 0)
            str_append(home_env, 5, "/", sizeof(home_env));
        else
            str_append(home_env, 5, "/root", sizeof(home_env));

        char user_env[NAME_MAX_LEN + 6] = "USER=";
        char logname_env[NAME_MAX_LEN + 9] = "LOGNAME=";
        if (user_name && user_name[0]) {
            str_append(user_env, 5, user_name, sizeof(user_env));
            str_append(logname_env, 8, user_name, sizeof(logname_env));
        } else if (uid == 0) {
            str_append(user_env, 5, "root", sizeof(user_env));
            str_append(logname_env, 8, "root", sizeof(logname_env));
        }

        const char *envp[6];
        int ei = 0;
        envp[ei++] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
        envp[ei++] = home_env;
        envp[ei++] = "TERM=xterm";
        if (user_env[5]) envp[ei++] = user_env;
        if (logname_env[8]) envp[ei++] = logname_env;
        envp[ei] = NULL;
        exec_program(cmd_argv[0], cmd_argv, envp);
        die2("Error: failed to exec command: ", cmd_argv[0]);
    }

    int32_t status;
    if (wait_child((int32_t)child, &status) < 0)
        die("Error: failed to wait for the command");
    return status;
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

/*
 * Remove an interface if it is there. The kernel removes a container's
 * interfaces by itself a moment after its init has ended, so one that was
 * there at the first look can be gone at the delete: that is not a failure.
 * 0 when the interface is gone afterwards, however it went; -1 when it is
 * still there.
 */
static int delete_veth_if_present(const char *ifname) {
    const char *show[] = { "ip", "link", "show", ifname, NULL };
    if (run_cmd_quiet(tool_path_ip(), show) != 0)
        return 0;

    const char *del[] = { "ip", "link", "delete", ifname, NULL };
    if (run_cmd_quiet(tool_path_ip(), del) == 0)
        return 0;
    return run_cmd_quiet(tool_path_ip(), show) != 0 ? 0 : -1;
}

/* What a start that failed leaves behind, removed. Init is gone by now. */
static void cleanup_start_failure(const char *name, const char *ip, const char *veth_host) {
    if (veth_host && veth_host[0])
        (void)delete_veth_if_present(veth_host);    /* clean-up: best effort */

    (void)cgroup_destroy(name);     /* it has said so if it could not */
    if (ip && ip[0])
        (void)update_link_rules(name, ip, false);

    container_forget_pid(name);
    (void)record_container_state(name, "failed\n");
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

    /* read volume config and set up bind mounts */
    char conf_buf[CONF_MAX];
    if (container_conf_read(ca->name, conf_buf) > 0) {
        char *p = conf_buf;
        while (*p) {
            if (p[0] == 'v' && p[1] == 'o' && p[2] == 'l' && p[3] == '=') {
                char vol_line[MAX_PATH * 2 + 4];
                char *end = p + 4;
                while (*end && *end != '\n') end++;
                size_t vlen = (size_t)(end - (p + 4));
                if (vlen < sizeof(vol_line)) {
                    lc_bytes_copy(vol_line, p + 4, vlen);
                    vol_line[vlen] = '\0';

                    /* parse src:dst[:ro] */
                    char *colon1 = NULL, *colon2 = NULL;
                    for (char *q = vol_line; *q; q++) {
                        if (*q == ':') { if (!colon1) colon1 = q; else if (!colon2) colon2 = q; }
                    }
                        if (colon1) {
                            *colon1 = '\0';
                            char *dst = colon1 + 1;
                            int ro = 0;
                            if (colon2) { *colon2 = '\0'; ro = (colon2[1] == 'r'); }

                        /* create the correct mount target type for file or directory binds */
                        char mount_point[MAX_PATH];
                        path_join(mount_point, MAX_PATH, ca->root, dst);
                        if (!path_exists(vol_line))
                            die2("Error: volume source does not exist: ", vol_line);

                        if (path_is_directory(vol_line)) {
                            mkdir_p_or_die(mount_point);
                        } else {
                            char parent[MAX_PATH];
                            parent_dir(parent, sizeof(parent), mount_point);
                            mkdir_p_or_die(parent);
                            lc_sysret fd = lc_kernel_open_file(mount_point, O_WRONLY | O_CREAT, 0644);
                            if (fd < 0)
                                die2("Error: failed to create volume target file: ", mount_point);
                            lc_kernel_close_file((int32_t)fd);
                        }

                        require_mount(vol_line, mount_point, NULL, MS_BIND, NULL);
                        {
                            uint64_t remount_flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV;
                            if (ro) remount_flags |= MS_RDONLY;
                            require_mount(NULL, mount_point, NULL, remount_flags, NULL);
                        }
                    }
                }
            }
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
        }
    }

    /* set up /dev via bind mounts (works in both userns and non-userns) */
    {
        char dev_path[MAX_PATH];
        path_join(dev_path, MAX_PATH, ca->root, "dev");
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
            path_join(host_dev, sizeof(host_dev), "/dev", devs[i].name);
            path_join(cont_dev, MAX_PATH, dev_path, devs[i].name);
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
        path_join(pts, MAX_PATH, dev_path, "pts");
        path_join(shm, MAX_PATH, dev_path, "shm");
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

    /* mount tmpfs for /tmp and /run before /init.sh so services started from
     * the init hook see the final runtime filesystem layout. */
    require_mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
    /* /tmp is for everyone; /run is for root's services to share with them */
    require_mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755");
    if (ca->read_only)
        require_mount("tmpfs", "/var/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL);
}

/* What the clone that becomes a container's init runs. */
static int container_child(void *arg) {
    const struct child_args *ca = (const struct child_args *)arg;

    init_begin(ca);
    build_container(ca);
    return init_main(ca);
}

/* ─── cmd_start ─────────────────────────────────────────────────────────── */

/* "<before><number><after>" in buf, for a message that names a number. */
static const char *text_with_number(char *buf, size_t bufsz, const char *before, int number,
                                    const char *after) {
    char digits[16];
    fmt_int(digits, number);
    size_t pos = str_copy(buf, before, bufsz);
    pos = str_append(buf, pos, digits, bufsz);
    str_append(buf, pos, after, bufsz);
    return buf;
}

static void cmd_start(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox start <name> [-t <seconds>]");
    const char *name = argv[0];
    validate_name(name);

    /* how long to wait for the init hook */
    int hook_wait = cfg_global.start_timeout;
    for (int i = 1; i < argc; i++) {
        if (!streq(argv[i], "-t") && !streq(argv[i], "--timeout"))
            die2(argv[i][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[i]);
        if (i + 1 >= argc)
            die2("Error: option needs a number of seconds: ", argv[i]);
        if (!parse_seconds(argv[++i], &hook_wait))
            die2("Error: not a number of seconds from 0 to " STRINGIFY(SECONDS_MAX) ": ", argv[i]);
    }

    require_tool("ip", tool_path_ip());
    require_tool("nsenter", tool_path_nsenter());

    char root[MAX_PATH];
    container_root(root, name);
    if (!path_exists(root)) die2("Error: container does not exist: ", name);

    if (is_running(name)) die2("Error: container is already running: ", name);
    container_reap_if_dead(name);   /* a previous init that died without a stop */
    container_forget_pid(name);     /* and whatever else an earlier run left on record */

    /* read container IP */
    char ip[16];
    if (read_container_ip(name, ip, sizeof(ip)) < 0) die("Error: no IP file for container");

    /* read config */
    int userns = conf_get_int(name, "userns", 0);
    int uid_start = conf_get_int(name, "uid_start", 100000);
    int privileged = conf_get_int(name, "privileged", 0);
    int read_only = conf_get_int(name, "readonly", 0);
    int oom_score = conf_get_int(name, "oom_score", cfg_global.default_oom);

    if (userns)
        die("Error: containers configured with user namespaces are not supported yet");

    /* A container without links gets an isolated port on the bridge: it
     * reaches the host and, through it, the outside, and no other container.
     * One with links has to share the bridge with the containers it is linked
     * to, and then the firewall is all that keeps it to those. The firewall
     * sees what the bridge switches only with br_netfilter, so without that
     * such a container is not started. Decided before anything is set up. */
    char first_link[NAME_MAX_LEN + 1];
    bool linked = conf_get(name, "link", first_link, sizeof(first_link), "") == 1;
    if (linked && !bridge_traffic_is_filtered()) {
        print_str(STDERR, "Error: container '");
        print_str(STDERR, name);
        print_str(STDERR,
            "' has links, and on this host bridged traffic does not pass\n"
            "through iptables. A linked container shares the bridge with the others, and\n"
            "only the firewall keeps it to its links. Let the firewall see that traffic,\n"
            "then start the container again:\n"
            "  modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1\n");
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
    bool undo_is_ours = true;
    bool hook_failed = false;
    int32_t null_fd = -1, log_fd = -1;
    struct init_link init = INIT_LINK_NONE;
    struct start_report report = { 0, 0 };
    int stop_signal = 0;

    /* set up veth pair */
    char veth_host[16], veth_cont[16];
    {
        size_t p1 = str_copy(veth_host, "vb-", sizeof(veth_host));
        str_append(veth_host, p1, name, sizeof(veth_host));
        size_t p2 = str_copy(veth_cont, "ve-", sizeof(veth_cont));
        str_append(veth_cont, p2, name, sizeof(veth_cont));
    }

    /* clean up stale veth endpoints if either name is left behind */
    if (delete_veth_if_present(veth_host) != 0 ||
        delete_veth_if_present(veth_cont) != 0) {
        start_err = "failed to delete stale veth";
        goto fail_start;
    }

    /* create veth pair */
    { const char *a[] = { "ip", "link", "add", veth_cont, "type", "veth", "peer", "name", veth_host, NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to create veth pair"; goto fail_start; } }
    { const char *a[] = { "ip", "link", "set", veth_host, "master", cfg_global.bridge, NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to attach veth to bridge"; goto fail_start; } }
    if (!linked) {
        /* isolated ports do not reach each other, whatever the firewall does */
        const char *a[] = { "ip", "link", "set", "dev", veth_host, "type", "bridge_slave", "isolated", "on", NULL };
        if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to isolate the container's port on the bridge"; goto fail_start; }
    }
    { const char *a[] = { "ip", "link", "set", veth_host, "up", NULL };
      if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to bring host veth up"; goto fail_start; } }

    /* what the container reads from and writes to, once it is built */
    char log_path[MAX_PATH];
    container_log_path(log_path, name);
    if (!open_container_streams(log_path, &null_fd, &log_fd)) {
        start_err = "failed to open the container's log";
        goto fail_start;
    }

    /* clone init; it waits for its first byte */
    struct child_args ca = {
        .starter_signals = signal_fd,
        .null_fd = null_fd,
        .log_fd = log_fd,
        .name = name,
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
    if (start_err)
        goto fail_start;
    int child_pid = (int)init.pid;

    /* write uid/gid maps if userns */
    if (userns) {
        char proc_path[64], map_buf[32];
        char pidbuf[16]; fmt_int(pidbuf, child_pid);

        /* deny setgroups */
        size_t pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/setgroups", sizeof(proc_path));
        if (write_file(proc_path, "deny") < 0) { start_err = "failed to write setgroups"; goto fail_start; }

        /* uid_map */
        pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/uid_map", sizeof(proc_path));
        {
            size_t mp = str_copy(map_buf, "0 ", sizeof(map_buf));
            char ub[16]; fmt_int(ub, uid_start);
            mp = str_append(map_buf, mp, ub, sizeof(map_buf));
            str_append(map_buf, mp, " 65536", sizeof(map_buf));
        }
        if (write_file(proc_path, map_buf) < 0) { start_err = "failed to write uid_map"; goto fail_start; }

        /* gid_map */
        pp = str_copy(proc_path, "/proc/", sizeof(proc_path));
        pp = str_append(proc_path, pp, pidbuf, sizeof(proc_path));
        str_append(proc_path, pp, "/gid_map", sizeof(proc_path));
        if (write_file(proc_path, map_buf) < 0) { start_err = "failed to write gid_map"; goto fail_start; }
    }

    /*
     * Set up cgroup, networking, and OOM score before init gets its first
     * byte. While it waits for that byte it is certainly there, so everything
     * that names its PID or its network namespace has something to name.
     */

    /* set up cgroup */
    if (cgroup_create(name, child_pid) != 0) {
        start_err = "failed to create cgroup";
        goto fail_start;
    }

    /* before the namespace has an interface that could come up with it */
    if (netns_disable_ipv6(child_pid) != 0) {
        start_err = "failed to switch IPv6 off in the container";
        goto fail_start;
    }

    /* move veth into container network namespace */
    {
        char nsbuf[16]; fmt_int(nsbuf, child_pid);
        const char *a[] = { "ip", "link", "set", veth_cont, "netns", nsbuf, NULL };
        if (run_cmd(tool_path_ip(), a) != 0) { start_err = "failed to move veth into netns"; goto fail_start; }
    }

    /* configure networking inside the container */
    {
        char nsbuf[16]; fmt_int(nsbuf, child_pid);
        char ip_cidr[20];
        str_copy(ip_cidr, ip, sizeof(ip_cidr));
        str_append(ip_cidr, lc_string_length(ip_cidr), "/24", sizeof(ip_cidr));

        const char *a1[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "link", "set", veth_cont, "up", NULL };
        if (run_cmd(tool_path_nsenter(), a1) != 0) { start_err = "failed to bring container veth up"; goto fail_start; }
        const char *a2[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "addr", "add", ip_cidr, "dev", veth_cont, NULL };
        if (run_cmd(tool_path_nsenter(), a2) != 0) { start_err = "failed to assign container IP"; goto fail_start; }
        const char *a3[] = { "nsenter", "-t", nsbuf, "-n", "--", "ip", "route", "add", "default", "via", cfg_global.gw, NULL };
        if (run_cmd(tool_path_nsenter(), a3) != 0) { start_err = "failed to install default route"; goto fail_start; }
    }

    /* set OOM score */
    {
        char oom_path[64], oom_buf[16];
        char pidb[16]; fmt_int(pidb, child_pid);
        size_t pp = str_copy(oom_path, "/proc/", sizeof(oom_path));
        pp = str_append(oom_path, pp, pidb, sizeof(oom_path));
        str_append(oom_path, pp, "/oom_score_adj", sizeof(oom_path));
        fmt_int(oom_buf, oom_score);
        if (write_file(oom_path, oom_buf) < 0) { start_err = "failed to set oom_score_adj"; goto fail_start; }
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
    if (update_link_rules(name, ip, true) != 0) {
        start_err = "failed to install link iptables rules";
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
            case AWAIT_CLOSED: {
                /* a stop that got to it first clears up after itself */
                char state[32];
                get_container_state(name, state, sizeof(state));
                undo_is_ours = !streq(state, "stopping") && !streq(state, "stopped");
                start_err = undo_is_ours ? "the container stopped while its init hook was running"
                                         : "the container was stopped while its init hook was running";
                goto fail_start;
            }
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
    if (undo_is_ours)
        cleanup_start_failure(name, ip, veth_host);
    lc_kernel_exit(exit_code);
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

static void cmd_stop(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox stop <name> [-t <seconds>]");
    const char *name = argv[0];
    validate_name(name);

    /* how long the container gets to end by itself */
    int seconds = cfg_global.stop_timeout;
    for (int i = 1; i < argc; i++) {
        if (!streq(argv[i], "-t") && !streq(argv[i], "--timeout"))
            die2(argv[i][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[i]);
        if (i + 1 >= argc)
            die2("Error: option needs a number of seconds: ", argv[i]);
        if (!parse_seconds(argv[++i], &seconds))
            die2("Error: not a number of seconds from 0 to " STRINGIFY(SECONDS_MAX) ": ", argv[i]);
    }

    if (!is_running(name)) {
        container_reap_if_dead(name);
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
        container_reap_if_dead(name);
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

    /* whatever is still in the cgroup, and the cgroup itself */
    if (cgroup_destroy(name) != 0)
        clean = false;

    /* clean up link iptables rules */
    {
        char ip_buf[16];
        if (read_container_ip(name, ip_buf, sizeof(ip_buf)) == 0 &&
            update_link_rules(name, ip_buf, false) != 0) {
            print_str(STDERR, "Error: failed to remove link iptables rules\n");
        }
    }

    /* the host's end of the container's interface, if the kernel has not
     * removed it with the container's network namespace already */
    {
        char veth_host[16];
        size_t p = str_copy(veth_host, "vb-", sizeof(veth_host));
        str_append(veth_host, p, name, sizeof(veth_host));
        if (delete_veth_if_present(veth_host) != 0) {
            print_str(STDERR, "Error: cannot remove the interface ");
            print_str(STDERR, veth_host);
            lc_print_char(STDERR, '\n');
            clean = false;
        }
    }

    container_forget_pid(name);
    set_container_state(name, "stopped\n");

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

static void cmd_add_vol(int argc, char **argv) {
    if (argc < 2) die("Usage: lightbox add-vol <name> <src:dst[:ro]>");
    const char *name = argv[0];
    validate_name(name);

    char cdir[MAX_PATH];
    container_dir_path(cdir, name);
    if (!path_exists(cdir)) die2("Error: container does not exist: ", name);

    volume_spec vol = {0};
    parse_volume_spec_or_die(argv[1], &vol);

    if (!path_exists(vol.src))
        die2("Error: volume source does not exist: ", vol.src);

    if (container_has_volume(name, &vol)) {
        print_str(STDOUT, "Volume already present for container '");
        print_str(STDOUT, name);
        print_str(STDOUT, "'\n");
        return;
    }

    append_container_volume(name, &vol);

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

/* ─── cmd_rm ────────────────────────────────────────────────────────────── */

static void cmd_rm(int argc, char **argv) {
    require_tool("rm", tool_path_rm());
    if (argc < 1) die("Usage: lightbox rm <name>");
    const char *name = argv[0];
    validate_name(name);

    if (is_running(name)) die2("Error: container is running (stop it first): ", name);

    char cdir[MAX_PATH];
    container_dir_path(cdir, name);
    if (!path_exists(cdir)) die2("Error: container does not exist: ", name);

    print_str(STDOUT,"Removing container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"'...\n");

    cgroup_destroy(name);

    /* remove entire container directory (rootfs + metadata) */
    require_rm_rf(cdir);

    print_str(STDOUT,"Container '");
    print_str(STDOUT,name);
    print_str(STDOUT,"' removed\n");
}

/* ─── cmd_exec ──────────────────────────────────────────────────────────── */

/* Resolve a username from the container's /etc/passwd.
 * Returns 0 on success, -1 if user not found. */
static int resolve_passwd_user(const char *name, const char *username,
                               int *out_uid, int *out_gid,
                               char *out_home, size_t home_sz) {
    char root[MAX_PATH];
    container_root(root, name);

    char passwd_path[MAX_PATH];
    path_join(passwd_path, sizeof(passwd_path), root, "etc/passwd");

    char buf[4096];
    if (read_file(passwd_path, buf, sizeof(buf)) < 0)
        return -1;

    size_t ulen = lc_string_length(username);

    /* scan line by line: user:x:uid:gid:gecos:home:shell */
    char *p = buf;
    while (*p) {
        char *line = p;
        /* find end of line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') *p++ = '\0';

        /* match username before first colon */
        char *c1 = NULL;
        for (char *q = line; *q; q++) {
            if (*q == ':') { c1 = q; break; }
        }
        if (!c1) continue;
        if ((size_t)(c1 - line) != ulen) continue;

        bool match = true;
        for (size_t i = 0; i < ulen; i++) {
            if (line[i] != username[i]) { match = false; break; }
        }
        if (!match) continue;

        /* skip password field (field 2) */
        char *f = c1 + 1;
        char *c2 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c2 = q; break; }
        }
        if (!c2) continue;

        /* uid field (field 3) */
        f = c2 + 1;
        char *c3 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c3 = q; break; }
        }
        if (!c3) continue;
        *c3 = '\0';
        *out_uid = parse_int(f);

        /* gid field (field 4) */
        f = c3 + 1;
        char *c4 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c4 = q; break; }
        }
        if (!c4) continue;
        *c4 = '\0';
        *out_gid = parse_int(f);

        /* skip gecos (field 5) */
        f = c4 + 1;
        char *c5 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c5 = q; break; }
        }
        if (!c5) continue;

        /* home field (field 6) */
        f = c5 + 1;
        char *c6 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c6 = q; break; }
        }
        if (c6) *c6 = '\0';
        str_copy(out_home, f, home_sz);

        return 0;
    }
    return -1;
}

/* Resolve an account by numeric UID from the container's /etc/passwd.
 * Returns 0 on success, -1 if user not found. */
static int resolve_passwd_uid(const char *name, int uid,
                              char *out_user, size_t user_sz,
                              int *out_gid,
                              char *out_home, size_t home_sz) {
    char root[MAX_PATH];
    container_root(root, name);

    char passwd_path[MAX_PATH];
    path_join(passwd_path, sizeof(passwd_path), root, "etc/passwd");

    char buf[4096];
    if (read_file(passwd_path, buf, sizeof(buf)) < 0)
        return -1;

    char *p = buf;
    while (*p) {
        char *line = p;
        while (*p && *p != '\n') p++;
        if (*p == '\n') *p++ = '\0';

        char *c1 = NULL;
        for (char *q = line; *q; q++) {
            if (*q == ':') { c1 = q; break; }
        }
        if (!c1) continue;
        *c1 = '\0';

        char *f = c1 + 1;
        char *c2 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c2 = q; break; }
        }
        if (!c2) continue;

        f = c2 + 1;
        char *c3 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c3 = q; break; }
        }
        if (!c3) continue;
        *c3 = '\0';
        if (parse_int(f) != uid)
            continue;

        f = c3 + 1;
        char *c4 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c4 = q; break; }
        }
        if (!c4) continue;
        *c4 = '\0';
        *out_gid = parse_int(f);

        f = c4 + 1;
        char *c5 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c5 = q; break; }
        }
        if (!c5) continue;

        f = c5 + 1;
        char *c6 = NULL;
        for (char *q = f; *q; q++) {
            if (*q == ':') { c6 = q; break; }
        }
        if (c6) *c6 = '\0';

        str_copy(out_user, line, user_sz);
        str_copy(out_home, f, home_sz);
        return 0;
    }

    return -1;
}

static int resolve_group_memberships(const char *name, const char *username,
                                     int primary_gid, uint32_t *out_groups,
                                     int max_groups) {
    char root[MAX_PATH];
    container_root(root, name);

    char group_path[MAX_PATH];
    path_join(group_path, sizeof(group_path), root, "etc/group");

    char buf[4096];
    if (read_file(group_path, buf, sizeof(buf)) < 0)
        return 0;

    size_t ulen = lc_string_length(username);
    int count = 0;
    char *p = buf;
    while (*p) {
        char *line = p;
        while (*p && *p != '\n') p++;
        if (*p == '\n') *p++ = '\0';
        if (!line[0]) continue;

        char *c1 = NULL, *c2 = NULL, *c3 = NULL;
        for (char *q = line; *q; q++) {
            if (*q == ':') {
                if (!c1) c1 = q;
                else if (!c2) c2 = q;
                else { c3 = q; break; }
            }
        }
        if (!c1 || !c2 || !c3) continue;

        char *gid_field = c2 + 1;
        *c3 = '\0';
        int gid = parse_int(gid_field);
        if (gid == primary_gid)
            continue;

        char *members = c3 + 1;
        bool member = false;
        while (*members) {
            char *entry = members;
            while (*members && *members != ',') members++;
            char saved = *members;
            *members = '\0';

            size_t len = lc_string_length(entry);
            if (len == ulen) {
                member = true;
                for (size_t i = 0; i < ulen; i++) {
                    if (entry[i] != username[i]) {
                        member = false;
                        break;
                    }
                }
                if (member) break;
            }

            *members = saved;
            if (saved == ',') members++;
        }

        if (member) {
            if (count >= max_groups)
                die("Error: too many supplementary groups for exec user");
            out_groups[count++] = (uint32_t)gid;
        }
    }

    return count;
}

static void cmd_exec(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox exec <name> [--user <uid[:gid]>] [cmd...]");
    const char *name = argv[0];
    validate_name(name);

    if (!is_running(name)) die2("Error: container is not running: ", name);

    int pid = get_container_pid(name);
    int userns = conf_get_int(name, "userns", 0);
    int privileged = conf_get_int(name, "privileged", 0);

    if (userns)
        die("Error: exec into userns containers is not supported yet");

    /* parse exec options */
    int uid = -1;
    int gid = -1;
    char home[MAX_PATH] = {0};
    char user_name[NAME_MAX_LEN + 1] = {0};
    uint32_t groups[32];
    int ngroups = -1;
    int cmd_start = 1;

    for (int i = 1; i < argc; i++) {
        if (streq(argv[i], "--user") && i + 1 < argc) {
            const char *spec = argv[++i];

            /* check if spec starts with a digit — numeric uid[:gid] */
            bool numeric = (spec[0] >= '0' && spec[0] <= '9');

            if (numeric) {
                const char *colon = NULL;
                bool explicit_gid = false;
                for (const char *p = spec; *p; p++) {
                    if (*p == ':') { colon = p; break; }
                }
                if (colon) {
                    explicit_gid = true;
                    char uid_buf[16];
                    size_t uid_len = (size_t)(colon - spec);
                    if (uid_len == 0 || uid_len >= sizeof(uid_buf))
                        die("Error: invalid uid in --user");
                    for (size_t j = 0; j < uid_len; j++)
                        uid_buf[j] = spec[j];
                    uid_buf[uid_len] = '\0';
                    uid = parse_int(uid_buf);
                    gid = parse_int(colon + 1);
                } else {
                    uid = parse_int(spec);
                    gid = uid;
                }
                if (uid < 0) die("Error: invalid uid in --user");
                if (gid < 0) die("Error: invalid gid in --user");

                int passwd_gid = gid;
                if (resolve_passwd_uid(name, uid, user_name, sizeof(user_name), &passwd_gid,
                                       home, sizeof(home)) == 0) {
                    int primary_gid = explicit_gid ? gid : passwd_gid;
                    if (!explicit_gid)
                        gid = passwd_gid;
                    ngroups = resolve_group_memberships(name, user_name, primary_gid, groups,
                                                        (int)(sizeof(groups) / sizeof(groups[0])));
                }
            } else {
                /* resolve username from container's /etc/passwd */
                if (resolve_passwd_user(name, spec, &uid, &gid, home, sizeof(home)) < 0)
                    die2("Error: user not found in container: ", spec);
                str_copy(user_name, spec, sizeof(user_name));
                ngroups = resolve_group_memberships(name, spec, gid, groups, (int)(sizeof(groups) / sizeof(groups[0])));
            }
            cmd_start = i + 1;
        } else {
            cmd_start = i;
            break;
        }
    }

    const char *cmd_argv[32];
    int ai = 0;
    if (cmd_start < argc) {
        for (int i = cmd_start; i < argc && ai < 31; i++)
            cmd_argv[ai++] = argv[i];
    } else {
        cmd_argv[ai++] = "/bin/sh";
    }
    cmd_argv[ai] = NULL;

    lc_sysret worker = lc_kernel_fork();
    if (worker < 0)
        die("Error: failed to fork exec worker");

    if (worker == 0) {
        int status = exec_inside_container(name, pid, userns, privileged,
                                           uid, gid, home, user_name,
                                           ngroups, groups, cmd_argv);
        lc_kernel_exit(exit_code_from_status(status));
    }

    int32_t status;
    if (wait_child((int32_t)worker, &status) < 0)
        die("Error: failed to wait for the exec worker");
    lc_kernel_exit(exit_code_from_status(status));
}

/* ─── cmd_ls ────────────────────────────────────────────────────────────── */

/* ─── Usage ─────────────────────────────────────────────────────────────── */

[[noreturn]] static void usage(void) {
    print_str(STDERR,
        "Usage: lightbox <command> [args]\n"
        "\n"
        "Commands:\n"
        "  create <name> <ip> [options]  Create a new container\n"
        "         --mem  <limit>         Memory limit (default: 256M)\n"
        "         --pids <limit>         Max processes (default: 128)\n"
        "         --cpu  <num>           CPU cores (default: 1)\n"
        "         --vol  <src:dst[:ro]>  Bind mount (repeatable)\n"
        "         --rootfs <path>         Base rootfs to copy (default: $LIGHTBOX_ROOTFS or lightbox.conf)\n"
        "         --userns               Future improvement; not supported yet\n"
        "         --uid-start <n>        Future improvement; not supported yet\n"
        "         --read-only            Read-only root filesystem\n"
        "         --privileged           Disable security sandbox\n"
        "         --oom-score <n>        OOM score adjustment (default: 500)\n"
        "         --link <name>          Allow network to another container\n"
        "  start  <name> [-t <seconds>]  Start a stopped container\n"
        "         -t <seconds>            How long to wait for /init.sh (default: 30, 0: do not wait)\n"
        "  stop   <name> [-t <seconds>]  Stop a running container\n"
        "         -t <seconds>            How long its processes get to end (default: 10)\n"
        "  add-vol <name> <src:dst[:ro]> Add a volume to an existing container\n"
        "  rm     <name>                 Remove a container (must be stopped)\n"
        "  exec   <name> [options] [cmd...]  Execute a command in a running container\n"
        "         --user <name|uid[:gid]> Run as specified user/group (default: root)\n"
        "  logs   <name> [-f]            Show what the container has printed; -f follows it\n"
        "  inspect <name>                Show container metadata and runtime state\n"
        "  doctor                        Show host/runtime dependency status\n"
        "  ls                            List all containers\n"
        "  setup                         Setup host networking\n"
    );
    lc_kernel_exit(1);
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
    if (argc < 2) usage();

    /* load configuration: built-in defaults → lightbox.conf → env vars */
    cfg_global_init();
    cfg_global_load(envp);

    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub_argv = argv + 2;

    if (streq(cmd, "setup"))       cmd_setup();
    else if (streq(cmd, "create")) cmd_create(sub_argc, sub_argv);
    else if (streq(cmd, "start"))  cmd_start(sub_argc, sub_argv);
    else if (streq(cmd, "stop"))   cmd_stop(sub_argc, sub_argv);
    else if (streq(cmd, "add-vol")) cmd_add_vol(sub_argc, sub_argv);
    else if (streq(cmd, "rm"))     cmd_rm(sub_argc, sub_argv);
    else if (streq(cmd, "exec"))   cmd_exec(sub_argc, sub_argv);
    else if (streq(cmd, "logs"))   cmd_logs(sub_argc, sub_argv);
    else if (streq(cmd, "inspect")) cmd_inspect(sub_argc, sub_argv);
    else if (streq(cmd, "doctor")) cmd_doctor();
    else if (streq(cmd, "ls"))     cmd_ls(sub_argc, sub_argv);
    else                           usage();

    return 0;
}
