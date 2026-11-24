/*
 * What a container is configured with.
 *
 * A container's .conf is read in one place and written in one place, both
 * here, and between them it is a container_config. The checks of what a
 * value may be are here too, so that an option, a setting in lightbox.conf
 * and a line of the file are all held to the same rule.
 *
 * The file is lines of key=value:
 *
 *   version=1
 *   mem=256M
 *   swap=64M                only when given; without it the container has none
 *   pids=128
 *   cpu=0.5
 *   oom_score=500
 *   privileged=1            only when set, like the three after it
 *   readonly=1
 *   userns=1                only with --userns, and then with the two after it:
 *   uid_start=<n>           the host's uid and gid of the container's 0, the
 *   gid_start=<n>           first of USERNS_SIZE of each; userns=0 and a
 *                           uid_start alone, which lightbox up to 0.5 could
 *                           write, mean nothing
 *   io=8:0 rbps=1048576     only when given: <major>:<minor>, and rbps, wbps,
 *                           riops or wiops, each at most once
 *   vol=/src:/dst[:ro]      once for each volume, in the order they are mounted
 *   link=name               once for each link
 */

#include "lightbox.h"

/* ─── Limits ────────────────────────────────────────────────────────────── */

/*
 * A size for memory.max: a decimal number with an optional K, M, G or T, or
 * "max". The kernel reads the text itself, and reads a number that begins
 * with 0 as octal, so one may not: 0100M would be 64M.
 */
bool mem_limit_ok(const char *text) {
    uint64_t bytes;
    return !streq(text, "0") && limit_bytes(text, &bytes);
}

/* What memory.swap.max takes: what memory.max does, or none at all. */
bool swap_limit_ok(const char *text) {
    return streq(text, "0") || mem_limit_ok(text);
}

bool limit_bytes(const char *text, uint64_t *bytes) {
    *bytes = 0;
    if (streq(text, "max")) {
        *bytes = UINT64_MAX;
        return true;
    }
    if (streq(text, "0"))
        return true;
    if (text[0] < '1' || text[0] > '9')
        return false;

    uint64_t value = 0;
    size_t i = 0;
    for (; text[i] >= '0' && text[i] <= '9'; i++) {
        uint64_t digit = (uint64_t)(text[i] - '0');
        if (value > ((uint64_t)INT64_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }

    unsigned shift = 0;
    switch (text[i]) {
        case '\0':          break;
        case 'K': case 'k': shift = 10; break;
        case 'M': case 'm': shift = 20; break;
        case 'G': case 'g': shift = 30; break;
        case 'T': case 't': shift = 40; break;
        default:            return false;
    }
    if ((shift && text[i + 1] != '\0') || value > ((uint64_t)INT64_MAX >> shift))
        return false;
    *bytes = value << shift;
    return true;
}

/* A number at *p from min to max, without a zero in front unless it is 0;
 * *p then stands after it. */
static bool number_at(const char **p, int64_t min, int64_t max, int64_t *out) {
    const char *s = *p;
    if (*s < '0' || *s > '9' || (s[0] == '0' && s[1] >= '0' && s[1] <= '9'))
        return false;
    uint64_t value = 0;
    for (; *s >= '0' && *s <= '9'; s++) {
        uint64_t digit = (uint64_t)(*s - '0');
        if (value > ((uint64_t)INT64_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    if ((int64_t)value < min || (int64_t)value > max)
        return false;
    *p = s;
    *out = (int64_t)value;
    return true;
}

/*
 * A line of io.max for one disk: "8:0 rbps=1048576 wiops=max". The kernel
 * reads its numbers in any base, so 010 would be 8 to it: a zero in front
 * is refused here, as it is for the other limits.
 */
bool io_limit_ok(const char *text) {
    static const char *const keys[] = { "rbps", "wbps", "riops", "wiops" };
    const char *p = text;
    int64_t major, minor, value;
    if (!number_at(&p, 1, 4095, &major) || *p++ != ':' || !number_at(&p, 0, 1048575, &minor))
        return false;
    unsigned seen = 0;
    while (*p == ' ') {
        p++;
        size_t len = 0;
        while (p[len] && p[len] != '=' && p[len] != ' ')
            len++;
        size_t k = 0;
        while (k < 4 && !(lc_string_length(keys[k]) == len &&
                          lc_string_starts_with(p, len, keys[k], len)))
            k++;
        if (k == 4 || (seen & (1u << k)) || p[len] != '=')
            return false;
        seen |= 1u << k;
        p += len + 1;
        if (p[0] == 'm' && p[1] == 'a' && p[2] == 'x' && (p[3] == ' ' || p[3] == '\0'))
            p += 3;
        else if (!number_at(&p, 1, INT64_MAX, &value))
            return false;
    }
    return seen != 0 && *p == '\0';
}

/* A count for pids.max, or "max". The same about a leading 0. */
bool pids_limit_ok(const char *text) {
    int64_t count;
    return streq(text, "max") ||
           (text[0] != '0' && parse_number(text, 1, PIDS_LIMIT_MAX, &count));
}

/*
 * CPUs, whole or with one or two decimals: "2", "0.5", "1.25". The quota is
 * what cpu.max takes beside CPU_PERIOD_US; the smallest one the kernel
 * accepts is a hundredth of that period, which is 0.01.
 */
bool parse_cpu_limit(const char *text, int *quota_us) {
    if (text[0] < '0' || text[0] > '9')
        return false;

    int whole = 0, hundredths = 0;
    size_t i = 0;
    for (; text[i] >= '0' && text[i] <= '9'; i++) {
        whole = whole * 10 + (text[i] - '0');
        if (whole > CPU_LIMIT_MAX)
            return false;
    }
    if (text[i] == '.') {
        int digits = 0;
        for (i++; text[i] >= '0' && text[i] <= '9'; i++, digits++) {
            if (digits == 2)
                return false;
            hundredths = hundredths * 10 + (text[i] - '0');
        }
        if (digits == 0)
            return false;
        if (digits == 1)
            hundredths *= 10;
    }
    if (text[i] != '\0')
        return false;

    int total = whole * 100 + hundredths;
    if (total < 1 || total > CPU_LIMIT_MAX * 100)
        return false;
    *quota_us = total * (CPU_PERIOD_US / 100);
    return true;
}

bool parse_oom_score(const char *text, int *out) {
    return parse_int_in(text, OOM_SCORE_MIN, OOM_SCORE_MAX, out);
}

bool parse_seccomp_profile(const char *text, bool *allow) {
    if (!streq(text, "allow") && !streq(text, "deny"))
        return false;
    *allow = streq(text, "allow");
    return true;
}

static const char *const NET_MODE_NAMES[] = { [NET_NAT] = "nat", [NET_OUTSIDE] = "outside", [NET_NONE] = "none" };

#define NET_PROXY_PREFIX "proxy:"

/* proxy:<port>: a port from 1 to 65535 in decimal, as fmt_int writes it */
bool parse_net_mode(const char *text, int *mode, int *proxy_port) {
    for (int i = 0; i < (int)(sizeof(NET_MODE_NAMES) / sizeof(NET_MODE_NAMES[0])); i++) {
        if (streq(text, NET_MODE_NAMES[i])) {
            *mode = i;
            *proxy_port = 0;
            return true;
        }
    }
    size_t head = sizeof(NET_PROXY_PREFIX) - 1;
    int64_t port;
    if (!lc_string_starts_with(text, lc_string_length(text), NET_PROXY_PREFIX, head) ||
        text[head] < '1' || text[head] > '9' || !parse_number(text + head, 1, 65535, &port))
        return false;
    *mode = NET_PROXY;
    *proxy_port = (int)port;
    return true;
}

void net_mode_text(char out[NET_MODE_TEXT_MAX], int mode, int proxy_port) {
    if (mode == NET_PROXY && proxy_port >= 1 && proxy_port <= 65535) {
        size_t head = sizeof(NET_PROXY_PREFIX) - 1;
        lc_bytes_copy(out, NET_PROXY_PREFIX, head);
        fmt_int(out + head, proxy_port);
        return;
    }
    const char *name = mode >= NET_NAT && mode <= NET_NONE ? NET_MODE_NAMES[mode] : "?";
    lc_bytes_copy(out, name, lc_string_length(name) + 1);
}

/* "a,b,c": one to MAX_DNS IPv4 addresses, each in the form format_ipv4 writes */
static bool parse_dns_list(const char *text, container_config *config) {
    int n = 0;
    const char *p = text;
    for (;;) {
        char one[16];
        size_t len = 0;
        while (p[len] && p[len] != ',')
            len++;
        uint32_t addr;
        char back[IPV4_TEXT_MAX];
        if (len == 0 || len >= sizeof(one) || n >= MAX_DNS)
            return false;
        lc_bytes_copy(one, p, len);
        one[len] = '\0';
        if (!parse_ipv4(one, &addr))
            return false;
        format_ipv4(back, addr);
        if (!streq(back, one))
            return false;
        lc_bytes_copy(config->dns[n++], one, len + 1);
        if (!p[len])
            break;
        p += len + 1;
    }
    config->ndns = n;
    return true;
}

/* ─── Volumes ───────────────────────────────────────────────────────────── */

/*
 * Bring an absolute path to one spelling: single slashes, no "." component,
 * no slash at the end. False for a path that is not absolute or that has a
 * ".." component: where that leads depends on what is in the directories
 * before it, and a volume's paths are to mean what they say.
 */
static bool normalise_path(char *path) {
    if (path[0] != '/')
        return false;

    size_t out = 0;
    for (size_t in = 0; path[in]; ) {
        while (path[in] == '/')
            in++;
        size_t len = 0;
        while (path[in + len] && path[in + len] != '/')
            len++;
        if (len == 0)
            break;
        if (len == 2 && path[in] == '.' && path[in + 1] == '.')
            return false;
        if (!(len == 1 && path[in] == '.')) {
            path[out++] = '/';
            for (size_t i = 0; i < len; i++)
                path[out++] = path[in + i];
        }
        in += len;
    }
    if (out == 0)
        path[out++] = '/';
    path[out] = '\0';
    return true;
}

/* Is a normalised path this directory, or something inside it? */
static bool path_is_under(const char *path, const char *dir) {
    size_t len = lc_string_length(dir);
    return lc_string_starts_with(path, lc_string_length(path), dir, len) &&
           (path[len] == '\0' || path[len] == '/');
}

/* Bring a destination to its one spelling. NULL, or why a volume cannot be there. */
static const char *destination_problem(char *dst) {
    if (!normalise_path(dst))
        return "the volume's destination must be an absolute path without ..";
    if (streq(dst, "/"))
        return "a volume may not be mounted over /";
    if (path_is_under(dst, "/.old_root"))
        return "/.old_root is a name lightbox uses itself while it builds a container";
    if (path_is_under(dst, "/proc") || path_is_under(dst, "/sys") || path_is_under(dst, "/dev"))
        return "a volume's destination may not be under /proc, /sys or /dev";
    return NULL;
}

const char *parse_volume_destination(const char *text, char dst[MAX_PATH]) {
    if (has_control_chars(text))
        return "a volume's paths may not contain control characters";
    for (const char *c = text; *c; c++) {
        if (*c == ':')
            return "a volume's destination has no colon in it";
    }
    if (!text[0] || !str_copy(dst, text, MAX_PATH))
        return "the volume's destination is empty or too long";
    return destination_problem(dst);
}

const char *parse_volume_spec(const char *spec, volume_spec *vol) {
    /* A volume is kept as one line of a file of lines. A path with a newline
     * in it would be more than one line, and the rest of it would be read as
     * settings of the container that nobody gave. */
    if (has_control_chars(spec))
        return "a volume's paths may not contain control characters";

    const char *colon1 = NULL, *colon2 = NULL;
    for (size_t i = 0; spec[i]; i++) {
        if (spec[i] != ':') continue;
        if (!colon1) colon1 = spec + i;
        else if (!colon2) colon2 = spec + i;
    }
    if (!colon1)
        return "a volume is written src:dst[:ro]";

    size_t slen = (size_t)(colon1 - spec);
    if (slen == 0 || slen >= sizeof(vol->src))
        return "the volume's source is empty or too long";
    lc_bytes_copy(vol->src, spec, slen);
    vol->src[slen] = '\0';

    const char *dst_start = colon1 + 1;
    const char *dst_end = colon2 ? colon2 : spec + lc_string_length(spec);
    size_t dlen = (size_t)(dst_end - dst_start);
    if (dlen == 0 || dlen >= sizeof(vol->dst))
        return "the volume's destination is empty or too long";
    lc_bytes_copy(vol->dst, dst_start, dlen);
    vol->dst[dlen] = '\0';

    vol->ro = false;
    if (colon2) {
        if (colon2[1] == 'r' && colon2[2] == 'o' && colon2[3] == '\0')
            vol->ro = true;
        else
            return "after the volume's destination only :ro may follow";
    }

    if (!normalise_path(vol->src))
        return "the volume's source must be an absolute path without ..";
    if (path_is_under(vol->src, "/proc") || path_is_under(vol->src, "/sys") ||
        path_is_under(vol->src, "/dev"))
        return "a volume's source may not be under /proc, /sys or /dev";
    return destination_problem(vol->dst);
}

/* ─── Devices (ROADMAP G.1) ─────────────────────────────────────────────── */

/* What every container has in its /dev already, and what init makes there:
 * no device is put in their place, nor below one, which would make it a
 * directory before init puts it there. */
static bool device_path_taken(const char *path) {
    static const char *const nodes[] = {
        "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx",
        "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/pts", "/dev/shm",
    };
    for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++)
        if (path_is_under(path, nodes[i]))
            return true;
    return false;
}

const char *parse_device_spec(const char *spec, device_spec *dev) {
    /* one line of a file of lines, as a volume is */
    if (has_control_chars(spec))
        return "a device's paths may not contain control characters";
    const char *parts[4] = { spec, NULL, NULL, NULL };
    size_t nparts = 1;
    for (const char *c = spec; *c; c++)
        if (*c == ':') {
            if (nparts == 3)
                return "a device is written <host path>[:<path in the container>][:ro], and its paths have no colon in them";
            parts[nparts++] = c + 1;
        }
    *dev = (device_spec){ 0 };
    size_t hlen = (size_t)((nparts > 1 ? parts[1] - 1 : spec + lc_string_length(spec)) - spec);
    if (hlen == 0 || hlen >= sizeof(dev->host))
        return "the device's path on the host is empty or too long";
    lc_bytes_copy(dev->host, spec, hlen);
    dev->host[hlen] = '\0';
    if (!normalise_path(dev->host))
        return "the device's path on the host must be an absolute path without ..";

    /* host:ro, host:path or host:path:ro */
    const char *path = NULL;
    size_t plen = 0;
    if (nparts == 3) {
        if (!streq(parts[2], "ro"))
            return "after the device's path in the container only :ro may follow";
        dev->ro = true;
        path = parts[1];
        plen = (size_t)(parts[2] - 1 - parts[1]);
    } else if (nparts == 2) {
        if (streq(parts[1], "ro"))
            dev->ro = true;
        else {
            path = parts[1];
            plen = lc_string_length(parts[1]);
        }
    }
    if (path) {
        if (plen == 0 || plen >= sizeof(dev->path))
            return "the device's path in the container is empty or too long";
        lc_bytes_copy(dev->path, path, plen);
        dev->path[plen] = '\0';
    } else {
        if (!path_is_under(dev->host, "/dev"))
            return "a device that is not under /dev on the host needs its path in the container: <host path>:/dev/<name>";
        lc_bytes_copy(dev->path, dev->host, hlen + 1);
    }
    if (!normalise_path(dev->path))
        return "the device's path in the container must be an absolute path without ..";
    if (!path_is_under(dev->path, "/dev") || streq(dev->path, "/dev"))
        return "a device's path in the container is under /dev";
    if (device_path_taken(dev->path))
        return "every container has that path of /dev already";
    return NULL;
}

const char *config_add_device(container_config *config, const device_spec *dev) {
    for (int i = 0; i < config->ndevs; i++)
        if (streq(config->devs[i].path, dev->path))
            return "there is already a device at that path in the container";
    if (config->ndevs >= MAX_DEVICES)
        return "the container already has the maximum of " STRINGIFY(MAX_DEVICES) " devices";
    config->devs[config->ndevs++] = *dev;
    return NULL;
}

/*
 * The devices whose use is the host's (ROADMAP G.1, by the maintainer's word
 * of 2026-11-23), by their numbers (Documentation/admin-guide/devices.txt):
 * no container is given one, whatever its path.
 */
#define DEV_ANY_MINOR 0xfffffU
static const struct { uint32_t major, minor_first, minor_last; const char *what; } DEVICES_REFUSED[] = {
    { 1,   1,   2,   "the host's memory" },
    { 1,   4,   4,   "the host's I/O ports" },
    { 1,   11,  11,  "the kernel's log" },
    { 4,   0,   63,  "a virtual console of the host's" },
    { 5,   1,   1,   "the host's console" },
    { 7,   0,   DEV_ANY_MINOR, "what a virtual console of the host's shows" },
    { 13,  0,   DEV_ANY_MINOR, "an input device of the host's, which reads its keys and its pointer" },
    { 10,  223, 223, "uinput, which makes a host's keys and pointer" },
    { 10,  130, 130, "the watchdog, which restarts the host when it is closed" },
    { 202, 0,   DEV_ANY_MINOR, "a CPU's model-specific registers" },
    { 203, 0,   DEV_ANY_MINOR, "a CPU's cpuid" },
};

/* The major of a kind of character device as /proc/devices names it, given
 * by the kernel at boot, or 0. */
static uint32_t char_major_named(const char *name) {
    static char text[8192];
    if (read_file("/proc/devices", text, sizeof(text)) <= 0)
        return 0;
    bool chars = false;
    size_t len = lc_string_length(name);
    for (const char *line = text; *line; ) {
        const char *end = line;
        while (*end && *end != '\n')
            end++;
        if (lc_string_starts_with(line, (size_t)(end - line), "Character devices:", 18))
            chars = true;
        else if (lc_string_starts_with(line, (size_t)(end - line), "Block devices:", 14))
            chars = false;
        else if (chars) {
            const char *p = line;
            while (p < end && *p == ' ')
                p++;
            uint32_t major = 0;
            while (p < end && *p >= '0' && *p <= '9')
                major = major * 10 + (uint32_t)(*p++ - '0');
            if (p < end && *p == ' ' && (size_t)(end - p - 1) == len && lc_bytes_compare(p + 1, name, len) == 0)
                return major;
        }
        line = *end ? end + 1 : end;
    }
    return 0;
}

/* A GPU's compute nodes, the devices a box of --profile agent may have: a
 * render node; NVIDIA's GPUs, its control node and nvidia-uvm, whose major
 * is given at boot, but nvidia-modeset; and AMD's kfd. */
static bool gpu_compute_node(uint32_t major, uint32_t minor) {
    if (major == 226)
        return minor >= 128 && minor <= 255;
    if (major == 195)
        return minor <= 253 || minor == 255;
    uint32_t uvm = char_major_named("nvidia-uvm"), kfd = char_major_named("kfd");
    return (uvm && major == uvm) || (kfd && major == kfd);
}

const char *device_refused(const char *host, const struct lb_statx *stx, bool agent) {
    static char why[MAX_PATH + 160];
    bool cut = false;
    const char *wrong = NULL;
    uint32_t major = stx->stx_rdev_major, minor = stx->stx_rdev_minor;
    if ((stx->stx_mode & LB_S_IFMT) == LB_S_IFBLK)
        wrong = " is a block device: no container is given one";
    else if ((stx->stx_mode & LB_S_IFMT) != LB_S_IFCHR)
        wrong = " is not a character device";
    for (size_t i = 0; i < sizeof(DEVICES_REFUSED) / sizeof(DEVICES_REFUSED[0]) && !wrong; i++)
        if (major == DEVICES_REFUSED[i].major && minor >= DEVICES_REFUSED[i].minor_first &&
            minor <= DEVICES_REFUSED[i].minor_last) {
            size_t pos = str_append(why, 0, host, sizeof(why), &cut);
            pos = str_append(why, pos, " is ", sizeof(why), &cut);
            pos = str_append(why, pos, DEVICES_REFUSED[i].what, sizeof(why), &cut);
            str_append(why, pos, ": no container is given it", sizeof(why), &cut);
            return why;
        }
    if (!wrong && agent && !gpu_compute_node(major, minor))
        wrong = " is not a GPU's compute node: a box of --profile agent is given render nodes, NVIDIA's "
                "and AMD's kfd, and nothing else";
    if (!wrong)
        return NULL;
    str_append(why, str_append(why, 0, host, sizeof(why), &cut), wrong, sizeof(why), &cut);
    return why;
}

const char *device_on_nodev(const char *host) {
    static char why[MAX_PATH + 80];
    bool cut = false;
    str_append(why, str_append(why, 0, host, sizeof(why), &cut),
               " is on a mount of the host's with nodev, where no device opens, nor is it lifted for a container",
               sizeof(why), &cut);
    return why;
}

const char *device_userns_group(const char *host, const struct lb_statx *stx, bool ro, uint32_t *gid) {
    static char why[MAX_PATH + 160];
    bool cut = false;
    uint32_t want = ro ? 04u : 06u, other = stx->stx_mode & 07u, group = (stx->stx_mode >> 3) & 07u;
    *gid = 0;
    if ((other & want) == want)
        return NULL;                        /* anyone may: nothing to map */
    const char *wrong;
    if ((group & want) != want)
        wrong = ro ? " is read by its owner alone, whom no container of --userns stands for"
                   : " is read and written by its owner alone, whom no container of --userns stands for";
    else if (stx->stx_gid == 0)
        wrong = " opens to its group, which is root's, gid 0, and that a container of --userns never holds: give the "
                "node a group of its own";
    else {
        *gid = stx->stx_gid;
        return NULL;
    }
    str_append(why, str_append(why, 0, host, sizeof(why), &cut), wrong, sizeof(why), &cut);
    return why;
}

const char *device_check(const device_spec *dev, bool agent, uint32_t *major, uint32_t *minor) {
    static char why[MAX_PATH + 40];
    bool cut = false;
    struct lb_statx stx;
    lc_sysret rc = lb_sys_statx(AT_FDCWD, dev->host, 0, LB_STATX_TYPE, &stx);
    if (rc < 0) {
        str_append(why, str_append(why, 0, dev->host, sizeof(why), &cut),
                   rc == -LB_ENOENT ? " is not there" : " cannot be looked at", sizeof(why), &cut);
        return why;
    }
    struct lb_statfs sfs;
    if ((stx.stx_mode & LB_S_IFMT) == LB_S_IFCHR && lb_sys_statfs(dev->host, &sfs) == 0 && (sfs.f_flags & LB_ST_NODEV))
        return device_on_nodev(dev->host);
    *major = stx.stx_rdev_major;
    *minor = stx.stx_rdev_minor;
    return device_refused(dev->host, &stx, agent);
}

int config_volume_at(const container_config *config, const char *dst) {
    for (int i = 0; i < config->nvols; i++) {
        if (streq(config->vols[i].dst, dst))
            return i;
    }
    return -1;
}

const char *config_add_volume(container_config *config, const volume_spec *vol) {
    /* Two volumes at one place would be mounted one over the other, and only
     * the later one would ever be seen. */
    if (config_volume_at(config, vol->dst) >= 0)
        return "there is already a volume at that destination";
    if (config->nvols >= MAX_VOLS)
        return "the container already has the maximum of " STRINGIFY(MAX_VOLS) " volumes";
    config->vols[config->nvols++] = *vol;
    return NULL;
}

int config_remove_volumes_at(container_config *config, const char *dst) {
    int kept = 0, removed = 0;
    for (int i = 0; i < config->nvols; i++) {
        if (streq(config->vols[i].dst, dst)) {
            removed++;
            continue;
        }
        if (kept != i)
            config->vols[kept] = config->vols[i];
        kept++;
    }
    config->nvols = kept;
    return removed;
}

/* ─── The configuration ─────────────────────────────────────────────────── */

/* an oom_score no file and no option can give: none has been given */
#define OOM_SCORE_UNSET  (OOM_SCORE_MAX + 1)

void container_config_init(container_config *config) {
    *config = (container_config){0};
    config->version = CONTAINER_CONFIG_VERSION;
    config->oom_score = OOM_SCORE_UNSET;
}

/*
 * Give every limit that has none the default of lightbox.conf. NULL, or the
 * name of a default_* setting that was needed and cannot be used.
 */
const char *container_config_fill_defaults(container_config *config) {
    if (!config->mem[0]) {
        if (!cfg_global.default_mem[0] ||
            !str_copy(config->mem, cfg_global.default_mem, sizeof(config->mem)))
            return "default_mem";
    }
    if (!config->pids[0]) {
        if (!cfg_global.default_pids[0] ||
            !str_copy(config->pids, cfg_global.default_pids, sizeof(config->pids)))
            return "default_pids";
    }
    if (!config->cpu[0]) {
        if (!cfg_global.default_cpu[0] ||
            !str_copy(config->cpu, cfg_global.default_cpu, sizeof(config->cpu)))
            return "default_cpu";
    }
    if (config->oom_score == OOM_SCORE_UNSET) {
        if (!cfg_global.default_oom_ok)
            return "default_oom";
        config->oom_score = cfg_global.default_oom;
    }
    return NULL;
}

/* ─── Reading ───────────────────────────────────────────────────────────── */

/* "<file>: line <n>: <what><detail>", kept until the next one is made */
static const char *config_problem(const char *path, int line, const char *what, const char *detail) {
    static char problem[MAX_PATH + 256];
    bool cut = false;
    size_t pos = str_append(problem, 0, path, sizeof(problem), &cut);
    if (line > 0) {
        char digits[16];
        fmt_int(digits, line);
        pos = str_append(problem, pos, ": line ", sizeof(problem), &cut);
        pos = str_append(problem, pos, digits, sizeof(problem), &cut);
    }
    pos = str_append(problem, pos, ": ", sizeof(problem), &cut);
    pos = str_append(problem, pos, what, sizeof(problem), &cut);
    str_append(problem, pos, detail ? detail : "", sizeof(problem), &cut);
    /* a message that lost its end still says where to look */
    return problem;
}

/* A box's id: BOX_ID_LEN lowercase hex digits */
static bool box_id_ok(const char *id) {
    size_t len = lc_string_length(id);
    if (len != BOX_ID_LEN)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
            return false;
    }
    return true;
}

/* The keys a file has once at most. */
enum {
    KEY_MEM = 1 << 0, KEY_PIDS = 1 << 1, KEY_CPU = 1 << 2, KEY_OOM = 1 << 3,
    KEY_PRIVILEGED = 1 << 4, KEY_READONLY = 1 << 5, KEY_USERNS = 1 << 6,
    KEY_UID_START = 1 << 7, KEY_IO = 1 << 8, KEY_SWAP = 1 << 9, KEY_BASE = 1 << 10,
    KEY_GID_START = 1 << 11, KEY_SECCOMP = 1 << 12, KEY_NET = 1 << 13, KEY_DNS = 1 << 14,
    KEY_TTL = 1 << 15, KEY_ID = 1 << 16, KEY_PROFILE = 1 << 17, KEY_WORKDIR = 1 << 18,
};

static unsigned key_bit(const char *key) {
    static const struct { const char *name; unsigned bit; } keys[] = {
        { "mem", KEY_MEM }, { "pids", KEY_PIDS }, { "cpu", KEY_CPU }, { "oom_score", KEY_OOM },
        { "privileged", KEY_PRIVILEGED }, { "readonly", KEY_READONLY }, { "userns", KEY_USERNS },
        { "uid_start", KEY_UID_START }, { "io", KEY_IO }, { "swap", KEY_SWAP }, { "base", KEY_BASE },
        { "gid_start", KEY_GID_START }, { "seccomp", KEY_SECCOMP }, { "net", KEY_NET },
        { "dns", KEY_DNS }, { "ttl", KEY_TTL }, { "id", KEY_ID },
        { "profile", KEY_PROFILE }, { "workdir", KEY_WORKDIR },
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (streq(key, keys[i].name))
            return keys[i].bit;
    }
    return 0;
}

static bool parse_flag(const char *value, bool *out) {
    if (!streq(value, "0") && !streq(value, "1"))
        return false;
    *out = value[0] == '1';
    return true;
}

/* One line that is not empty. NULL, or what is wrong with it. */
static const char *config_line(container_config *config, char *line, unsigned *seen, bool first) {
    bool strict = config->version != 0;

    if (has_control_chars(line))
        return "has a control character";

    char *eq = line;
    while (*eq && *eq != '=') eq++;
    if (!*eq)
        return strict ? "is not key=value" : NULL;
    *eq = '\0';
    const char *key = line, *value = eq + 1;

    if (streq(key, "version")) {
        int version;
        if (!first)
            return "the version is not the first line";
        if (!parse_int_in(value, 1, INT32_MAX, &version))
            return "the version is not a number";
        if (version > CONTAINER_CONFIG_VERSION)
            return "was written by a newer lightbox than this one";
        config->version = version;
        return NULL;
    }

    if (streq(key, "vol")) {
        if (config->nvols >= MAX_VOLS)
            return "more than " STRINGIFY(MAX_VOLS) " volumes";
        const char *wrong = parse_volume_spec(value, &config->vols[config->nvols]);
        if (wrong)
            return wrong;
        config->nvols++;
        return NULL;
    }

    if (streq(key, "device")) {
        if (config->ndevs >= MAX_DEVICES)
            return "more than " STRINGIFY(MAX_DEVICES) " devices";
        device_spec dev;
        const char *wrong = parse_device_spec(value, &dev);
        if (wrong)
            return wrong;
        return config_add_device(config, &dev);
    }

    if (streq(key, "link")) {
        if (config->nlinks >= MAX_LINKS)
            return "more than " STRINGIFY(MAX_LINKS) " links";
        if (!name_is_valid(value) ||
            !str_copy(config->links[config->nlinks], value, sizeof(config->links[0])))
            return "the link is not the name of a container";
        config->nlinks++;
        return NULL;
    }

    unsigned bit = key_bit(key);
    if (bit == 0)
        return strict ? "a key lightbox does not know" : NULL;
    if (*seen & bit)        /* before the version line, the first one counted */
        return strict ? "a key the file already has" : NULL;
    *seen |= bit;

    switch (bit) {
        case KEY_MEM:
            if (!mem_limit_ok(value) || !str_copy(config->mem, value, sizeof(config->mem)))
                return "mem is not <number>[K|M|G|T] or max";
            return NULL;
        case KEY_SWAP:
            if (!swap_limit_ok(value) || !str_copy(config->swap, value, sizeof(config->swap)))
                return "swap is not 0, <number>[K|M|G|T] or max";
            return NULL;
        case KEY_PIDS:
            if (!pids_limit_ok(value) || !str_copy(config->pids, value, sizeof(config->pids)))
                return "pids is not a number from 1 to " STRINGIFY(PIDS_LIMIT_MAX) " or max";
            return NULL;
        case KEY_CPU: {
            int quota;
            if (!parse_cpu_limit(value, &quota) || !str_copy(config->cpu, value, sizeof(config->cpu)))
                return "cpu is not a number of CPUs from 0.01 to " STRINGIFY(CPU_LIMIT_MAX);
            return NULL;
        }
        case KEY_OOM:
            if (!parse_oom_score(value, &config->oom_score))
                return "oom_score is not a number from -1000 to 1000";
            return NULL;
        case KEY_PRIVILEGED:
            return parse_flag(value, &config->privileged) ? NULL : "privileged is not 0 or 1";
        case KEY_READONLY:
            return parse_flag(value, &config->read_only) ? NULL : "readonly is not 0 or 1";
        case KEY_USERNS:
            return parse_flag(value, &config->userns) ? NULL : "userns is not 0 or 1";
        case KEY_BASE:
            return base_id_ok(value) && str_copy(config->base, value, sizeof(config->base))
                   ? NULL : "base is not the id of a base snapshot";
        case KEY_UID_START:
            /* up to 0.5, a number that meant nothing; checked as a range when userns=1 */
            return parse_u32_text(value, &config->uid_start) ? NULL : "uid_start is not a number";
        case KEY_GID_START:
            return parse_u32_text(value, &config->gid_start) ? NULL : "gid_start is not a number";
        case KEY_SECCOMP:
            return parse_seccomp_profile(value, &config->seccomp_allow) ? NULL : "seccomp is not allow or deny";
        case KEY_NET:
            return parse_net_mode(value, &config->net, &config->proxy_port)
                   ? NULL : "net is not nat, outside, none or proxy:<port>";
        case KEY_DNS:
            return parse_dns_list(value, config) ? NULL : "dns is not a list of up to " STRINGIFY(MAX_DNS) " IPv4 addresses";
        case KEY_TTL:
            return parse_duration_ms(value, &config->ttl_ms) && str_copy(config->ttl, value, sizeof(config->ttl))
                   ? NULL : "ttl is not a duration from 1 ms to 365 days, such as 30m or 8h";
        case KEY_ID:
            return box_id_ok(value) && str_copy(config->id, value, sizeof(config->id))
                   ? NULL : "id is not " STRINGIFY(BOX_ID_LEN) " lowercase hex digits";
        case KEY_PROFILE:
            config->profile = PROFILE_AGENT;
            return streq(value, "agent") ? NULL : "profile is not agent";
        case KEY_WORKDIR:
            return value[0] == '/' && str_copy(config->workdir, value, sizeof(config->workdir))
                   ? NULL : "workdir is not an absolute path";
        default:    /* KEY_IO */
            return io_limit_ok(value) && str_copy(config->io, value, sizeof(config->io))
                   ? NULL : "io is not <major>:<minor> with rbps, wbps, riops or wiops =<number> or =max";
    }
}

/*
 * A .conf's text, which this cuts into lines where it stands. path is only
 * for the message.
 */
const char *container_config_parse(char *text, const char *path, container_config *config) {
    container_config_init(config);
    config->version = 0;        /* until the file says otherwise */

    unsigned seen = 0;
    int line_number = 0;
    bool first = true;
    for (char *line = text; *line; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        bool last = *end == '\0';
        *end = '\0';
        line_number++;

        if (line[0]) {
            const char *wrong = config_line(config, line, &seen, first);
            if (wrong)
                return config_problem(path, line_number, wrong, NULL);
            first = false;
        }
        line = last ? end : end + 1;
    }

    if (config->userns) {
        char text_uid[11], text_gid[11];
        format_u32(text_uid, config->uid_start);
        format_u32(text_gid, config->gid_start);
        uint32_t ignored;
        /* one that is not there is 0, which starts no range */
        if (!userns_start_ok(text_uid, &ignored) || !userns_start_ok(text_gid, &ignored))
            return config_problem(path, 0, "has userns=1 without a uid_start and a gid_start of a range of "
                                  "65536 ids that has neither 0 nor 4294967295 in it", NULL);
    } else {
        config->uid_start = config->gid_start = 0;
    }

    const char *unusable = container_config_fill_defaults(config);
    if (unusable)
        return config_problem(path, 0, "leaves a limit to a setting of lightbox.conf that cannot be used: ",
                              unusable);
    return NULL;
}

const char *container_config_load(const char *name, container_config *config) {
    static char text[CONF_MAX];
    char path[MAX_PATH];
    container_conf_path(path, name);

    int n = read_file(path, text, sizeof(text));
    if (n < 0)
        return config_problem(path, 0, "cannot be read", NULL);
    if (n >= CONF_MAX - 1)
        return config_problem(path, 0, "is larger than lightbox supports", NULL);
    /* what comes after a NUL byte would not be read at all */
    if (lc_string_length(text) != (size_t)n)
        return config_problem(path, 0, "has a NUL byte", NULL);
    return container_config_parse(text, path, config);
}

void container_config_load_or_die(const char *name, container_config *config) {
    const char *wrong = container_config_load(name, config);
    if (wrong)
        die2("Error: the container's configuration cannot be used: ", wrong);
}

/* ─── Writing ───────────────────────────────────────────────────────────── */

struct config_text {
    char   *text;
    size_t  max;
    size_t  pos;
    bool    cut;        /* something did not fit */
};

static void put(struct config_text *out, const char *s) {
    out->pos = str_append(out->text, out->pos, s, out->max, &out->cut);
}

static void put_line(struct config_text *out, const char *key, const char *value) {
    put(out, key);
    put(out, "=");
    put(out, value);
    put(out, "\n");
}

static void put_number(struct config_text *out, const char *key, int value) {
    char digits[16];
    fmt_int(digits, value);
    put_line(out, key, digits);
}

/* Do two configurations say the same about a container? */
static bool same_config(const container_config *a, const container_config *b) {
    if (!streq(a->mem, b->mem) || !streq(a->swap, b->swap) || !streq(a->pids, b->pids) ||
        !streq(a->cpu, b->cpu) ||
        !streq(a->io, b->io) || !streq(a->base, b->base) || a->oom_score != b->oom_score ||
        a->privileged != b->privileged || a->read_only != b->read_only || a->userns != b->userns ||
        a->uid_start != b->uid_start || a->gid_start != b->gid_start ||
        a->seccomp_allow != b->seccomp_allow || a->net != b->net || a->proxy_port != b->proxy_port ||
        a->ndns != b->ndns || !streq(a->ttl, b->ttl) || a->ttl_ms != b->ttl_ms || !streq(a->id, b->id) ||
        a->profile != b->profile || !streq(a->workdir, b->workdir) ||
        a->nvols != b->nvols || a->nlinks != b->nlinks)
        return false;
    for (int i = 0; i < a->ndns; i++) {
        if (!streq(a->dns[i], b->dns[i]))
            return false;
    }
    for (int i = 0; i < a->nvols; i++) {
        if (!streq(a->vols[i].src, b->vols[i].src) || !streq(a->vols[i].dst, b->vols[i].dst) ||
            a->vols[i].ro != b->vols[i].ro)
            return false;
    }
    for (int i = 0; i < a->nlinks; i++) {
        if (!streq(a->links[i], b->links[i]))
            return false;
    }
    return true;
}

const char *container_config_save(const char *name, const container_config *config) {
    static char text[CONF_MAX];
    struct config_text out = { .text = text, .max = sizeof(text), .pos = 0, .cut = false };
    text[0] = '\0';

    put_number(&out, "version", CONTAINER_CONFIG_VERSION);
    put_line(&out, "mem", config->mem);
    if (config->swap[0])
        put_line(&out, "swap", config->swap);
    put_line(&out, "pids", config->pids);
    put_line(&out, "cpu", config->cpu);
    put_number(&out, "oom_score", config->oom_score);
    if (config->privileged) put_line(&out, "privileged", "1");
    if (config->read_only)  put_line(&out, "readonly", "1");
    /* without the line, the deny-list: what create --seccomp deny makes, and
     * what every container had before 0.8 */
    if (config->seccomp_allow) put_line(&out, "seccomp", "allow");
    /* without the line, nat: what create --net nat makes, and what every
     * container had before 0.8 */
    if (config->net != NET_NAT) {
        char mode[NET_MODE_TEXT_MAX];
        net_mode_text(mode, config->net, config->proxy_port);
        put_line(&out, "net", mode);
    }
    if (config->ndns > 0) {
        put(&out, "dns=");
        for (int i = 0; i < config->ndns; i++) {
            if (i) put(&out, ",");
            put(&out, config->dns[i]);
        }
        put(&out, "\n");
    }
    if (config->userns) {
        char digits[11];
        put_line(&out, "userns", "1");
        format_u32(digits, config->uid_start);
        put_line(&out, "uid_start", digits);
        format_u32(digits, config->gid_start);
        put_line(&out, "gid_start", digits);
    }
    if (config->io[0])
        put_line(&out, "io", config->io);
    if (config->base[0])
        put_line(&out, "base", config->base);
    if (config->ttl[0])
        put_line(&out, "ttl", config->ttl);
    if (config->id[0])
        put_line(&out, "id", config->id);
    if (config->profile == PROFILE_AGENT)
        put_line(&out, "profile", "agent");
    if (config->workdir[0])
        put_line(&out, "workdir", config->workdir);

    for (int i = 0; i < config->nvols; i++) {
        const volume_spec *vol = &config->vols[i];
        put(&out, "vol=");
        put(&out, vol->src);
        put(&out, ":");
        put(&out, vol->dst);
        put(&out, vol->ro ? ":ro\n" : "\n");
    }
    for (int i = 0; i < config->ndevs; i++) {
        const device_spec *dev = &config->devs[i];
        put(&out, "device=");
        put(&out, dev->host);
        put(&out, ":");
        put(&out, dev->path);
        put(&out, dev->ro ? ":ro\n" : "\n");
    }
    for (int i = 0; i < config->nlinks; i++)
        put_line(&out, "link", config->links[i]);

    /* never a file that lost part of itself */
    if (out.cut)
        return "the configuration does not fit its file";

    /*
     * And never a file that says something else than this configuration.
     * The reader is the judge of what a file says, so it is asked: what it
     * makes of this text has to be what the text was made from. A value
     * that is not one, a path with a colon in it, a text with a newline
     * that would start a line of its own: none of them comes back the same,
     * whatever let them in.
     */
    static char copy[CONF_MAX];
    static container_config back;
    char path[MAX_PATH];
    container_conf_path(path, name);
    lc_bytes_copy(copy, text, out.pos + 1);
    if (container_config_parse(copy, path, &back) != NULL || !same_config(config, &back))
        return "the configuration has a value that would not be read back as it is";

    if (write_file_atomic(path, text, MODE_PRIVATE_FILE) < 0)
        return "the configuration could not be written";
    return NULL;
}
