#include "lightbox.h"

/*
 * User namespaces (ROADMAP 8.1). A container created with --userns has a
 * range of USERNS_SIZE host uids and as many host gids of its own, taken from
 * the ranges that /etc/subuid and /etc/subgid give the name "lightbox", as
 * rootful Podman's --userns=auto takes those of "containers". The
 * container's uid 0 is the first uid of its range on the host, and so on.
 *
 * Its root is an idmapped mount (Linux 5.12): the base's files, owned by host
 * root, are its root's, and nothing is chowned. An overlay container's
 * snapshot is idmapped and becomes the overlay's lower layer (Linux 5.19);
 * its own files, the upper layer, are owned by its range on the host.
 *
 * Its volumes (ROADMAP 8.2) are idmapped too, each to its source's owner:
 * the container's root stands for the owner and group of the source on the
 * host, and no other id is mapped. Host root's are never mapped.
 */

/* ─── Ranges ────────────────────────────────────────────────────────────── */

/* A decimal number of at most 4294967295, without a zero in front. */
static bool parse_u32(const char *text, size_t len, uint32_t *out) {
    if (len == 0 || len > 10 || (len > 1 && text[0] == '0'))
        return false;
    uint64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        if (text[i] < '0' || text[i] > '9')
            return false;
        value = value * 10 + (uint64_t)(text[i] - '0');
    }
    if (value > 0xffffffffu)
        return false;
    *out = (uint32_t)value;
    return true;
}

bool parse_u32_text(const char *text, uint32_t *out) {
    return parse_u32(text, lc_string_length(text), out);
}

bool userns_start_ok(const char *text, uint32_t *start) {
    uint32_t value;
    if (!parse_u32(text, lc_string_length(text), &value))
        return false;
    /* never host root, and no id of the range past 4294967294, which is (uid_t)-1 */
    if (value == 0 || (uint64_t)value + USERNS_SIZE - 1 > 0xfffffffeu)
        return false;
    *start = value;
    return true;
}

void format_u32(char out[11], uint32_t value) {
    char digits[11];
    int n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    for (int i = 0; i < n; i++)
        out[i] = digits[n - 1 - i];
    out[n] = '\0';
}

/*
 * The ranges a subid file gives owner: lines of name:start:count. Lines of
 * other names, empty lines and lines that begin with # are passed over. How
 * many, or -1 when a line of owner's is no range, or a range that would map
 * host root or (uid_t)-1; *line then has its number.
 */
int subid_ranges(const char *text, const char *owner, subid_range *out, int max, int *line) {
    size_t owner_len = lc_string_length(owner);
    int n = 0;
    *line = 0;
    for (const char *p = text; *p; ) {
        const char *end = p;
        while (*end && *end != '\n') end++;
        (*line)++;
        size_t len = (size_t)(end - p);
        if (len > owner_len && p[owner_len] == ':' && lc_bytes_compare(p, owner, owner_len) == 0) {
            const char *start = p + owner_len + 1;
            const char *colon = start;
            while (colon < end && *colon != ':') colon++;
            subid_range r;
            if (colon == end || !parse_u32(start, (size_t)(colon - start), &r.start) ||
                !parse_u32(colon + 1, (size_t)(end - colon - 1), &r.count) ||
                r.start == 0 || (uint64_t)r.start + r.count - 1 > 0xfffffffeu)
                return -1;
            if (n < max)
                out[n++] = r;
        }
        p = *end ? end + 1 : end;
    }
    return n;
}

/* The start of the k-th range of USERNS_SIZE ids in ranges, in their order. */
static bool subid_slot(const subid_range *r, int n, int k, uint32_t *start) {
    for (int i = 0; i < n; i++) {
        int slots = (int)(r[i].count / USERNS_SIZE);
        if (k < slots) {
            *start = r[i].start + (uint32_t)k * USERNS_SIZE;
            return true;
        }
        k -= slots;
    }
    return false;
}

static bool overlaps(uint32_t a, uint32_t b) {
    return (uint64_t)a < (uint64_t)b + USERNS_SIZE && (uint64_t)b < (uint64_t)a + USERNS_SIZE;
}

/* The first range of 65536 of one file's that overlaps none of the taken
 * ones of that kind: which, 0 uids and 1 gids. NULL, or why there is none. */
static const char *first_free(const subid_range *r, int n, const uint32_t taken[][2], int ntaken, int which,
                              uint32_t *start) {
    for (int k = 0;; k++) {
        uint32_t s;
        if (!subid_slot(r, n, k, &s))
            return k == 0 ? "no range of 65536 ids" : "every range of 65536 ids is a container's";
        bool free = true;
        for (int t = 0; t < ntaken && free; t++)
            free = !overlaps(s, taken[t][which]);
        if (free) {
            *start = s;
            return NULL;
        }
    }
}

const char *userns_choose(const subid_range *uids, int nu, const subid_range *gids, int ng,
                          const uint32_t taken[][2], int ntaken, uint32_t *uid_start, uint32_t *gid_start) {
    const char *why = first_free(uids, nu, taken, ntaken, 0, uid_start);
    return why ? why : first_free(gids, ng, taken, ntaken, 1, gid_start);
}

static const char *ranges_of(const char *path, subid_range *out, int max, int *n) {
    static char text[65536];
    static char problem[MAX_PATH + 96];
    int got = read_file(path, text, sizeof(text));
    if (got < 0) {
        *n = 0;     /* no file: no range */
        return NULL;
    }
    if (got >= (int)sizeof(text) - 1) {
        str_copy_or_die(problem, path, sizeof(problem), "a path");
        bool cut = false;
        str_append(problem, lc_string_length(problem), " is too long to read", sizeof(problem), &cut);
        return problem;
    }
    int line = 0;
    *n = subid_ranges(text, USERNS_OWNER, out, max, &line);
    if (*n < 0) {
        char digits[16];
        fmt_int(digits, line);
        bool cut = false;
        size_t pos = str_append(problem, 0, path, sizeof(problem), &cut);
        pos = str_append(problem, pos, ", line ", sizeof(problem), &cut);
        pos = str_append(problem, pos, digits, sizeof(problem), &cut);
        str_append(problem, pos, ": a range of " USERNS_OWNER " that is not start:count, or that has uid 0 or 4294967295 in it",
                   sizeof(problem), &cut);
        return problem;
    }
    return NULL;
}

int userns_range_count(void) {
    static subid_range uids[SUBID_RANGES_MAX], gids[SUBID_RANGES_MAX];
    int nu = 0, ng = 0;
    if (ranges_of(SUBUID_FILE, uids, SUBID_RANGES_MAX, &nu) || ranges_of(SUBGID_FILE, gids, SUBID_RANGES_MAX, &ng))
        return -1;
    int k = 0;
    uint32_t u, g;
    while (k < 1 << 20 && subid_slot(uids, nu, k, &u) && subid_slot(gids, ng, k, &g))
        k++;
    return k;
}

/*
 * The range of a new container: the first one of 65536 uids and gids that
 * /etc/subuid and /etc/subgid give lightbox and no container has. The
 * caller holds the store's lock. NULL, or what is wrong.
 */
const char *userns_allocate(uint32_t *uid_start, uint32_t *gid_start) {
    static subid_range uids[SUBID_RANGES_MAX], gids[SUBID_RANGES_MAX];
    int nu = 0, ng = 0;
    const char *wrong = ranges_of(SUBUID_FILE, uids, SUBID_RANGES_MAX, &nu);
    if (!wrong)
        wrong = ranges_of(SUBGID_FILE, gids, SUBID_RANGES_MAX, &ng);
    if (wrong)
        return wrong;

    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    static uint32_t taken[MAX_LISTED][2];
    static container_config config;
    bool more = false;
    int count = list_containers(names, MAX_LISTED, &more);
    if (more)
        return "there are more containers than lightbox can look at";
    int ntaken = 0;
    for (int i = 0; i < count; i++) {
        if (container_config_load(names[i], &config) != NULL) {
            /* a range is not given out while a .conf that may have it cannot be read */
            static char problem[NAME_MAX_LEN + 96];
            bool cut = false;
            size_t pos = str_append(problem, 0, "the configuration of container '", sizeof(problem), &cut);
            pos = str_append(problem, pos, names[i], sizeof(problem), &cut);
            str_append(problem, pos, "' cannot be read, and its range may be the one", sizeof(problem), &cut);
            return problem;
        }
        if (config.userns) {
            taken[ntaken][0] = config.uid_start;
            taken[ntaken][1] = config.gid_start;
            ntaken++;
        }
    }
    wrong = userns_choose(uids, nu, gids, ng, (const uint32_t (*)[2])taken, ntaken, uid_start, gid_start);
    return wrong;
}

/* ─── Maps and idmapped mounts ──────────────────────────────────────────── */

void id_map_line(char out[ID_MAP_LINE_MAX], const id_map *map) {
    char inside[11], outside[11], count[11];
    format_u32(inside, map->inside);
    format_u32(outside, map->outside);
    format_u32(count, map->count);
    bool cut = false;
    size_t pos = str_append(out, 0, inside, ID_MAP_LINE_MAX, &cut);
    pos = str_append(out, pos, " ", ID_MAP_LINE_MAX, &cut);
    pos = str_append(out, pos, outside, ID_MAP_LINE_MAX, &cut);
    pos = str_append(out, pos, " ", ID_MAP_LINE_MAX, &cut);
    pos = str_append(out, pos, count, ID_MAP_LINE_MAX, &cut);
    str_append(out, pos, "\n", ID_MAP_LINE_MAX, &cut);
}

bool volume_maps(uint32_t owner_uid, uint32_t owner_gid, uint32_t uid_start, uint32_t gid_start,
                 id_map *uids, id_map *gids) {
    if (owner_uid == 0 || owner_gid == 0)
        return false;
    *uids = (id_map){ .inside = owner_uid, .outside = uid_start, .count = 1 };
    *gids = (id_map){ .inside = owner_gid, .outside = gid_start, .count = 1 };
    return true;
}

/* the line of map into /proc/<pid>/<file> */
static int write_map(int pid, const char *file, const id_map *map) {
    char path[64], line[ID_MAP_LINE_MAX];
    if (!proc_pid_path(path, sizeof(path), pid, file))
        return -LB_EINVAL;
    id_map_line(line, map);
    return write_file(path, line) < 0 ? -LB_EINVAL : 0;
}

static int write_maps(int pid, const id_map *uids, const id_map *gids) {
    int rc = write_map(pid, "/uid_map", uids);
    return rc ? rc : write_map(pid, "/gid_map", gids);
}

/* a container's: its uid and gid 0 and the USERNS_SIZE ids after them */
static void container_maps(uint32_t uid_start, uint32_t gid_start, id_map *uids, id_map *gids) {
    *uids = (id_map){ .inside = 0, .outside = uid_start, .count = USERNS_SIZE };
    *gids = (id_map){ .inside = 0, .outside = gid_start, .count = USERNS_SIZE };
}

int userns_write_maps(int pid, uint32_t uid_start, uint32_t gid_start) {
    id_map uids, gids;
    container_maps(uid_start, gid_start, &uids, &gids);
    return write_maps(pid, &uids, &gids);
}

int userns_fd_with(uint32_t uid_start, uint32_t gid_start) {
    id_map uids, gids;
    container_maps(uid_start, gid_start, &uids, &gids);
    return userns_fd_mapped(&uids, &gids);
}

/*
 * A user namespace with those maps, held by a descriptor: the one an
 * idmapped mount is made with. A child makes it and holds it until the
 * descriptor is open. The descriptor, or minus an errno.
 */
int userns_fd_mapped(const id_map *uids, const id_map *gids) {
    int32_t ready[2], hold[2];
    if (lc_kernel_create_pipe(ready, O_CLOEXEC) < 0)
        return -LB_EINVAL;
    if (lc_kernel_create_pipe(hold, O_CLOEXEC) < 0) {
        lc_kernel_close_file(ready[0]);
        lc_kernel_close_file(ready[1]);
        return -LB_EINVAL;
    }
    lc_sysret child = lc_kernel_fork();
    if (child == 0) {
        lc_kernel_close_file(ready[0]);
        lc_kernel_close_file(hold[1]);
        char said = lc_kernel_unshare(CLONE_NEWUSER) == 0 ? 'y' : 'n';
        (void)lc_kernel_write_all(ready[1], &said, 1);
        char byte;
        (void)lc_kernel_read_retry(hold[0], &byte, 1);     /* until the parent is done */
        lc_kernel_exit(0);
    }
    lc_kernel_close_file(ready[1]);
    lc_kernel_close_file(hold[0]);
    int fd = -LB_EINVAL;
    if (child > 0) {
        char said = 'n';
        if (lc_kernel_read_retry(ready[0], &said, 1) == 1 && said == 'y') {
            fd = write_maps((int)child, uids, gids);
            if (fd == 0) {
                char path[64];
                fd = proc_pid_path(path, sizeof(path), (int)child, "/ns/user")
                     ? (int)lc_kernel_open_file(path, O_RDONLY | O_CLOEXEC, 0) : -LB_EINVAL;
            }
        }
    } else {
        fd = (int)child;
    }
    lc_kernel_close_file(ready[0]);
    lc_kernel_close_file(hold[1]);
    if (child > 0) {
        int32_t status;
        (void)wait_child((int32_t)child, &status);
    }
    return fd;
}

/*
 * A copy of the mount at path, not attached anywhere yet, that shows its
 * files with the ids of the user namespace userns_fd: a file of host uid 0
 * is the container's root's. nodev, and nosuid unless privileged. The tree's
 * descriptor, or minus an errno, with *step the call that failed.
 */
int idmapped_tree(const char *path, int userns_fd, bool privileged, const char **step) {
    *step = "open_tree";
    lc_sysret tree = lb_sys_open_tree(AT_FDCWD, path, LB_OPEN_TREE_CLONE | LB_OPEN_TREE_CLOEXEC);
    if (tree < 0)
        return (int)tree;
    struct lb_mount_attr attr = {
        .attr_set = LB_MOUNT_ATTR_IDMAP | LB_MOUNT_ATTR_NODEV | (privileged ? 0 : LB_MOUNT_ATTR_NOSUID),
        .userns_fd = (uint64_t)userns_fd,
    };
    *step = "mount_setattr";
    lc_sysret rc = lb_sys_mount_setattr((int32_t)tree, "", LB_AT_EMPTY_PATH, &attr);
    if (rc < 0) {
        lc_kernel_close_file((int32_t)tree);
        return (int)rc;
    }
    return (int)tree;
}

int attach_tree(int tree, const char *target) {
    lc_sysret rc = lb_sys_move_mount(tree, "", AT_FDCWD, target, LB_MOVE_MOUNT_F_EMPTY_PATH);
    return rc < 0 ? (int)rc : 0;
}
