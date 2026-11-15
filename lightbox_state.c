#include "lightbox.h"

void container_dir_path(char *buf, const char *name) {
    path_join(buf, MAX_PATH, cfg_global.container_dir, name);
}

void container_root(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, "rootfs");
}

void container_pid_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".pid");
}

void container_pid_start_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".pid_start");
}

void container_ip_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".ip");
}

void container_conf_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".conf");
}

void container_log_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, "console.log");
}

void container_state_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join(buf, MAX_PATH, base, ".state");
}

int record_container_state(const char *name, const char *state) {
    char path[MAX_PATH];
    container_state_path(path, name);
    return write_file_atomic(path, state, MODE_PRIVATE_FILE);
}

void set_container_state(const char *name, const char *state) {
    if (record_container_state(name, state) < 0)
        die2("Error: cannot record the state of container ", name);
}

void get_container_state(const char *name, char *buf, size_t bufsz) {
    char path[MAX_PATH];
    container_state_path(path, name);
    if (read_file(path, buf, bufsz) <= 0) {
        str_copy(buf, "unknown", bufsz);
        return;
    }
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    }
    if (!buf[0]) str_copy(buf, "unknown", bufsz);
}

/*
 * Read a container's whole .conf into a buffer of CONF_MAX bytes. Returns the
 * length, or -1 if the file cannot be read. A file that does not fit stops the
 * command: a shorter config would silently drop volumes or their ":ro".
 */
int container_conf_read(const char *name, char *buf) {
    char path[MAX_PATH];
    container_conf_path(path, name);
    int n = read_file(path, buf, CONF_MAX);
    if (n >= CONF_MAX - 1)
        die2("Error: container config is larger than lightbox supports: ", path);
    return n;
}

int conf_get(const char *name, const char *key, char *val, size_t valsz, const char *def) {
    char buf[CONF_MAX];
    if (container_conf_read(name, buf) < 0) {
        str_copy(val, def, valsz);
        return 0;
    }

    size_t keylen = lc_string_length(key);
    char *p = buf;
    while (*p) {
        if (lc_string_starts_with(p, lc_string_length(p), key, keylen) && p[keylen] == '=') {
            char *v = p + keylen + 1;
            char *end = v;
            while (*end && *end != '\n') end++;
            size_t len = (size_t)(end - v);
            if (len >= valsz) len = valsz - 1;
            lc_bytes_copy(val, v, len);
            val[len] = '\0';
            return 1;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    str_copy(val, def, valsz);
    return 0;
}

int conf_get_int(const char *name, const char *key, int def) {
    char val[32];
    if (conf_get(name, key, val, sizeof(val), "") && val[0])
        return parse_int(val);
    return def;
}

int get_container_pid(const char *name) {
    char path[MAX_PATH], buf[16];
    container_pid_path(path, name);
    if (read_file(path, buf, sizeof(buf)) < 0) return -1;
    return parse_int(buf);
}

static void clear_runtime_identity(const char *name, bool mark_failed) {
    char path[MAX_PATH];
    container_pid_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    container_pid_start_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    if (mark_failed)
        set_container_state(name, "failed\n");
}

static int read_proc_starttime(int pid, char *buf, size_t bufsz) {
    char path[64], statbuf[512], pidbuf[16];
    fmt_int(pidbuf, pid);
    size_t pos = str_copy(path, "/proc/", sizeof(path));
    pos = str_append(path, pos, pidbuf, sizeof(path));
    str_append(path, pos, "/stat", sizeof(path));

    if (read_file(path, statbuf, sizeof(statbuf)) <= 0)
        return -1;

    char *p = statbuf;
    char *last_paren = NULL;
    while (*p) {
        if (*p == ')') last_paren = p;
        p++;
    }
    if (!last_paren) return -1;

    p = last_paren + 1;
    while (*p == ' ') p++;

    for (int field = 3; field < 22; field++) {
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
    }

    if (!*p) return -1;

    size_t len = 0;
    while (p[len] && p[len] != ' ' && p[len] != '\n')
        len++;
    if (len == 0 || len >= bufsz)
        return -1;

    lc_bytes_copy(buf, p, len);
    buf[len] = '\0';
    return 0;
}

/*
 * Record a container's init: its PID and, as what tells it from a later
 * process with the same PID, its start time. The start time goes first, so a
 * PID is never on record without it. 0, or -1 when either could not be had.
 */
int container_record_pid(const char *name, int pid) {
    char path[MAX_PATH], pidbuf[16], started[32];

    if (read_proc_starttime(pid, started, sizeof(started)) < 0)
        return -1;
    container_pid_start_path(path, name);
    if (write_file_atomic(path, started, MODE_PRIVATE_FILE) < 0)
        return -1;
    fmt_int(pidbuf, pid);
    container_pid_path(path, name);
    if (write_file_atomic(path, pidbuf, MODE_PRIVATE_FILE) < 0)
        return -1;
    return 0;
}

/* Forget whatever is recorded about a container's init. */
void container_forget_pid(const char *name) {
    clear_runtime_identity(name, false);
}

int get_container_pid_starttime(const char *name, char *buf, size_t bufsz) {
    char path[MAX_PATH];
    container_pid_start_path(path, name);
    if (read_file(path, buf, bufsz) <= 0)
        return -1;
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    }
    return buf[0] ? 0 : -1;
}

/*
 * What the runtime files say about a container's init process.
 *
 * This only reads. A query must never change what is recorded: an unprivileged
 * caller, or one on a host that hides other users' processes, cannot tell a
 * dead process from one it is not allowed to look at. Only "no such process"
 * counts as gone. A permission error does not.
 */
container_liveness container_probe(const char *name) {
    int pid = get_container_pid(name);
    if (pid <= 0)
        return CONTAINER_NO_RECORD;

    lc_sysret sig = lc_kernel_send_signal(pid, 0);
    if (sig == -LB_ESRCH)
        return CONTAINER_DEAD;
    bool may_look = (sig == 0);

    /* The PID may have been reused since: the start time is the identity. */
    char expected_start[32], actual_start[32];
    if (get_container_pid_starttime(name, expected_start, sizeof(expected_start)) < 0)
        return CONTAINER_DEAD;
    if (read_proc_starttime(pid, actual_start, sizeof(actual_start)) < 0)
        return may_look ? CONTAINER_DEAD : CONTAINER_RUNNING;
    if (!streq(expected_start, actual_start))
        return CONTAINER_DEAD;

    /* A container's init lives in a PID namespace of its own. */
    char proc_path[64], pidbuf[16], pid_ns[64], init_ns[64];
    fmt_int(pidbuf, pid);
    size_t pos = str_copy(proc_path, "/proc/", sizeof(proc_path));
    pos = str_append(proc_path, pos, pidbuf, sizeof(proc_path));
    str_append(proc_path, pos, "/ns/pid", sizeof(proc_path));

    lc_sysret n1 = lc_kernel_readlinkat(AT_FDCWD, proc_path, pid_ns, sizeof(pid_ns) - 1);
    if (n1 == -LB_ENOENT || n1 == -LB_ESRCH)
        return CONTAINER_DEAD;
    lc_sysret n2 = lc_kernel_readlinkat(AT_FDCWD, "/proc/1/ns/pid", init_ns, sizeof(init_ns) - 1);
    if (n1 <= 0 || n2 <= 0)
        return CONTAINER_RUNNING;   /* not allowed to look; the start time matched */
    pid_ns[n1] = '\0';
    init_ns[n2] = '\0';

    return streq(pid_ns, init_ns) ? CONTAINER_DEAD : CONTAINER_RUNNING;
}

bool is_running(const char *name) {
    return container_probe(name) == CONTAINER_RUNNING;
}

/*
 * The clean-up for a container whose init is gone: forget the PID and record
 * the state as failed. Only commands that change a container call this (start
 * and stop). ls, inspect and exec report what they see and write nothing.
 */
void container_reap_if_dead(const char *name) {
    if (container_probe(name) == CONTAINER_DEAD)
        clear_runtime_identity(name, true);
}

/*
 * The state to show: what is recorded, corrected by what was observed. A
 * record that still says "running" for a process that is gone reads "exited".
 */
void container_shown_state(const char *name, container_liveness live, char *buf, size_t bufsz) {
    if (live == CONTAINER_RUNNING) {
        str_copy(buf, "running", bufsz);
        return;
    }
    get_container_state(name, buf, bufsz);
    if (live == CONTAINER_DEAD || streq(buf, "running"))
        str_copy(buf, "exited", bufsz);
}

/* ─── Locks ─────────────────────────────────────────────────────────────── */

/*
 * A lock on a directory, taken with flock on a descriptor that stays open
 * until the process ends. The descriptor is close-on-exec, so no tool this
 * process runs holds the lock on; a container's init closes everything it
 * inherits. The descriptor, or a negative errno when the directory cannot be
 * opened.
 */
static lc_sysret lock_directory(const char *path, bool shared, bool wait, const char *whose) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return fd;

    int32_t kind = shared ? LB_LOCK_SH : LB_LOCK_EX;
    lc_sysret rc = lb_sys_flock((int32_t)fd, kind | LB_LOCK_NB);
    if (rc == -LB_EAGAIN && wait) {
        print_str(STDERR, "Waiting for another lightbox command to finish with ");
        print_str(STDERR, whose);
        print_str(STDERR, "...\n");
        do {
            rc = lb_sys_flock((int32_t)fd, kind);
        } while (rc == -LB_EINTR);
    }
    if (rc < 0) {
        lc_kernel_close_file((int32_t)fd);
        return rc;
    }
    return fd;
}

/* Is the directory a descriptor is open on still the one at this path? rm
 * removes a container while others may wait for its lock. */
static bool still_at(int32_t fd, const char *path) {
    struct lb_statx held, there;
    if (lb_sys_statx(fd, "", LB_AT_EMPTY_PATH, LB_STATX_INO, &held) < 0 ||
        lb_sys_statx(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW, LB_STATX_INO, &there) < 0)
        return false;
    return held.stx_ino == there.stx_ino && held.stx_dev_major == there.stx_dev_major &&
           held.stx_dev_minor == there.stx_dev_minor;
}

void container_lock(const char *name) {
    char dir[MAX_PATH], whose[NAME_MAX_LEN + 16];
    container_dir_path(dir, name);
    size_t pos = str_copy(whose, "container '", sizeof(whose));
    pos = str_append(whose, pos, name, sizeof(whose));
    str_append(whose, pos, "'", sizeof(whose));

    lc_sysret fd = lock_directory(dir, false, true, whose);
    if (fd == -LB_ENOENT || (fd >= 0 && !still_at((int32_t)fd, dir)))
        die2("Error: container does not exist: ", name);
    if (fd < 0)
        die2("Error: cannot lock container ", name);
}

void container_lock_if_free(const char *name) {
    char dir[MAX_PATH];
    container_dir_path(dir, name);
    (void)lock_directory(dir, true, false, "");
}

void store_lock(void) {
    lc_sysret fd = lock_directory(cfg_global.container_dir, false, true, "the container store");
    /* a store that is not there yet is locked by nobody; what needs it says so itself */
    if (fd < 0 && fd != -LB_ENOENT)
        die2("Error: cannot lock ", cfg_global.container_dir);
}

void require_root(const char *command) {
    if (lb_sys_geteuid() == 0)
        return;
    print_str(STDERR, "Error: lightbox ");
    print_str(STDERR, command);
    print_str(STDERR, " must be run as root\n");
    lc_kernel_exit(1);
}

/* ─── Listing ───────────────────────────────────────────────────────────── */

/* struct linux_dirent64, as getdents64 fills a buffer with it: d_ino and d_off
 * of 8 bytes each, then these. A record starts wherever the previous one
 * ended, so its fields are read bytewise and never through a cast. */
#define DIRENT_RECLEN  16   /* uint16_t */
#define DIRENT_TYPE    18   /* uint8_t */
#define DIRENT_NAME    19   /* NUL-terminated */

#define DIRENT_UNKNOWN 0    /* DT_UNKNOWN: the filesystem does not say */
#define DIRENT_DIR     4    /* DT_DIR */

static bool entry_is_directory(int32_t dirfd, const char *entry) {
    struct lb_statx stx;
    if (lb_sys_statx(dirfd, entry, AT_SYMLINK_NOFOLLOW, LB_STATX_TYPE, &stx) < 0)
        return false;
    return (stx.stx_mode & LB_S_IFMT) == LB_S_IFDIR;
}

static bool name_before(const char *a, const char *b) {
    return lc_string_compare(a, lc_string_length(a), b, lc_string_length(b)) < 0;
}

int list_containers(char names[][NAME_MAX_LEN + 1], int max, bool *more) {
    if (more)
        *more = false;

    lc_sysret dirfd = lc_kernel_open_file(cfg_global.container_dir, O_RDONLY | O_DIRECTORY, 0);
    if (dirfd < 0)
        return 0;

    int count = 0;
    char buf[4096];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)dirfd, buf, sizeof(buf));
        if (n <= 0)
            break;

        for (lc_sysret pos = 0; pos < n; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + DIRENT_RECLEN, sizeof(reclen));
            if (reclen == 0)
                break;
            uint8_t type = (uint8_t)buf[pos + DIRENT_TYPE];
            const char *entry = buf + pos + DIRENT_NAME;
            pos += reclen;

            /* "." and ".." are not valid names either */
            if (!name_is_valid(entry))
                continue;
            if (type != DIRENT_DIR &&
                (type != DIRENT_UNKNOWN || !entry_is_directory((int32_t)dirfd, entry)))
                continue;
            if (count == max) {
                if (more)
                    *more = true;
                continue;
            }

            /* insert in order: a listing is small, and already sorted
             * directories cost one comparison per name */
            int at = count;
            while (at > 0 && name_before(entry, names[at - 1])) {
                lc_bytes_copy(names[at], names[at - 1], NAME_MAX_LEN + 1);
                at--;
            }
            str_copy(names[at], entry, NAME_MAX_LEN + 1);
            count++;
        }
    }

    lc_kernel_close_file((int32_t)dirfd);
    return count;
}
