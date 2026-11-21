#include "lightbox.h"

/*
 * Where a container's files are. Each of these fits MAX_PATH: a container's
 * name is short, and the settings are refused when they are read if they are
 * so long that one of these paths would not fit (cfg_global_load). Should
 * one not fit all the same, the process ends here; no path is ever cut.
 */
void container_dir_path(char *buf, const char *name) {
    path_join_or_die(buf, MAX_PATH, cfg_global.container_dir, name);
}

void container_root(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, "rootfs");
}

void container_ip_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, ".ip");
}

void container_conf_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, ".conf");
}

void container_log_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, "console.log");
}

/* What create wrote in the container's resolv.conf, for reset (ROADMAP 8.8). */
void container_resolv_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, ".resolv");
}

/* A mark that create has not finished with the container. It is in the
 * container's directory, written to stay: a container that is half made is
 * still half made after a reboot. */
void container_creating_path(char *buf, const char *name) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, ".creating");
}

/*
 * The records of a container that is running, or was: <run_dir>/<name>/ with
 * the PID of its init, that process's start time, the state of the container
 * and what init said when it ended. They are of no use after a reboot, which
 * ends every container, so they are kept where a reboot takes them away,
 * and are written without waiting for a disk.
 */
void container_run_path(char *buf, const char *name) {
    path_join_or_die(buf, MAX_PATH, cfg_global.run_dir, name);
}

static void run_file_path(char *buf, const char *name, const char *file) {
    char base[MAX_PATH];
    container_run_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, file);
}

void container_pid_path(char *buf, const char *name)       { run_file_path(buf, name, "pid"); }
void container_pid_start_path(char *buf, const char *name) { run_file_path(buf, name, "pid_start"); }
void container_state_path(char *buf, const char *name)     { run_file_path(buf, name, "state"); }
void container_exit_path(char *buf, const char *name)      { run_file_path(buf, name, "exit"); }
void container_firewall_path(char *buf, const char *name)  { run_file_path(buf, name, "firewall"); }
void container_egress_path(char *buf, const char *name)    { run_file_path(buf, name, "egress"); }

/*
 * Before 0.5 these records were files in the container's directory: .pid,
 * .pid_start and .state. A container that an older lightbox started, and
 * that is still running, has them there. They are read where the records of
 * today are missing, so that such a container is seen to be running and can
 * be stopped, and they are removed with today's.
 */
static void old_record_path(char *buf, const char *name, const char *file) {
    char base[MAX_PATH];
    container_dir_path(base, name);
    path_join_or_die(buf, MAX_PATH, base, file);
}

/* A record's text, without the newline after it: its length, 0 for an empty
 * one and -1 for one that is not there, in either place. */
static int read_record(const char *name, const char *file, const char *old_file, char *buf, size_t bufsz) {
    char path[MAX_PATH];
    run_file_path(path, name, file);
    int n = read_file(path, buf, bufsz);
    if (n < 0) {
        old_record_path(path, name, old_file);
        n = read_file(path, buf, bufsz);
    }
    if (n < 0)
        return -1;
    for (size_t i = 0; buf[i]; i++) {
        if (buf[i] == '\n') { buf[i] = '\0'; break; }
    }
    return (int)lc_string_length(buf);
}

static void forget_old_record(const char *name, const char *old_file) {
    char path[MAX_PATH];
    old_record_path(path, name, old_file);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
}

static int report_run_dir(const char *what, const char *path) {
    print_str(STDERR, "Error: ");
    print_str(STDERR, what);
    print_str(STDERR, path);
    print_str(STDERR, "\n");
    return -1;
}

/*
 * Make run_dir, if a reboot or nobody yet has left none, and the container's
 * directory in it, both for root alone. A directory that is there is left as
 * it is; a name that is there and is no directory is an error, a link too.
 */
int container_run_dir_make(const char *name) {
    lc_sysret rc = lc_kernel_mkdirat(AT_FDCWD, cfg_global.run_dir, MODE_PRIVATE_DIR);
    if (rc == -LB_ENOENT) {
        /* its parents are missing as well */
        if (make_dirs(cfg_global.run_dir) != 0)
            return -1;
        (void)lc_kernel_fchmodat(AT_FDCWD, cfg_global.run_dir, MODE_PRIVATE_DIR, 0);
    } else if (rc < 0 && rc != -LB_EEXIST) {
        return report_run_dir("cannot make the directory for runtime records: ", cfg_global.run_dir);
    }

    char dir[MAX_PATH];
    container_run_path(dir, name);
    rc = lc_kernel_mkdirat(AT_FDCWD, dir, MODE_PRIVATE_DIR);
    if (rc < 0 && rc != -LB_EEXIST)
        return report_run_dir("cannot make the directory for the container's runtime records: ", dir);

    struct lb_statx stx;
    if (lb_sys_statx(AT_FDCWD, dir, AT_SYMLINK_NOFOLLOW, LB_STATX_TYPE, &stx) < 0 ||
        (stx.stx_mode & LB_S_IFMT) != LB_S_IFDIR)
        return report_run_dir("not a directory: ", dir);
    return 0;
}

/* Take the container's runtime records away, and their directory: what is
 * left says that the container is stopped. */
void container_forget_run(const char *name) {
    char path[MAX_PATH];
    container_forget_pid(name);
    container_state_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    forget_old_record(name, ".state");
    container_run_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

int record_container_state(const char *name, const char *state) {
    char path[MAX_PATH];
    if (container_run_dir_make(name) != 0)
        return -1;
    container_state_path(path, name);
    if (write_file_volatile(path, state) < 0)
        return -1;
    forget_old_record(name, ".state");      /* what an older lightbox last said */
    return 0;
}

void set_container_state(const char *name, const char *state) {
    if (record_container_state(name, state) < 0)
        die2("Error: cannot record the state of container ", name);
}

/*
 * The state on record. Without a runtime record a container is stopped,
 * whether it was stopped, never started or running before a reboot; unless
 * create never finished with it.
 */
void get_container_state(const char *name, char *buf, size_t bufsz) {
    char path[MAX_PATH];
    if (read_record(name, "state", ".state", buf, bufsz) > 0)
        return;
    container_creating_path(path, name);
    str_copy_or_die(buf, path_exists(path) ? "creating" : "stopped", bufsz, "a container's state");
}

/* What init said when it ended: its exit status. False when it said
 * nothing, as an init that was killed does. */
bool container_exit_report(const char *name, int *status) {
    char path[MAX_PATH], text[16];
    container_exit_path(path, name);
    if (read_file(path, text, sizeof(text)) <= 0)
        return false;
    for (size_t i = 0; text[i]; i++) {
        if (text[i] == '\n') { text[i] = '\0'; break; }
    }
    return parse_int_in(text, 0, 255, status);
}

int get_container_pid(const char *name) {
    char buf[16];
    int pid;
    if (read_record(name, "pid", ".pid", buf, sizeof(buf)) <= 0)
        return -1;
    /* a record that is not the number of a process is no record */
    return parse_int_in(buf, 1, PIDS_LIMIT_MAX, &pid) ? pid : -1;
}

int proc_starttime(int pid, char *buf, size_t bufsz) {
    char path[64], statbuf[512];
    if (!proc_pid_path(path, sizeof(path), pid, "/stat") ||
        read_file(path, statbuf, sizeof(statbuf)) <= 0)
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

    if (proc_starttime(pid, started, sizeof(started)) < 0)
        return -1;
    if (container_run_dir_make(name) != 0)
        return -1;
    container_pid_start_path(path, name);
    if (write_file_volatile(path, started) < 0)
        return -1;
    fmt_int(pidbuf, pid);
    container_pid_path(path, name);
    if (write_file_volatile(path, pidbuf) < 0)
        return -1;
    return 0;
}

/* Forget whatever is recorded about a container's init: which process it
 * was, and what it said when it ended. */
void container_forget_pid(const char *name) {
    char path[MAX_PATH];
    container_pid_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    container_pid_start_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    container_exit_path(path, name);
    lc_kernel_unlinkat(AT_FDCWD, path, 0);
    forget_old_record(name, ".pid");
    forget_old_record(name, ".pid_start");
}

int get_container_pid_starttime(const char *name, char *buf, size_t bufsz) {
    return read_record(name, "pid_start", ".pid_start", buf, bufsz) > 0 ? 0 : -1;
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
    if (proc_starttime(pid, actual_start, sizeof(actual_start)) < 0)
        return may_look ? CONTAINER_DEAD : CONTAINER_RUNNING;
    if (!streq(expected_start, actual_start))
        return CONTAINER_DEAD;

    /* A container's init lives in a PID namespace of its own. */
    char proc_path[64], pid_ns[64], init_ns[64];
    if (!proc_pid_path(proc_path, sizeof(proc_path), pid, "/ns/pid"))
        return CONTAINER_RUNNING;   /* cannot look; the start time matched */

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
 * The state to show: what is recorded, corrected by what was observed. A
 * record that still says "running" for a process that is gone reads "exited".
 */
void container_shown_state(const char *name, container_liveness live, char *buf, size_t bufsz) {
    if (live == CONTAINER_RUNNING) {
        str_copy_or_die(buf, "running", bufsz, "a container's state");
        return;
    }
    get_container_state(name, buf, bufsz);
    if (live == CONTAINER_DEAD || streq(buf, "running")) {
        /* init says so when --ttl ended it (ROADMAP 8.8) */
        int status = 0;
        bool expired = container_exit_report(name, &status) && status == INIT_EXPIRED;
        str_copy_or_die(buf, expired ? "expired" : "exited", bufsz, "a container's state");
    }
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
    bool cut = false;
    size_t pos = str_append(whose, 0, "container '", sizeof(whose), &cut);
    pos = str_append(whose, pos, name, sizeof(whose), &cut);
    str_append(whose, pos, "'", sizeof(whose), &cut);
    if (cut)
        die2("Error: not the name of a container: ", name);

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

int32_t store_lock(void) {
    lc_sysret fd = lock_directory(cfg_global.container_dir, false, true, "the container store");
    /* a store that is not there yet is locked by nobody; what needs it says so itself */
    if (fd < 0 && fd != -LB_ENOENT)
        die2("Error: cannot lock ", cfg_global.container_dir);
    return fd < 0 ? -1 : (int32_t)fd;
}

int32_t container_lock_try(const char *name) {
    char dir[MAX_PATH];
    container_dir_path(dir, name);
    lc_sysret fd = lock_directory(dir, false, false, "");
    return fd < 0 ? -1 : (int32_t)fd;
}

void require_root(const char *command) {
    if (lb_sys_geteuid() == 0)
        return;
    print_str(STDERR, "Error: lightbox ");
    print_str(STDERR, command);
    print_str(STDERR, " must be run as root\n");
    lc_kernel_exit(failure_status);
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
    return list_entries(cfg_global.container_dir, name_is_valid, names, max, more);
}

int list_entries(const char *dir, bool (*valid)(const char *), char names[][NAME_MAX_LEN + 1], int max, bool *more) {
    if (more)
        *more = false;

    lc_sysret dirfd = lc_kernel_open_file(dir, O_RDONLY | O_DIRECTORY, 0);
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
            if (!valid(entry))
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
            /* entry is a valid name, so it fits */
            lc_bytes_copy(names[at], entry, lc_string_length(entry) + 1);
            count++;
        }
    }

    lc_kernel_close_file((int32_t)dirfd);
    return count;
}
