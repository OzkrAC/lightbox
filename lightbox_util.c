#include "lightbox.h"

void print_str(int32_t fd, const char *s) {
    lc_print_string(fd, s, lc_string_length(s));
}

void die(const char *msg) {
    print_str(STDERR, msg);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

void die2(const char *prefix, const char *detail) {
    print_str(STDERR, prefix);
    print_str(STDERR, detail);
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

bool streq(const char *a, const char *b) {
    size_t la = lc_string_length(a);
    size_t lb = lc_string_length(b);
    if (la != lb) return false;
    return lc_string_equal(a, la, b, lb);
}

size_t str_copy(char *dst, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (len >= max) len = max - 1;
    lc_bytes_copy(dst, src, len);
    dst[len] = '\0';
    return len;
}

size_t str_append(char *dst, size_t pos, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (pos + len >= max) len = max - pos - 1;
    lc_bytes_copy(dst + pos, src, len);
    dst[pos + len] = '\0';
    return pos + len;
}

/*
 * Like str_append, for text that must be stored whole: a source that does not
 * fit is not cut. Nothing is appended and *overflow is set, and stays set.
 */
size_t str_append_whole(char *dst, size_t pos, const char *src, size_t max, bool *overflow) {
    size_t len = lc_string_length(src);
    if (pos >= max || len >= max - pos) {
        *overflow = true;
        if (pos < max) dst[pos] = '\0';
        return pos;
    }
    lc_bytes_copy(dst + pos, src, len);
    dst[pos + len] = '\0';
    return pos + len;
}

void path_join(char *buf, size_t bufsz, const char *a, const char *b) {
    size_t pos = str_copy(buf, a, bufsz);
    if (pos > 0 && buf[pos - 1] != '/')
        pos = str_append(buf, pos, "/", bufsz);
    if (b[0] == '/') b++;
    str_append(buf, pos, b, bufsz);
}

int parse_int(const char *s) {
    int neg = 0, val = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') {
        val = val * 10 + (*s - '0');
        s++;
    }
    return neg ? -val : val;
}

int fmt_int(char *buf, int val) {
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    int neg = 0, len = 0;
    char tmp[16];
    if (val < 0) { neg = 1; val = -val; }
    while (val > 0) { tmp[len++] = '0' + (val % 10); val /= 10; }
    int pos = 0;
    if (neg) buf[pos++] = '-';
    for (int i = len - 1; i >= 0; i--) buf[pos++] = tmp[i];
    buf[pos] = '\0';
    return pos;
}

int write_file(const char *path, const char *data) {
    lc_sysret fd = lc_kernel_open_file(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t len = lc_string_length(data);
    size_t off = 0;
    while (off < len) {
        lc_sysret n = lc_kernel_write_bytes((int32_t)fd, data + off, len - off);
        if (n <= 0) {
            lc_kernel_close_file((int32_t)fd);
            return -1;
        }
        off += (size_t)n;
    }
    lc_kernel_close_file((int32_t)fd);
    return 0;
}

void require_write_file(const char *path, const char *data) {
    if (write_file(path, data) < 0)
        die2("Error: write failed: ", path);
}

static int sync_parent_dir(const char *path) {
    char dirpath[MAX_PATH];
    size_t len = lc_string_length(path);

    if (len == 0 || len >= sizeof(dirpath))
        return -1;

    str_copy(dirpath, path, sizeof(dirpath));
    while (len > 0 && dirpath[len - 1] != '/')
        len--;

    if (len == 0)
        str_copy(dirpath, ".", sizeof(dirpath));
    else if (len == 1)
        dirpath[1] = '\0';
    else
        dirpath[len - 1] = '\0';

    lc_sysret dirfd = lc_kernel_open_file(dirpath, O_RDONLY, 0);
    if (dirfd < 0)
        return -1;

    lc_sysret rc = lb_sys_fsync((int32_t)dirfd);
    lc_kernel_close_file((int32_t)dirfd);
    return (rc < 0) ? -1 : 0;
}

static const char *pick_tool_path(const char *const *candidates, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (path_exists(candidates[i]))
            return candidates[i];
    }
    return candidates[0];
}

const char *tool_path_ip(void) {
    static const char *const candidates[] = {
        "/sbin/ip",
        "/usr/sbin/ip",
        "/bin/ip",
        "/usr/bin/ip",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_iptables(void) {
    static const char *const candidates[] = {
        "/usr/sbin/iptables",
        "/sbin/iptables",
        "/usr/bin/iptables",
        "/bin/iptables",
        "/usr/sbin/iptables-nft",
        "/sbin/iptables-nft",
        "/usr/bin/iptables-nft",
        "/bin/iptables-nft",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_mount(void) {
    static const char *const candidates[] = {
        "/bin/mount",
        "/usr/bin/mount",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_umount(void) {
    static const char *const candidates[] = {
        "/bin/umount",
        "/usr/bin/umount",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_mkdir(void) {
    static const char *const candidates[] = {
        "/bin/mkdir",
        "/usr/bin/mkdir",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_cp(void) {
    static const char *const candidates[] = {
        "/bin/cp",
        "/usr/bin/cp",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_chown(void) {
    static const char *const candidates[] = {
        "/bin/chown",
        "/usr/bin/chown",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_rm(void) {
    static const char *const candidates[] = {
        "/bin/rm",
        "/usr/bin/rm",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_nsenter(void) {
    static const char *const candidates[] = {
        "/usr/bin/nsenter",
        "/bin/nsenter",
        "/usr/sbin/nsenter",
        "/sbin/nsenter",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

bool tool_available(const char *path) {
    return path && path[0] && path_exists(path);
}

void require_tool(const char *label, const char *path) {
    if (tool_available(path))
        return;
    print_str(STDERR, "Error: required host tool is missing: ");
    print_str(STDERR, label);
    print_str(STDERR, " (expected at ");
    print_str(STDERR, path ? path : "-");
    print_str(STDERR, ")\n");
    lc_kernel_exit(1);
}


int write_file_atomic(const char *path, const char *data, int32_t mode) {
    char tmp[MAX_PATH];
    char pidbuf[16];
    int pid = lc_kernel_get_process_id();

    fmt_int(pidbuf, pid);
    size_t pos = str_copy(tmp, path, sizeof(tmp));
    pos = str_append(tmp, pos, ".tmp.", sizeof(tmp));
    str_append(tmp, pos, pidbuf, sizeof(tmp));

    lc_sysret fd = lc_kernel_open_file(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        return -1;

    size_t len = lc_string_length(data);
    size_t off = 0;
    while (off < len) {
        lc_sysret n = lc_kernel_write_bytes((int32_t)fd, data + off, len - off);
        if (n <= 0) {
            lc_kernel_close_file((int32_t)fd);
            lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
            return -1;
        }
        off += (size_t)n;
    }

    if (lb_sys_fsync((int32_t)fd) < 0) {
        lc_kernel_close_file((int32_t)fd);
        lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
        return -1;
    }
    lc_kernel_close_file((int32_t)fd);

    if (lb_sys_renameat(AT_FDCWD, tmp, AT_FDCWD, path) < 0) {
        lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
        return -1;
    }

    if (sync_parent_dir(path) < 0)
        return -1;
    return 0;
}

void require_write_file_atomic(const char *path, const char *data) {
    if (write_file_atomic(path, data, MODE_PRIVATE_FILE) < 0)
        die2("Error: atomic write failed: ", path);
}

int read_file(const char *path, char *buf, size_t bufsz) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY, 0);
    if (fd < 0) return -1;
    lc_sysret n = lc_kernel_read_bytes((int32_t)fd, buf, bufsz - 1);
    lc_kernel_close_file((int32_t)fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return (int)n;
}

/* 1 if the directory has no entries, 0 if it has some, -1 if it cannot be read. */
int dir_is_empty(const char *path) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    char buf[1024];
    int empty = 1;
    while (empty == 1) {
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, buf, sizeof(buf));
        if (n < 0) { empty = -1; break; }
        if (n == 0) break;
        for (lc_sysret pos = 0; pos < n; ) {
            /* struct linux_dirent64: d_reclen at offset 16, d_name at 19 */
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + 16, sizeof(reclen));
            const char *entry = buf + pos + 19;
            bool dot = entry[0] == '.' &&
                       (entry[1] == '\0' || (entry[1] == '.' && entry[2] == '\0'));
            if (!dot) { empty = 0; break; }
            if (reclen == 0) { empty = -1; break; }
            pos += reclen;
        }
    }
    lc_kernel_close_file((int32_t)fd);
    return empty;
}

bool path_exists(const char *path) {
    return lc_kernel_faccessat2(AT_FDCWD, path, F_OK, 0) == 0;
}

/* ─── Running programs ──────────────────────────────────────────────────── */

/* The environment of every tool lightbox runs: a fixed PATH and nothing of
 * the caller's. */
const char *const TOOL_ENV[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };

/* execve takes char *const[] for historical reasons and never writes to the
 * strings. This is the one place that drops the const lightbox keeps on them;
 * going through an integer says so to the compiler. */
lc_sysret exec_program(const char *prog, const char *const argv[], const char *const envp[]) {
    return lc_kernel_execute(prog, (char *const *)(uintptr_t)argv, (char *const *)(uintptr_t)envp);
}

/* Wait for one child, however often a signal interrupts the wait.
 * 0 with *status filled in, or -1 when the child cannot be waited for. */
int wait_child(int32_t pid, int32_t *status) {
    for (;;) {
        lc_sysret got = lc_kernel_wait_for_child(pid, status, 0);
        if (got == pid)
            return 0;
        if (got != -LB_EINTR)
            return -1;
    }
}

/* A wait status as a shell would report it: the exit status, or 128 plus the
 * number of the signal that ended the process. */
int exit_code_from_status(int32_t status) {
    int sig = status & 0x7f;
    return sig ? 128 + sig : (status >> 8) & 0xff;
}

static lc_sysret read_retry(int32_t fd, void *buf, size_t len) {
    for (;;) {
        lc_sysret n = lc_kernel_read_bytes(fd, buf, len);
        if (n != -LB_EINTR)
            return n;
    }
}

/* "Error: <before><prog><after><number>)" or, with after == NULL,
 * "Error: <before><prog>". */
static void report_run(const char *before, const char *prog, const char *after, int number) {
    print_str(STDERR, "Error: ");
    print_str(STDERR, before);
    print_str(STDERR, prog);
    if (after) {
        char digits[16];
        fmt_int(digits, number);
        print_str(STDERR, after);
        print_str(STDERR, digits);
        print_str(STDERR, ")");
    }
    lc_print_char(STDERR, '\n');
}

struct run_opts {
    const char *const *envp;    /* NULL: TOOL_ENV */
    bool   quiet;               /* the program's stdout and stderr go to /dev/null */
    char  *capture;             /* when set, its stdout is collected here as a string */
    size_t capture_size;
};

/*
 * Fork, execute prog and wait for it. The one place lightbox does this.
 *
 * Returns the program's exit status (0 to 255), or one of the RUN_* values of
 * lightbox.h when there is no exit status to return: no child could be made,
 * the program could not be executed, a signal ended it, or it could not be
 * waited for. Those four are reported on stderr here, in quiet mode too,
 * because no caller can tell them from each other otherwise. A non-zero exit
 * status is not reported: the program has said why, and for some callers it
 * is an answer ("no such interface"), not a failure.
 *
 * Whether execve worked is learned through a close-on-exec pipe: a successful
 * execve closes it, a failed one is followed by its errno.
 */
static int run_program(const char *prog, const char *const argv[], const struct run_opts *opts) {
    int32_t exec_pipe[2];
    int32_t out_pipe[2] = { -1, -1 };

    lc_sysret rc = lc_kernel_create_pipe(exec_pipe, O_CLOEXEC);
    if (rc >= 0 && opts->capture) {
        rc = lc_kernel_create_pipe(out_pipe, O_CLOEXEC);
        if (rc < 0) {
            lc_kernel_close_file(exec_pipe[0]);
            lc_kernel_close_file(exec_pipe[1]);
        }
    }
    if (rc < 0) {
        report_run("cannot start ", prog, " (pipe failed, errno ", (int)-rc);
        return RUN_FORK_FAILED;
    }

    lc_sysret pid = lc_kernel_fork();
    if (pid < 0) {
        lc_kernel_close_file(exec_pipe[0]);
        lc_kernel_close_file(exec_pipe[1]);
        if (opts->capture) {
            lc_kernel_close_file(out_pipe[0]);
            lc_kernel_close_file(out_pipe[1]);
        }
        report_run("cannot start ", prog, " (fork failed, errno ", (int)-pid);
        return RUN_FORK_FAILED;
    }

    if (pid == 0) {
        /* a tool starts with no signal blocked, whatever the caller blocks */
        uint64_t no_signals = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &no_signals, NULL);

        if (opts->quiet) {
            lc_sysret devnull = lc_kernel_open_file("/dev/null", O_WRONLY, 0);
            if (devnull >= 0) {
                lc_kernel_duplicate_fd((int32_t)devnull, STDOUT, 0);
                lc_kernel_duplicate_fd((int32_t)devnull, STDERR, 0);
            }
        }
        if (opts->capture)
            lc_kernel_duplicate_fd(out_pipe[1], STDOUT, 0);

        lc_sysret failed = exec_program(prog, argv, opts->envp ? opts->envp : TOOL_ENV);
        int32_t exec_errno = (int32_t)-failed;
        lc_kernel_write_bytes(exec_pipe[1], &exec_errno, sizeof(exec_errno));
        lc_kernel_exit(127);
    }

    lc_kernel_close_file(exec_pipe[1]);

    if (opts->capture) {
        lc_kernel_close_file(out_pipe[1]);
        size_t have = 0;
        for (;;) {
            /* keep what fits and read the rest away, so the program is never
             * left blocked on a full pipe */
            char spill[256];
            bool room = have + 1 < opts->capture_size;
            lc_sysret n = room
                ? read_retry(out_pipe[0], opts->capture + have, opts->capture_size - 1 - have)
                : read_retry(out_pipe[0], spill, sizeof(spill));
            if (n <= 0)
                break;
            if (room)
                have += (size_t)n;
        }
        if (opts->capture_size > 0)
            opts->capture[have] = '\0';
        lc_kernel_close_file(out_pipe[0]);
    }

    int32_t exec_errno = 0;
    lc_sysret told = read_retry(exec_pipe[0], &exec_errno, sizeof(exec_errno));
    lc_kernel_close_file(exec_pipe[0]);

    int32_t status = 0;
    if (wait_child((int32_t)pid, &status) < 0) {
        report_run("lost track of ", prog, NULL, 0);
        return RUN_WAIT_FAILED;
    }
    if (told == (lc_sysret)sizeof(exec_errno)) {
        report_run("cannot execute ", prog, " (errno ", exec_errno);
        return RUN_EXEC_FAILED;
    }
    if (status & 0x7f) {
        report_run("", prog, " was killed (signal ", status & 0x7f);
        return RUN_SIGNALED;
    }
    return (status >> 8) & 0xff;
}

int run_cmd(const char *prog, const char *const argv[]) {
    return run_program(prog, argv, &(struct run_opts){ 0 });
}

int run_cmd_quiet(const char *prog, const char *const argv[]) {
    return run_program(prog, argv, &(struct run_opts){ .quiet = true });
}

int run_cmd_env(const char *prog, const char *const argv[], const char *const envp[]) {
    return run_program(prog, argv, &(struct run_opts){ .envp = envp });
}

int run_cmd_capture(const char *prog, const char *const argv[], char *out, size_t outsz) {
    return run_program(prog, argv, &(struct run_opts){ .capture = out, .capture_size = outsz });
}

void require_rm_rf(const char *path) {
    const char *argv[] = { "rm", "-rf", path, NULL };
    if (run_cmd(tool_path_rm(), argv) != 0)
        die2("Error: rm -rf failed: ", path);
}

int do_mount(const char *source, const char *target,
             const char *fstype, uint64_t flags, const char *data) {
    const char *argv[16];
    int ai = 0;
    argv[ai++] = "mount";
    if ((flags & MS_PRIVATE) && (flags & MS_REC)) {
        argv[ai++] = "--make-rprivate";
        argv[ai++] = target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    if ((flags & MS_REMOUNT) && (flags & MS_BIND)) {
        char remount_opts[64];
        int rolen = 0;
        argv[ai++] = "-o";
        rolen = (int)str_copy(remount_opts, "remount,bind", sizeof(remount_opts));
        if (flags & MS_RDONLY) { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "ro", sizeof(remount_opts) - (size_t)rolen); }
        if (flags & MS_NOSUID) { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "nosuid", sizeof(remount_opts) - (size_t)rolen); }
        if (flags & MS_NODEV)  { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "nodev", sizeof(remount_opts) - (size_t)rolen); }
        if (flags & MS_NOEXEC) { remount_opts[rolen++] = ','; rolen += (int)str_copy(remount_opts + rolen, "noexec", sizeof(remount_opts) - (size_t)rolen); }
        argv[ai++] = remount_opts;
        argv[ai++] = target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    if ((flags & MS_BIND) && (flags & MS_REC)) {
        argv[ai++] = "--rbind";
        argv[ai++] = source;
        argv[ai++] = target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    if (flags & MS_BIND) {
        argv[ai++] = "--bind";
        argv[ai++] = source;
        argv[ai++] = target;
        argv[ai] = NULL;
        return run_cmd(tool_path_mount(), argv);
    }
    char opts[256];
    int olen = 0;
    if (flags & MS_RDONLY)  { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "ro", sizeof(opts) - (size_t)olen); }
    if (flags & MS_NOSUID)  { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "nosuid", sizeof(opts) - (size_t)olen); }
    if (flags & MS_NODEV)   { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "nodev", sizeof(opts) - (size_t)olen); }
    if (flags & MS_NOEXEC)  { if (olen) opts[olen++] = ','; olen += (int)str_copy(opts + olen, "noexec", sizeof(opts) - (size_t)olen); }
    if (data && data[0])    { if (olen) opts[olen++] = ','; str_copy(opts + olen, data, sizeof(opts) - (size_t)olen); olen += (int)lc_string_length(data); }
    opts[olen] = '\0';
    if (fstype && fstype[0]) { argv[ai++] = "-t"; argv[ai++] = fstype; }
    if (olen > 0)            { argv[ai++] = "-o"; argv[ai++] = opts; }
    if (source && source[0]) argv[ai++] = source;
    argv[ai++] = target;
    argv[ai] = NULL;
    return run_cmd(tool_path_mount(), argv);
}

void require_mount(const char *source, const char *target,
                   const char *fstype, uint64_t flags, const char *data) {
    if (do_mount(source, target, fstype, flags, data) != 0)
        die2("Error: mount failed: ", target);
}
