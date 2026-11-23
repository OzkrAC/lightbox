#include "lightbox.h"
#include "lightbox_devices.h"

void print_str(int32_t fd, const char *s) {
    lc_print_string(fd, s, lc_string_length(s));
}

int failure_status = 1;

/* What a failure does before it ends the process, in the process that asked
 * for it only, as a child it forks has not asked: exec's end in the audit
 * log. Done once. */
static void (*before_failing)(void);
static int32_t before_failing_pid;

void on_failure(void (*fn)(void)) {
    before_failing = fn;
    before_failing_pid = fn ? lc_kernel_get_process_id() : 0;
}

void fail_now(void) {
    void (*fn)(void) = before_failing;
    before_failing = NULL;
    if (fn && before_failing_pid == lc_kernel_get_process_id())
        fn();
    lc_kernel_exit(failure_status);
}

void die(const char *msg) {
    print_str(STDERR, msg);
    lc_print_char(STDERR, '\n');
    fail_now();
}

void die2(const char *prefix, const char *detail) {
    print_str(STDERR, prefix);
    print_str(STDERR, detail);
    lc_print_char(STDERR, '\n');
    fail_now();
}

bool streq(const char *a, const char *b) {
    size_t la = lc_string_length(a);
    size_t lb = lc_string_length(b);
    if (la != lb) return false;
    return lc_string_equal(a, la, b, lb);
}

/*
 * Text that has to arrive whole. None of these cut: a source that does not
 * fit is not copied in part, and the caller is told.
 */

/* dst is src, or an empty string and false when src does not fit */
bool str_copy(char *dst, const char *src, size_t max) {
    size_t len = lc_string_length(src);
    if (len >= max) {
        if (max > 0) dst[0] = '\0';
        return false;
    }
    lc_bytes_copy(dst, src, len);
    dst[len] = '\0';
    return true;
}

/* src after the pos characters dst holds: the new length. When it does not
 * fit nothing is appended and *overflow is set, and stays set, so a text can
 * be put together from many pieces and asked once whether it is whole. */
size_t str_append(char *dst, size_t pos, const char *src, size_t max, bool *overflow) {
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

/* "a/b" with one slash between them, or an empty string and false */
bool path_join(char *buf, size_t bufsz, const char *a, const char *b) {
    bool cut = false;
    size_t pos = str_append(buf, 0, a, bufsz, &cut);
    if (pos > 0 && buf[pos - 1] != '/')
        pos = str_append(buf, pos, "/", bufsz, &cut);
    if (b[0] == '/') b++;
    str_append(buf, pos, b, bufsz, &cut);
    if (cut && bufsz > 0)
        buf[0] = '\0';
    return !cut;
}

void str_copy_or_die(char *dst, const char *src, size_t max, const char *what) {
    if (str_copy(dst, src, max))
        return;
    print_str(STDERR, "Error: ");
    print_str(STDERR, what);
    print_str(STDERR, " is too long: ");
    print_str(STDERR, src);
    print_str(STDERR, "\n");
    lc_kernel_exit(failure_status);
}

void path_join_or_die(char *buf, size_t bufsz, const char *a, const char *b) {
    if (path_join(buf, bufsz, a, b))
        return;
    print_str(STDERR, "Error: path is too long: ");
    print_str(STDERR, a);
    print_str(STDERR, "/");
    print_str(STDERR, b);
    print_str(STDERR, "\n");
    lc_kernel_exit(failure_status);
}

/* "/proc/<pid><suffix>" */
bool proc_pid_path(char *buf, size_t bufsz, int pid, const char *suffix) {
    char digits[16];
    bool cut = false;
    fmt_int(digits, pid);
    size_t pos = str_append(buf, 0, "/proc/", bufsz, &cut);
    pos = str_append(buf, pos, digits, bufsz, &cut);
    str_append(buf, pos, suffix ? suffix : "", bufsz, &cut);
    return !cut;
}

/* "<path>.tmp.<pid of this process>": the name a file is written under
 * before it takes its own */
static bool temporary_name(char *tmp, size_t max, const char *path) {
    char digits[16];
    bool cut = false;
    fmt_int(digits, lc_kernel_get_process_id());
    size_t pos = str_append(tmp, 0, path, max, &cut);
    pos = str_append(tmp, pos, ".tmp.", max, &cut);
    str_append(tmp, pos, digits, max, &cut);
    return !cut;
}

/* Does the text have a byte that is not printable: a control character,
 * among them the newline that would end a line in a file of lines? */
bool has_control_chars(const char *s) {
    for (; *s; s++) {
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            return true;
    }
    return false;
}

/*
 * A whole number written in decimal, from min to max: an optional minus sign
 * and digits, and nothing else. Empty text, anything after the digits and a
 * value outside the range are all refused; nothing wraps around.
 */
bool parse_number(const char *s, int64_t min, int64_t max, int64_t *out) {
    if (!s)
        return false;
    bool negative = *s == '-';
    if (negative)
        s++;
    if (!*s)
        return false;

    /* the magnitude, which for the most negative number is one more than
     * the largest positive one */
    uint64_t limit = negative ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX;
    uint64_t magnitude = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return false;
        uint64_t digit = (uint64_t)(*s - '0');
        if (magnitude > (limit - digit) / 10)
            return false;
        magnitude = magnitude * 10 + digit;
    }

    if (negative && magnitude == 0)     /* "-0" is nobody's way to write a number */
        return false;
    int64_t value = negative ? (int64_t)(0 - magnitude) : (int64_t)magnitude;
    if (value < min || value > max)
        return false;
    *out = value;
    return true;
}

bool parse_int_in(const char *s, int min, int max, int *out) {
    int64_t value;
    if (!parse_number(s, min, max, &value))
        return false;
    *out = (int)value;
    return true;
}

bool parse_seconds(const char *s, int *out) {
    return s && s[0] != '-' && parse_int_in(s, 0, SECONDS_MAX, out);
}

bool parse_duration_ms(const char *text, int64_t *ms) {
    if (!text || text[0] < '0' || text[0] > '9')
        return false;

    /* the whole seconds stop growing past the largest duration, so that
     * nothing wraps around however many digits there are */
    const int64_t max_seconds = DURATION_MAX_MS / 1000;
    int64_t whole = 0, thousandths = 0;
    size_t i = 0;
    for (; text[i] >= '0' && text[i] <= '9'; i++) {
        whole = whole * 10 + (text[i] - '0');
        if (whole > max_seconds)
            return false;
    }
    if (text[i] == '.') {
        int digits = 0;
        for (i++; text[i] >= '0' && text[i] <= '9'; i++, digits++) {
            if (digits == 3)
                return false;
            thousandths = thousandths * 10 + (text[i] - '0');
        }
        if (digits == 0)
            return false;
        for (; digits < 3; digits++)
            thousandths *= 10;
    }

    int64_t unit = 1;
    if (text[i] == 's') unit = 1;
    else if (text[i] == 'm') unit = 60;
    else if (text[i] == 'h') unit = 3600;
    else if (text[i] == 'd') unit = 86400;
    else if (text[i] != '\0') return false;
    if (text[i] != '\0' && text[i + 1] != '\0')
        return false;

    /* whole is at most max_seconds, so this fits; the test is on its parts */
    if (whole > max_seconds / unit)
        return false;
    int64_t value = (whole * 1000 + thousandths) * unit;
    if (value < 1 || value > DURATION_MAX_MS)
        return false;
    *ms = value;
    return true;
}

/* bytes random bytes, from getrandom, as twice as many lowercase hex digits
 * and a NUL: false, with out empty, if the kernel gave fewer. */
bool random_hex(char *out, size_t bytes) {
    static const char hex[] = "0123456789abcdef";
    uint8_t drawn[32];
    out[0] = '\0';
    if (bytes > sizeof(drawn) || lb_sys_getrandom(drawn, bytes, 0) != (lc_sysret)bytes)
        return false;
    for (size_t i = 0; i < bytes; i++) {
        out[2 * i] = hex[drawn[i] >> 4];
        out[2 * i + 1] = hex[drawn[i] & 15];
    }
    out[2 * bytes] = '\0';
    return true;
}

int fmt_int(char *buf, int val) {
    if (val == 0) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    int neg = val < 0, len = 0;
    char tmp[16];
    unsigned int rest = neg ? 0u - (unsigned int)val : (unsigned int)val;
    while (rest > 0) { tmp[len++] = (char)('0' + rest % 10); rest /= 10; }
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

/* The directory a path's last component is in: "." for a bare name, "/" for
 * something in the root. False for an empty path or one that does not fit. */
bool parent_dir(char *buf, size_t bufsz, const char *path) {
    size_t len = lc_string_length(path);
    if (len == 0 || !str_copy(buf, path, bufsz))
        return false;

    while (len > 0 && buf[len - 1] != '/')
        len--;
    if (len == 0)
        return str_copy(buf, ".", bufsz);
    buf[len == 1 ? 1 : len - 1] = '\0';
    return true;
}

static int sync_parent_dir(const char *path) {
    char dirpath[MAX_PATH];
    if (!parent_dir(dirpath, sizeof(dirpath), path))
        return -1;

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

const char *tool_path_iptables_restore(void) {
    static const char *const candidates[] = {
        "/usr/sbin/iptables-restore",
        "/sbin/iptables-restore",
        "/usr/bin/iptables-restore",
        "/bin/iptables-restore",
        "/usr/sbin/iptables-nft-restore",
        "/sbin/iptables-nft-restore",
        "/usr/bin/iptables-nft-restore",
        "/bin/iptables-nft-restore",
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

const char *tool_path_nft(void) {
    static const char *const candidates[] = {
        "/usr/sbin/nft",
        "/sbin/nft",
        "/usr/bin/nft",
        "/bin/nft",
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

const char *tool_path_rm(void) {
    static const char *const candidates[] = {
        "/bin/rm",
        "/usr/bin/rm",
    };
    return pick_tool_path(candidates, sizeof(candidates) / sizeof(candidates[0]));
}

const char *tool_path_gzip(void) {
    static const char *const candidates[] = {
        "/usr/bin/gzip",
        "/bin/gzip",
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
    lc_kernel_exit(failure_status);
}


/*
 * Give a file its content in one step: written under another name and then
 * renamed, so a reader finds the old content or the new and never part of
 * either. Durable, it is on the disk when this returns, and so is its name.
 */
static int write_file_replacing(const char *path, const char *data, int32_t mode, bool durable) {
    char tmp[MAX_PATH];
    if (!temporary_name(tmp, sizeof(tmp), path))
        return -1;

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

    if (durable && lb_sys_fsync((int32_t)fd) < 0) {
        lc_kernel_close_file((int32_t)fd);
        lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
        return -1;
    }
    lc_kernel_close_file((int32_t)fd);

    if (lb_sys_renameat(AT_FDCWD, tmp, AT_FDCWD, path) < 0) {
        lc_kernel_unlinkat(AT_FDCWD, tmp, 0);
        return -1;
    }

    if (durable && sync_parent_dir(path) < 0)
        return -1;
    return 0;
}

int write_file_atomic(const char *path, const char *data, int32_t mode) {
    return write_file_replacing(path, data, mode, true);
}

int write_file_volatile(const char *path, const char *data) {
    return write_file_replacing(path, data, MODE_PRIVATE_FILE, false);
}

int remove_file_durably(const char *path) {
    lc_sysret rc = lc_kernel_unlinkat(AT_FDCWD, path, 0);
    if (rc < 0 && rc != -LB_ENOENT)
        return -1;
    return sync_parent_dir(path);
}

/* <root>/<dir>, opened as a process whose root is <root> would find it. */
static lc_sysret open_dir_in_root(const char *root, const char *dir, bool make) {
    lc_sysret rootfd = lc_kernel_open_file(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (rootfd < 0)
        return rootfd;
    if (make)
        lc_kernel_mkdirat((int32_t)rootfd, dir, 0755);      /* a link of that name stays what it is */

    struct lb_open_how how = {
        .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
        .mode = 0,
        .resolve = LB_RESOLVE_IN_ROOT,
    };
    lc_sysret dirfd = lb_sys_openat2((int32_t)rootfd, dir, &how);
    lc_kernel_close_file((int32_t)rootfd);
    return dirfd;
}

int write_file_in_root(const char *root, const char *dir, const char *name,
                       const char *data, int32_t mode) {
    lc_sysret dirfd = open_dir_in_root(root, dir, true);
    if (dirfd < 0)
        return -1;

    /* From here on every name is one component, looked up in that directory
     * and never through a link: the temporary file is made new, and the
     * rename puts it in the place of whatever had the name. */
    char tmp[MAX_PATH];
    if (!temporary_name(tmp, sizeof(tmp), name)) {
        lc_kernel_close_file((int32_t)dirfd);
        return -1;
    }

    lc_kernel_unlinkat((int32_t)dirfd, tmp, 0);
    lc_sysret fd = lc_kernel_open_file_at((int32_t)dirfd, tmp,
                                          O_WRONLY | O_CREAT | LB_O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    int result = -1;
    if (fd >= 0) {
        size_t len = lc_string_length(data);
        bool written = lc_kernel_write_all((int32_t)fd, data, len) == (lc_sysret)len &&
                       lb_sys_fsync((int32_t)fd) >= 0;
        lc_kernel_close_file((int32_t)fd);
        if (written && lb_sys_renameat((int32_t)dirfd, tmp, (int32_t)dirfd, name) >= 0 &&
            lb_sys_fsync((int32_t)dirfd) >= 0)
            result = 0;
        else
            lc_kernel_unlinkat((int32_t)dirfd, tmp, 0);
    }
    lc_kernel_close_file((int32_t)dirfd);
    return result;
}

int read_file_in_root(const char *root, const char *dir, const char *name, char *buf, size_t bufsz) {
    buf[0] = '\0';
    lc_sysret dirfd = open_dir_in_root(root, dir, false);
    if (dirfd == -LB_ENOENT)
        return 0;
    if (dirfd < 0)
        return -1;

    lc_sysret fd = lc_kernel_open_file_at((int32_t)dirfd, name,
                                          O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    lc_kernel_close_file((int32_t)dirfd);
    if (fd == -LB_ENOENT)
        return 0;
    if (fd < 0)
        return -1;

    struct lb_statx stx;
    lc_sysret n = -1;
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE, &stx) >= 0 &&
        (stx.stx_mode & LB_S_IFMT) == LB_S_IFREG)
        n = lc_kernel_read_all((int32_t)fd, buf, bufsz);
    lc_kernel_close_file((int32_t)fd);
    if (n < 0 || (size_t)n >= bufsz) {
        buf[0] = '\0';
        return -1;              /* not a file to read, or more than fits */
    }
    buf[n] = '\0';
    return (int)n;
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

/* access(2) as faccessat2 has it, and as faccessat on a kernel before 5.8,
 * where faccessat2 is not, so that doctor can say which kernel it is on. */
static lc_sysret access_path(const char *path, int32_t mode) {
    lc_sysret rc = lc_kernel_faccessat2(AT_FDCWD, path, mode, 0);
    if (rc == -LB_ENOSYS)
        rc = lb_sys_faccessat(AT_FDCWD, path, mode);
    return rc;
}

bool path_exists(const char *path) {
    return access_path(path, F_OK) == 0;
}

bool path_executable(const char *path) {
    return access_path(path, X_OK) == 0;
}

bool kernel_release_at_least(const char *release, int want_major, int want_minor, int *major, int *minor) {
    *major = *minor = -1;
    int parts[2] = { 0, 0 };
    const char *p = release;
    for (int i = 0; i < 2; i++) {
        if (*p < '0' || *p > '9')
            return false;
        int n = 0;
        while (*p >= '0' && *p <= '9' && n < 100000)
            n = n * 10 + (*p++ - '0');
        parts[i] = n;
        if (i == 0) {
            if (*p != '.')
                return false;
            p++;
        }
    }
    *major = parts[0];
    *minor = parts[1];
    return parts[0] > want_major || (parts[0] == want_major && parts[1] >= want_minor);
}

bool path_is_directory(const char *path) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0)
        return false;
    lc_kernel_close_file((int32_t)fd);
    return true;
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

/* "Error: <before><what><after><number>)" or, with after == NULL,
 * "Error: <before><what>". */
static void report_failure(const char *before, const char *prog, const char *after, int number) {
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
    bool   capture_stderr;      /* and its stderr with it */
    const char *input;          /* when set, its stdin, at most RUN_INPUT_MAX bytes */
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
    int32_t in_pipe[2] = { -1, -1 };

    /* The input is in its pipe before there is a program to read it: a pipe
     * holds this much, so the write does not wait, and nothing can make it
     * fail half way, as a program that ends before it has read would. */
    if (opts->input) {
        size_t len = lc_string_length(opts->input);
        if (len > RUN_INPUT_MAX) {
            report_failure("the input is too long for ", prog, NULL, 0);
            return RUN_FORK_FAILED;
        }
        lc_sysret made = lc_kernel_create_pipe(in_pipe, O_CLOEXEC);
        if (made < 0) {
            report_failure("cannot start ", prog, " (no pipe for its input, errno ", (int)-made);
            return RUN_FORK_FAILED;
        }
        lc_sysret wrote = lc_kernel_write_all(in_pipe[1], opts->input, len);
        lc_kernel_close_file(in_pipe[1]);
        if (wrote < 0 || (size_t)wrote != len) {
            lc_kernel_close_file(in_pipe[0]);
            report_failure("the input did not go into the pipe of ", prog, NULL, 0);
            return RUN_FORK_FAILED;
        }
    }

    lc_sysret rc = lc_kernel_create_pipe(exec_pipe, O_CLOEXEC);
    if (rc >= 0 && opts->capture) {
        rc = lc_kernel_create_pipe(out_pipe, O_CLOEXEC);
        if (rc < 0) {
            lc_kernel_close_file(exec_pipe[0]);
            lc_kernel_close_file(exec_pipe[1]);
        }
    }
    if (rc < 0) {
        if (in_pipe[0] >= 0)
            lc_kernel_close_file(in_pipe[0]);
        report_failure("cannot start ", prog, " (pipe failed, errno ", (int)-rc);
        return RUN_FORK_FAILED;
    }

    lc_sysret pid = lc_kernel_fork();
    if (pid < 0) {
        if (in_pipe[0] >= 0)
            lc_kernel_close_file(in_pipe[0]);
        lc_kernel_close_file(exec_pipe[0]);
        lc_kernel_close_file(exec_pipe[1]);
        if (opts->capture) {
            lc_kernel_close_file(out_pipe[0]);
            lc_kernel_close_file(out_pipe[1]);
        }
        report_failure("cannot start ", prog, " (fork failed, errno ", (int)-pid);
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
        if (opts->capture && opts->capture_stderr)
            lc_kernel_duplicate_fd(out_pipe[1], STDERR, 0);
        if (in_pipe[0] >= 0)
            lc_kernel_duplicate_fd(in_pipe[0], STDIN, 0);

        lc_sysret failed = exec_program(prog, argv, opts->envp ? opts->envp : TOOL_ENV);
        int32_t exec_errno = (int32_t)-failed;
        lc_kernel_write_bytes(exec_pipe[1], &exec_errno, sizeof(exec_errno));
        lc_kernel_exit(127);
    }

    lc_kernel_close_file(exec_pipe[1]);
    if (in_pipe[0] >= 0)
        lc_kernel_close_file(in_pipe[0]);

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
        report_failure("lost track of ", prog, NULL, 0);
        return RUN_WAIT_FAILED;
    }
    if (told == (lc_sysret)sizeof(exec_errno)) {
        report_failure("cannot execute ", prog, " (errno ", exec_errno);
        return RUN_EXEC_FAILED;
    }
    if (status & 0x7f) {
        report_failure("", prog, " was killed (signal ", status & 0x7f);
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

int run_cmd_capture_quiet(const char *prog, const char *const argv[], char *out, size_t outsz) {
    return run_program(prog, argv, &(struct run_opts){ .capture = out, .capture_size = outsz, .quiet = true });
}

int run_cmd_input(const char *prog, const char *const argv[], const char *input, bool quiet) {
    return run_program(prog, argv, &(struct run_opts){ .input = input, .quiet = quiet });
}

int run_cmd_input_capture(const char *prog, const char *const argv[], const char *input, char *out, size_t outsz) {
    return run_program(prog, argv, &(struct run_opts){ .input = input, .capture = out, .capture_size = outsz,
                                                       .capture_stderr = true });
}

void require_rm_rf(const char *path) {
    const char *argv[] = { "rm", "-rf", path, NULL };
    if (run_cmd(tool_path_rm(), argv) != 0)
        die2("Error: rm -rf failed: ", path);
}

/* ─── Directories and the loopback interface ────────────────────────────── */

/*
 * What "mkdir -p" does: make the directory and every missing one above it,
 * with mode 0755 before the umask. 0, or -1 once the path and the errno have
 * been reported. Something that is in the way of a directory is an error.
 */
int make_dirs(const char *path) {
    char buf[MAX_PATH];
    size_t len = lc_string_length(path);
    if (len == 0 || len >= sizeof(buf)) {
        report_failure("path is empty or too long: ", path, NULL, 0);
        return -1;
    }
    lc_bytes_copy(buf, path, len + 1);

    /* every prefix that ends where a component ends, the whole path last */
    for (size_t i = 1; i <= len; i++) {
        if (buf[i] != '/' && buf[i] != '\0')
            continue;
        if (buf[i - 1] == '/')
            continue;               /* "a//b", or a slash at the end */
        char after = buf[i];
        buf[i] = '\0';
        lc_sysret rc = lc_kernel_mkdirat(AT_FDCWD, buf, 0755);
        if (rc < 0 && rc != -LB_EEXIST) {
            report_failure("cannot make directory: ", buf, " (errno ", (int)-rc);
            return -1;
        }
        buf[i] = after;
    }
    if (!path_is_directory(path)) {
        report_failure("not a directory: ", path, NULL, 0);
        return -1;
    }
    return 0;
}

/*
 * What "ip link set lo up" does: read the loopback interface's flags, add
 * "up", write them back. Any socket carries the two requests. 0, or -1 once
 * the failing step and its errno have been reported.
 */
int loopback_up(void) {
    lc_sysret fd = lb_sys_socket(LB_AF_INET, LB_SOCK_DGRAM, 0);
    if (fd < 0) {
        report_failure("cannot bring up ", "lo", ": no socket (errno ", (int)-fd);
        return -1;
    }

    struct lb_ifreq_flags ifr = { .name = "lo" };
    lc_sysret rc = lc_kernel_device_control((int32_t)fd, LB_SIOCGIFFLAGS, &ifr);
    if (rc >= 0) {
        ifr.flags |= LB_IFF_UP;
        rc = lc_kernel_device_control((int32_t)fd, LB_SIOCSIFFLAGS, &ifr);
    }
    lc_kernel_close_file((int32_t)fd);

    if (rc < 0) {
        report_failure("cannot bring up ", "lo", " (errno ", (int)-rc);
        return -1;
    }
    return 0;
}

/* ─── Mounting ──────────────────────────────────────────────────────────── */

/* What a mount carries that a change of its flags would drop unless the call
 * names it again. In f_flags of statfs these have the bits mount(2) takes. */
#define MOUNT_KEPT_FLAGS (LB_ST_RDONLY | LB_ST_NOSUID | LB_ST_NODEV | LB_ST_NOEXEC)

/*
 * mount(2), checked: 0, or -1 once the target and the errno have been
 * reported.
 *
 * The arguments reach the kernel as they are, with one addition. Changing the
 * flags of a mount (MS_REMOUNT | MS_BIND) replaces all of them, so a call
 * that asks for nosuid would quietly take nodev away. Here such a call keeps
 * read-only, nosuid, nodev and noexec from what the mount has now: it can add
 * restrictions and never removes one. mount(8), which lightbox ran for every
 * mount until 0.2, behaved the same way. It keeps how the mount keeps access
 * times too, unless the call says: in a user namespace, a mount that came
 * with the copy of the host's may not have that changed.
 */
int do_mount(const char *source, const char *target,
             const char *fstype, uint64_t flags, const char *data) {
    lc_sysret rc = 0;

    if ((flags & MS_REMOUNT) && (flags & MS_BIND)) {
        struct lb_statfs now;
        rc = lb_sys_statfs(target, &now);
        if (rc >= 0)
            flags |= (uint64_t)now.f_flags & MOUNT_KEPT_FLAGS;
        if (rc >= 0 && !(flags & (LB_MS_NOATIME | LB_MS_RELATIME | LB_MS_STRICTATIME))) {
            uint64_t f = (uint64_t)now.f_flags;
            flags |= (f & LB_ST_NOATIME) ? LB_MS_NOATIME : (f & LB_ST_RELATIME) ? LB_MS_RELATIME : LB_MS_STRICTATIME;
            flags |= (f & LB_ST_NODIRATIME) ? LB_MS_NODIRATIME : 0;
        }
    }
    if (rc >= 0)
        rc = lc_kernel_mount(source, target, fstype, flags, data);
    if (rc < 0) {
        report_failure("mount failed: ", target, " (errno ", (int)-rc);
        return -1;
    }
    return 0;
}

void require_mount(const char *source, const char *target,
                   const char *fstype, uint64_t flags, const char *data) {
    if (do_mount(source, target, fstype, flags, data) != 0)
        lc_kernel_exit(failure_status);      /* do_mount has said what failed */
}

/* ─── The device program ────────────────────────────────────────────────── */

bool bpf_call_missing(void) {
    /* given no program, refused whoever asks; ENOSYS where there is no call */
    return lb_sys_bpf(LB_BPF_PROG_LOAD, NULL, 0) == -LB_ENOSYS;
}

lc_sysret device_program_load(const struct lb_dev_row *extra, size_t nextra, char *log, uint32_t log_size) {
    static struct lb_ebpf_insn prog[LB_DEV_PROG_MAX];
    if (log && log_size)
        log[0] = '\0';
    size_t len = lb_devices_build_with(prog, extra, nextra);
    if (len == 0 || len != LB_DEV_PROG_LEN_FOR(nextra))
        return -LB_EINVAL;
    /* It calls no helper of the kernel's, which is all a license decides. */
    struct lb_bpf_prog_load load = {
        .prog_type = LB_BPF_PROG_TYPE_CGROUP_DEVICE,
        .insn_cnt = (uint32_t)len,
        .insns = (uint64_t)(uintptr_t)prog,
        .license = (uint64_t)(uintptr_t)"",
        .prog_name = "lightbox_dev",
    };
    lc_sysret fd = lb_sys_bpf(LB_BPF_PROG_LOAD, &load, sizeof(load));
    if (fd < 0 && fd != -LB_EPERM && log && log_size > 1) {
        load.log_level = 1;
        load.log_size = log_size;
        load.log_buf = (uint64_t)(uintptr_t)log;
        lc_sysret again = lb_sys_bpf(LB_BPF_PROG_LOAD, &load, sizeof(load));
        if (again >= 0)
            lc_kernel_close_file((int32_t)again);
        log[log_size - 1] = '\0';
    }
    return fd;
}
