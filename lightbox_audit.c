#include "lightbox.h"

/*
 * The audit log (ROADMAP 8.9): <lightbox_dir>/audit.log. Every exec, and so
 * every run, appends two lines to it: one as the command is about to start
 * and one when it has ended. Each line is one JSON object, written with one
 * write(2) on a descriptor opened with O_APPEND, so that the lines of execs
 * that run at once never mix. The directory is root's alone (mode 0700) and
 * no box has it mounted: a box can neither read the log nor change it.
 *
 * It is one file for the host, by the maintainer's decision of 2026-11-21,
 * not one in each box's directory, as rm removes that directory and run its
 * box: a box's record outlives the box. Each line names its box first, and
 * the box's id, which tells a box from a later one of the same name.
 *
 * What it records is what was asked of the box, not what the command then
 * did. The arguments are as they were given, so the log is as sensitive as
 * they are; --env is recorded by its keys only, as its values are often
 * credentials. A start with no end is an exec whose process was killed.
 */

void audit_log_path(char *buf) {
    path_join_or_die(buf, MAX_PATH, cfg_global.lightbox_dir, "audit.log");
}

/* ─── JSON in ASCII ─────────────────────────────────────────────────────── */

/* The character that starts at s, with n bytes left, in strict UTF-8: no
 * longer form than it needs, no surrogate, nothing above U+10FFFF. Its
 * length, or 0 if s starts none. */
static size_t utf8_char(const unsigned char *s, size_t n, uint32_t *cp) {
    unsigned char c = s[0];
    size_t len;
    uint32_t v, least;
    if (c < 0x80) {
        *cp = c;
        return 1;
    } else if ((c & 0xe0) == 0xc0) {
        len = 2; v = c & 0x1f; least = 0x80;
    } else if ((c & 0xf0) == 0xe0) {
        len = 3; v = c & 0x0f; least = 0x800;
    } else if ((c & 0xf8) == 0xf0) {
        len = 4; v = c & 0x07; least = 0x10000;
    } else {
        return 0;
    }
    if (len > n)
        return 0;
    for (size_t i = 1; i < len; i++) {
        if ((s[i] & 0xc0) != 0x80)
            return 0;
        v = (v << 6) | (s[i] & 0x3f);
    }
    if (v < least || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff))
        return 0;
    *cp = v;
    return len;
}

/* \uXXXX of one UTF-16 unit: 6 bytes, written when out is not NULL */
static size_t put_unit(char *out, uint32_t unit) {
    static const char hex[] = "0123456789abcdef";
    if (out) {
        out[0] = '\\';
        out[1] = 'u';
        out[2] = hex[(unit >> 12) & 15];
        out[3] = hex[(unit >> 8) & 15];
        out[4] = hex[(unit >> 4) & 15];
        out[5] = hex[unit & 15];
    }
    return 6;
}

/*
 * s[0..len) as a JSON string, quotes and all, in ASCII alone: " and \
 * escaped, and the control characters; every other character of valid UTF-8
 * as \uXXXX, or two of them above U+FFFF; and each byte that is not part of
 * valid UTF-8 as \udcXX, a low surrogate after no high one, which stands for
 * no character. That is Python's surrogateescape: a reader gets the bytes
 * back exactly, and a terminal that shows the log takes no control sequence
 * or reordering mark in an argument for its own. With out NULL it only
 * counts; the number of bytes, at most 6 for each of s and 2.
 */
size_t json_quote(char *out, const char *s, size_t len) {
    const unsigned char *u = (const unsigned char *)s;
    size_t at = 0;
    if (out) out[at] = '"';
    at++;
    for (size_t i = 0; i < len;) {
        uint32_t cp;
        size_t n = utf8_char(u + i, len - i, &cp);
        char *o = out ? out + at : NULL;
        if (n == 0) {
            at += put_unit(o, 0xdc00 + u[i]);      /* a byte of no character */
            i++;
            continue;
        }
        i += n;
        char short_form = cp == '"' ? '"' : cp == '\\' ? '\\' : cp == '\n' ? 'n' : cp == '\t' ? 't' :
                          cp == '\r' ? 'r' : cp == '\b' ? 'b' : cp == '\f' ? 'f' : 0;
        if (short_form) {
            if (o) { o[0] = '\\'; o[1] = short_form; }
            at += 2;
        } else if (cp >= 0x20 && cp < 0x7f) {
            if (o) o[0] = (char)cp;
            at++;
        } else if (cp < 0x10000) {
            at += put_unit(o, cp);
        } else {
            cp -= 0x10000;
            at += put_unit(o, 0xd800 + (cp >> 10));
            at += put_unit(out ? out + at : NULL, 0xdc00 + (cp & 0x3ff));
        }
    }
    if (out) out[at] = '"';
    return at + 1;
}

/* ─── Time ──────────────────────────────────────────────────────────────── */

/* 9999-12-31T23:59:59Z, the last second that four digits of a year can name */
#define UTC_SECONDS_MAX INT64_C(253402300799)

/*
 * A time as UTC in RFC 3339, to the millisecond: "2026-11-21T16:39:23.123Z".
 * A clock before 1970 is shown as 1970 began, one past the year 9999 as that
 * year ends. The civil date is Howard Hinnant's days_from_civil reversed.
 */
void format_utc(char out[UTC_TEXT_LEN + 1], int64_t seconds, int64_t nanoseconds) {
    if (seconds < 0 || nanoseconds < 0 || nanoseconds > 999999999) {
        seconds = seconds < 0 ? 0 : seconds;
        nanoseconds = 0;
    }
    if (seconds > UTC_SECONDS_MAX) {
        seconds = UTC_SECONDS_MAX;
        nanoseconds = 999999999;
    }
    int64_t days = seconds / 86400, rest = seconds % 86400;
    int64_t z = days + 719468;              /* days since 0000-03-01 */
    int64_t era = z / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    int64_t day = doy - (153 * mp + 2) / 5 + 1;
    int64_t month = mp < 10 ? mp + 3 : mp - 9;
    int64_t year = yoe + era * 400 + (month <= 2);

    lc_format f = lc_format_start(out, UTC_TEXT_LEN + 1);
    lc_format_add_unsigned_padded(&f, (uint64_t)year, 4, '0');
    lc_format_add_char(&f, '-');
    lc_format_add_unsigned_padded(&f, (uint64_t)month, 2, '0');
    lc_format_add_char(&f, '-');
    lc_format_add_unsigned_padded(&f, (uint64_t)day, 2, '0');
    lc_format_add_char(&f, 'T');
    lc_format_add_unsigned_padded(&f, (uint64_t)(rest / 3600), 2, '0');
    lc_format_add_char(&f, ':');
    lc_format_add_unsigned_padded(&f, (uint64_t)(rest / 60 % 60), 2, '0');
    lc_format_add_char(&f, ':');
    lc_format_add_unsigned_padded(&f, (uint64_t)(rest % 60), 2, '0');
    lc_format_add_char(&f, '.');
    lc_format_add_unsigned_padded(&f, (uint64_t)(nanoseconds / 1000000), 3, '0');
    lc_format_add_char(&f, 'Z');
    (void)lc_format_finish(&f);
}

/* ─── The lines ─────────────────────────────────────────────────────────── */

/* A line as it is built: with buf NULL, its length is counted only. */
struct jout {
    char  *buf;
    size_t len;
};

static void put(struct jout *o, const char *s, size_t n) {
    if (o->buf)
        lc_bytes_copy(o->buf + o->len, s, n);
    o->len += n;
}

static void put_raw(struct jout *o, const char *s) {
    put(o, s, lc_string_length(s));
}

static void put_quoted(struct jout *o, const char *s, size_t n) {
    o->len += json_quote(o->buf ? o->buf + o->len : NULL, s, n);
}

static void put_text(struct jout *o, const char *s) {   /* NULL: null */
    if (s)
        put_quoted(o, s, lc_string_length(s));
    else
        put_raw(o, "null");
}

static void put_number(struct jout *o, int64_t v) {
    char digits[24];
    lc_format f = lc_format_start(digits, sizeof(digits));
    lc_format_add_signed(&f, v);
    put(o, digits, lc_format_finish(&f));
}

/* {"box":..., "box_id":..., "time":..., "event":..., "exec_id":... : what
 * both lines begin with, the box first, which logs --audit looks for */
static void put_head(struct jout *o, const char *box, const char *box_id, const char *time,
                     const char *event, const char *exec_id) {
    put_raw(o, "{\"box\":");
    put_text(o, box);
    put_raw(o, ",\"box_id\":");
    put_text(o, box_id && box_id[0] ? box_id : NULL);
    put_raw(o, ",\"time\":");
    put_text(o, time);
    put_raw(o, ",\"event\":");
    put_text(o, event);
    put_raw(o, ",\"exec_id\":");
    put_text(o, exec_id);
}

size_t audit_start_line(char *out, const struct audit_start *a, const char *time) {
    struct jout o = { out, 0 };
    put_head(&o, a->box, a->box_id, time, "start", a->exec_id);
    put_raw(&o, ",\"via\":");
    put_text(&o, a->via);
    put_raw(&o, ",\"uid\":");
    put_number(&o, a->uid);
    put_raw(&o, ",\"loginuid\":");
    if (a->loginuid >= 0)
        put_number(&o, a->loginuid);
    else
        put_raw(&o, "null");
    put_raw(&o, ",\"user\":");
    put_text(&o, a->user);
    put_raw(&o, ",\"workdir\":");
    put_text(&o, a->workdir);
    put_raw(&o, ",\"timeout\":");
    put_text(&o, a->timeout);
    put_raw(&o, ",\"env\":[");
    for (int i = 0; i < a->nenv; i++) {
        size_t key = 0;
        while (a->env[i][key] && a->env[i][key] != '=')
            key++;
        if (i) put_raw(&o, ",");
        put_quoted(&o, a->env[i], key);
    }
    put_raw(&o, "],\"argv\":[");
    for (int i = 0; a->argv[i]; i++) {
        if (i) put_raw(&o, ",");
        put_text(&o, a->argv[i]);
    }
    put_raw(&o, "]}\n");
    return o.len;
}

size_t audit_end_line(char *out, const struct audit_end *e, const char *time) {
    struct jout o = { out, 0 };
    put_head(&o, e->box, e->box_id, time, "end", e->exec_id);
    put_raw(&o, ",\"status\":");
    put_number(&o, e->status);
    put_raw(&o, ",\"duration_ms\":");
    put_number(&o, e->duration_ms);
    put_raw(&o, ",\"timed_out\":");
    put_raw(&o, e->timed_out ? "true" : "false");
    put_raw(&o, "}\n");
    return o.len;
}

/* ─── Writing ───────────────────────────────────────────────────────────── */

/* Append one line with one write: 0, or a negative errno. The log is made
 * mode 0600, never followed through a link, and only ever a plain file; the
 * descriptor is closed again at once, so that no process exec forks later
 * holds it. */
static int append_line(const char *line, size_t len) {
    char path[MAX_PATH];
    audit_log_path(path);
    int flags = O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    lc_sysret fd = lc_kernel_open_file(path, flags, MODE_PRIVATE_FILE);
    if (fd == -LB_ENOENT) {
        /* <lightbox_dir> is made by setup and create; made here as they make it */
        (void)lc_kernel_mkdirat(AT_FDCWD, cfg_global.lightbox_dir, MODE_PRIVATE_DIR);
        fd = lc_kernel_open_file(path, flags, MODE_PRIVATE_FILE);
    }
    if (fd < 0)
        return (int)fd;
    struct lb_statx stx;
    lc_sysret rc = lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE, &stx);
    if (rc >= 0 && (stx.stx_mode & LB_S_IFMT) != LB_S_IFREG)
        rc = -LB_EINVAL;
    if (rc >= 0) {
        lc_sysret n;
        do
            n = lc_kernel_write_bytes((int32_t)fd, line, len);
        while (n == -LB_EINTR);
        rc = n < 0 ? n : (size_t)n == len ? 0 : -LB_EIO;    /* a line cut short */
    }
    lc_kernel_close_file((int32_t)fd);
    return (int)rc;
}

/* A line of the length that fmt counts, built in memory mapped for it, as
 * the arguments of a command can be megabytes, and appended. */
static int record(size_t (*fmt)(char *, const void *, const char *), const void *what) {
    lc_timespec now = { 0, 0 };
    lc_kernel_get_clock(LC_CLOCK_REALTIME, &now);
    char time[UTC_TEXT_LEN + 1] = { 0 };
    format_utc(time, now.seconds, now.nanoseconds);

    size_t len = fmt(NULL, what, time);
    size_t size = (len + 4095) & ~(size_t)4095;
    char *buf = lc_kernel_map_memory(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        return -LB_ENOMEM;
    (void)fmt(buf, what, time);
    int rc = append_line(buf, len);
    lc_kernel_unmap_memory(buf, size);
    return rc;
}

static size_t start_fmt(char *out, const void *what, const char *time) {
    return audit_start_line(out, what, time);
}

static size_t end_fmt(char *out, const void *what, const char *time) {
    return audit_end_line(out, what, time);
}

int audit_record_start(const struct audit_start *a) { return record(start_fmt, a); }
int audit_record_end(const struct audit_end *e)     { return record(end_fmt, e); }

/* The caller's loginuid, which login sets and sudo and su keep: who logged
 * in, where uid is 0 for anyone who runs lightbox with sudo. -1 when there is
 * none, as for a process that no login started. */
int64_t audit_loginuid(void) {
    char text[16];
    if (read_file("/proc/self/loginuid", text, sizeof(text)) <= 0)
        return -1;
    int64_t v = 0;
    size_t i = 0;
    for (; text[i] >= '0' && text[i] <= '9' && i < 10; i++)
        v = v * 10 + (text[i] - '0');
    if (i == 0 || (text[i] != '\0' && text[i] != '\n') || v >= INT64_C(4294967295))
        return -1;                          /* (uid_t)-1: not set */
    return v;
}

/* ─── Reading: logs --audit ─────────────────────────────────────────────── */

void audit_filter_start(struct audit_filter *f, const char *box) {
    size_t at = 0;
    bool cut = false;
    at = str_append(f->prefix, at, "{\"box\":\"", sizeof(f->prefix), &cut);
    at = str_append(f->prefix, at, box, sizeof(f->prefix), &cut);
    at = str_append(f->prefix, at, "\",", sizeof(f->prefix), &cut);
    f->len = cut ? 0 : at;
    f->matched = 0;
    f->state = AUDIT_LINE_START;
}

/*
 * The lines of in[0..n) that begin with the box's head, into out, which has
 * room for n and the head: their length. A line may be cut anywhere between
 * one call and the next. A box's name has no " or \ (validate_name), so its
 * head in a line is the name as it is.
 */
size_t audit_filter(struct audit_filter *f, const char *in, size_t n, char *out) {
    size_t w = 0;
    for (size_t i = 0; i < n;) {
        if (f->state == AUDIT_LINE_START) {
            char c = in[i++];
            if (f->len && c == f->prefix[f->matched]) {
                if (++f->matched == f->len) {
                    lc_bytes_copy(out + w, f->prefix, f->len);
                    w += f->len;
                    f->state = AUDIT_LINE_KEPT;
                }
            } else if (c != '\n') {
                f->state = AUDIT_LINE_SKIPPED;
            } else {
                f->matched = 0;
            }
            continue;
        }
        size_t end = i;
        while (end < n && in[end] != '\n')
            end++;
        bool whole = end < n;
        if (whole)
            end++;
        if (f->state == AUDIT_LINE_KEPT) {
            lc_bytes_copy(out + w, in + i, end - i);
            w += end - i;
        }
        i = end;
        if (whole) {
            f->state = AUDIT_LINE_START;
            f->matched = 0;
        }
    }
    return w;
}
