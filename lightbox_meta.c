#include "lightbox.h"

static void print_padded(const char *s, int width) {
    print_str(STDOUT, s);
    int len = (int)lc_string_length(s);
    for (int i = len; i < width; i++) lc_print_char(STDOUT, ' ');
}

/* A JSON string: quoted, with everything escaped that JSON requires, and any
 * byte outside printable ASCII written as \u00XX. The values lightbox prints
 * are ASCII by construction; escaping the rest keeps the output valid JSON
 * whatever a damaged file holds. */
static void json_string(const char *s) {
    static const char hex[] = "0123456789abcdef";
    lc_print_char(STDOUT, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            lc_print_char(STDOUT, '\\');
            lc_print_char(STDOUT, (char)c);
        } else if (c < 0x20 || c >= 0x7f) {
            print_str(STDOUT, "\\u00");
            lc_print_char(STDOUT, hex[c >> 4]);
            lc_print_char(STDOUT, hex[c & 0xf]);
        } else {
            lc_print_char(STDOUT, (char)c);
        }
    }
    lc_print_char(STDOUT, '"');
}

/* "key": with the comma that separates it from the member before it */
static void json_key(const char *key, bool first) {
    if (!first) lc_print_char(STDOUT, ',');
    json_string(key);
    lc_print_char(STDOUT, ':');
}

void cmd_ls(int argc, char **argv) {
    bool json = false;
    for (int i = 0; i < argc; i++) {
        if (streq(argv[i], "--json"))
            json = true;
        else
            die2(argv[i][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[i]);
    }

    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    bool more = false;
    int count = list_containers(names, MAX_LISTED, &more);

    if (!json) {
        print_padded("NAME", NAME_MAX_LEN + 2);
        print_padded("IP", 16);
        print_padded("STATUS", 10);
        print_str(STDOUT, "PID\n");
        print_padded("----", NAME_MAX_LEN + 2);
        print_padded("--", 16);
        print_padded("------", 10);
        print_str(STDOUT, "---\n");
    } else {
        print_str(STDOUT, "[");
    }

    for (int i = 0; i < count; i++) {
        const char *name = names[i];
        char ip_buf[16] = "-";
        char state_buf[32];
        const char *status = "stopped";
        char pid_str[16] = "-";

        (void)read_container_ip(name, ip_buf, sizeof(ip_buf));

        container_lock_if_free(name);   /* a command that changes it waits until this has read */
        container_liveness live = container_probe(name);
        bool running = live == CONTAINER_RUNNING;
        if (running)
            fmt_int(pid_str, get_container_pid(name));
        container_shown_state(name, live, state_buf, sizeof(state_buf));
        if (state_buf[0] && !streq(state_buf, "unknown"))
            status = state_buf;

        if (json) {
            if (i > 0) print_str(STDOUT, ",");
            print_str(STDOUT, "{");
            json_key("name", true);    json_string(name);
            json_key("ip", false);     json_string(ip_buf);
            json_key("status", false); json_string(status);
            /* a number while the container runs, null otherwise */
            json_key("pid", false);    print_str(STDOUT, running ? pid_str : "null");
            print_str(STDOUT, "}");
        } else {
            print_padded(name, NAME_MAX_LEN + 2);
            print_padded(ip_buf, 16);
            print_padded(status, 10);
            print_str(STDOUT, pid_str);
            lc_print_char(STDOUT, '\n');
        }
    }

    if (json) print_str(STDOUT, "]\n");
    if (more)
        print_str(STDERR, "Warning: more than " STRINGIFY(MAX_LISTED) " containers; this list is incomplete\n");
}

static void print_kv(const char *key, const char *val) {
    print_str(STDOUT, key);
    print_str(STDOUT, ": ");
    print_str(STDOUT, val);
    lc_print_char(STDOUT, '\n');
}

static void print_kv_int(const char *key, int val) {
    char buf[32];
    fmt_int(buf, val);
    print_kv(key, buf);
}


/*
 * logs <name> [-f] [--audit]: what the container's init, its hook and its
 * services wrote to stdout and stderr, from every start since the container
 * was made. With --audit, the lines of the audit log about the box of that
 * name (ROADMAP 8.9): what exec and run asked of it, kept after it is
 * removed. With -f it goes on for as long as the container runs.
 */
void cmd_logs(int argc, char **argv) {
    const char *name = NULL;
    bool follow = false, audit = false;
    for (int i = 0; i < argc; i++) {
        if (streq(argv[i], "-f") || streq(argv[i], "--follow"))
            follow = true;
        else if (streq(argv[i], "--audit"))
            audit = true;
        else if (argv[i][0] == '-' && argv[i][1])
            die2("Error: unknown option: ", argv[i]);
        else if (!name)
            name = argv[i];
        else
            die2("Error: unexpected argument: ", argv[i]);
    }
    if (!name) die("Usage: lightbox logs <name> [-f] [--audit]");
    validate_name(name);

    char path[MAX_PATH];
    struct audit_filter filter;
    if (audit) {
        /* a box that was removed has its lines there still */
        audit_log_path(path);
        audit_filter_start(&filter, name);
    } else {
        container_dir_path(path, name);
        if (!path_exists(path)) die2("Error: container does not exist: ", name);
        container_log_path(path, name);
    }

    lc_sysret fd = -LB_ENOENT;
    for (;;) {
        /* Look whether the container runs before reading, not after: what it
         * wrote before it ended is then in the file by the time of the read. */
        bool running = follow && is_running(name);

        if (fd == -LB_ENOENT)
            fd = lc_kernel_open_file(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
        if (fd < 0 && fd != -LB_ENOENT) {
            char digits[16];
            fmt_int(digits, (int)-fd);
            print_str(STDERR, audit ? "Error: cannot read the audit log " : "Error: cannot read the log of container '");
            print_str(STDERR, audit ? path : name);
            print_str(STDERR, audit ? " (errno " : "' (errno ");
            print_str(STDERR, digits);
            print_str(STDERR, ")\n");
            lc_kernel_exit(failure_status);
        }

        /* a container that was never started has no log, which is an empty
         * one, and a host where no exec ran no audit log */
        bool got_some = false;
        while (fd >= 0) {
            char buf[4096];
            static char kept[sizeof(buf) + sizeof(filter.prefix)];
            lc_sysret n = lc_kernel_read_retry((int32_t)fd, buf, sizeof(buf));
            if (n < 0)
                die("Error: reading the log failed");
            if (n == 0)
                break;
            const char *out = buf;
            size_t len = (size_t)n;
            if (audit) {
                len = audit_filter(&filter, buf, len, kept);
                out = kept;
            }
            if (lc_kernel_write_all(STDOUT, out, len) < 0)
                lc_kernel_exit(failure_status);          /* nobody reads this any more */
            got_some = true;
        }

        if (!running)
            break;
        if (!got_some) {
            lc_timespec nap = { .seconds = 0, .nanoseconds = 100000000 };
            lc_kernel_sleep(&nap);
        }
    }
    if (fd >= 0)
        lc_kernel_close_file((int32_t)fd);
}

/*
 * What inspect prints, one value at a time: "key: value" lines, or the
 * members of one JSON object. Text shows what has no value as "-", and JSON
 * as null; a flag is yes and no, or 1 and 0, in text, as it always was, and
 * true and false in JSON.
 */
struct report {
    bool json;
    bool first;
};

static void report_text(struct report *r, const char *key, const char *value) {
    if (!r->json) {
        print_kv(key, value ? value : "-");
        return;
    }
    json_key(key, r->first);
    r->first = false;
    if (value)
        json_string(value);
    else
        print_str(STDOUT, "null");
}

static void report_number(struct report *r, const char *key, int value) {
    if (!r->json) {
        print_kv_int(key, value);
        return;
    }
    char digits[16];
    fmt_int(digits, value);
    json_key(key, r->first);
    r->first = false;
    print_str(STDOUT, digits);
}

/* An id up to 4294967295, or none: "-" and null. */
static void report_id(struct report *r, const char *key, bool have, uint32_t value) {
    char digits[11];
    format_u32(digits, value);
    if (!r->json) {
        print_kv(key, have ? digits : "-");
        return;
    }
    json_key(key, r->first);
    r->first = false;
    print_str(STDOUT, have ? digits : "null");
}

static void report_flag(struct report *r, const char *key, bool value, const char *yes, const char *no) {
    if (!r->json) {
        print_kv(key, value ? yes : no);
        return;
    }
    json_key(key, r->first);
    r->first = false;
    print_str(STDOUT, value ? "true" : "false");
}

/* The volumes: a line each, "<src>:<dst>[:ro]", or an array of objects. */
static void report_volumes(struct report *r, const container_config *config) {
    if (!r->json) {
        if (config->nvols == 0)
            print_kv("volume", "-");
        for (int i = 0; i < config->nvols; i++) {
            print_str(STDOUT, "volume: ");
            print_str(STDOUT, config->vols[i].src);
            lc_print_char(STDOUT, ':');
            print_str(STDOUT, config->vols[i].dst);
            print_str(STDOUT, config->vols[i].ro ? ":ro\n" : "\n");
        }
        return;
    }
    json_key("volumes", r->first);
    r->first = false;
    lc_print_char(STDOUT, '[');
    for (int i = 0; i < config->nvols; i++) {
        if (i) lc_print_char(STDOUT, ',');
        lc_print_char(STDOUT, '{');
        json_key("src", true);  json_string(config->vols[i].src);
        json_key("dst", false); json_string(config->vols[i].dst);
        json_key("ro", false);  print_str(STDOUT, config->vols[i].ro ? "true" : "false");
        lc_print_char(STDOUT, '}');
    }
    lc_print_char(STDOUT, ']');
}

/* The devices (ROADMAP G.1): a line each, "<host>:<path>[:ro]", or an array of objects. */
static void report_devices(struct report *r, const container_config *config) {
    if (!r->json) {
        if (config->ndevs == 0)
            print_kv("device", "-");
        for (int i = 0; i < config->ndevs; i++) {
            print_str(STDOUT, "device: ");
            print_str(STDOUT, config->devs[i].host);
            lc_print_char(STDOUT, ':');
            print_str(STDOUT, config->devs[i].path);
            print_str(STDOUT, config->devs[i].ro ? ":ro\n" : "\n");
        }
        return;
    }
    json_key("devices", r->first);
    r->first = false;
    lc_print_char(STDOUT, '[');
    for (int i = 0; i < config->ndevs; i++) {
        if (i) lc_print_char(STDOUT, ',');
        lc_print_char(STDOUT, '{');
        json_key("host", true);  json_string(config->devs[i].host);
        json_key("path", false); json_string(config->devs[i].path);
        json_key("ro", false);   print_str(STDOUT, config->devs[i].ro ? "true" : "false");
        lc_print_char(STDOUT, '}');
    }
    lc_print_char(STDOUT, ']');
}

/* The containers it is linked to: a line each, or an array of names. */
static void report_links(struct report *r, const container_config *config) {
    if (!r->json) {
        if (config->nlinks == 0)
            print_kv("link", "-");
        for (int i = 0; i < config->nlinks; i++)
            print_kv("link", config->links[i]);
        return;
    }
    json_key("links", r->first);
    r->first = false;
    lc_print_char(STDOUT, '[');
    for (int i = 0; i < config->nlinks; i++) {
        if (i) lc_print_char(STDOUT, ',');
        json_string(config->links[i]);
    }
    lc_print_char(STDOUT, ']');
}

void cmd_inspect(int argc, char **argv) {
    bool json = false;
    const char *name = NULL;
    for (int i = 0; i < argc; i++) {
        if (streq(argv[i], "--json"))
            json = true;
        else if (argv[i][0] == '-')
            die2("Error: unknown option: ", argv[i]);
        else if (!name)
            name = argv[i];
        else
            die2("Error: unexpected argument: ", argv[i]);
    }
    if (!name) die("Usage: lightbox inspect <name> [--json]");
    validate_name(name);

    char cdir[MAX_PATH], root[MAX_PATH], conf_path[MAX_PATH], ip_path[MAX_PATH], log_path[MAX_PATH];
    char pid_path[MAX_PATH], pid_start_path[MAX_PATH], state_path[MAX_PATH], state[32], ip[16], pid_start[32];
    container_dir_path(cdir, name);
    if (!path_exists(cdir)) die2("Error: container does not exist: ", name);

    container_root(root, name);
    container_conf_path(conf_path, name);
    container_ip_path(ip_path, name);
    container_log_path(log_path, name);
    container_pid_path(pid_path, name);
    container_pid_start_path(pid_start_path, name);
    container_state_path(state_path, name);

    container_lock_if_free(name);
    bool have_ip = read_container_ip(name, ip, sizeof(ip)) >= 0;
    container_liveness live = container_probe(name);
    container_shown_state(name, live, state, sizeof(state));
    /* a record that is not the number of a process is no record */
    int pid = get_container_pid(name);
    bool have_start = get_container_pid_starttime(name, pid_start, sizeof(pid_start)) == 0;

    /* What it is configured with. In text, a configuration that cannot be
     * used is said to be so after everything that could be shown; JSON is
     * a whole document or none. */
    static container_config config;
    const char *wrong = container_config_load(name, &config);
    if (wrong && json)
        die2("Error: the container's configuration cannot be used: ", wrong);

    struct report r = { .json = json, .first = true };
    if (json)
        print_str(STDOUT, "[{");
    report_text(&r, "name", name);
    report_text(&r, "state", state);
    report_flag(&r, "running", live == CONTAINER_RUNNING, "yes", "no");
    report_text(&r, "ip", have_ip ? ip : NULL);
    {
        char port[IFNAME_TEXT_MAX];
        host_port_name(name, port);
        report_text(&r, "host_interface", port);
    }
    report_text(&r, "dir", cdir);
    report_text(&r, "rootfs", root);
    report_text(&r, "config_path", conf_path);
    report_text(&r, "ip_path", ip_path);
    report_text(&r, "log_path", log_path);
    {
        char audit_path[MAX_PATH];
        audit_log_path(audit_path);
        report_text(&r, "audit_path", audit_path);
    }
    report_text(&r, "pid_path", pid_path);
    report_text(&r, "pid_start_path", pid_start_path);
    report_text(&r, "state_path", state_path);
    if (pid > 0)
        report_number(&r, "pid", pid);
    else
        report_text(&r, "pid", NULL);
    report_text(&r, "pid_starttime", have_start ? pid_start : NULL);

    if (!wrong) {
        report_text(&r, "mem", config.mem);
        report_text(&r, "swap", config.swap[0] ? config.swap : "0");
        report_text(&r, "pids", config.pids);
        report_text(&r, "cpu", config.cpu);
        report_text(&r, "io", config.io[0] ? config.io : NULL);
        report_text(&r, "storage", config.base[0] ? "overlay" : "copy");
        report_text(&r, "base", config.base[0] ? config.base : NULL);
        report_flag(&r, "userns", config.userns, "1", "0");
        report_id(&r, "uid_start", config.userns, config.uid_start);
        report_id(&r, "gid_start", config.userns, config.gid_start);
        report_number(&r, "oom_score", config.oom_score);
        report_flag(&r, "privileged", config.privileged, "1", "0");
        report_flag(&r, "readonly", config.read_only, "1", "0");
        report_text(&r, "seccomp", config.privileged ? NULL : config.seccomp_allow ? "allow" : "deny");
        char mode[NET_MODE_TEXT_MAX];
        net_mode_text(mode, config.net, config.proxy_port);
        report_text(&r, "net", mode);
        report_text(&r, "ttl", config.ttl[0] ? config.ttl : NULL);
        report_text(&r, "id", config.id[0] ? config.id : NULL);
        report_text(&r, "profile", config.profile == PROFILE_AGENT ? "agent" : NULL);
        report_text(&r, "workdir", config.workdir[0] ? config.workdir : NULL);
        report_volumes(&r, &config);
        report_devices(&r, &config);
        report_links(&r, &config);
    }
    if (json)
        print_str(STDOUT, "}]\n");
    if (wrong)
        die2("Error: the container's configuration cannot be used: ", wrong);
}

/* ─── doctor ────────────────────────────────────────────────────────────── */

/*
 * doctor's report: the settings, then the checks of what start and the
 * other commands need. In text a check is "<name>: <what it found>", and one
 * that fails is followed by "  to fix: <what to do>". --json gives the same
 * as {"settings": {...}, "checks": [{"check", "ok", "text", "fix"}, ...],
 * "overall"}, the text being what the line says after the name.
 */
struct doctor {
    bool json;
    bool first;
    int failed;
};

/* a setting: its text, and in JSON that text or the literal given */
static void doc_setting(struct doctor *d, const char *key, const char *text, const char *literal) {
    if (!d->json) {
        print_kv(key, text);
        return;
    }
    json_key(key, d->first);
    d->first = false;
    if (literal)
        print_str(STDOUT, literal);
    else
        json_string(text);
}

static void doc_flag(struct doctor *d, const char *key, bool value, const char *text_true, const char *text_false) {
    doc_setting(d, key, value ? text_true : text_false, value ? "true" : "false");
}

static void doc_begin_checks(struct doctor *d) {
    if (d->json)
        print_str(STDOUT, "},\"checks\":[");
    d->first = true;
}

static void doc_check(struct doctor *d, const char *name, bool ok, const char *text, const char *fix) {
    if (!ok)
        d->failed++;
    if (!d->json) {
        print_kv(name, text);
        if (!ok && fix) {
            print_str(STDOUT, "  to fix: ");
            print_str(STDOUT, fix);
            lc_print_char(STDOUT, '\n');
        }
        return;
    }
    if (!d->first)
        lc_print_char(STDOUT, ',');
    d->first = false;
    lc_print_char(STDOUT, '{');
    json_key("check", true);
    json_string(name);
    json_key("ok", false);
    print_str(STDOUT, ok ? "true" : "false");
    json_key("text", false);
    json_string(text);
    json_key("fix", false);
    if (!ok && fix)
        json_string(fix);
    else
        print_str(STDOUT, "null");
    lc_print_char(STDOUT, '}');
}

/* "<word> (<detail>)", or the word alone */
static const char *worded(char *buf, size_t max, const char *word, const char *detail) {
    bool cut = false;
    size_t pos = str_append(buf, 0, word, max, &cut);
    if (detail && detail[0]) {
        pos = str_append(buf, pos, " (", max, &cut);
        pos = str_append(buf, pos, detail, max, &cut);
        str_append(buf, pos, ")", max, &cut);
    }
    return buf;
}

/* A file a check names, and what to do when it is not right: ok or missing. */
static void doc_file(struct doctor *d, const char *name, bool ok, const char *detail, const char *fix) {
    char text[MAX_PATH + 64];
    doc_check(d, name, ok, worded(text, sizeof(text), ok ? "ok" : "missing", detail), fix);
}

/* Anything else: yes or no. */
static void doc_yes_no(struct doctor *d, const char *name, bool ok, const char *detail, const char *fix) {
    char text[MAX_PATH + 128];
    doc_check(d, name, ok, worded(text, sizeof(text), ok ? "yes" : "no", detail), fix);
}

static void check_root(struct doctor *d) {
    char detail[32];
    uint32_t uid = (uint32_t)lb_sys_geteuid();
    bool cut = false;
    fmt_int(detail + str_append(detail, 0, "uid ", sizeof(detail), &cut), (int)uid);
    doc_yes_no(d, "root", uid == 0, detail,
               "run lightbox as root, as setup, start, stop and exec need: sudo lightbox doctor");
}

/* The kernel's release, or "" when it cannot be read: its length. */
static int kernel_release(char *release, size_t max) {
    int n = read_file("/proc/sys/kernel/osrelease", release, max);
    if (n < 0)
        n = 0;
    release[n] = '\0';
    while (n > 0 && (release[n - 1] == '\n' || release[n - 1] == ' '))
        release[--n] = '\0';
    return n;
}

/* "<release>; <needs>", and whether the release is that version or later */
static void doc_kernel(struct doctor *d, const char *name, int want_major, int want_minor, const char *needs,
                       const char *fix) {
    char release[128];
    int n = kernel_release(release, sizeof(release));
    int major, minor;
    bool ok = kernel_release_at_least(release, want_major, want_minor, &major, &minor);
    char detail[256];
    bool cut = false;
    size_t pos = str_append(detail, 0, n > 0 ? release : "the release cannot be read", sizeof(detail), &cut);
    pos = str_append(detail, pos, "; ", sizeof(detail), &cut);
    str_append(detail, pos, needs, sizeof(detail), &cut);
    doc_yes_no(d, name, ok, detail, fix);
}

static void check_kernel(struct doctor *d) {
    doc_kernel(d, "kernel", KERNEL_FLOOR_MAJOR, KERNEL_FLOOR_MINOR,
               "lightbox needs Linux " STRINGIFY(KERNEL_FLOOR_MAJOR) "." STRINGIFY(KERNEL_FLOOR_MINOR) " or later",
               "boot Linux " STRINGIFY(KERNEL_FLOOR_MAJOR) "." STRINGIFY(KERNEL_FLOOR_MINOR) " or later");
}

/*
 * The system calls of the kernels after 5.0 that start, stop and exec make,
 * each called so that it fails at once without doing anything: a kernel that
 * has it says what is wrong with the arguments, one that does not says
 * ENOSYS.
 */
static void check_syscalls(struct doctor *d) {
    const struct { const char *name; int64_t nr, a, b, c, e, f; } probes[] = {
        { "pidfd_open",        LB_SYS_pidfd_open,        0, 0, 0, 0, 0 },                  /* pid 0 */
        { "pidfd_send_signal", LB_SYS_pidfd_send_signal, -1, 0, 0, 0, 0 },                 /* no descriptor */
        { "open_tree",         LB_SYS_open_tree,         -1, (int64_t)(uintptr_t)"", 0, 0, 0 },
        { "move_mount",        LB_SYS_move_mount,        -1, (int64_t)(uintptr_t)"", -1, (int64_t)(uintptr_t)"", 0 },
        { "openat2",           LB_SYS_openat2,           -1, 0, 0, 0, 0 },                 /* no how */
        { "close_range",       LB_SYS_close_range,       1, 0, 0, 0, 0 },                  /* first after last */
        { "faccessat2",        SYS_faccessat2,           AT_FDCWD, (int64_t)(uintptr_t)"/", F_OK, 0, 0 },
    };
    char missing[256] = "";
    size_t pos = 0;
    bool cut = false;
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        lc_sysret rc = lc_syscall5(probes[i].nr, probes[i].a, probes[i].b, probes[i].c, probes[i].e, probes[i].f);
        if (rc != -LB_ENOSYS)
            continue;
        pos = str_append(missing, pos, pos ? ", " : "missing: ", sizeof(missing), &cut);
        pos = str_append(missing, pos, probes[i].name, sizeof(missing), &cut);
    }
    doc_yes_no(d, "syscalls", !missing[0], missing[0] ? missing : "the ones of Linux 5.10 that lightbox makes",
               "boot Linux " STRINGIFY(KERNEL_FLOOR_MAJOR) "." STRINGIFY(KERNEL_FLOOR_MINOR) " or later");
}

/* cgroup_root a cgroup v2 hierarchy, and the controllers a container's
 * limits need in it: cpu, memory and pids for every container, io only
 * for one with --io-max, which is said and not counted. */
static void check_cgroups(struct doctor *d) {
    const char *root = cfg_global.cgroup_root;
    struct lb_statfs sfs;
    bool v2 = lb_sys_statfs(root, &sfs) == 0 && sfs.f_type == LB_CGROUP2_SUPER_MAGIC;
    doc_yes_no(d, "cgroup2", v2, root,
               "boot with cgroup_no_v1=all, or set cgroup_root to an empty directory, which setup and start mount cgroup2 on");
    if (!v2)
        return;
    char path[MAX_PATH], list[256];
    if (!path_join(path, sizeof(path), root, "cgroup.controllers") || read_file(path, list, sizeof(list)) < 0)
        list[0] = '\0';
    static const char *const needed[] = { "cpu", "memory", "pids", "io" };
    char missing[64] = "", found[64] = "";
    size_t mpos = 0, fpos = 0;
    bool cut = false, io = true;
    for (size_t i = 0; i < sizeof(needed) / sizeof(needed[0]); i++) {
        bool there = false;
        size_t len = lc_string_length(needed[i]);
        for (const char *p = list; *p && !there; ) {
            while (*p == ' ' || *p == '\n') p++;
            const char *w = p;
            while (*p && *p != ' ' && *p != '\n') p++;
            there = (size_t)(p - w) == len && lc_string_starts_with(w, len, needed[i], len);
        }
        if (there) {
            fpos = str_append(found, fpos, fpos ? " " : "", sizeof(found), &cut);
            fpos = str_append(found, fpos, needed[i], sizeof(found), &cut);
        } else if (i == 3) {
            io = false;
        } else {
            mpos = str_append(missing, mpos, mpos ? " " : "missing: ", sizeof(missing), &cut);
            mpos = str_append(missing, mpos, needed[i], sizeof(missing), &cut);
        }
    }
    char detail[160];
    size_t pos = str_append(detail, 0, missing[0] ? missing : found, sizeof(detail), &cut);
    if (!io)
        str_append(detail, pos, missing[0] ? "; no io either" : "; no io, so --io-max cannot be used", sizeof(detail), &cut);
    doc_yes_no(d, "cgroup_controllers", !missing[0], detail,
               "the kernel offers them in cgroup.controllers of cgroup_root unless its command line has cgroup_disable= for one");
}

/* The cgroup device program a container that is not privileged starts with
 * (ROADMAP 8.4): loaded and let go, which only root may. */
static void check_device_filter(struct doctor *d) {
    static const char fix[] = "boot a kernel with CONFIG_CGROUP_BPF and CONFIG_BPF_SYSCALL; only a --privileged container "
                              "starts without it";
    /* a call the kernel does not have answers ENOSYS to anyone (ROADMAP R.4) */
    if (bpf_call_missing()) {
        doc_yes_no(d, "device_filter", false, "the kernel has no bpf system call, which loads the program", fix);
        return;
    }
    if (lb_sys_geteuid() != 0) {
        doc_yes_no(d, "device_filter", false, "not known: only root may load the program", "sudo lightbox doctor");
        return;
    }
    static char log[2048];
    lc_sysret fd = device_program_load(NULL, 0, log, sizeof(log));
    if (fd >= 0) {
        lc_kernel_close_file((int32_t)fd);
        doc_yes_no(d, "device_filter", true, "the kernel loads the cgroup device program", NULL);
        return;
    }
    char text[96];
    bool cut = false;
    size_t pos = str_append(text, 0, "the kernel refuses the cgroup device program: errno ", sizeof(text), &cut);
    fmt_int(text + pos, (int)-fd);
    doc_yes_no(d, "device_filter", false, text, fix);
}

/*
 * What the rules of the firewall need of the kernel (ROADMAP R.3), asked
 * without a rule put in: with nftables, what nft --check of the rules setup
 * puts in says; with iptables, each target and match of its rules that the
 * kernel has neither registered nor can load. What only a container with
 * --link needs is said and not counted, as bridge_filtering is.
 */
static void check_firewall_kernel(struct doctor *d, const container_network *net) {
    if (!cfg_global.firewall)
        return;
    static char text[1024];
    bool cut = false;
    if (cfg_global.firewall_backend == FIREWALL_NFTABLES) {
        static const char fix[] = "boot a kernel with nf_tables with NAT, masquerading, conntrack, rejection and the bridge "
                                  "family (CONFIG_NF_TABLES_BRIDGE, CONFIG_NFT_BRIDGE_META)";
        if (lb_sys_geteuid() != 0) {
            doc_check(d, "firewall_kernel", false, "not known: only root may ask the kernel, with nft --check",
                      "sudo lightbox doctor");
            return;
        }
        static char said[1024];
        int rc = nft_kernel_check(net, said, sizeof(said));
        if (rc < 0) {
            doc_check(d, "firewall_kernel", false, "not known: there is no nft, or the bridge's name is not one nft takes",
                      "install nftables");
            return;
        }
        if (rc == 1) {
            doc_check(d, "firewall_kernel", true, "yes (the kernel takes the nftables rules setup puts in: nft --check)", NULL);
            return;
        }
        /* nft's first error, and the line of the rules it is about */
        int64_t at = lc_string_find_substring(said, lc_string_length(said), "Error: ", 7);
        const char *error = at >= 0 ? said + at + 7 : said;
        size_t pos = str_append(text, 0, "no (nft --check: ", sizeof(text), &cut);
        const char *end = error;
        while (*end && *end != '\n')
            end++;
        const char *rule = *end ? end + 1 : end, *rule_end = rule;
        while (*rule_end && *rule_end != '\n')
            rule_end++;
        for (const char *p = error; p < end && !cut; p++)
            pos = str_append(text, pos, (char[2]){ *p, '\0' }, sizeof(text), &cut);
        if (rule < rule_end) {
            pos = str_append(text, pos, ", at: ", sizeof(text), &cut);
            for (const char *p = rule; p < rule_end && !cut; p++)
                pos = str_append(text, pos, (char[2]){ *p, '\0' }, sizeof(text), &cut);
        }
        str_append(text, pos, ")", sizeof(text), &cut);
        doc_check(d, "firewall_kernel", false, text, fix);
        return;
    }
    char modules[MAX_PATH];
    if (!running_kernel_modules(modules))
        lc_bytes_copy(modules, "/lib/modules/(unknown)", sizeof("/lib/modules/(unknown)"));
    static char missing[512], links[256];
    int rc = iptables_kernel_missing("/proc/net", modules, missing, sizeof(missing), links, sizeof(links));
    size_t pos;
    if (rc < 0) {
        pos = str_append(text, 0, "not known: /proc/net/ip_tables_targets cannot be read, and ", sizeof(text), &cut);
        pos = str_append(text, pos, modules, sizeof(text), &cut);
        str_append(text, pos, " lists no modules", sizeof(text), &cut);
        doc_check(d, "firewall_kernel", false, text, "sudo lightbox doctor");
        return;
    }
    pos = str_append(text, 0, rc ? "yes (the targets and matches of its iptables rules)" : "no (missing: ", sizeof(text), &cut);
    if (!rc)
        pos = str_append(text, str_append(text, pos, missing, sizeof(text), &cut), ")", sizeof(text), &cut);
    if (links[0]) {
        pos = str_append(text, pos, "; a container with --link does not start without the ", sizeof(text), &cut);
        str_append(text, pos, links, sizeof(text), &cut);
    }
    doc_check(d, "firewall_kernel", rc == 1, text,
              "boot a kernel with each CONFIG_ option named, as a module or built in; firewall_backend = nftables in "
              "lightbox.conf needs none of iptables' targets and matches, and the kernel's nf_tables with the bridge family");
}

/* The base root filesystem: a directory with something in it to copy. */
static void check_rootfs(struct doctor *d) {
    const char *rootfs = cfg_global.rootfs;
    bool dir = path_is_directory(rootfs);
    int empty = dir ? dir_is_empty(rootfs) : -1;
    char detail[MAX_PATH + 32];
    bool cut = false;
    size_t pos = str_append(detail, 0, rootfs, sizeof(detail), &cut);
    if (!path_exists(rootfs))
        str_append(detail, pos, " is not there", sizeof(detail), &cut);
    else if (!dir)
        str_append(detail, pos, " is not a directory", sizeof(detail), &cut);
    else if (empty != 0)
        str_append(detail, pos, empty > 0 ? " is empty" : " cannot be read", sizeof(detail), &cut);
    doc_file(d, "path.rootfs", dir && empty == 0, detail,
             "put a root filesystem there, such as Alpine's minirootfs: tar -xzf alpine-minirootfs-*.tar.gz -C <rootfs>");
}

/* doctor: can exec run from a copy of the binary that cannot be written to? */
static void check_exec_sealing(struct doctor *d) {
    switch (exec_seal_method()) {
        case SEAL_MEMFD:
            doc_check(d, "exec_sealing", true, "yes (a sealed copy in memory)", NULL);
            return;
        case SEAL_READONLY:
            doc_check(d, "exec_sealing", true,
                      "yes (a read-only mount of the binary; executable memfds are refused here)", NULL);
            return;
        case SEAL_NONE:
        default:
            doc_check(d, "exec_sealing", false, "no (exec will not run: it needs memfd_create, or root and Linux 5.12)",
                      "boot Linux 5.12 or later and run exec as root, or let memfds be executed (vm.memfd_noexec = 0)");
            return;
    }
}

/* Is overlayfs among the filesystems the kernel has, or a module of the
 * running kernel's that the first mount of one loads? /proc/filesystems
 * lists it only once it is loaded (ROADMAP R.4). */
enum overlayfs_kind { OVERLAYFS_LISTED, OVERLAYFS_MODULE, OVERLAYFS_NONE, OVERLAYFS_UNKNOWN };
static enum overlayfs_kind overlayfs_here(void) {
    static char filesystems[8192];
    if (read_file("/proc/filesystems", filesystems, sizeof(filesystems)) > 0 &&
        lc_string_contains(filesystems, lc_string_length(filesystems), "\toverlay\n", 9))
        return OVERLAYFS_LISTED;
    char modules[MAX_PATH];
    bool listed = false;
    if (running_kernel_modules(modules) && kernel_module_listed(modules, "overlay", &listed))
        return OVERLAYFS_MODULE;
    return listed ? OVERLAYFS_NONE : OVERLAYFS_UNKNOWN;
}

/*
 * doctor --profile agent (ROADMAP 8.11): what a box of the profile needs
 * beyond what every container does. Its root is an overlay on an idmapped
 * snapshot of its base, which needs Linux 5.19, a filesystem under the
 * snapshots and the containers that idmaps, and a range of ids; exec and
 * stop end what it started with cgroup.kill; and nft is what filters its
 * traffic at the bridge with firewall_backend = nftables. overlayfs is
 * looked for in /proc/filesystems and among the running kernel's modules,
 * as a box is an overlay and the profile refuses --copy (ROADMAP R.4).
 */
#define AGENT_KERNEL_MAJOR 5
#define AGENT_KERNEL_MINOR 19
#define AGENT_PROBE_ID     65534u      /* the id a probe's mount is idmapped to: nobody's */

/* An idmapped copy of the mount at each path made and let go, never
 * attached: whether the filesystems there take one. Root's alone. */
static void check_agent_idmap(struct doctor *d) {
    char bases[MAX_PATH];
    bases_dir_path(bases);
    const char *paths[2] = { path_is_directory(bases) ? bases : cfg_global.lightbox_dir, cfg_global.container_dir };
    char text[2 * MAX_PATH + 96];
    bool cut = false;
    if (lb_sys_geteuid() != 0) {
        doc_yes_no(d, "agent.idmap", false, "not known: only root may make an idmapped mount",
                   "sudo lightbox doctor --profile agent");
        return;
    }
    id_map one = { .inside = 0, .outside = AGENT_PROBE_ID, .count = 1 };
    int ns = userns_fd_mapped(&one, &one);
    if (ns < 0) {
        size_t pos = str_append(text, 0, "a user namespace cannot be made: errno ", sizeof(text), &cut);
        fmt_int(text + pos, -ns);
        doc_yes_no(d, "agent.idmap", false, text,
                   "boot a kernel with CONFIG_USER_NS, and with user.max_user_namespaces above 0");
        return;
    }
    const char *wrong = NULL, *where = NULL, *step = "";
    int rc = 0;
    for (size_t i = 0; i < 2 && !wrong; i++) {
        where = paths[i];
        if (!path_is_directory(where)) {
            wrong = "is not there";
            break;
        }
        int tree = idmapped_tree(where, ns, false, &step);
        if (tree < 0) {
            wrong = "cannot be idmapped";
            rc = -tree;
        } else {
            lc_kernel_close_file(tree);
        }
    }
    lc_kernel_close_file(ns);
    if (!wrong) {
        size_t pos = str_append(text, 0, paths[0], sizeof(text), &cut);
        pos = str_append(text, pos, " and ", sizeof(text), &cut);
        str_append(text, pos, paths[1], sizeof(text), &cut);
        doc_yes_no(d, "agent.idmap", true, text, NULL);
        return;
    }
    size_t pos = str_append(text, 0, where, sizeof(text), &cut);
    pos = str_append(text, pos, " ", sizeof(text), &cut);
    pos = str_append(text, pos, wrong, sizeof(text), &cut);
    if (rc) {
        pos = str_append(text, pos, ": ", sizeof(text), &cut);
        pos = str_append(text, pos, step, sizeof(text), &cut);
        pos = str_append(text, pos, ", errno ", sizeof(text), &cut);
        fmt_int(text + pos, rc);
    }
    doc_yes_no(d, "agent.idmap", false, text,
               rc ? "keep lightbox_dir and container_dir on a filesystem with idmapped mounts, such as ext4, xfs or btrfs"
                  : "lightbox setup makes it");
}

/* cgroup.kill in lightbox's cgroup, or, before a container has made that,
 * in the cgroup doctor runs in. The root cgroup has none; the root of a
 * cgroup namespace, which /proc/self/cgroup shows as "/", may be another. */
static void check_agent_cgroup_kill(struct doctor *d) {
    char path[MAX_PATH] = "";
    bool cut = false, known = true;
    if (path_is_directory(cfg_global.cgroup_base)) {
        if (!path_join(path, sizeof(path), cfg_global.cgroup_base, "cgroup.kill"))
            path[0] = '\0';
    } else {
        static char self[MAX_PATH];
        int n = read_file("/proc/self/cgroup", self, sizeof(self));
        while (n > 0 && self[n - 1] == '\n')
            self[--n] = '\0';
        /* "0::<path>", the one line of cgroup v2 */
        if (n >= 4 && lc_string_starts_with(self, (size_t)n, "0::/", 4)) {
            bool top = n == 4;
            size_t pos = str_append(path, 0, cfg_global.cgroup_root, sizeof(path), &cut);
            pos = str_append(path, pos, top ? "" : self + 3, sizeof(path), &cut);
            str_append(path, pos, "/cgroup.kill", sizeof(path), &cut);
            if (cut)
                path[0] = '\0';
            known = !top || path_exists(path);
        }
    }
    if (!path[0] || !known) {
        doc_yes_no(d, "agent.cgroup_kill", false, "not known: no cgroup but the root one to look in",
                   "start a container, which makes cgroup_base, and run doctor again");
        return;
    }
    doc_yes_no(d, "agent.cgroup_kill", path_exists(path), path,
               "boot Linux 5.14 or later: without cgroup.kill a box's processes are ended a list at a time");
}

static void check_agent(struct doctor *d) {
    doc_kernel(d, "agent.kernel", AGENT_KERNEL_MAJOR, AGENT_KERNEL_MINOR,
               "the profile needs Linux " STRINGIFY(AGENT_KERNEL_MAJOR) "." STRINGIFY(AGENT_KERNEL_MINOR)
               " or later, for an overlay on an idmapped layer",
               "boot Linux " STRINGIFY(AGENT_KERNEL_MAJOR) "." STRINGIFY(AGENT_KERNEL_MINOR) " or later");
    {
        int ranges = userns_range_count();
        char text[160];
        bool cut = false;
        if (ranges < 0) {
            str_append(text, 0, SUBUID_FILE " or " SUBGID_FILE " has a line of " USERNS_OWNER "'s that is no range",
                       sizeof(text), &cut);
        } else if (ranges == 0) {
            str_append(text, 0, "none of " USERNS_OWNER "'s in " SUBUID_FILE " and " SUBGID_FILE, sizeof(text), &cut);
        } else {
            fmt_int(text, ranges);
            str_append(text, lc_string_length(text), " ranges of 65536 ids, one for each box", sizeof(text), &cut);
        }
        doc_yes_no(d, "agent.userns_ranges", ranges > 0, text,
                   "give " USERNS_OWNER " a range in " SUBUID_FILE " and " SUBGID_FILE ", such as "
                   USERNS_OWNER ":2147483647:2147483648");
    }
    {
        enum overlayfs_kind kind = overlayfs_here();
        static const char *const said[] = {
            [OVERLAYFS_LISTED] = "in /proc/filesystems",
            [OVERLAYFS_MODULE] = "a module of the kernel's, which the first overlay mounted loads",
            [OVERLAYFS_NONE] = "the kernel has none, built in or as a module: a box is an overlay of its base",
            [OVERLAYFS_UNKNOWN] = "not in /proc/filesystems, and the running kernel's modules are not listed",
        };
        doc_yes_no(d, "agent.overlayfs", kind == OVERLAYFS_LISTED || kind == OVERLAYFS_MODULE, said[kind],
                   kind == OVERLAYFS_UNKNOWN ? "modprobe overlay, and see that /proc/filesystems lists it"
                                             : "boot a kernel with CONFIG_OVERLAY_FS: --profile agent refuses --copy");
    }
    check_agent_idmap(d);
    const char *nft = tool_path_nft();
    doc_file(d, "agent.nft", path_executable(nft), nft,
             "install nftables, and set firewall_backend = nftables in lightbox.conf: lightbox then filters a "
             "box's traffic at the bridge, which with iptables needs br_netfilter");
    check_agent_cgroup_kill(d);
}

void cmd_doctor(int argc, char **argv) {
    struct doctor doc = { .json = false, .first = true, .failed = 0 };
    bool agent = false;
    for (int i = 0; i < argc; i++) {
        if (streq(argv[i], "--json")) {
            doc.json = true;
        } else if (streq(argv[i], "--profile")) {
            if (i + 1 >= argc)
                die("Error: option --profile requires a value");
            if (!streq(argv[++i], "agent"))
                die2("Error: --profile takes agent, not: ", argv[i]);
            agent = true;
        } else {
            die2(argv[i][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[i]);
        }
    }
    struct doctor *d = &doc;
    static const struct {
        const char *key;
        const char *(*resolve)(void);
        bool nftables;      /* the firewall tools of one backend: the other's are not looked for */
        bool iptables;
        const char *fix;
    } bins[] = {
        { "bin.iptables", tool_path_iptables, false, true, "install iptables" },
        { "bin.iptables-restore", tool_path_iptables_restore, false, true, "install iptables" },
        { "bin.nft", tool_path_nft, true, false, "install nftables" },
        { "bin.cp", tool_path_cp, true, true, "install coreutils" },
        { "bin.rm", tool_path_rm, true, true, "install coreutils" },
    };
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;

    if (d->json)
        print_str(STDOUT, "{\"settings\":{");
    doc_setting(d, "lightbox_dir", cfg_global.lightbox_dir, NULL);
    doc_setting(d, "rootfs", cfg_global.rootfs, NULL);
    doc_setting(d, "container_dir", cfg_global.container_dir, NULL);
    doc_setting(d, "run_dir", cfg_global.run_dir, NULL);
    doc_setting(d, "cgroup_root", cfg_global.cgroup_root, NULL);
    doc_setting(d, "cgroup_base", cfg_global.cgroup_base, NULL);
    doc_setting(d, "bridge", cfg_global.bridge, NULL);
    doc_setting(d, "subnet", cfg_global.subnet, NULL);
    doc_setting(d, "gw", cfg_global.gw, NULL);
    doc_flag(d, "firewall", cfg_global.firewall, "true", "false (lightbox makes no firewall rules)");
    doc_flag(d, "ip_forward", cfg_global.ip_forward, "true", "false");
    doc_flag(d, "ip_forward_no_drop", cfg_global.ip_forward_no_drop, "true", "false");
    doc_flag(d, "ip_masq", cfg_global.ip_masq, "true", "false");
    doc_setting(d, "firewall_backend", nftables ? "nftables" : "iptables", NULL);
    if (cfg_global.accept_fwmark_set) {
        char mark[24], text[96];
        fwmark_text(mark, cfg_global.accept_fwmark, cfg_global.accept_fwmask);
        bool cut = false;
        str_append(text, str_append(text, 0, mark, sizeof(text), &cut),
                   nftables ? "" : " (not used: with iptables, rules in LIGHTBOX-USER decide first)", sizeof(text), &cut);
        doc_setting(d, "bridge_accept_fwmark", text, NULL);
    } else {
        doc_setting(d, "bridge_accept_fwmark", "none", "null");
    }
    /* told, not counted as missing: only a container with links depends on it */
    if (nftables)
        doc_setting(d, "bridge_filtering", "not needed (firewall_backend = nftables filters at the bridge)", NULL);
    else
        doc_setting(d, "bridge_filtering", bridge_traffic_is_filtered()
                    ? "yes" : "no (a container with --link will not start; it needs br_netfilter)", NULL);
    if (nftables && cfg_global.firewall) {
        /* told, not counted: it is the host's to change */
        static char drops[1024];
        if (lb_sys_geteuid() != 0) {
            doc_setting(d, "forward_drops", "unknown (doctor is not run as root)", NULL);
        } else {
            forward_drops_on_host(drops, sizeof(drops));
            doc_setting(d, "forward_drops", drops[0] ? drops : "none", NULL);
        }
    }
    /* told, not counted: without it a new container is a copy of its base */
    {
        enum overlayfs_kind kind = overlayfs_here();
        bool overlay = kind == OVERLAYFS_LISTED || kind == OVERLAYFS_MODULE;
        doc_setting(d, "overlayfs", kind == OVERLAYFS_LISTED ? "yes"
                                    : kind == OVERLAYFS_MODULE ? "yes (a module, which the first overlay mounted loads)"
                                    : "no (a new container is a copy of its base, not an overlay)",
                    overlay ? "true" : "false");
    }
    /* told, not counted: only a container created with --userns needs one */
    {
        int ranges = userns_range_count();
        char text[200], digits[16];
        fmt_int(digits, ranges);
        bool cut = false;
        size_t pos = str_append(text, 0, ranges < 0 ? "unreadable" : digits, sizeof(text), &cut);
        str_append(text, pos, ranges < 0 ? " (" SUBUID_FILE " or " SUBGID_FILE " has a line of " USERNS_OWNER "'s that is no range)"
                              : ranges == 0 ? " (create --userns needs a line such as " USERNS_OWNER ":2147483647:2147483648 in "
                                              SUBUID_FILE " and in " SUBGID_FILE ")"
                              : " (ranges of 65536 ids; a container created with --userns takes one)",
                   sizeof(text), &cut);
        doc_setting(d, "userns_ranges", text, ranges < 0 ? "null" : digits);
    }
    /* told, not counted: start makes what is missing, as setup does */
    {
        const char *missing = host_network_missing();
        char text[160];
        bool cut = false;
        if (missing)
            str_append(text, str_append(text, str_append(text, 0, "not all there (missing: ", sizeof(text), &cut),
                                        missing, sizeof(text), &cut),
                       "; start makes it, as lightbox setup does)", sizeof(text), &cut);
        else if (host_forwarding_left_off())
            /* lightbox's part is there; what it leaves to the host is told */
            str_append(text, 0, "ready (IPv4 forwarding is off, and with firewall = false it is this host's to turn on: "
                                "containers reach this host and nothing beyond it)", sizeof(text), &cut);
        doc_setting(d, "host_network", missing || host_forwarding_left_off() ? text : "ready", NULL);
    }

    doc_begin_checks(d);
    check_root(d);
    check_kernel(d);
    check_syscalls(d);
    /* the two as one network: what setup, create and start go by */
    container_network net;
    const char *wrong;
    {
        const char *setting;
        wrong = container_network_parse(cfg_global.subnet, cfg_global.gw, &net, &setting);
        char text[128], subnet[CIDR_TEXT_MAX];
        if (wrong) {
            char detail[96];
            bool cut = false;
            str_append(detail, str_append(detail, str_append(detail, 0, setting, sizeof(detail), &cut),
                                          " ", sizeof(detail), &cut), wrong, sizeof(detail), &cut);
            doc_check(d, "network", false, worded(text, sizeof(text), "unusable", detail),
                      "set subnet to <address>/<8 to 30> and gw to an address in it in lightbox.conf");
        } else {
            subnet_text(subnet, &net);
            doc_check(d, "network", true, subnet, NULL);
        }
    }
    check_cgroups(d);
    check_device_filter(d);
    if (!wrong)                     /* the rules are of the network; one that is unusable has none */
        check_firewall_kernel(d, &net);
    if (nftables && cfg_global.firewall && cfg_global.ip_forward) {
        char forwarding[8];
        bool on = read_file("/proc/sys/net/ipv4/ip_forward", forwarding, sizeof(forwarding)) > 0 && forwarding[0] == '1';
        doc_yes_no(d, "ip_forwarding", on,
                   on ? "on" : "off, and with firewall_backend = nftables lightbox does not turn it on",
                   "sysctl -w net.ipv4.ip_forward=1, with rules of this host's against forwarding between its other "
                   "interfaces; or ip_forward = false in lightbox.conf");
    }

    doc_file(d, "path.lightbox_dir", path_exists(cfg_global.lightbox_dir), cfg_global.lightbox_dir,
             "lightbox setup makes it");
    check_rootfs(d);
    doc_file(d, "path.container_dir", path_exists(cfg_global.container_dir), cfg_global.container_dir,
             "lightbox setup makes it");
    doc_file(d, "path.cgroup_root", path_exists(cfg_global.cgroup_root), cfg_global.cgroup_root,
             "lightbox setup mounts cgroup2 at an empty directory there");
    doc_file(d, "path.proc_ip_forward", path_exists("/proc/sys/net/ipv4/ip_forward"), "/proc/sys/net/ipv4/ip_forward",
             "mount /proc: mount -t proc proc /proc");

    for (size_t i = 0; i < sizeof(bins) / sizeof(bins[0]); i++) {
        if (nftables ? !bins[i].nftables : !bins[i].iptables)
            continue;
        const char *path = bins[i].resolve();
        doc_file(d, bins[i].key, path_executable(path), path, bins[i].fix);
    }

    check_exec_sealing(d);
    if (agent)
        check_agent(d);

    if (d->json) {
        print_str(STDOUT, "],\"overall\":");
        json_string(d->failed == 0 ? "ok" : "degraded");
        print_str(STDOUT, "}\n");
    } else {
        print_kv("overall", d->failed == 0 ? "ok" : "degraded");
    }
    if (d->failed != 0)
        lc_kernel_exit(failure_status);
}
