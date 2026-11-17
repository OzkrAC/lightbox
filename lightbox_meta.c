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

static void print_check(const char *key, bool ok, const char *detail) {
    print_str(STDOUT, key);
    print_str(STDOUT, ": ");
    print_str(STDOUT, ok ? "ok" : "missing");
    if (detail && detail[0]) {
        print_str(STDOUT, " (");
        print_str(STDOUT, detail);
        print_str(STDOUT, ")");
    }
    lc_print_char(STDOUT, '\n');
}

/*
 * logs <name> [-f]: what the container's init, its hook and its services
 * wrote to stdout and stderr, from every start since the container was made.
 * With -f it goes on for as long as the container runs.
 */
void cmd_logs(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox logs <name> [-f]");
    const char *name = argv[0];
    validate_name(name);

    bool follow = false;
    for (int i = 1; i < argc; i++) {
        if (streq(argv[i], "-f") || streq(argv[i], "--follow"))
            follow = true;
        else
            die2(argv[i][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[i]);
    }

    char path[MAX_PATH];
    container_dir_path(path, name);
    if (!path_exists(path)) die2("Error: container does not exist: ", name);
    container_log_path(path, name);

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
            print_str(STDERR, "Error: cannot read the log of container '");
            print_str(STDERR, name);
            print_str(STDERR, "' (errno ");
            print_str(STDERR, digits);
            print_str(STDERR, ")\n");
            lc_kernel_exit(1);
        }

        /* a container that was never started has no log, which is an empty one */
        bool got_some = false;
        while (fd >= 0) {
            char buf[4096];
            lc_sysret n = lc_kernel_read_retry((int32_t)fd, buf, sizeof(buf));
            if (n < 0)
                die("Error: reading the log failed");
            if (n == 0)
                break;
            if (lc_kernel_write_all(STDOUT, buf, (size_t)n) < 0)
                lc_kernel_exit(1);          /* nobody reads this any more */
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
        report_number(&r, "oom_score", config.oom_score);
        report_flag(&r, "userns", config.userns, "1", "0");
        report_number(&r, "uid_start", config.uid_start);
        report_flag(&r, "privileged", config.privileged, "1", "0");
        report_flag(&r, "readonly", config.read_only, "1", "0");
        report_volumes(&r, &config);
        report_links(&r, &config);
    }
    if (json)
        print_str(STDOUT, "}]\n");
    if (wrong)
        die2("Error: the container's configuration cannot be used: ", wrong);
}

/* doctor: can exec run from a copy of the binary that cannot be written to? */
static bool report_exec_sealing(void) {
    switch (exec_seal_method()) {
        case SEAL_MEMFD:
            print_kv("exec_sealing", "yes (a sealed copy in memory)");
            return true;
        case SEAL_READONLY:
            print_kv("exec_sealing", "yes (a read-only mount of the binary; executable memfds are refused here)");
            return true;
        case SEAL_NONE:
        default:
            print_kv("exec_sealing", "no (exec will not run: it needs memfd_create, or root and Linux 5.12)");
            return false;
    }
}

void cmd_doctor(void) {
    static const struct {
        const char *key;
        const char *(*resolve)(void);
        bool nftables;      /* the firewall tools of one backend: the other's are not looked for */
        bool iptables;
    } bins[] = {
        { "bin.ip", tool_path_ip, true, true },
        { "bin.iptables", tool_path_iptables, false, true },
        { "bin.iptables-restore", tool_path_iptables_restore, false, true },
        { "bin.nft", tool_path_nft, true, false },
        { "bin.cp", tool_path_cp, true, true },
        { "bin.chown", tool_path_chown, true, true },
        { "bin.rm", tool_path_rm, true, true },
    };
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;

    int missing = 0;
    bool ok;

    print_kv("lightbox_dir", cfg_global.lightbox_dir);
    print_kv("rootfs", cfg_global.rootfs);
    print_kv("container_dir", cfg_global.container_dir);
    print_kv("run_dir", cfg_global.run_dir);
    print_kv("cgroup_root", cfg_global.cgroup_root);
    print_kv("cgroup_base", cfg_global.cgroup_base);
    print_kv("bridge", cfg_global.bridge);
    print_kv("subnet", cfg_global.subnet);
    print_kv("gw", cfg_global.gw);
    {
        /* the two as one network: what setup, create and start go by */
        container_network net;
        const char *setting;
        const char *wrong = container_network_parse(cfg_global.subnet, cfg_global.gw, &net, &setting);
        if (wrong) {
            print_str(STDOUT, "network: unusable (");
            print_str(STDOUT, setting);
            print_str(STDOUT, " ");
            print_str(STDOUT, wrong);
            print_str(STDOUT, ")\n");
            missing++;
        } else {
            char subnet[CIDR_TEXT_MAX];
            subnet_text(subnet, &net);
            print_kv("network", subnet);
        }
    }
    print_kv("firewall", cfg_global.firewall ? "true" : "false (lightbox makes no firewall rules)");
    print_kv("ip_forward", cfg_global.ip_forward ? "true" : "false");
    print_kv("ip_forward_no_drop", cfg_global.ip_forward_no_drop ? "true" : "false");
    print_kv("ip_masq", cfg_global.ip_masq ? "true" : "false");
    print_kv("firewall_backend", nftables ? "nftables" : "iptables");
    if (cfg_global.accept_fwmark_set) {
        char mark[24];
        fwmark_text(mark, cfg_global.accept_fwmark, cfg_global.accept_fwmask);
        print_str(STDOUT, "bridge_accept_fwmark: ");
        print_str(STDOUT, mark);
        print_str(STDOUT, nftables ? "\n" : " (not used: with iptables, rules in LIGHTBOX-USER decide first)\n");
    } else {
        print_kv("bridge_accept_fwmark", "none");
    }
    /* told, not counted as missing: only a container with links depends on it */
    if (nftables)
        print_kv("bridge_filtering", "not needed (firewall_backend = nftables filters at the bridge)");
    else
        print_kv("bridge_filtering", bridge_traffic_is_filtered()
                 ? "yes" : "no (a container with --link will not start; it needs br_netfilter)");
    if (nftables && cfg_global.firewall) {
        /* told, not counted: it is the host's to change */
        static char drops[1024];
        if (lb_sys_geteuid() != 0) {
            print_kv("forward_drops", "unknown (doctor is not run as root)");
        } else {
            forward_drops_on_host(drops, sizeof(drops));
            print_kv("forward_drops", drops[0] ? drops : "none");
        }
    }

    ok = path_exists(cfg_global.lightbox_dir);
    print_check("path.lightbox_dir", ok, cfg_global.lightbox_dir);
    if (!ok) missing++;
    ok = path_exists(cfg_global.rootfs);
    print_check("path.rootfs", ok, cfg_global.rootfs);
    if (!ok) missing++;
    ok = path_exists(cfg_global.container_dir);
    print_check("path.container_dir", ok, cfg_global.container_dir);
    if (!ok) missing++;
    ok = path_exists(cfg_global.cgroup_root);
    print_check("path.cgroup_root", ok, cfg_global.cgroup_root);
    if (!ok) missing++;
    ok = path_exists("/proc/sys/net/ipv4/ip_forward");
    print_check("path.proc_ip_forward", ok, "/proc/sys/net/ipv4/ip_forward");
    if (!ok) missing++;

    for (size_t i = 0; i < sizeof(bins) / sizeof(bins[0]); i++) {
        if (nftables ? !bins[i].nftables : !bins[i].iptables)
            continue;
        const char *path = bins[i].resolve();
        ok = path_exists(path);
        print_check(bins[i].key, ok, path);
        if (!ok) missing++;
    }

    if (!report_exec_sealing())
        missing++;

    print_kv("overall", missing == 0 ? "ok" : "degraded");
    if (missing != 0)
        lc_kernel_exit(1);
}
