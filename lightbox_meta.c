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
    for (int i = 0; i < argc; i++)
        if (streq(argv[i], "--json")) json = true;

    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    bool more = false;
    int count = list_containers(names, MAX_LISTED, &more);

    if (!json) {
        print_padded("NAME", 20);
        print_padded("IP", 16);
        print_padded("STATUS", 10);
        print_str(STDOUT, "PID\n");
        print_padded("----", 20);
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
            print_padded(name, 20);
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

static void print_conf_kv(const char *name, const char *key, const char *fallback) {
    char buf[128];
    conf_get(name, key, buf, sizeof(buf), fallback);
    print_kv(key, buf);
}

void cmd_inspect(int argc, char **argv) {
    if (argc < 1) die("Usage: lightbox inspect <name>");
    const char *name = argv[0];
    validate_name(name);

    char cdir[MAX_PATH], root[MAX_PATH], conf_path[MAX_PATH], ip_path[MAX_PATH];
    char pid_path[MAX_PATH], pid_start_path[MAX_PATH], state_path[MAX_PATH], state[32], ip[16], pid_start[32];
    container_dir_path(cdir, name);
    if (!path_exists(cdir)) die2("Error: container does not exist: ", name);

    container_root(root, name);
    container_conf_path(conf_path, name);
    container_ip_path(ip_path, name);
    container_pid_path(pid_path, name);
    container_pid_start_path(pid_start_path, name);
    container_state_path(state_path, name);

    if (read_container_ip(name, ip, sizeof(ip)) < 0)
        str_copy(ip, "-", sizeof(ip));
    container_liveness live = container_probe(name);
    container_shown_state(name, live, state, sizeof(state));

    print_kv("name", name);
    print_kv("state", state);
    print_kv("running", live == CONTAINER_RUNNING ? "yes" : "no");
    print_kv("ip", ip);
    print_kv("dir", cdir);
    print_kv("rootfs", root);
    print_kv("config_path", conf_path);
    print_kv("ip_path", ip_path);
    print_kv("pid_path", pid_path);
    print_kv("pid_start_path", pid_start_path);
    print_kv("state_path", state_path);

    if (path_exists(pid_path))
        print_kv_int("pid", get_container_pid(name));
    else
        print_kv("pid", "-");
    if (get_container_pid_starttime(name, pid_start, sizeof(pid_start)) == 0)
        print_kv("pid_starttime", pid_start);
    else
        print_kv("pid_starttime", "-");

    print_conf_kv(name, "mem", cfg_global.default_mem);
    print_conf_kv(name, "pids", cfg_global.default_pids);
    print_conf_kv(name, "cpu", cfg_global.default_cpu);
    print_kv_int("oom_score", conf_get_int(name, "oom_score", cfg_global.default_oom));
    print_kv_int("userns", conf_get_int(name, "userns", 0));
    print_kv_int("uid_start", conf_get_int(name, "uid_start", 0));
    print_kv_int("privileged", conf_get_int(name, "privileged", 0));
    print_kv_int("readonly", conf_get_int(name, "readonly", 0));
}

void cmd_doctor(void) {
    static const struct {
        const char *key;
        const char *(*resolve)(void);
    } bins[] = {
        { "bin.ip", tool_path_ip },
        { "bin.iptables", tool_path_iptables },
        { "bin.mount", tool_path_mount },
        { "bin.umount", tool_path_umount },
        { "bin.mkdir", tool_path_mkdir },
        { "bin.cp", tool_path_cp },
        { "bin.chown", tool_path_chown },
        { "bin.rm", tool_path_rm },
    };

    int missing = 0;
    bool ok;

    print_kv("lightbox_dir", cfg_global.lightbox_dir);
    print_kv("rootfs", cfg_global.rootfs);
    print_kv("container_dir", cfg_global.container_dir);
    print_kv("cgroup_root", cfg_global.cgroup_root);
    print_kv("cgroup_base", cfg_global.cgroup_base);
    print_kv("bridge", cfg_global.bridge);
    print_kv("subnet", cfg_global.subnet);
    print_kv("gw", cfg_global.gw);

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
        const char *path = bins[i].resolve();
        ok = path_exists(path);
        print_check(bins[i].key, ok, path);
        if (!ok) missing++;
    }

    print_kv("overall", missing == 0 ? "ok" : "degraded");
    if (missing != 0)
        lc_kernel_exit(1);
}
