#include "lightbox.h"

/* The most of lightbox.conf that is read. A file that is longer is refused:
 * read in part, its last settings would silently not count. */
#define CONF_BUF_SIZE 16384

/*
 * The longest a directory setting may be. Every path lightbox builds below
 * one of them adds a container's name and a file name of its own, and all of
 * them have to fit MAX_PATH; the longest addition is well below this margin.
 */
#define DIR_SETTING_MAX      (MAX_PATH - 64)
#define DIR_SETTING_MAX_TEXT 448
_Static_assert(DIR_SETTING_MAX == DIR_SETTING_MAX_TEXT, "the message names the limit");

const char *env_get(char **envp, const char *name) {
    if (!envp) return NULL;
    size_t nlen = lc_string_length(name);
    for (int i = 0; envp[i]; i++) {
        if (lc_string_starts_with(envp[i], lc_string_length(envp[i]), name, nlen)
            && envp[i][nlen] == '=')
            return envp[i] + nlen + 1;
    }
    return NULL;
}

void cfg_global_init(void) {
    static const struct { char *setting; size_t max; const char *value; } built_in[] = {
        { cfg_global.lightbox_dir,  MAX_PATH, "/var/lib/lightbox" },
        { cfg_global.rootfs,        MAX_PATH, "/var/lib/lightbox/rootfs" },
        { cfg_global.container_dir, MAX_PATH, "/var/lib/lightbox/containers" },
        { cfg_global.run_dir,       MAX_PATH, "/run/lightbox" },
        { cfg_global.cgroup_root,   MAX_PATH, "/sys/fs/cgroup" },
        { cfg_global.cgroup_base,   MAX_PATH, "/sys/fs/cgroup/lightbox" },
        { cfg_global.bridge,        sizeof(cfg_global.bridge),       "br0" },
        { cfg_global.subnet,        sizeof(cfg_global.subnet),       "10.0.0.0/24" },
        { cfg_global.gw,            sizeof(cfg_global.gw),           "10.0.0.1" },
        { cfg_global.default_mem,   sizeof(cfg_global.default_mem),  "256M" },
        { cfg_global.default_pids,  sizeof(cfg_global.default_pids), "128" },
        { cfg_global.default_cpu,   sizeof(cfg_global.default_cpu),  "1" },
        /* what a box of --profile agent needs to build and test with: a
         * compiler, Node or Python and git, for a working day at most */
        { cfg_global.agent_mem,     sizeof(cfg_global.agent_mem),    "2G" },
        { cfg_global.agent_pids,    sizeof(cfg_global.agent_pids),   "512" },
        { cfg_global.agent_cpu,     sizeof(cfg_global.agent_cpu),    "2" },
        { cfg_global.agent_ttl,     sizeof(cfg_global.agent_ttl),    "8h" },
    };
    for (size_t i = 0; i < sizeof(built_in) / sizeof(built_in[0]); i++)
        str_copy_or_die(built_in[i].setting, built_in[i].value, built_in[i].max, "a built-in setting");
    cfg_global.default_oom = 500;
    cfg_global.default_oom_ok = true;
    cfg_global.agent_ttl_ok = true;
    cfg_global.start_timeout = START_TIMEOUT_DEFAULT;
    cfg_global.stop_timeout = STOP_TIMEOUT_DEFAULT;
    cfg_global.dns[0] = '\0';
    cfg_global.firewall = true;
    cfg_global.ip_forward = true;
    cfg_global.ip_forward_no_drop = false;
    cfg_global.ip_masq = true;
    cfg_global.firewall_backend = FIREWALL_IPTABLES;
    cfg_global.accept_fwmark_set = false;
    cfg_global.accept_fwmark = 0;
    cfg_global.accept_fwmask = 0;
}

/* true or false. Anything else is said, and the built-in value kept: a
 * firewall setting that is wrong does not get to open the firewall. */
static void cfg_set_flag(const char *key, const char *val, bool *setting) {
    if (streq(val, "true") || streq(val, "false")) {
        *setting = val[0] == 't';
        return;
    }
    print_str(STDERR, "Warning: ");
    print_str(STDERR, key);
    print_str(STDERR, " in lightbox.conf is not true or false: ");
    print_str(STDERR, val);
    print_str(STDERR, *setting ? "; using true\n" : "; using false\n");
}

/* A setting in seconds. One that cannot be read must not stop every command,
 * stop among them: say so and keep what the setting was. */
static void cfg_set_seconds(const char *key, const char *val, int *setting) {
    int seconds;
    if (parse_seconds(val, &seconds)) {
        *setting = seconds;
        return;
    }
    char kept[16];
    fmt_int(kept, *setting);
    print_str(STDERR, "Warning: ");
    print_str(STDERR, key);
    print_str(STDERR, " in lightbox.conf is not a number of seconds from 0 to " STRINGIFY(SECONDS_MAX) ": ");
    print_str(STDERR, val);
    print_str(STDERR, "; using ");
    print_str(STDERR, kept);
    print_str(STDERR, "\n");
}

/*
 * A setting that is kept as text. One that does not fit ends the command:
 * there is nothing to fall back on for a directory or a bridge, and the
 * first part of its name is the name of something else.
 */
static void cfg_set_text(const char *key, const char *val, char *setting, size_t max) {
    if (str_copy(setting, val, max))
        return;
    print_str(STDERR, "Error: ");
    print_str(STDERR, key);
    print_str(STDERR, " in lightbox.conf is too long: ");
    print_str(STDERR, val);
    print_str(STDERR, "\n");
    lc_kernel_exit(failure_status);
}

/*
 * A default for the limits of new containers. One that is not a limit must
 * not stop every command either, and it must not be replaced by a limit
 * nobody chose: it is said here, once, and left empty, and a container that
 * would have needed it is refused.
 */
static void cfg_set_default(const char *key, const char *val, char *setting, size_t max,
                            bool usable, const char *what) {
    if (usable && str_copy(setting, val, max))
        return;
    setting[0] = '\0';
    print_str(STDERR, "Warning: ");
    print_str(STDERR, key);
    print_str(STDERR, " in lightbox.conf is not ");
    print_str(STDERR, what);
    print_str(STDERR, ": ");
    print_str(STDERR, val);
    print_str(STDERR, "; a container that needs it will be refused\n");
}

static bool cfg_set(const char *key, const char *val, bool derived[3]) {
    int number;
    if (streq(key, "lightbox_dir")) {
        cfg_set_text(key, val, cfg_global.lightbox_dir, MAX_PATH);
        if (!derived[0]) path_join_or_die(cfg_global.rootfs, MAX_PATH, val, "rootfs");
        if (!derived[1]) path_join_or_die(cfg_global.container_dir, MAX_PATH, val, "containers");
    } else if (streq(key, "rootfs")) {
        cfg_set_text(key, val, cfg_global.rootfs, MAX_PATH);
        derived[0] = true;
    } else if (streq(key, "container_dir")) {
        cfg_set_text(key, val, cfg_global.container_dir, MAX_PATH);
        derived[1] = true;
    } else if (streq(key, "run_dir")) {
        cfg_set_text(key, val, cfg_global.run_dir, MAX_PATH);
    } else if (streq(key, "cgroup_root")) {
        cfg_set_text(key, val, cfg_global.cgroup_root, MAX_PATH);
    } else if (streq(key, "cgroup_base")) {
        cfg_set_text(key, val, cfg_global.cgroup_base, MAX_PATH);
        derived[2] = true;
    } else if (streq(key, "bridge")) {
        cfg_set_text(key, val, cfg_global.bridge, sizeof(cfg_global.bridge));
    } else if (streq(key, "subnet")) {
        cfg_set_text(key, val, cfg_global.subnet, sizeof(cfg_global.subnet));
    } else if (streq(key, "gw")) {
        cfg_set_text(key, val, cfg_global.gw, sizeof(cfg_global.gw));
    } else if (streq(key, "default_mem")) {
        cfg_set_default(key, val, cfg_global.default_mem, sizeof(cfg_global.default_mem),
                        mem_limit_ok(val), "<number>[K|M|G|T] or max");
    } else if (streq(key, "default_pids")) {
        cfg_set_default(key, val, cfg_global.default_pids, sizeof(cfg_global.default_pids),
                        pids_limit_ok(val), "a number from 1 to " STRINGIFY(PIDS_LIMIT_MAX) " or max");
    } else if (streq(key, "default_cpu")) {
        cfg_set_default(key, val, cfg_global.default_cpu, sizeof(cfg_global.default_cpu),
                        parse_cpu_limit(val, &number),
                        "a number of CPUs from 0.01 to " STRINGIFY(CPU_LIMIT_MAX));
    } else if (streq(key, "agent_mem")) {
        cfg_set_default(key, val, cfg_global.agent_mem, sizeof(cfg_global.agent_mem),
                        mem_limit_ok(val), "<number>[K|M|G|T] or max");
    } else if (streq(key, "agent_pids")) {
        cfg_set_default(key, val, cfg_global.agent_pids, sizeof(cfg_global.agent_pids),
                        pids_limit_ok(val), "a number from 1 to " STRINGIFY(PIDS_LIMIT_MAX) " or max");
    } else if (streq(key, "agent_cpu")) {
        cfg_set_default(key, val, cfg_global.agent_cpu, sizeof(cfg_global.agent_cpu),
                        parse_cpu_limit(val, &number),
                        "a number of CPUs from 0.01 to " STRINGIFY(CPU_LIMIT_MAX));
    } else if (streq(key, "agent_ttl")) {
        int64_t ms;
        cfg_set_default(key, val, cfg_global.agent_ttl, sizeof(cfg_global.agent_ttl),
                        streq(val, "none") || parse_duration_ms(val, &ms),
                        "a duration from 1 ms to 365 days, such as 8h, or none");
        cfg_global.agent_ttl_ok = cfg_global.agent_ttl[0] != '\0';
    } else if (streq(key, "default_oom")) {
        char unused[2];
        cfg_global.default_oom_ok = parse_oom_score(val, &cfg_global.default_oom);
        if (!cfg_global.default_oom_ok)
            cfg_set_default(key, val, unused, sizeof(unused), false, "a number from -1000 to 1000");
    } else if (streq(key, "start_timeout")) {
        cfg_set_seconds(key, val, &cfg_global.start_timeout);
    } else if (streq(key, "stop_timeout")) {
        cfg_set_seconds(key, val, &cfg_global.stop_timeout);
    } else if (streq(key, "firewall")) {
        cfg_set_flag(key, val, &cfg_global.firewall);
    } else if (streq(key, "ip_forward")) {
        cfg_set_flag(key, val, &cfg_global.ip_forward);
    } else if (streq(key, "ip_forward_no_drop")) {
        cfg_set_flag(key, val, &cfg_global.ip_forward_no_drop);
    } else if (streq(key, "ip_masq")) {
        cfg_set_flag(key, val, &cfg_global.ip_masq);
    } else if (streq(key, "firewall_backend")) {
        if (streq(val, "iptables") || streq(val, "nftables")) {
            cfg_global.firewall_backend = val[0] == 'n' ? FIREWALL_NFTABLES : FIREWALL_IPTABLES;
        } else {
            print_str(STDERR, "Warning: firewall_backend in lightbox.conf is not iptables or nftables: ");
            print_str(STDERR, val);
            print_str(STDERR, cfg_global.firewall_backend == FIREWALL_NFTABLES ? "; using nftables\n" : "; using iptables\n");
        }
    } else if (streq(key, "bridge_accept_fwmark")) {
        uint32_t mark, mask;
        if (parse_fwmark(val, &mark, &mask)) {
            cfg_global.accept_fwmark_set = true;
            cfg_global.accept_fwmark = mark;
            cfg_global.accept_fwmask = mask;
        } else {
            /* a mark that is wrong accepts nothing it was not meant to */
            print_str(STDERR, "Warning: bridge_accept_fwmark in lightbox.conf is not a mark, or a mark and a mask,\n"
                              "that a packet can carry: ");
            print_str(STDERR, val);
            if (cfg_global.accept_fwmark_set) {
                char kept[24];
                fwmark_text(kept, cfg_global.accept_fwmark, cfg_global.accept_fwmask);
                print_str(STDERR, "; using ");
                print_str(STDERR, kept);
                lc_print_char(STDERR, '\n');
            } else {
                print_str(STDERR, "; using none\n");
            }
        }
    } else if (streq(key, "dns")) {
        /* create reads it, and says so if it is not a list of addresses */
        cfg_set_text(key, val, cfg_global.dns, sizeof(cfg_global.dns));
    } else {
        return false;
    }
    return true;
}

/* Every directory short enough that the paths built below it fit. */
static void require_short_directories(void) {
    static const struct { const char *key; const char *value; } dirs[] = {
        { "lightbox_dir", cfg_global.lightbox_dir }, { "rootfs", cfg_global.rootfs },
        { "container_dir", cfg_global.container_dir }, { "run_dir", cfg_global.run_dir },
        { "cgroup_root", cfg_global.cgroup_root }, { "cgroup_base", cfg_global.cgroup_base },
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        if (lc_string_length(dirs[i].value) <= DIR_SETTING_MAX)
            continue;
        print_str(STDERR, "Error: ");
        print_str(STDERR, dirs[i].key);
        print_str(STDERR, " is longer than the " STRINGIFY(DIR_SETTING_MAX_TEXT)
                          " characters a directory setting may have: ");
        print_str(STDERR, dirs[i].value);
        print_str(STDERR, "\n");
        lc_kernel_exit(failure_status);
    }
}

static void cfg_warn_line(const char *path, int line, const char *what, const char *text) {
    char number[16];
    fmt_int(number, line);
    print_str(STDERR, "Warning: ");
    print_str(STDERR, path);
    print_str(STDERR, ": line ");
    print_str(STDERR, number);
    print_str(STDERR, ": ");
    print_str(STDERR, what);
    print_str(STDERR, text);
    lc_print_char(STDERR, '\n');
}

/*
 * The settings of a lightbox.conf, line by line: "<key> = <value>", blank
 * lines and lines that begin with #. A carriage return at the end of a line
 * is no part of it, and a # after a space or a tab begins a comment. A line
 * that is not a setting, and a key lightbox does not know, are said with
 * the line they are on, and change nothing. A file that is not there is no
 * error unless it was named.
 */
static void cfg_read_file(const char *conf_path, bool named, bool derived[3]) {
    static char buf[CONF_BUF_SIZE];
    int n = read_file(conf_path, buf, sizeof(buf));
    if (n < 0) {
        if (named)
            die2("Error: cannot read the configuration: ", conf_path);
        print_str(STDERR, "Warning: cannot read ");
        print_str(STDERR, conf_path);
        print_str(STDERR, "; the built-in settings are used\n");
        return;
    }
    if (n >= CONF_BUF_SIZE - 1)
        die2("Error: the configuration is larger than lightbox reads: ", conf_path);

    int line = 0;
    for (char *p = buf; *p; ) {
        line++;
        char *end = p;
        while (*end && *end != '\n') end++;
        char *next = *end ? end + 1 : end;
        while (end > p && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) end--;
        *end = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') {
            p = next;
            continue;
        }

        char *eq = p;
        while (*eq && *eq != '=') eq++;
        if (!*eq) {
            cfg_warn_line(conf_path, line, "not a setting, which is <key> = <value>: ", p);
            p = next;
            continue;
        }

        /* a key too long to be one lightbox knows is one it does not know */
        char key[64];
        size_t klen = (size_t)(eq - p);
        while (klen > 0 && (p[klen - 1] == ' ' || p[klen - 1] == '\t')) klen--;
        bool long_key = klen >= sizeof(key);
        if (long_key)
            klen = sizeof(key) - 4;
        lc_bytes_copy(key, p, klen);
        if (long_key) {
            lc_bytes_copy(key + klen, "...", 3);
            klen += 3;
        }
        key[klen] = '\0';

        char *vs = eq + 1;
        while (*vs == ' ' || *vs == '\t') vs++;
        char *ve = vs;
        while (*ve && !(*ve == '#' && (ve == eq + 1 || ve[-1] == ' ' || ve[-1] == '\t'))) ve++;
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;

        /* no setting takes a value this long, and none is cut to fit */
        char val[MAX_PATH];
        size_t vlen = (size_t)(ve - vs);
        if (vlen >= sizeof(val))
            die2("Error: lightbox.conf has a value that is too long, for ", key);
        lc_bytes_copy(val, vs, vlen);
        val[vlen] = '\0';

        if (long_key || !cfg_set(key, val, derived))
            cfg_warn_line(conf_path, line, "a key lightbox does not know: ", key);
        p = next;
    }
}

config_source config_source_of(const char *given, const char *from_env, bool etc_there, bool home_there) {
    if (given)
        return CONFIG_GIVEN;
    if (from_env && from_env[0])
        return CONFIG_ENV;
    if (etc_there)
        return CONFIG_ETC;
    return home_there ? CONFIG_HOME : CONFIG_NONE;
}

/*
 * The settings: what is built in, then what lightbox.conf says, then what
 * the environment says. The last two steps do not depend on each other:
 * LIGHTBOX_ROOTFS counts whether there is a lightbox.conf or not.
 */
void cfg_global_load(char **envp, const char *given) {
    const char *home = env_get(envp, "HOME");
    if (!home) home = "/root";

    /* --config, then $LIGHTBOX_CONFIG, then /etc. Where lightbox looked before
     * 0.6, in $HOME, it does not read: a command that runs as root takes no
     * settings from a home directory. A file that is there, and that nothing
     * stands in for, ends the command: going on with the built-in values in
     * its place would be another host network and other directories than the
     * file says. Beside a file in /etc it is only said to be left. A home so
     * long that the path does not fit has no file there. */
    char home_conf[MAX_PATH];
    bool home_there = path_join(home_conf, MAX_PATH, home, CONFIG_HOME_FILE) && path_exists(home_conf);
    const char *from_env = env_get(envp, "LIGHTBOX_CONFIG");
    config_source source = config_source_of(given, from_env, path_exists(CONFIG_ETC_FILE), home_there);
    const char *path = source == CONFIG_GIVEN ? given : source == CONFIG_ENV ? from_env
                     : source == CONFIG_ETC ? CONFIG_ETC_FILE : NULL;
    if (source == CONFIG_HOME) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, home_conf);
        print_str(STDERR, " is where lightbox looked for its settings before 0.6, and it is\n"
                          "not read. Move it to " CONFIG_ETC_FILE ", or name it with --config or LIGHTBOX_CONFIG\n");
        lc_kernel_exit(failure_status);
    } else if (source == CONFIG_ETC && home_there) {
        print_str(STDERR, "Note: ");
        print_str(STDERR, home_conf);
        print_str(STDERR, " is not read; " CONFIG_ETC_FILE " is\n");
    }

    bool derived[3] = { false, false, false };
    if (path)
        cfg_read_file(path, source == CONFIG_GIVEN || source == CONFIG_ENV, derived);

    if (!derived[2])
        path_join_or_die(cfg_global.cgroup_base, MAX_PATH, cfg_global.cgroup_root, "lightbox");

    const char *env_rootfs = env_get(envp, "LIGHTBOX_ROOTFS");
    if (env_rootfs && env_rootfs[0])
        str_copy_or_die(cfg_global.rootfs, env_rootfs, DIR_SETTING_MAX + 1, "LIGHTBOX_ROOTFS");

    require_short_directories();
}
