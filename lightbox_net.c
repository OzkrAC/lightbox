#include "lightbox.h"

[[noreturn]] static void die_cmd(const char *prefix, const char *prog) {
    die2(prefix, prog);
}

static void require_cmd(const char *prog, char *const argv[]) {
    if (run_cmd(prog, argv) != 0)
        die_cmd("Error: command failed: ", prog);
}

static int iptables_check(char *const argv[]) {
    return run_cmd_quiet(tool_path_iptables(), argv);
}

static void iptables_idempotent(char **check_argv, char **add_argv) {
    if (iptables_check(check_argv) != 0)
        run_cmd(tool_path_iptables(), add_argv);
}

static int iptables_ensure_rule(char *const check_argv[], char *const add_argv[]) {
    if (iptables_check(check_argv) == 0)
        return 0;
    return run_cmd(tool_path_iptables(), add_argv);
}

static int iptables_remove_rule(char *const check_argv[], char *const del_argv[]) {
    if (iptables_check(check_argv) != 0)
        return 0;
    return run_cmd(tool_path_iptables(), del_argv);
}

int read_container_ip(const char *name, char *ip, size_t ipsz) {
    char ip_path[MAX_PATH];
    container_ip_path(ip_path, name);
    if (read_file(ip_path, ip, ipsz) <= 0) return -1;
    for (size_t i = 0; ip[i]; i++) {
        if (ip[i] == '\n') { ip[i] = '\0'; break; }
    }
    return 0;
}

int update_link_rules(const char *name, const char *ip, bool add_rules) {
    char conf_buf[CONF_MAX];
    if (container_conf_read(name, conf_buf) <= 0) return 0;

    char *p = conf_buf;
    while (*p) {
        if (p[0] == 'l' && p[1] == 'i' && p[2] == 'n' && p[3] == 'k' && p[4] == '=') {
            char link_name[NAME_MAX_LEN + 1];
            char *v = p + 5;
            char *end = v;
            while (*end && *end != '\n') end++;
            size_t ln = (size_t)(end - v);
            if (ln > NAME_MAX_LEN) ln = NAME_MAX_LEN;
            lc_bytes_copy(link_name, v, ln);
            link_name[ln] = '\0';

            char link_ip[16];
            if (read_container_ip(link_name, link_ip, sizeof(link_ip)) == 0) {
                char *c1[] = { "iptables", "-C", "FORWARD",
                               "-s", (char *)ip, "-d", link_ip,
                               "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                               "-j", "ACCEPT", NULL };
                char *m1[] = { "iptables", add_rules ? "-I" : "-D", "FORWARD",
                               "-s", (char *)ip, "-d", link_ip,
                               "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                               "-j", "ACCEPT", NULL };
                if ((add_rules ? iptables_ensure_rule(c1, m1) : iptables_remove_rule(c1, m1)) != 0)
                    return -1;

                char *c2[] = { "iptables", "-C", "FORWARD",
                               "-s", link_ip, "-d", (char *)ip,
                               "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                               "-j", "ACCEPT", NULL };
                char *m2[] = { "iptables", add_rules ? "-I" : "-D", "FORWARD",
                               "-s", link_ip, "-d", (char *)ip,
                               "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                               "-j", "ACCEPT", NULL };
                if ((add_rules ? iptables_ensure_rule(c2, m2) : iptables_remove_rule(c2, m2)) != 0)
                    return -1;
            }
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }

    return 0;
}

static void detect_wan_interface(char *wan_if, size_t bufsz) {
    char route_buf[256];
    int pipefd[2];
    lc_kernel_create_pipe(pipefd, 0);
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        lc_kernel_close_file(pipefd[0]);
        lc_kernel_duplicate_fd(pipefd[1], STDOUT, 0);
        lc_kernel_close_file(pipefd[1]);
        char *argv[] = { "ip", "route", "show", "default", NULL };
        char *envp[] = { "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL };
        lc_kernel_execute(tool_path_ip(), argv, envp);
        lc_kernel_exit(1);
    }
    lc_kernel_close_file(pipefd[1]);
    lc_sysret n = lc_kernel_read_bytes(pipefd[0], route_buf, sizeof(route_buf) - 1);
    lc_kernel_close_file(pipefd[0]);
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    if (n <= 0) die("Error: could not detect default network interface");
    route_buf[n] = '\0';

    const char *dev = NULL;
    for (char *p = route_buf; *p; p++) {
        if (p[0] == 'd' && p[1] == 'e' && p[2] == 'v' && p[3] == ' ') {
            dev = p + 4;
            break;
        }
    }
    if (!dev) die("Error: could not parse default route");
    size_t i = 0;
    while (dev[i] && dev[i] != ' ' && dev[i] != '\n' && i < bufsz - 1) {
        wan_if[i] = dev[i];
        i++;
    }
    wan_if[i] = '\0';
}

[[noreturn]] static void die_cgroup_root(const char *root, const char *reason) {
    print_str(STDERR, "Error: cgroup_root ");
    print_str(STDERR, root);
    print_str(STDERR, " is not a cgroup v2 hierarchy (");
    print_str(STDERR, reason);
    print_str(STDERR, ").\n"
        "lightbox needs cgroup v2. On a cgroup v1 or hybrid host, boot with\n"
        "cgroup_no_v1=all, or set cgroup_root to a cgroup2 mount or to an empty\n"
        "directory for lightbox to mount one on.\n");
    lc_kernel_exit(1);
}

/*
 * Make sure cgroup_root is a cgroup2 hierarchy without mounting blindly.
 *
 *   already cgroup2                         -> nothing to do
 *   missing, or an empty plain directory    -> mount cgroup2 there, checked
 *   anything else (v1, hybrid, other mount) -> stop with a message
 *
 * setup used to call mount unconditionally and ignore the result. That only
 * looked harmless because the call never reached mount(2); on a host where
 * cgroup_root is already cgroup2 it would add one more mount on every run.
 */
static void ensure_cgroup2_root(void) {
    const char *root = cfg_global.cgroup_root;
    struct lb_statfs sfs;

    lc_sysret rc = lb_sys_statfs(root, &sfs);
    if (rc == -LB_ENOENT) {
        if (lc_kernel_mkdirat(AT_FDCWD, root, 0755) < 0)
            die2("Error: cannot create cgroup_root: ", root);
        rc = lb_sys_statfs(root, &sfs);
    }
    if (rc < 0)
        die2("Error: cannot examine cgroup_root: ", root);

    if (sfs.f_type == LB_CGROUP2_SUPER_MAGIC)
        return;
    if (sfs.f_type == LB_CGROUP_SUPER_MAGIC)
        die_cgroup_root(root, "it is a cgroup v1 hierarchy");

    struct lb_statx stx;
    if (lb_sys_statx(AT_FDCWD, root, 0, LB_STATX_TYPE, &stx) < 0)
        die2("Error: cannot examine cgroup_root: ", root);
    if ((stx.stx_mode & LB_S_IFMT) != LB_S_IFDIR)
        die_cgroup_root(root, "it is not a directory");
    if (!(stx.stx_attributes_mask & LB_STATX_ATTR_MOUNT_ROOT))
        die_cgroup_root(root, "this kernel cannot tell whether it is a mount point; Linux 5.8 or later is needed");
    if (stx.stx_attributes & LB_STATX_ATTR_MOUNT_ROOT)
        die_cgroup_root(root, "another filesystem is mounted there");

    int empty = dir_is_empty(root);
    if (empty < 0)
        die2("Error: cannot read cgroup_root: ", root);
    if (empty == 0)
        die_cgroup_root(root, "it is a directory that is not empty");

    if (lb_sys_mount("none", root, "cgroup2", 0, NULL) < 0)
        die2("Error: failed to mount cgroup2 at ", root);
    print_str(STDOUT, "Mounted cgroup2 at ");
    print_str(STDOUT, root);
    lc_print_char(STDOUT, '\n');
}

/*
 * Create a storage directory for root alone, or restrict one that exists.
 * Installations made before this check have these directories at 0755.
 */
static void ensure_private_dir(const char *path) {
    lc_kernel_mkdirat(AT_FDCWD, path, MODE_PRIVATE_DIR);   /* it may exist */

    struct lb_statx stx;
    if (lb_sys_statx(AT_FDCWD, path, 0, LB_STATX_TYPE | LB_STATX_MODE, &stx) < 0 ||
        (stx.stx_mode & LB_S_IFMT) != LB_S_IFDIR)
        die2("Error: cannot create storage directory: ", path);
    if ((stx.stx_mode & 0777) == MODE_PRIVATE_DIR)
        return;

    if (lc_kernel_fchmodat(AT_FDCWD, path, MODE_PRIVATE_DIR, 0) < 0)
        die2("Error: cannot restrict storage directory to root: ", path);
    print_str(STDOUT, "Restricted ");
    print_str(STDOUT, path);
    print_str(STDOUT, " to its owner (mode 0700)\n");
}

void cmd_setup(void) {
    require_tool("ip", tool_path_ip());
    require_tool("iptables", tool_path_iptables());

    /* Before anything on the host changes: a host without cgroup v2 cannot
     * run containers, so setup stops here and leaves no bridge behind. */
    ensure_cgroup2_root();

    print_str(STDOUT, "Setting up host networking...\n");

    ensure_private_dir(cfg_global.lightbox_dir);
    ensure_private_dir(cfg_global.container_dir);

    {
        char *show[] = { "ip", "link", "show", cfg_global.bridge, NULL };
        if (run_cmd_quiet(tool_path_ip(), show) != 0) {
            print_str(STDOUT, "Creating bridge ");
            print_str(STDOUT, cfg_global.bridge);
            print_str(STDOUT, "...\n");
            char *add[] = { "ip", "link", "add", "name", cfg_global.bridge, "type", "bridge", NULL };
            require_cmd(tool_path_ip(), add);
            char gw_cidr[20];
            str_copy(gw_cidr, cfg_global.gw, sizeof(gw_cidr));
            str_append(gw_cidr, lc_string_length(gw_cidr), "/24", sizeof(gw_cidr));
            char *addr[] = { "ip", "addr", "add", gw_cidr, "dev", cfg_global.bridge, NULL };
            require_cmd(tool_path_ip(), addr);
            char *up[] = { "ip", "link", "set", cfg_global.bridge, "up", NULL };
            require_cmd(tool_path_ip(), up);
        } else {
            print_str(STDOUT, "Bridge ");
            print_str(STDOUT, cfg_global.bridge);
            print_str(STDOUT, " already exists, skipping\n");
        }
    }

    require_write_file("/proc/sys/net/ipv4/ip_forward", "1");

    char wan_if[32];
    detect_wan_interface(wan_if, sizeof(wan_if));
    print_str(STDOUT, "WAN interface: ");
    print_str(STDOUT, wan_if);
    lc_print_char(STDOUT, '\n');

    {
        char *chk[] = { "iptables", "-t", "nat", "-C", "POSTROUTING",
                        "-s", cfg_global.subnet, "-o", wan_if, "-j", "MASQUERADE", NULL };
        char *add[] = { "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-s", cfg_global.subnet, "-o", wan_if, "-j", "MASQUERADE", NULL };
        iptables_idempotent(chk, add);
    }

    {
        char *chk[] = { "iptables", "-C", "FORWARD", "-i", cfg_global.bridge,
                        "-o", wan_if, "-j", "ACCEPT", NULL };
        char *add[] = { "iptables", "-A", "FORWARD", "-i", cfg_global.bridge,
                        "-o", wan_if, "-j", "ACCEPT", NULL };
        iptables_idempotent(chk, add);
    }

    {
        char *chk[] = { "iptables", "-C", "FORWARD", "-i", wan_if,
                        "-o", cfg_global.bridge, "-m", "state", "--state", "RELATED,ESTABLISHED",
                        "-j", "ACCEPT", NULL };
        char *add[] = { "iptables", "-A", "FORWARD", "-i", wan_if,
                        "-o", cfg_global.bridge, "-m", "state", "--state", "RELATED,ESTABLISHED",
                        "-j", "ACCEPT", NULL };
        iptables_idempotent(chk, add);
    }

    {
        char *chk[] = { "iptables", "-C", "FORWARD", "-i", cfg_global.bridge,
                        "-o", cfg_global.bridge, "-j", "DROP", NULL };
        char *add[] = { "iptables", "-A", "FORWARD", "-i", cfg_global.bridge,
                        "-o", cfg_global.bridge, "-j", "DROP", NULL };
        iptables_idempotent(chk, add);
    }

    print_str(STDOUT, "Host networking ready\n");
}
