#include "lightbox.h"

[[noreturn]] static void die_cmd(const char *prefix, const char *prog) {
    die2(prefix, prog);
}

static void require_cmd(const char *prog, const char *const argv[]) {
    if (run_cmd(prog, argv) != 0)
        die_cmd("Error: command failed: ", prog);
}

static int iptables_check(const char *const argv[]) {
    return run_cmd_quiet(tool_path_iptables(), argv);
}

/* Add a rule setup depends on, unless it is there already. A rule that
 * cannot be added ends setup: without it the network it reports as ready
 * would not forward or isolate. */
static void iptables_idempotent(const char *const check_argv[], const char *const add_argv[]) {
    if (iptables_check(check_argv) != 0)
        require_cmd(tool_path_iptables(), add_argv);
}

static int iptables_ensure_rule(const char *const check_argv[], const char *const add_argv[]) {
    if (iptables_check(check_argv) == 0)
        return 0;
    return run_cmd(tool_path_iptables(), add_argv);
}

static int iptables_remove_rule(const char *const check_argv[], const char *const del_argv[]) {
    if (iptables_check(check_argv) != 0)
        return 0;
    return run_cmd(tool_path_iptables(), del_argv);
}

/* ─── Addresses ─────────────────────────────────────────────────────────── */

/*
 * An IPv4 address the one way everything that is handed the text reads it
 * alike: four numbers and three dots. No shorter form, no sign, no space,
 * and no zero in front of a number, which some programs read as octal and
 * others refuse.
 */
bool parse_ipv4(const char *text, uint32_t *addr) {
    if (!text)
        return false;
    uint32_t value = 0;
    const char *p = text;
    for (int octets = 1;; octets++) {
        uint32_t octet = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (digits == 3 || (digits > 0 && octet == 0))
                return false;       /* too long to be one, or a zero in front */
            octet = octet * 10u + (uint32_t)(*p - '0');
            digits++;
            p++;
        }
        if (digits == 0 || octet > 255u)
            return false;
        value = (value << 8) | octet;
        if (octets == 4)
            break;
        if (*p != '.')
            return false;
        p++;
    }
    if (*p != '\0')
        return false;
    *addr = value;
    return true;
}

void format_ipv4(char out[IPV4_TEXT_MAX], uint32_t addr) {
    size_t pos = 0;
    for (int shift = 24; shift >= 0; shift -= 8) {
        pos += (size_t)fmt_int(out + pos, (int)((addr >> shift) & 0xffu));
        out[pos++] = shift ? '.' : '\0';
    }
}

static void with_prefix(char out[CIDR_TEXT_MAX], uint32_t addr, int prefix) {
    format_ipv4(out, addr);
    size_t pos = lc_string_length(out);
    out[pos++] = '/';
    pos += (size_t)fmt_int(out + pos, prefix);
    out[pos] = '\0';
}

void address_with_prefix(char out[CIDR_TEXT_MAX], uint32_t addr, const container_network *net) {
    with_prefix(out, addr, net->prefix);
}

void subnet_text(char out[CIDR_TEXT_MAX], const container_network *net) {
    with_prefix(out, net->network, net->prefix);
}

/*
 * The network of the containers from its two settings: subnet, as
 * <address>/<bits>, and gw, the address the bridge has in it. The address in
 * subnet may be any of the subnet's. Both are checked here, together, by every
 * command that puts an address to use: a gateway that is not in the subnet
 * gives containers that start and reach nothing.
 */
const char *container_network_parse(const char *subnet, const char *gw, container_network *net,
                                    const char **setting) {
    *setting = "subnet";
    const char *slash = subnet;
    while (*slash && *slash != '/')
        slash++;
    size_t len = (size_t)(slash - subnet);
    char address[IPV4_TEXT_MAX];
    uint32_t base;
    if (*slash != '/' || len >= sizeof(address))
        return "is not <address>/<bits>";
    lc_bytes_copy(address, subnet, len);
    address[len] = '\0';
    if (!parse_ipv4(address, &base))
        return "is not <address>/<bits>";
    int64_t bits;
    if (slash[1] == '0' || !parse_number(slash + 1, SUBNET_PREFIX_MIN, SUBNET_PREFIX_MAX, &bits))
        return "takes " STRINGIFY(SUBNET_PREFIX_MIN) " to " STRINGIFY(SUBNET_PREFIX_MAX) " bits after the /";

    uint32_t mask = 0xffffffffu << (32 - (int)bits);
    net->prefix = (int)bits;
    net->network = base & mask;
    net->broadcast = net->network | ~mask;

    *setting = "gw";
    if (!parse_ipv4(gw, &net->gateway))
        return "is not an IPv4 address";
    if ((net->gateway & mask) != net->network)
        return "is not in the subnet";
    if (net->gateway == net->network || net->gateway == net->broadcast)
        return "is the first or the last address of the subnet, which no interface can have";
    return NULL;
}

void container_network_load_or_die(container_network *net) {
    const char *setting;
    const char *wrong = container_network_parse(cfg_global.subnet, cfg_global.gw, net, &setting);
    if (!wrong)
        return;
    print_str(STDERR, "Error: ");
    print_str(STDERR, setting);
    print_str(STDERR, " in lightbox.conf ");
    print_str(STDERR, wrong);
    print_str(STDERR, ": ");
    print_str(STDERR, streq(setting, "gw") ? cfg_global.gw : cfg_global.subnet);
    if (streq(setting, "gw")) {
        print_str(STDERR, " (subnet = ");
        print_str(STDERR, cfg_global.subnet);
        print_str(STDERR, ")");
    }
    lc_print_char(STDERR, '\n');
    lc_kernel_exit(1);
}

const char *address_unusable(const container_network *net, uint32_t addr) {
    if (addr < net->network || addr > net->broadcast)
        return "it is outside the subnet of lightbox.conf";
    if (addr == net->network)
        return "it is the address of the subnet itself";
    if (addr == net->broadcast)
        return "it is the broadcast address of the subnet";
    if (addr == net->gateway)
        return "it is the gateway's, the address of the bridge";
    return NULL;
}

/*
 * What is on record is used as it is read, in rules and in commands, so it
 * is an address or it is not read: a file that is longer than one, or that
 * holds anything beside it, gives nothing.
 */
int read_container_ip(const char *name, char *ip, size_t ipsz) {
    char ip_path[MAX_PATH], text[IPV4_TEXT_MAX + 2];
    container_ip_path(ip_path, name);
    int n = read_file(ip_path, text, sizeof(text));
    if (n <= 0)
        return -1;
    if (text[n - 1] == '\n')
        text[n - 1] = '\0';
    uint32_t addr;
    if (!parse_ipv4(text, &addr) || lc_string_length(text) >= ipsz)
        return -1;
    return str_copy(ip, text, ipsz) ? 0 : -1;
}

/*
 * The rules that let a container and each container it is linked to reach
 * one another: put in, or taken out. A link to a container that has no
 * address on record is passed over.
 */
int update_link_rules(const container_config *config, const char *ip, bool add_rules) {
    for (int i = 0; i < config->nlinks; i++) {
        char link_ip[16];
        if (read_container_ip(config->links[i], link_ip, sizeof(link_ip)) != 0)
            continue;

        /* one rule for each direction */
        for (int back = 0; back < 2; back++) {
            const char *from = back ? link_ip : ip;
            const char *to = back ? ip : link_ip;
            const char *check[] = { "iptables", "-C", "FORWARD",
                                    "-s", from, "-d", to,
                                    "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                    "-j", "ACCEPT", NULL };
            const char *change[] = { "iptables", add_rules ? "-I" : "-D", "FORWARD",
                                     "-s", from, "-d", to,
                                     "-i", cfg_global.bridge, "-o", cfg_global.bridge,
                                     "-j", "ACCEPT", NULL };
            if ((add_rules ? iptables_ensure_rule(check, change)
                           : iptables_remove_rule(check, change)) != 0)
                return -1;
        }
    }

    return 0;
}

/*
 * Whether traffic that the bridge switches between two of its ports passes
 * through iptables. It does only when br_netfilter is loaded and its switch
 * is on; without it the rules of setup see what the host routes and nothing
 * that one container sends another directly.
 */
bool bridge_traffic_is_filtered(void) {
    char value[8];
    return read_file("/proc/sys/net/bridge/bridge-nf-call-iptables", value, sizeof(value)) > 0 &&
           value[0] == '1';
}

static void detect_wan_interface(char *wan_if, size_t bufsz) {
    char route_buf[256];
    const char *argv[] = { "ip", "route", "show", "default", NULL };
    if (run_cmd_capture(tool_path_ip(), argv, route_buf, sizeof(route_buf)) != 0 || !route_buf[0])
        die("Error: could not detect default network interface");

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

    if (lc_kernel_mount("none", root, "cgroup2", 0, NULL) < 0)
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
    require_root("setup");
    require_tool("ip", tool_path_ip());
    require_tool("iptables", tool_path_iptables());

    /* Before anything on the host changes: the bridge gets an address of a
     * network that the settings do describe, */
    container_network net;
    container_network_load_or_die(&net);
    /* and a host without cgroup v2 cannot run containers, so setup stops
     * here and leaves no bridge behind. */
    ensure_cgroup2_root();

    print_str(STDOUT, "Setting up host networking...\n");

    ensure_private_dir(cfg_global.lightbox_dir);
    ensure_private_dir(cfg_global.container_dir);
    /* gone again after a reboot, when start makes it anew */
    ensure_private_dir(cfg_global.run_dir);

    /* one setup at a time, and no create while the bridge is being made */
    store_lock();

    {
        const char *show[] = { "ip", "link", "show", cfg_global.bridge, NULL };
        if (run_cmd_quiet(tool_path_ip(), show) != 0) {
            print_str(STDOUT, "Creating bridge ");
            print_str(STDOUT, cfg_global.bridge);
            print_str(STDOUT, "...\n");
            const char *add[] = { "ip", "link", "add", "name", cfg_global.bridge, "type", "bridge", NULL };
            require_cmd(tool_path_ip(), add);
            char gw_cidr[CIDR_TEXT_MAX];
            address_with_prefix(gw_cidr, net.gateway, &net);
            const char *addr[] = { "ip", "addr", "add", gw_cidr, "dev", cfg_global.bridge, NULL };
            require_cmd(tool_path_ip(), addr);
            const char *up[] = { "ip", "link", "set", cfg_global.bridge, "up", NULL };
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
        char subnet[CIDR_TEXT_MAX];
        subnet_text(subnet, &net);
        const char *chk[] = { "iptables", "-t", "nat", "-C", "POSTROUTING",
                        "-s", subnet, "-o", wan_if, "-j", "MASQUERADE", NULL };
        const char *add[] = { "iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-s", subnet, "-o", wan_if, "-j", "MASQUERADE", NULL };
        iptables_idempotent(chk, add);
    }

    {
        const char *chk[] = { "iptables", "-C", "FORWARD", "-i", cfg_global.bridge,
                        "-o", wan_if, "-j", "ACCEPT", NULL };
        const char *add[] = { "iptables", "-A", "FORWARD", "-i", cfg_global.bridge,
                        "-o", wan_if, "-j", "ACCEPT", NULL };
        iptables_idempotent(chk, add);
    }

    {
        const char *chk[] = { "iptables", "-C", "FORWARD", "-i", wan_if,
                        "-o", cfg_global.bridge, "-m", "state", "--state", "RELATED,ESTABLISHED",
                        "-j", "ACCEPT", NULL };
        const char *add[] = { "iptables", "-A", "FORWARD", "-i", wan_if,
                        "-o", cfg_global.bridge, "-m", "state", "--state", "RELATED,ESTABLISHED",
                        "-j", "ACCEPT", NULL };
        iptables_idempotent(chk, add);
    }

    {
        const char *chk[] = { "iptables", "-C", "FORWARD", "-i", cfg_global.bridge,
                        "-o", cfg_global.bridge, "-j", "DROP", NULL };
        const char *add[] = { "iptables", "-A", "FORWARD", "-i", cfg_global.bridge,
                        "-o", cfg_global.bridge, "-j", "DROP", NULL };
        iptables_idempotent(chk, add);
    }

    if (!bridge_traffic_is_filtered())
        print_str(STDOUT,
            "Note: br_netfilter is not filtering bridged traffic on this host. Containers\n"
            "are kept apart at the bridge, so that needs nothing. A container created with\n"
            "--link will not start until it does:\n"
            "  modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1\n");

    print_str(STDOUT, "Host networking ready\n");
}
