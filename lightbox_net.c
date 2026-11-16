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

/* Run a rule's delete until there is no such rule left. How many went. */
static int iptables_delete_all(const char *const del_argv[]) {
    int removed = 0;
    while (removed < 64 && run_cmd_quiet(tool_path_iptables(), del_argv) == 0)
        removed++;
    return removed;
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

/* ─── The firewall ──────────────────────────────────────────────────────── */

_Static_assert(NAME_MAX_LEN + 3 < 16, "an interface name holds a container's name and three more");
void veth_names(const char *name, char host[16], char cont[16]) {
    bool cut = false;       /* never: the name has been checked to be one */
    size_t pos = str_append(host, 0, "vb-", 16, &cut);
    str_append(host, pos, name, 16, &cut);
    pos = str_append(cont, 0, "ve-", 16, &cut);
    str_append(cont, pos, name, 16, &cut);
}

struct text_out {
    char  *text;
    size_t max;
    size_t pos;
    bool   cut;
};

static void out_put(struct text_out *out, const char *s) {
    out->pos = str_append(out->text, out->pos, s, out->max, &out->cut);
}

/* LB-<name>: the chain of a container's links */
static void link_chain(char out[32], const char *name) {
    bool cut = false;       /* never: the name has been checked to be one */
    size_t pos = str_append(out, 0, "LB-", 32, &cut);
    str_append(out, pos, name, 32, &cut);
}

/*
 * A container's links, as iptables-restore is given them: a chain of the
 * container's own, which LIGHTBOX-LINKS jumps to, with a rule for each way of
 * each link. The rules name the two ports on the bridge and no address, so
 * a link holds whichever of the two starts first, and to a container that
 * did not exist yet when this one was created.
 */
bool firewall_links_text(const char *name, const container_config *config, char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    char chain[32], port[16], unused[16];
    link_chain(chain, name);
    veth_names(name, port, unused);
    text[0] = '\0';
    out_put(&out, "*filter\n:");
    out_put(&out, chain);
    out_put(&out, " - [0:0]\n");
    for (int i = 0; i < config->nlinks; i++) {
        char other[16];
        veth_names(config->links[i], other, unused);
        for (int back = 0; back < 2; back++) {
            out_put(&out, "-A ");
            out_put(&out, chain);
            out_put(&out, " -m physdev --physdev-in ");
            out_put(&out, back ? other : port);
            out_put(&out, " --physdev-out ");
            out_put(&out, back ? port : other);
            out_put(&out, " -j ACCEPT\n");
        }
    }
    out_put(&out, "-A LIGHTBOX-LINKS -j ");
    out_put(&out, chain);
    out_put(&out, "\nCOMMIT\n");
    return !out.cut;
}

/*
 * What setup puts in LIGHTBOX-FORWARD and LIGHTBOX-POSTROUTING, each flushed
 * and filled again in one transaction, so that a second setup changes
 * nothing and no packet meets a chain half made. Between two of its ports
 * the bridge forwards what a link allows and nothing else; out of it,
 * anything that leaves by an interface other than the bridge, whichever it
 * is, and back what belongs to such a connection.
 */
bool firewall_setup_text(const container_network *net, char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    const char *br = cfg_global.bridge;
    char subnet[CIDR_TEXT_MAX];
    subnet_text(subnet, net);
    text[0] = '\0';
    out_put(&out, "*filter\n-F LIGHTBOX-FORWARD\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -i "); out_put(&out, br); out_put(&out, " -o "); out_put(&out, br);
    out_put(&out, " -j LIGHTBOX-LINKS\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -i "); out_put(&out, br); out_put(&out, " -o "); out_put(&out, br);
    out_put(&out, " -j DROP\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -i "); out_put(&out, br); out_put(&out, " ! -o "); out_put(&out, br);
    out_put(&out, " -j ACCEPT\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -o "); out_put(&out, br);
    out_put(&out, " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\nCOMMIT\n");
    out_put(&out, "*nat\n-F LIGHTBOX-POSTROUTING\n");
    if (cfg_global.ip_masq) {
        out_put(&out, "-A LIGHTBOX-POSTROUTING -s "); out_put(&out, subnet);
        out_put(&out, " ! -o "); out_put(&out, br); out_put(&out, " -j MASQUERADE\n");
    }
    out_put(&out, "COMMIT\n");
    return !out.cut;
}

int firewall_remove_links(const char *name) {
    char record[MAX_PATH], chain[32];
    container_firewall_path(record, name);
    if (!path_exists(record))
        return 0;
    link_chain(chain, name);

    /* As a start left it: the jump, the chain's rules and the chain, in one
     * transaction. Anything else, one piece at a time, as far as it is there. */
    static char text[256];
    struct text_out out = { .text = text, .max = sizeof(text), .pos = 0, .cut = false };
    text[0] = '\0';
    out_put(&out, "*filter\n-D LIGHTBOX-LINKS -j "); out_put(&out, chain);
    out_put(&out, "\n-F "); out_put(&out, chain);
    out_put(&out, "\n-X "); out_put(&out, chain);
    out_put(&out, "\nCOMMIT\n");
    const char *restore[] = { "iptables-restore", "--noflush", NULL };
    bool gone = !out.cut && run_cmd_input(tool_path_iptables_restore(), restore, text, true) == 0;
    if (!gone) {
        const char *jump[] = { "iptables", "-D", "LIGHTBOX-LINKS", "-j", chain, NULL };
        const char *flush[] = { "iptables", "-F", chain, NULL };
        const char *drop[] = { "iptables", "-X", chain, NULL };
        const char *look[] = { "iptables", "-n", "-L", chain, NULL };
        (void)iptables_delete_all(jump);
        (void)run_cmd_quiet(tool_path_iptables(), flush);
        (void)run_cmd_quiet(tool_path_iptables(), drop);
        gone = run_cmd_quiet(tool_path_iptables(), look) != 0;
    }
    if (!gone) {
        print_str(STDERR, "Error: cannot remove the firewall chain of the container's links: ");
        print_str(STDERR, chain);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    lc_kernel_unlinkat(AT_FDCWD, record, 0);
    return 0;
}

int firewall_add_links(const char *name, const container_config *config) {
    if (config->nlinks == 0)
        return 0;
    static char text[FIREWALL_TEXT_MAX];
    if (!firewall_links_text(name, config, text, sizeof(text))) {
        print_str(STDERR, "Error: the firewall rules of the container's links are too long\n");
        return -1;
    }
    /* what an earlier run left of them */
    if (firewall_remove_links(name) != 0)
        return -1;

    /* On record before they are there: a command that is killed in between
     * leaves the record, and the next command takes away what it names. */
    char record[MAX_PATH], chain[32], line[34];
    container_firewall_path(record, name);
    link_chain(chain, name);
    bool cut = false;
    str_append(line, str_append(line, 0, chain, sizeof(line), &cut), "\n", sizeof(line), &cut);
    if (container_run_dir_make(name) != 0 || write_file_volatile(record, line) != 0) {
        print_str(STDERR, "Error: cannot record the firewall rules of the container's links\n");
        return -1;
    }
    const char *restore[] = { "iptables-restore", "--noflush", NULL };
    if (run_cmd_input(tool_path_iptables_restore(), restore, text, false) != 0) {
        print_str(STDERR, "Error: the firewall rules of the container's links could not be put in;\n"
                          "lightbox setup makes the chains they go into\n");
        return -1;
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

/* The interface of the default route, if there is one. */
static bool find_wan_interface(char *wan_if, size_t bufsz) {
    char route_buf[256];
    const char *argv[] = { "ip", "route", "show", "default", NULL };
    if (run_cmd_capture(tool_path_ip(), argv, route_buf, sizeof(route_buf)) != 0 || !route_buf[0])
        return false;

    const char *dev = NULL;
    for (char *p = route_buf; *p; p++) {
        if (p[0] == 'd' && p[1] == 'e' && p[2] == 'v' && p[3] == ' ') {
            dev = p + 4;
            break;
        }
    }
    if (!dev)
        return false;
    size_t i = 0;
    while (dev[i] && dev[i] != ' ' && dev[i] != '\n' && i < bufsz - 1) {
        wan_if[i] = dev[i];
        i++;
    }
    wan_if[i] = '\0';
    return i > 0;
}

/*
 * The rules that lightbox 0.4 and before put straight into FORWARD and
 * POSTROUTING, taken out: what setup made, with the interface of the default
 * route, and the rules of links, which name two addresses. How many went.
 */
static int forget_old_rules(const container_network *net) {
    const char *br = cfg_global.bridge;
    int removed = 0;
    char wan[32], subnet[CIDR_TEXT_MAX];
    subnet_text(subnet, net);
    if (find_wan_interface(wan, sizeof(wan))) {
        const char *masq[] = { "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-o", wan,
                               "-j", "MASQUERADE", NULL };
        const char *out[] = { "iptables", "-D", "FORWARD", "-i", br, "-o", wan, "-j", "ACCEPT", NULL };
        const char *back[] = { "iptables", "-D", "FORWARD", "-i", wan, "-o", br, "-m", "state",
                               "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT", NULL };
        removed += iptables_delete_all(masq) + iptables_delete_all(out) + iptables_delete_all(back);
    }
    const char *apart[] = { "iptables", "-D", "FORWARD", "-i", br, "-o", br, "-j", "DROP", NULL };
    removed += iptables_delete_all(apart);

    /* -A FORWARD -s <a>/32 -d <b>/32 -i <br> -o <br> -j ACCEPT */
    static char rules[65536];
    const char *list[] = { "iptables", "-S", "FORWARD", NULL };
    if (run_cmd_capture(tool_path_iptables(), list, rules, sizeof(rules)) != 0)
        return removed;
    for (char *line = rules; *line; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        bool last = *end == '\0';
        *end = '\0';
        const char *word[16];
        int n = 0;
        for (char *p = line; *p && n < 16; ) {
            while (*p == ' ') *p++ = '\0';
            if (!*p) break;
            word[n++] = p;
            while (*p && *p != ' ') p++;
        }
        if (n == 12 && streq(word[0], "-A") && streq(word[1], "FORWARD") && streq(word[2], "-s") &&
            streq(word[4], "-d") && streq(word[6], "-i") && streq(word[7], br) && streq(word[8], "-o") &&
            streq(word[9], br) && streq(word[10], "-j") && streq(word[11], "ACCEPT")) {
            const char *del[] = { "iptables", "-D", "FORWARD", "-s", word[3], "-d", word[5],
                                  "-i", br, "-o", br, "-j", "ACCEPT", NULL };
            removed += iptables_delete_all(del);
        }
        line = last ? end : end + 1;
    }
    return removed;
}

static bool iptables_chain_exists(const char *table, const char *chain) {
    const char *look[] = { "iptables", "-t", table, "-n", "-L", chain, NULL };
    return run_cmd_quiet(tool_path_iptables(), look) == 0;
}

/*
 * lightbox's chains, its rules in them, and the jumps to them from the top
 * of FORWARD and POSTROUTING: there, before the host's own rules and its
 * policy, they decide for the bridge whatever comes after them. LIGHTBOX-USER
 * is the host's, for rules that are to decide before lightbox's; it is made
 * when it is not there and never changed.
 */
static void firewall_setup(const container_network *net) {
    require_tool("iptables-restore", tool_path_iptables_restore());
    static const struct { const char *table, *chain; } chains[] = {
        { "filter", "LIGHTBOX-USER" }, { "filter", "LIGHTBOX-LINKS" },
        { "filter", "LIGHTBOX-FORWARD" }, { "nat", "LIGHTBOX-POSTROUTING" },
    };
    for (size_t i = 0; i < sizeof(chains) / sizeof(chains[0]); i++) {
        if (iptables_chain_exists(chains[i].table, chains[i].chain))
            continue;
        const char *make[] = { "iptables", "-t", chains[i].table, "-N", chains[i].chain, NULL };
        require_cmd(tool_path_iptables(), make);
    }

    static char text[FIREWALL_TEXT_MAX];
    const char *restore[] = { "iptables-restore", "--noflush", NULL };
    if (!firewall_setup_text(net, text, sizeof(text)))
        die("Error: setup's firewall rules are too long");
    if (run_cmd_input(tool_path_iptables_restore(), restore, text, false) != 0)
        die("Error: setup's firewall rules could not be put in");

    /* LIGHTBOX-USER first, then LIGHTBOX-FORWARD: when either is missing,
     * both are put back at the top in that order. */
    const char *has_user[] = { "iptables", "-C", "FORWARD", "-j", "LIGHTBOX-USER", NULL };
    const char *has_fwd[] = { "iptables", "-C", "FORWARD", "-j", "LIGHTBOX-FORWARD", NULL };
    if (iptables_check(has_user) != 0 || iptables_check(has_fwd) != 0) {
        const char *del_user[] = { "iptables", "-D", "FORWARD", "-j", "LIGHTBOX-USER", NULL };
        const char *del_fwd[] = { "iptables", "-D", "FORWARD", "-j", "LIGHTBOX-FORWARD", NULL };
        const char *ins_user[] = { "iptables", "-I", "FORWARD", "1", "-j", "LIGHTBOX-USER", NULL };
        const char *ins_fwd[] = { "iptables", "-I", "FORWARD", "1", "-j", "LIGHTBOX-FORWARD", NULL };
        (void)iptables_delete_all(del_user);
        (void)iptables_delete_all(del_fwd);
        require_cmd(tool_path_iptables(), ins_fwd);
        require_cmd(tool_path_iptables(), ins_user);
    }
    const char *has_nat[] = { "iptables", "-t", "nat", "-C", "POSTROUTING", "-j", "LIGHTBOX-POSTROUTING", NULL };
    const char *ins_nat[] = { "iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-j", "LIGHTBOX-POSTROUTING", NULL };
    iptables_idempotent(has_nat, ins_nat);

    int old = forget_old_rules(net);
    if (old > 0) {
        char digits[16];
        fmt_int(digits, old);
        print_str(STDOUT, "Removed ");
        print_str(STDOUT, digits);
        print_str(STDOUT, " firewall rules that an earlier lightbox put straight into FORWARD and POSTROUTING;\n"
                          "a running container with links has its link rules back when it is started again\n");
    }
    print_str(STDOUT, "Firewall rules are in LIGHTBOX-FORWARD, LIGHTBOX-LINKS and LIGHTBOX-POSTROUTING;\n"
                      "rules of this host's that are to decide first go in LIGHTBOX-USER\n");
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
    if (cfg_global.firewall)
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

    if (cfg_global.firewall)
        firewall_setup(&net);
    else
        print_str(STDOUT, "firewall = false in lightbox.conf: no firewall rules were made\n");

    /*
     * Forwarding, as Docker does it: when setup is the one that turns it on,
     * the FORWARD policy becomes DROP first, so that the host forwards what a
     * rule accepts and nothing else. A host that had forwarding on already
     * keeps its policy, and ip_forward_no_drop keeps it in any case.
     */
    char forwarding[8];
    bool was_on = read_file("/proc/sys/net/ipv4/ip_forward", forwarding, sizeof(forwarding)) > 0 &&
                  forwarding[0] == '1';
    if (!was_on && cfg_global.ip_forward) {
        if (cfg_global.firewall && !cfg_global.ip_forward_no_drop) {
            const char *drop[] = { "iptables", "-P", "FORWARD", "DROP", NULL };
            require_cmd(tool_path_iptables(), drop);
            print_str(STDOUT, "IPv4 forwarding was off. It is on, and the FORWARD policy is DROP: this host\n"
                              "forwards what a rule accepts and nothing else (ip_forward_no_drop = true\n"
                              "in lightbox.conf leaves the policy as it is)\n");
        } else {
            print_str(STDOUT, "IPv4 forwarding was off, and is on\n");
        }
        require_write_file("/proc/sys/net/ipv4/ip_forward", "1");
    } else if (!was_on) {
        print_str(STDOUT, "Warning: IPv4 forwarding is off, and ip_forward = false in lightbox.conf:\n"
                          "containers reach this host and nothing beyond it\n");
    }

    if (!bridge_traffic_is_filtered())
        print_str(STDOUT,
            "Note: br_netfilter is not filtering bridged traffic on this host. Containers\n"
            "are kept apart at the bridge, so that needs nothing. A container created with\n"
            "--link will not start until it does:\n"
            "  modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1\n");

    print_str(STDOUT, "Host networking ready\n");
}
