#include "lightbox.h"

[[noreturn]] static void die_cmd(const char *prefix, const char *prog) {
    die2(prefix, prog);
}

static void require_cmd(const char *prog, const char *const argv[]) {
    if (run_cmd(prog, argv) != 0)
        die_cmd("Error: command failed: ", prog);
}

/* "Error: <before><what> (errno <n>)", for a request the kernel refused */
[[noreturn]] static void die_errno(const char *before, const char *what, int rc) {
    char digits[16];
    fmt_int(digits, -rc);
    print_str(STDERR, "Error: ");
    print_str(STDERR, before);
    print_str(STDERR, what);
    print_str(STDERR, " (errno ");
    print_str(STDERR, digits);
    print_str(STDERR, ")\n");
    lc_kernel_exit(failure_status);
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
    lc_kernel_exit(failure_status);
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

/* <prefix> and the top 48 bits of the name's 64-bit FNV-1a hash, in hex */
static void hashed_name(const char *prefix, const char *name, char out[IFNAME_TEXT_MAX]) {
    static const char hex[] = "0123456789abcdef";
    uint64_t h = 0xcbf29ce484222325ull;
    for (const char *p = name; *p; p++) {
        h ^= (uint8_t)*p;
        h *= 0x100000001b3ull;
    }
    size_t pos = lc_string_length(prefix);     /* "vb-" or "LB-" */
    lc_bytes_copy(out, prefix, pos);
    for (int i = 0; i < 12; i++)
        out[pos++] = hex[(h >> (60 - 4 * i)) & 0xf];
    out[pos] = '\0';
}
_Static_assert(3 + 12 < IFNAME_TEXT_MAX, "an interface name holds the prefix and twelve digits");

void host_port_name(const char *name, char out[IFNAME_TEXT_MAX]) { hashed_name("vb-", name, out); }
void link_chain_name(const char *name, char out[IFNAME_TEXT_MAX]) { hashed_name("LB-", name, out); }
/* the chain of a container's --net outside rules under iptables */
static void egress_chain_name(const char *name, char out[IFNAME_TEXT_MAX]) { hashed_name("LO-", name, out); }

port_owner host_port_owner(const char *ifname, const char *name) {
    char alias[256];        /* the kernel's longest alias, and its end */
    rtnl nl;
    if (rtnl_open(&nl) < 0)
        return PORT_UNKNOWN;
    int rc = rtnl_link_get(&nl, ifname, alias, sizeof(alias));
    rtnl_close(&nl);
    if (rc == -LB_ENODEV)
        return PORT_ABSENT;
    if (rc < 0)
        return PORT_UNKNOWN;
    return port_owner_of_alias(alias, name);
}

port_owner port_owner_of_alias(const char *alias, const char *name) {
    char want[64];
    bool cut = false;
    str_append(want, str_append(want, 0, "lightbox:", sizeof(want), &cut), name, sizeof(want), &cut);
    return !cut && streq(alias, want) ? PORT_OURS : PORT_FOREIGN;
}

/*
 * The kernel removes a container's interface by itself a moment after its
 * init has ended, so one that was there at the first look can be gone at
 * the delete: that is not a failure.
 */
int remove_own_port(const char *ifname, const char *name) {
    port_owner owner = host_port_owner(ifname, name);
    if (owner == PORT_ABSENT)
        return 0;
    if (owner == PORT_FOREIGN)
        return 1;
    rtnl nl;
    if (owner == PORT_UNKNOWN || rtnl_open(&nl) < 0)
        return -1;
    int rc = rtnl_link_delete(&nl, ifname);
    rtnl_close(&nl);
    if (rc == 0 || rc == -LB_ENODEV)
        return 0;
    return host_port_owner(ifname, name) == PORT_ABSENT ? 0 : -1;
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

/* A chain's name as a record of it may give it: LB- and what a chain name
 * may hold, within the 28 characters of one. */
static bool chain_named(const char *chain, const char *prefix) {
    size_t len = lc_string_length(chain);
    if (len < 4 || len > 28 || !lc_string_starts_with(chain, len, prefix, 3))
        return false;
    for (size_t i = 3; i < len; i++) {
        char c = chain[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

bool link_chain_ok(const char *chain) { return chain_named(chain, "LB-"); }
static bool egress_chain_ok(const char *chain) { return chain_named(chain, "LO-"); }

/*
 * --net outside (ROADMAP 8.5): what a container may not reach beyond the
 * host, which refuses it everything but the answers to what it was asked
 * and its name servers. The ranges that are no one's on the internet: this
 * network, the private ones of RFC 1918, the shared space of carriers, in
 * which Alibaba's metadata service is, loopback, link-local with the
 * metadata services of AWS, Azure, Google Cloud and Oracle, the IETF's
 * protocol assignments, the benchmark range that proxies give out as fake
 * addresses, and multicast and what is reserved above it, broadcast among
 * it. The documentation ranges are left: no network routes them.
 */
static const char *const OUTSIDE_REFUSED[] = {
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
};
#define NOUTSIDE_REFUSED (sizeof(OUTSIDE_REFUSED) / sizeof(OUTSIDE_REFUSED[0]))
/* How what is refused is refused, at once: TCP with a reset, the rest with
 * ICMP "administratively prohibited". Not TCP with the ICMP: it comes back
 * across the veth while connect() still holds its socket, and the kernel
 * then keeps it as a soft error, so that the connection fails only when a
 * second SYN is refused, a second later. A reset waits for the socket. Each
 * match is two rules, the reset's first. */
#define OUTSIDE_REJECT_TCP " -p tcp -j REJECT --reject-with tcp-reset\n"
#define OUTSIDE_REJECT " -j REJECT --reject-with icmp-admin-prohibited\n"

/*
 * A container's links, as iptables-restore is given them: a chain of the
 * container's own, which LIGHTBOX-LINKS jumps to, with a rule for each way of
 * each link. The rules name the two ports on the bridge and no address, so
 * a link holds whichever of the two starts first, and to a container that
 * did not exist yet when this one was created.
 */
bool firewall_links_text(const char *name, const container_config *config, char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    char chain[IFNAME_TEXT_MAX], port[IFNAME_TEXT_MAX];
    link_chain_name(name, chain);
    host_port_name(name, port);
    text[0] = '\0';
    out_put(&out, "*filter\n:");
    out_put(&out, chain);
    out_put(&out, " - [0:0]\n");
    for (int i = 0; i < config->nlinks; i++) {
        char other[IFNAME_TEXT_MAX];
        host_port_name(config->links[i], other);
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
    out_put(&out, "-A LIGHTBOX-FORWARD -i "); out_put(&out, br); out_put(&out, " ! -o "); out_put(&out, br);
    out_put(&out, " -j LIGHTBOX-EGRESS\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -i "); out_put(&out, br); out_put(&out, " -o "); out_put(&out, br);
    out_put(&out, " -j DROP\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -i "); out_put(&out, br); out_put(&out, " ! -o "); out_put(&out, br);
    out_put(&out, " -j ACCEPT\n");
    out_put(&out, "-A LIGHTBOX-FORWARD -o "); out_put(&out, br);
    out_put(&out, " -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n");
    /* --net outside: what a container sends the host, and out of the bridge,
     * goes through the chain of its own that LIGHTBOX-EGRESS jumps to by its
     * address, and from there to LIGHTBOX-OUTSIDE. The host is refused it
     * whatever the address it was sent to, as all that reaches INPUT is the
     * host's own, broadcast or multicast. */
    out_put(&out, "-F LIGHTBOX-INPUT\n-A LIGHTBOX-INPUT -i "); out_put(&out, br);
    out_put(&out, " -j LIGHTBOX-EGRESS\n-F LIGHTBOX-OUTSIDE\n");
    static const char *const types[] = { "LOCAL", "BROADCAST", "MULTICAST" };
    for (size_t i = 0; i < 3; i++) {
        for (int tcp = 1; tcp >= 0; tcp--) {
            out_put(&out, "-A LIGHTBOX-OUTSIDE -m addrtype --dst-type ");
            out_put(&out, types[i]);
            out_put(&out, tcp ? OUTSIDE_REJECT_TCP : OUTSIDE_REJECT);
        }
    }
    for (size_t i = 0; i < NOUTSIDE_REFUSED; i++) {
        for (int tcp = 1; tcp >= 0; tcp--) {
            out_put(&out, "-A LIGHTBOX-OUTSIDE -d ");
            out_put(&out, OUTSIDE_REFUSED[i]);
            out_put(&out, tcp ? OUTSIDE_REJECT_TCP : OUTSIDE_REJECT);
        }
    }
    out_put(&out, "COMMIT\n");
    out_put(&out, "*nat\n-F LIGHTBOX-POSTROUTING\n");
    if (cfg_global.ip_masq) {
        out_put(&out, "-A LIGHTBOX-POSTROUTING -s "); out_put(&out, subnet);
        out_put(&out, " ! -o "); out_put(&out, br); out_put(&out, " -j MASQUERADE\n");
    }
    out_put(&out, "COMMIT\n");
    return !out.cut;
}

/* Elements of the set of links, as the record names them: each put in and
 * taken out again in one transaction, so that one a peer's stop took out
 * already does not keep the others in. */
static int nft_remove_links(const char *record, const char *recorded) {
    static char text[FIREWALL_TEXT_MAX];
    if (!nft_links_text(recorded, true, text, sizeof(text))) {
        print_str(STDERR, "Error: the record of the container's link rules is not one lightbox writes: ");
        print_str(STDERR, record);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    if (text[0]) {
        const char *nft[] = { "nft", "-f", "-", NULL };
        bool gone = run_cmd_input(tool_path_nft(), nft, text, true) == 0;
        if (!gone) {
            /* without lightbox's set nothing of them is left: a setup with
             * firewall_backend = iptables took the table away */
            const char *look[] = { "nft", "list", "set", "bridge", "lightbox", "links", NULL };
            gone = run_cmd_quiet(tool_path_nft(), look) != 0;
        }
        if (!gone) {
            print_str(STDERR, "Error: cannot take the container's links out of the nftables set bridge lightbox links\n");
            return -1;
        }
    }
    lc_kernel_unlinkat(AT_FDCWD, record, 0);
    return 0;
}

int firewall_remove_links(const char *name) {
    char record[MAX_PATH];
    static char recorded[FIREWALL_TEXT_MAX];
    container_firewall_path(record, name);
    if (!path_exists(record))
        return 0;
    int n = read_file(record, recorded, sizeof(recorded));
    if (n > 0 && n < (int)sizeof(recorded) - 1 && lc_string_starts_with(recorded, (size_t)n, NFT_RECORD_HEAD,
                                                                         lc_string_length(NFT_RECORD_HEAD)))
        return nft_remove_links(record, recorded);
    /* the chain the record names: the one a start put in, whatever name the
     * lightbox that started the container gave it */
    char *chain = recorded;
    if (n > 0 && chain[n - 1] == '\n')
        chain[n - 1] = '\0';
    if (n <= 0 || !link_chain_ok(chain)) {
        print_str(STDERR, "Error: the record of the container's link rules does not name a chain of lightbox's: ");
        print_str(STDERR, record);
        lc_print_char(STDERR, '\n');
        return -1;
    }

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

/* ─── --net outside and --net proxy, per container ──────────────────────── */

bool net_has_rules(int mode) { return mode == NET_OUTSIDE || mode == NET_PROXY; }

/* An address as format_ipv4 writes it, and no other text. */
static bool plain_ipv4(const char *text) {
    uint32_t addr;
    char back[IPV4_TEXT_MAX];
    if (!parse_ipv4(text, &addr))
        return false;
    format_ipv4(back, addr);
    return streq(back, text);
}

/* A port as fmt_int writes it, from 1 to 65535, and no other text. */
static bool plain_port(const char *text) {
    int64_t port;
    return text[0] >= '1' && text[0] <= '9' && parse_number(text, 1, 65535, &port);
}

/* The gateway of lightbox.conf, as format_ipv4 writes it: where the proxy of
 * a container of --net proxy listens. */
static bool gateway_text(char out[IPV4_TEXT_MAX]) {
    container_network net;
    const char *setting;
    if (container_network_parse(cfg_global.subnet, cfg_global.gw, &net, &setting) != NULL)
        return false;
    format_ipv4(out, net.gateway);
    return true;
}

/*
 * iptables: a chain of the container's own, which LIGHTBOX-EGRESS jumps to
 * for what comes from its address. What answers what it was asked goes on.
 * With --net outside, so does a question to one of its name servers on port
 * 53, and the rest goes to LIGHTBOX-OUTSIDE, which refuses the host and the
 * ranges that are no one's on the internet, and lets the rest of it go on.
 * With --net proxy, what goes to its proxy's port of the gateway goes on, and
 * the rest is refused; and at the top of LIGHTBOX-LINKS, before the chain of
 * any link, what the bridge switches from it or to it is dropped, so that a
 * container that names it with --link reaches it no more than it reaches
 * that one.
 */
bool firewall_egress_text(const char *name, const char *ip, const char *gw, const container_config *config,
                          char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    char chain[IFNAME_TEXT_MAX];
    egress_chain_name(name, chain);
    text[0] = '\0';
    bool proxy = config->net == NET_PROXY;
    if (!net_has_rules(config->net) || !plain_ipv4(ip))
        return false;
    if (proxy && (!plain_ipv4(gw) || config->proxy_port < 1 || config->proxy_port > 65535))
        return false;
    out_put(&out, "*filter\n:");
    out_put(&out, chain);
    out_put(&out, " - [0:0]\n-A ");
    out_put(&out, chain);
    out_put(&out, " -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n");
    if (proxy) {
        char port[8];
        fmt_int(port, config->proxy_port);
        out_put(&out, "-A ");
        out_put(&out, chain);
        out_put(&out, " -d ");
        out_put(&out, gw);
        out_put(&out, " -p tcp --dport ");
        out_put(&out, port);
        out_put(&out, " -j RETURN\n-A ");
        out_put(&out, chain);
        out_put(&out, OUTSIDE_REJECT_TCP);
        out_put(&out, "-A ");
        out_put(&out, chain);
        out_put(&out, OUTSIDE_REJECT);
    } else {
        for (int i = 0; i < config->ndns; i++) {
            if (!plain_ipv4(config->dns[i]))
                return false;
            for (int tcp = 0; tcp < 2; tcp++) {
                out_put(&out, "-A ");
                out_put(&out, chain);
                out_put(&out, " -d ");
                out_put(&out, config->dns[i]);
                out_put(&out, tcp ? " -p tcp --dport 53 -j RETURN\n" : " -p udp --dport 53 -j RETURN\n");
            }
        }
        out_put(&out, "-A ");
        out_put(&out, chain);
        out_put(&out, " -j LIGHTBOX-OUTSIDE\n");
    }
    out_put(&out, "-A LIGHTBOX-EGRESS -s ");
    out_put(&out, ip);
    out_put(&out, " -j ");
    out_put(&out, chain);
    out_put(&out, "\n");
    if (proxy) {
        for (int to = 0; to < 2; to++) {
            out_put(&out, to ? "-I LIGHTBOX-LINKS 1 -d " : "-I LIGHTBOX-LINKS 1 -s ");
            out_put(&out, ip);
            out_put(&out, " -j DROP\n");
        }
    }
    out_put(&out, "COMMIT\n");
    return !out.cut;
}

/* What begins the one line of a record of --net proxy under nftables. */
#define NFT_PROXY_LINE "proxy "

/* nftables: the record of --net outside is the container's address, then
 * its name servers, a line each; of --net proxy one line: "proxy", the
 * container's address, its proxy's address and port, and its port on the
 * bridge. */
bool nft_egress_record(const char *name, const char *ip, const char *gw, const container_config *config,
                       char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    text[0] = '\0';
    if (!net_has_rules(config->net) || !plain_ipv4(ip))
        return false;
    out_put(&out, NFT_RECORD_HEAD);
    if (config->net == NET_PROXY) {
        if (!plain_ipv4(gw) || config->proxy_port < 1 || config->proxy_port > 65535)
            return false;
        char port[8], ifname[IFNAME_TEXT_MAX];
        fmt_int(port, config->proxy_port);
        host_port_name(name, ifname);
        const char *const fields[] = { NFT_PROXY_LINE, ip, " ", gw, " ", port, " ", ifname, "\n" };
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
            out_put(&out, fields[i]);
        return !out.cut;
    }
    out_put(&out, ip);
    out_put(&out, "\n");
    for (int i = 0; i < config->ndns; i++) {
        if (!plain_ipv4(config->dns[i]))
            return false;
        out_put(&out, config->dns[i]);
        out_put(&out, "\n");
    }
    return !out.cut;
}

/* Is the record, after its head, one of --net proxy? */
static bool nft_record_is_proxy(const char *body) {
    return lc_string_starts_with(body, lc_string_length(body), NFT_PROXY_LINE, sizeof(NFT_PROXY_LINE) - 1);
}

/* The elements of a record of --net outside, a line for each set. */
static bool outside_elements(const char *body, struct text_out *list) {
    char addrs[1 + MAX_DNS][IPV4_TEXT_MAX];
    int n = 0;
    for (const char *line = body; *line; ) {
        const char *end = line;
        while (*end && *end != '\n') end++;
        size_t len = (size_t)(end - line);
        if (*end != '\n' || len == 0 || len >= IPV4_TEXT_MAX || n >= 1 + MAX_DNS)
            return false;
        lc_bytes_copy(addrs[n], line, len);
        addrs[n][len] = '\0';
        if (!plain_ipv4(addrs[n]))
            return false;
        n++;
        line = end + 1;
    }
    if (n == 0)
        return false;
    out_put(list, "element ip lightbox outside { ");
    out_put(list, addrs[0]);
    out_put(list, " }\n");
    if (n > 1) {
        out_put(list, "element ip lightbox outside_dns { ");
        for (int i = 1; i < n; i++) {
            out_put(list, i > 1 ? ", " : "");
            out_put(list, addrs[0]);
            out_put(list, " . ");
            out_put(list, addrs[i]);
        }
        out_put(list, " }\n");
    }
    return true;
}

/* The elements of a record of --net proxy: the container in the set of
 * those, its address with its proxy's address and port in the set of what
 * they may reach, and its port on the bridge in the set of the ports that
 * the bridge switches nothing from or to. */
static bool proxy_elements(const char *body, struct text_out *list) {
    char line[80];
    size_t len = 0;
    while (body[len] && body[len] != '\n')
        len++;
    if (body[len] != '\n' || body[len + 1] != '\0' || len >= sizeof(line))
        return false;
    lc_bytes_copy(line, body, len);
    line[len] = '\0';
    char *fields[4];
    int n = 0;
    char *p = line + sizeof(NFT_PROXY_LINE) - 1;
    for (;;) {
        if (n == 4)
            return false;
        fields[n++] = p;
        while (*p && *p != ' ')
            p++;
        if (!*p)
            break;
        *p++ = '\0';
    }
    if (n != 4 || !plain_ipv4(fields[0]) || !plain_ipv4(fields[1]) || !plain_port(fields[2]) || !host_port_ok(fields[3]))
        return false;
    const char *const parts[] = {
        "element ip lightbox proxied { ", fields[0], " }\n",
        "element ip lightbox proxy_to { ", fields[0], " . ", fields[1], " . ", fields[2], " }\n",
        "element bridge lightbox sealed { \"", fields[3], "\" }\n",
    };
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++)
        out_put(list, parts[i]);
    return true;
}

/* From a record, the elements of the sets; with removal, put in and taken
 * out again in one transaction, so that what is gone already does not keep
 * the rest in. */
bool nft_egress_text(const char *record, bool removal, char *text, size_t max) {
    size_t head = lc_string_length(NFT_RECORD_HEAD);
    if (!lc_string_starts_with(record, lc_string_length(record), NFT_RECORD_HEAD, head))
        return false;
    static char sets[512];
    struct text_out list = { .text = sets, .max = sizeof(sets), .pos = 0, .cut = false };
    sets[0] = '\0';
    const char *body = record + head;
    if (!(nft_record_is_proxy(body) ? proxy_elements(body, &list) : outside_elements(body, &list)))
        return false;
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = list.cut };
    text[0] = '\0';
    /* each line of the sets, as "add <line>" and with removal "delete <line>" after */
    for (int pass = 0; pass < (removal ? 2 : 1); pass++) {
        for (const char *line = sets; *line; ) {
            const char *end = line;
            while (*end != '\n') end++;
            out_put(&out, pass ? "delete " : "add ");
            char one[256];
            size_t len = (size_t)(end - line) + 1;
            if (len >= sizeof(one))
                return false;
            lc_bytes_copy(one, line, len);
            one[len] = '\0';
            out_put(&out, one);
            line = end + 1;
        }
    }
    return !out.cut;
}

static int nft_remove_egress(const char *record, const char *recorded) {
    static char text[FIREWALL_TEXT_MAX];
    if (!nft_egress_text(recorded, true, text, sizeof(text))) {
        print_str(STDERR, "Error: the record of the container's --net rules is not one lightbox writes: ");
        print_str(STDERR, record);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    const char *nft[] = { "nft", "-f", "-", NULL };
    bool gone = run_cmd_input(tool_path_nft(), nft, text, true) == 0;
    if (!gone) {
        /* without lightbox's set nothing of them is left */
        bool proxy = nft_record_is_proxy(recorded + lc_string_length(NFT_RECORD_HEAD));
        const char *look[] = { "nft", "list", "set", "ip", "lightbox", proxy ? "proxied" : "outside", NULL };
        gone = run_cmd_quiet(tool_path_nft(), look) != 0;
    }
    if (!gone) {
        print_str(STDERR, "Error: cannot take the container out of the nftables sets of its --net\n");
        return -1;
    }
    lc_kernel_unlinkat(AT_FDCWD, record, 0);
    return 0;
}

int firewall_remove_egress(const char *name) {
    char record[MAX_PATH];
    static char recorded[FIREWALL_TEXT_MAX];
    container_egress_path(record, name);
    if (!path_exists(record))
        return 0;
    int n = read_file(record, recorded, sizeof(recorded));
    if (n > 0 && n < (int)sizeof(recorded) - 1 &&
        lc_string_starts_with(recorded, (size_t)n, NFT_RECORD_HEAD, lc_string_length(NFT_RECORD_HEAD)))
        return nft_remove_egress(record, recorded);

    /* "<chain> <address>\n", and " proxy" before the end for --net proxy:
     * what a start put in, whatever lightbox started it */
    char *chain = recorded, *ip = NULL, *kind = NULL;
    if (n > 0 && chain[n - 1] == '\n')
        chain[--n] = '\0';
    for (int i = 0; n > 0 && i < n; i++) {
        if (chain[i] == ' ') {
            chain[i] = '\0';
            if (!ip) {
                ip = chain + i + 1;
            } else if (!kind) {
                kind = chain + i + 1;
            } else {
                ip = NULL;          /* more than three words */
                break;
            }
        }
    }
    bool proxy = kind && streq(kind, "proxy");
    if (!ip || (kind && !proxy) || !egress_chain_ok(chain) || !plain_ipv4(ip)) {
        print_str(STDERR, "Error: the record of the container's --net rules does not name a chain of lightbox's: ");
        print_str(STDERR, record);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    static char text[512];
    struct text_out out = { .text = text, .max = sizeof(text), .pos = 0, .cut = false };
    text[0] = '\0';
    out_put(&out, "*filter\n-D LIGHTBOX-EGRESS -s "); out_put(&out, ip); out_put(&out, " -j "); out_put(&out, chain);
    out_put(&out, "\n-F "); out_put(&out, chain);
    out_put(&out, "\n-X "); out_put(&out, chain);
    out_put(&out, "\n");
    if (proxy) {
        out_put(&out, "-D LIGHTBOX-LINKS -s "); out_put(&out, ip); out_put(&out, " -j DROP\n");
        out_put(&out, "-D LIGHTBOX-LINKS -d "); out_put(&out, ip); out_put(&out, " -j DROP\n");
    }
    out_put(&out, "COMMIT\n");
    const char *restore[] = { "iptables-restore", "--noflush", NULL };
    bool gone = !out.cut && run_cmd_input(tool_path_iptables_restore(), restore, text, true) == 0;
    if (!gone) {
        const char *jump[] = { "iptables", "-D", "LIGHTBOX-EGRESS", "-s", ip, "-j", chain, NULL };
        const char *flush[] = { "iptables", "-F", chain, NULL };
        const char *drop[] = { "iptables", "-X", chain, NULL };
        const char *look[] = { "iptables", "-n", "-L", chain, NULL };
        const char *from[] = { "iptables", "-D", "LIGHTBOX-LINKS", "-s", ip, "-j", "DROP", NULL };
        const char *to[] = { "iptables", "-D", "LIGHTBOX-LINKS", "-d", ip, "-j", "DROP", NULL };
        const char *has_from[] = { "iptables", "-C", "LIGHTBOX-LINKS", "-s", ip, "-j", "DROP", NULL };
        const char *has_to[] = { "iptables", "-C", "LIGHTBOX-LINKS", "-d", ip, "-j", "DROP", NULL };
        (void)iptables_delete_all(jump);
        (void)run_cmd_quiet(tool_path_iptables(), flush);
        (void)run_cmd_quiet(tool_path_iptables(), drop);
        if (proxy) {
            (void)iptables_delete_all(from);
            (void)iptables_delete_all(to);
        }
        gone = run_cmd_quiet(tool_path_iptables(), look) != 0 &&
               (!proxy || (iptables_check(has_from) != 0 && iptables_check(has_to) != 0));
    }
    if (!gone) {
        print_str(STDERR, "Error: cannot remove the firewall rules of the container's --net: ");
        print_str(STDERR, chain);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    lc_kernel_unlinkat(AT_FDCWD, record, 0);
    return 0;
}

/* ─── What a start puts in for a container ───────────────────────────────── */

/* The record of a container's rules, and the text that puts them in. */
struct rules_plan {
    char record[FIREWALL_TEXT_MAX];
    char text[FIREWALL_TEXT_MAX];
};

static bool links_plan(const char *name, const container_config *config, bool nftables, struct rules_plan *plan) {
    if (nftables)
        return nft_links_record(name, config, plan->record, sizeof(plan->record)) &&
               nft_links_text(plan->record, false, plan->text, sizeof(plan->text));
    char chain[IFNAME_TEXT_MAX];
    bool cut = false;
    link_chain_name(name, chain);
    str_append(plan->record, str_append(plan->record, 0, chain, sizeof(plan->record), &cut), "\n",
               sizeof(plan->record), &cut);
    return !cut && firewall_links_text(name, config, plan->text, sizeof(plan->text));
}

static bool egress_plan(const char *name, const char *ip, const container_config *config, bool nftables,
                        struct rules_plan *plan) {
    char gw[IPV4_TEXT_MAX];
    if (!gateway_text(gw))
        return false;
    if (nftables)
        return nft_egress_record(name, ip, gw, config, plan->record, sizeof(plan->record)) &&
               nft_egress_text(plan->record, false, plan->text, sizeof(plan->text));
    char chain[IFNAME_TEXT_MAX];
    bool cut = false;
    egress_chain_name(name, chain);
    size_t pos = str_append(plan->record, 0, chain, sizeof(plan->record), &cut);
    pos = str_append(plan->record, pos, " ", sizeof(plan->record), &cut);
    pos = str_append(plan->record, pos, ip, sizeof(plan->record), &cut);
    if (config->net == NET_PROXY)
        pos = str_append(plan->record, pos, " proxy", sizeof(plan->record), &cut);
    str_append(plan->record, pos, "\n", sizeof(plan->record), &cut);
    return !cut && firewall_egress_text(name, ip, gw, config, plan->text, sizeof(plan->text));
}

/* The text of a container's links and of the rules of its --net, as one: nft's
 * one after the other; for iptables-restore one table, the chains of both
 * declared before the rules of either. False when it does not fit. */
bool firewall_rules_text(bool nftables, const char *links, const char *egress, char *text, size_t max) {
    bool cut = false;
    size_t pos = 0;
    text[0] = '\0';
    const char *parts[2] = { links, egress };
    if (nftables) {
        pos = str_append(text, pos, parts[0], max, &cut);
        str_append(text, pos, parts[1], max, &cut);
        return !cut;
    }
    if (!links[0] && !egress[0])
        return true;
    pos = str_append(text, pos, "*filter\n", max, &cut);
    for (int rules = 0; rules < 2; rules++) {
        for (int k = 0; k < 2; k++) {
            for (const char *line = parts[k]; *line; ) {
                const char *end = line;
                while (*end && *end != '\n') end++;
                char one[256];
                size_t len = (size_t)(end - line);
                if (len >= sizeof(one) - 1) {
                    cut = true;
                } else if (rules ? line[0] == '-' : line[0] == ':') {
                    lc_bytes_copy(one, line, len);
                    one[len] = '\n';
                    one[len + 1] = '\0';
                    pos = str_append(text, pos, one, max, &cut);
                }
                line = *end ? end + 1 : end;
            }
        }
    }
    str_append(text, pos, "COMMIT\n", max, &cut);
    return !cut;
}

/*
 * The links and the --net rules of a container, either or both, put
 * in with one process: what an earlier run left of them taken out, then on
 * record before they are there, so that a command that is killed in between
 * leaves the record and the next one takes away what it names. 0, or -1 once
 * said.
 */
static int put_in(const char *name, struct rules_plan *links, struct rules_plan *egress) {
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;
    if ((links && firewall_remove_links(name) != 0) || (egress && firewall_remove_egress(name) != 0))
        return -1;
    char record[MAX_PATH];
    if (container_run_dir_make(name) != 0) {
        print_str(STDERR, "Error: cannot record the container's firewall rules\n");
        return -1;
    }
    if (links) {
        container_firewall_path(record, name);
        if (write_file_volatile(record, links->record) != 0) {
            print_str(STDERR, "Error: cannot record the firewall rules of the container's links\n");
            return -1;
        }
    }
    if (egress) {
        container_egress_path(record, name);
        if (write_file_volatile(record, egress->record) != 0) {
            print_str(STDERR, "Error: cannot record the firewall rules of the container's --net\n");
            return -1;
        }
    }

    static char text[2 * FIREWALL_TEXT_MAX];
    bool cut = !firewall_rules_text(nftables, links ? links->text : "", egress ? egress->text : "", text, sizeof(text));
    if (cut) {
        print_str(STDERR, "Error: the container's firewall rules are too long\n");
        return -1;
    }
    if (!text[0])
        return 0;
    if (nftables) {
        const char *nft[] = { "nft", "-f", "-", NULL };
        if (run_cmd_input(tool_path_nft(), nft, text, false) != 0) {
            print_str(STDERR, "Error: the container's links or --net rules could not be put in the nftables sets\n"
                              "of lightbox's tables; lightbox setup makes them\n");
            return -1;
        }
        return 0;
    }
    const char *restore[] = { "iptables-restore", "--noflush", NULL };
    if (run_cmd_input(tool_path_iptables_restore(), restore, text, false) != 0) {
        print_str(STDERR, "Error: the firewall rules of the container's links or --net could not be put in;\n"
                          "lightbox setup makes the chains they go into\n");
        return -1;
    }
    return 0;
}

int firewall_add_rules(const char *name, const char *ip, const container_config *config) {
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;
    static struct rules_plan links, egress;
    bool linked = config->nlinks > 0, ruled = net_has_rules(config->net);
    if (!linked && !ruled)
        return 0;
    if (linked && !links_plan(name, config, nftables, &links)) {
        print_str(STDERR, "Error: the firewall rules of the container's links are too long\n");
        return -1;
    }
    if (ruled && !egress_plan(name, ip, config, nftables, &egress)) {
        print_str(STDERR, "Error: the firewall rules of the container's --net are too long\n");
        return -1;
    }
    return put_in(name, linked ? &links : NULL, ruled ? &egress : NULL);
}

int firewall_add_links(const char *name, const container_config *config) {
    if (config->nlinks == 0)
        return 0;
    static struct rules_plan links;
    if (!links_plan(name, config, cfg_global.firewall_backend == FIREWALL_NFTABLES, &links)) {
        print_str(STDERR, "Error: the firewall rules of the container's links are too long\n");
        return -1;
    }
    return put_in(name, &links, NULL);
}

int firewall_add_egress(const char *name, const char *ip, const container_config *config) {
    if (!net_has_rules(config->net))
        return 0;
    static struct rules_plan egress;
    if (!egress_plan(name, ip, config, cfg_global.firewall_backend == FIREWALL_NFTABLES, &egress)) {
        print_str(STDERR, "Error: the firewall rules of the container's --net are too long\n");
        return -1;
    }
    return put_in(name, NULL, &egress);
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

/* ─── nftables ──────────────────────────────────────────────────────────── */

/* One number of a mark: decimal without a leading 0, which nft would take
 * for octal, or 0x and up to eight hex digits. */
static bool parse_mark_number(const char *s, size_t len, uint32_t *out) {
    uint64_t value = 0;
    if (len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        if (len - 2 > 8)
            return false;
        for (size_t i = 2; i < len; i++) {
            char c = s[i];
            int digit = c >= '0' && c <= '9' ? c - '0'
                      : c >= 'a' && c <= 'f' ? c - 'a' + 10
                      : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
            if (digit < 0)
                return false;
            value = value * 16 + (uint64_t)digit;
        }
    } else {
        if (len == 0 || len > 10 || (len > 1 && s[0] == '0'))
            return false;
        for (size_t i = 0; i < len; i++) {
            if (s[i] < '0' || s[i] > '9')
                return false;
            value = value * 10 + (uint64_t)(s[i] - '0');
        }
        if (value > 0xffffffffu)
            return false;
    }
    *out = (uint32_t)value;
    return true;
}

bool parse_fwmark(const char *text, uint32_t *mark, uint32_t *mask) {
    size_t len = lc_string_length(text), slash = len;
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '/') { slash = i; break; }
    }
    uint32_t m, k = 0xffffffffu;
    if (!parse_mark_number(text, slash, &m))
        return false;
    if (slash < len && !parse_mark_number(text + slash + 1, len - slash - 1, &k))
        return false;
    /* 0 is the mark of every packet that nothing marked, and a mark with
     * bits outside its mask is one that no packet has */
    if (m == 0 || k == 0 || (m & ~k) != 0)
        return false;
    *mark = m;
    *mask = k;
    return true;
}

static size_t put_hex32(char *out, uint32_t value) {
    static const char digits[] = "0123456789abcdef";
    char rev[8];
    size_t n = 0, len = 0;
    do { rev[n++] = digits[value & 0xf]; value >>= 4; } while (value);
    out[len++] = '0';
    out[len++] = 'x';
    while (n) out[len++] = rev[--n];
    return len;
}

void fwmark_text(char out[24], uint32_t mark, uint32_t mask) {
    size_t n = put_hex32(out, mark);
    if (mask != 0xffffffffu) {
        out[n++] = '/';
        n += put_hex32(out + n, mask);
    }
    out[n] = '\0';
}

bool host_port_ok(const char *ifname) {
    if (lc_string_length(ifname) != 15 || !lc_string_starts_with(ifname, 15, "vb-", 3))
        return false;
    for (size_t i = 3; i < 15; i++) {
        char c = ifname[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/* An interface name that can go between quotes in a rule as it is. */
static bool plain_ifname(const char *ifname) {
    size_t len = lc_string_length(ifname);
    if (len == 0 || len >= IFNAME_TEXT_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = ifname[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

/* "meta mark 0x10 accept", with the mask when there is one */
static void out_mark_accept(struct text_out *out, const char *family, const char *chain) {
    char number[24];
    out_put(out, "add rule ");
    out_put(out, family);
    out_put(out, " lightbox ");
    out_put(out, chain);
    out_put(out, " meta mark ");
    if (cfg_global.accept_fwmask != 0xffffffffu) {
        out_put(out, "& ");
        fwmark_text(number, cfg_global.accept_fwmask, 0xffffffffu);
        out_put(out, number);
        out_put(out, " == ");
    }
    fwmark_text(number, cfg_global.accept_fwmark, 0xffffffffu);
    out_put(out, number);
    out_put(out, " accept\n");
}

/*
 * What setup gives nft, in one transaction: both tables, made when they are
 * not there, their chains flushed and filled again, so that a second setup
 * changes nothing. The set of links is declared and not flushed: its
 * elements are the running containers'.
 */
bool nft_setup_text(const container_network *net, char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    const char *br = cfg_global.bridge;
    if (!plain_ifname(br))
        return false;
    char subnet[CIDR_TEXT_MAX];
    subnet_text(subnet, net);
    text[0] = '\0';
    /* --net outside: the containers' addresses, and each with its name
     * servers, are elements of sets that setup declares and does not flush,
     * as they are the running containers'. What one sends out of the bridge
     * goes through egress, and what it sends the host through egress_host,
     * which refuses it the host's every address: all that reaches input is
     * the host's own, broadcast or multicast. --net proxy: the containers'
     * addresses, and each with its proxy's address and port, the same way;
     * what one sends out of the bridge or to the host goes through
     * egress_proxy, which lets through what goes to its proxy and refuses the
     * rest. */
    out_put(&out,
        "table ip lightbox {\n"
        "\tset outside {\n\t\ttype ipv4_addr\n\t}\n"
        "\tset outside_dns {\n\t\ttype ipv4_addr . ipv4_addr\n\t}\n"
        "\tset proxied {\n\t\ttype ipv4_addr\n\t}\n"
        "\tset proxy_to {\n\t\ttype ipv4_addr . ipv4_addr . inet_service\n\t}\n"
        "\tset refused {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n"
        "\tchain egress {\n\t}\n"
        "\tchain egress_host {\n\t}\n"
        "\tchain egress_proxy {\n\t}\n"
        "\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n"
        "\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n"
        "\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t}\n"
        "}\n"
        "flush chain ip lightbox egress\n"
        "flush chain ip lightbox egress_host\n"
        "flush chain ip lightbox egress_proxy\n"
        "flush chain ip lightbox forward\n"
        "flush chain ip lightbox input\n"
        "flush chain ip lightbox postrouting\n"
        "flush set ip lightbox refused\n"
        "add element ip lightbox refused { ");
    for (size_t i = 0; i < NOUTSIDE_REFUSED; i++) {
        out_put(&out, i ? ", " : "");
        out_put(&out, OUTSIDE_REFUSED[i]);
    }
    out_put(&out, " }\n");
    if (cfg_global.accept_fwmark_set) {
        out_mark_accept(&out, "ip", "forward");
        out_mark_accept(&out, "ip", "input");
    }
    out_put(&out, "add rule ip lightbox forward oifname \""); out_put(&out, br);
    out_put(&out, "\" ct state established,related accept\n");
    out_put(&out, "add rule ip lightbox forward oifname \""); out_put(&out, br);
    out_put(&out, "\" iifname != \""); out_put(&out, br); out_put(&out, "\" drop\n");
    out_put(&out, "add rule ip lightbox forward iifname \""); out_put(&out, br);
    out_put(&out, "\" oifname != \""); out_put(&out, br); out_put(&out, "\" ip saddr @outside jump egress\n");
    out_put(&out, "add rule ip lightbox forward iifname \""); out_put(&out, br);
    out_put(&out, "\" oifname != \""); out_put(&out, br); out_put(&out, "\" ip saddr @proxied jump egress_proxy\n");
    out_put(&out, "add rule ip lightbox input iifname \""); out_put(&out, br);
    out_put(&out, "\" ip saddr @outside jump egress_host\n");
    out_put(&out, "add rule ip lightbox input iifname \""); out_put(&out, br);
    out_put(&out, "\" ip saddr @proxied jump egress_proxy\n");
    for (int host = 0; host < 2; host++) {
        const char *chain = host ? "egress_host" : "egress";
        static const char *const allowed[] = {
            " ct state established,related return\n",
            " ip saddr . ip daddr @outside_dns udp dport 53 return\n",
            " ip saddr . ip daddr @outside_dns tcp dport 53 return\n",
        };
        for (size_t i = 0; i < 3; i++) {
            out_put(&out, "add rule ip lightbox ");
            out_put(&out, chain);
            out_put(&out, allowed[i]);
        }
        /* refused as OUTSIDE_REJECT_TCP says, TCP with a reset */
        for (int tcp = 1; tcp >= 0; tcp--) {
            out_put(&out, "add rule ip lightbox ");
            out_put(&out, chain);
            out_put(&out, host ? "" : " ip daddr @refused");
            out_put(&out, tcp ? " meta l4proto tcp reject with tcp reset\n" : " reject with icmp type admin-prohibited\n");
        }
    }
    out_put(&out,
        "add rule ip lightbox egress_proxy ct state established,related return\n"
        "add rule ip lightbox egress_proxy ip saddr . ip daddr . tcp dport @proxy_to return\n"
        "add rule ip lightbox egress_proxy meta l4proto tcp reject with tcp reset\n"
        "add rule ip lightbox egress_proxy reject with icmp type admin-prohibited\n");
    if (cfg_global.ip_masq) {
        out_put(&out, "add rule ip lightbox postrouting ip saddr "); out_put(&out, subnet);
        out_put(&out, " oifname != \""); out_put(&out, br); out_put(&out, "\" masquerade\n");
    }
    out_put(&out,
        "table bridge lightbox {\n"
        "\tset links {\n\t\ttype ifname . ifname\n\t}\n"
        "\tset sealed {\n\t\ttype ifname\n\t}\n"
        "\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n"
        "}\n"
        "flush chain bridge lightbox forward\n");
    if (cfg_global.accept_fwmark_set)
        out_mark_accept(&out, "bridge", "forward");
    /* the ports of containers of --net proxy, before any link: what names
     * one with --link does not reach it */
    for (int to = 0; to < 2; to++) {
        out_put(&out, "add rule bridge lightbox forward meta ibrname \""); out_put(&out, br);
        out_put(&out, to ? "\" oifname @sealed drop\n" : "\" iifname @sealed drop\n");
    }
    out_put(&out, "add rule bridge lightbox forward meta ibrname \""); out_put(&out, br);
    out_put(&out, "\" iifname . oifname @links accept\n");
    out_put(&out, "add rule bridge lightbox forward meta ibrname \""); out_put(&out, br);
    out_put(&out, "\" drop\n");
    return !out.cut;
}

bool nft_links_record(const char *name, const container_config *config, char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    char port[IFNAME_TEXT_MAX], seen[MAX_LINKS][IFNAME_TEXT_MAX];
    int nseen = 0;
    host_port_name(name, port);
    text[0] = '\0';
    out_put(&out, NFT_RECORD_HEAD);
    for (int i = 0; i < config->nlinks && nseen < MAX_LINKS; i++) {
        char other[IFNAME_TEXT_MAX];
        host_port_name(config->links[i], other);
        /* a pair that is there once: nft takes out each element once */
        bool again = streq(other, port);
        for (int j = 0; j < nseen && !again; j++)
            again = streq(seen[j], other);
        if (again)
            continue;
        lc_bytes_copy(seen[nseen++], other, IFNAME_TEXT_MAX);
        out_put(&out, port);
        out_put(&out, " ");
        out_put(&out, other);
        out_put(&out, "\n");
    }
    return !out.cut;
}

bool nft_links_text(const char *record, bool removal, char *text, size_t max) {
    size_t head = lc_string_length(NFT_RECORD_HEAD);
    if (!lc_string_starts_with(record, lc_string_length(record), NFT_RECORD_HEAD, head))
        return false;
    static char elements[FIREWALL_TEXT_MAX];
    struct text_out list = { .text = elements, .max = sizeof(elements), .pos = 0, .cut = false };
    elements[0] = '\0';
    int pairs = 0;
    /* "<port> <other>\n" for each link, each a name host_port_name gives */
    for (const char *line = record + head; *line; ) {
        const char *end = line;
        while (*end && *end != '\n') end++;
        if (*end != '\n' || end - line != 31 || line[15] != ' ')
            return false;
        char a[IFNAME_TEXT_MAX], b[IFNAME_TEXT_MAX];
        lc_bytes_copy(a, line, 15);
        a[15] = '\0';
        lc_bytes_copy(b, line + 16, 15);
        b[15] = '\0';
        if (!host_port_ok(a) || !host_port_ok(b) || streq(a, b))
            return false;
        for (int back = 0; back < 2; back++) {
            out_put(&list, pairs++ ? ", \"" : "{ \"");
            out_put(&list, back ? b : a);
            out_put(&list, "\" . \"");
            out_put(&list, back ? a : b);
            out_put(&list, "\"");
        }
        line = end + 1;
    }
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = list.cut };
    text[0] = '\0';
    if (pairs == 0)
        return !out.cut;
    out_put(&list, " }\n");
    out_put(&out, "add element bridge lightbox links ");
    out_put(&out, elements);
    if (removal) {
        out_put(&out, "delete element bridge lightbox links ");
        out_put(&out, elements);
    }
    return !out.cut && !list.cut;
}

size_t forward_drop_chains(char *listing, char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    char table[64] = "", chain[64] = "";
    size_t found = 0;
    text[0] = '\0';
    for (char *line = listing; *line; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        bool last = *end == '\0';
        *end = '\0';
        while (*line == ' ' || *line == '\t') line++;
        size_t len = lc_string_length(line);
        /* "table <family> <name> {", "chain <name> {" */
        bool opens = len > 2 && line[len - 1] == '{' && line[len - 2] == ' ';
        if (opens && lc_string_starts_with(line, len, "table ", 6)) {
            line[len - 2] = '\0';
            bool cut = false;
            str_append(table, 0, line + 6, sizeof(table), &cut);
            chain[0] = '\0';
        } else if (opens && lc_string_starts_with(line, len, "chain ", 6)) {
            line[len - 2] = '\0';
            bool cut = false;
            str_append(chain, 0, line + 6, sizeof(chain), &cut);
        } else if (lc_string_starts_with(line, len, "type ", 5) && chain[0] &&
                   (lc_string_starts_with(table, lc_string_length(table), "ip ", 3) ||
                    lc_string_starts_with(table, lc_string_length(table), "inet ", 5) ||
                    lc_string_starts_with(table, lc_string_length(table), "bridge ", 7))) {
            /* "type filter hook forward priority filter; policy drop;" */
            bool forward = false, drop = false;
            for (const char *p = line; *p; p++) {
                if (lc_string_starts_with(p, lc_string_length(p), " hook forward ", 14)) forward = true;
                if (lc_string_starts_with(p, lc_string_length(p), " policy drop;", 13)) drop = true;
            }
            if (forward && drop) {
                if (found++)
                    out_put(&out, ", ");
                out_put(&out, table);
                out_put(&out, " ");
                out_put(&out, chain);
            }
        }
        line = last ? end : end + 1;
    }
    return found;
}

void forward_drops_on_host(char *text, size_t max) {
    struct text_out out = { .text = text, .max = max, .pos = 0, .cut = false };
    text[0] = '\0';
    static char listing[65536];
    bool iptables_drops = false;
    if (path_exists(tool_path_iptables())) {
        const char *list[] = { "iptables", "-S", "FORWARD", NULL };
        iptables_drops = run_cmd_capture_quiet(tool_path_iptables(), list, listing, sizeof(listing)) == 0 &&
                         lc_string_starts_with(listing, lc_string_length(listing), "-P FORWARD DROP\n", 16);
        if (iptables_drops)
            out_put(&out, "iptables FORWARD");
    }
    if (!path_exists(tool_path_nft()))
        return;
    const char *list[] = { "nft", "list", "chains", NULL };
    if (run_cmd_capture_quiet(tool_path_nft(), list, listing, sizeof(listing)) != 0)
        return;
    static char chains[1024];
    if (forward_drop_chains(listing, chains, sizeof(chains)) == 0)
        return;
    /* iptables-nft's FORWARD is the nftables chain "ip filter FORWARD" */
    char *chain = chains;
    while (*chain) {
        char *next = chain;
        while (*next && !(next[0] == ',' && next[1] == ' ')) next++;
        bool more = *next != '\0';
        *next = '\0';
        if (!(iptables_drops && streq(chain, "ip filter FORWARD"))) {
            if (out.pos)
                out_put(&out, ", ");
            out_put(&out, chain);
        }
        chain = more ? next + 2 : next;
    }
}

/* The interface of the default route, if there is one. */
static bool find_wan_interface(char *wan_if, size_t bufsz) {
    rtnl nl;
    if (rtnl_open(&nl) < 0)
        return false;
    char name[IFNAME_TEXT_MAX];
    int index = rtnl_default_route_index(&nl);
    bool found = index > 0 && rtnl_link_name(&nl, index, name) == 0 && str_copy(wan_if, name, bufsz);
    rtnl_close(&nl);
    return found;
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

/* ─── What the firewall needs of the kernel (ROADMAP R.3) ──────────────── */

/*
 * The extensions of iptables that the rules of firewall_setup_text and of a
 * container's links use, each as the kernel registers it, the modules that
 * give it and the option that builds them. iptables-nft takes them from the
 * kernel as the legacy one does, through nft_compat.
 */
enum { XT_ALWAYS, XT_MASQ, XT_LINKS };
static const struct {
    const char *name;
    bool target;
    const char *modules[2];
    const char *config;
    int when;
} XT_NEEDS[] = {
    { "REJECT",     true,  { "ipt_REJECT", NULL },              "CONFIG_IP_NF_TARGET_REJECT",            XT_ALWAYS },
    { "MASQUERADE", true,  { "xt_MASQUERADE", "ipt_MASQUERADE" }, "CONFIG_NETFILTER_XT_TARGET_MASQUERADE", XT_MASQ },
    { "conntrack",  false, { "xt_conntrack", NULL },            "CONFIG_NETFILTER_XT_MATCH_CONNTRACK",   XT_ALWAYS },
    { "addrtype",   false, { "xt_addrtype", NULL },             "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE",    XT_ALWAYS },
    { "tcp",        false, { "xt_tcpudp", NULL },               "CONFIG_NETFILTER_XTABLES",              XT_ALWAYS },
    { "physdev",    false, { "xt_physdev", NULL },              "CONFIG_NETFILTER_XT_MATCH_PHYSDEV",     XT_LINKS },
};

/* Is name a line of the text? */
static bool text_has_line(const char *text, const char *name) {
    size_t len = lc_string_length(name);
    for (const char *p = text; *p; ) {
        const char *end = p;
        while (*end && *end != '\n')
            end++;
        if ((size_t)(end - p) == len && lc_bytes_compare(p, name, len) == 0)
            return true;
        p = *end ? end + 1 : end;
    }
    return false;
}

/*
 * Which of the needles a file has in it, read a piece at a time: a list of
 * modules is a megabyte on some hosts. found[i] is set for each one there;
 * false when the file cannot be read.
 */
static bool file_mentions(const char *path, const char *const needles[], bool found[], size_t count) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return false;
    static char buf[65536 + 64];
    size_t kept = 0;          /* the end of the piece before, which a needle may begin in */
    for (;;) {
        lc_sysret n = lc_kernel_read_retry((int32_t)fd, buf + kept, sizeof(buf) - 1 - kept);
        if (n <= 0)
            break;
        size_t have = kept + (size_t)n;
        buf[have] = '\0';
        for (size_t i = 0; i < count; i++) {
            size_t len = lc_string_length(needles[i]);
            for (size_t at = 0; !found[i] && at + len <= have; at++)
                found[i] = buf[at] == needles[i][0] && lc_bytes_compare(buf + at, needles[i], len) == 0;
        }
        kept = have < 63 ? have : 63;
        lc_bytes_move(buf, buf + have - kept, kept);
    }
    lc_kernel_close_file((int32_t)fd);
    return true;
}

int iptables_kernel_missing(const char *proc_net, const char *modules, char *missing, size_t max,
                            char *links, size_t links_max) {
    char path[MAX_PATH];
    static char targets[4096], matches[8192];
    bool registered = path_join(path, sizeof(path), proc_net, "ip_tables_targets") &&
                      read_file(path, targets, sizeof(targets)) >= 0 &&
                      path_join(path, sizeof(path), proc_net, "ip_tables_matches") &&
                      read_file(path, matches, sizeof(matches)) >= 0;
    if (!registered)
        targets[0] = matches[0] = '\0';

    /* "/<module>.ko", as modules.dep and modules.builtin name a module's file,
     * compressed or not */
    enum { MAX_NEEDLES = 2 * (sizeof(XT_NEEDS) / sizeof(XT_NEEDS[0])) };
    char names[MAX_NEEDLES][40];
    const char *needles[MAX_NEEDLES];
    bool found[MAX_NEEDLES] = { false };
    size_t count = 0;
    for (size_t i = 0; i < sizeof(XT_NEEDS) / sizeof(XT_NEEDS[0]); i++)
        for (size_t m = 0; m < 2 && XT_NEEDS[i].modules[m]; m++) {
            bool cut = false;
            str_append(names[count], str_append(names[count], str_append(names[count], 0, "/", 40, &cut),
                                                XT_NEEDS[i].modules[m], 40, &cut), ".ko", 40, &cut);
            needles[count] = names[count];
            count++;
        }
    bool listed = false;
    static const char *const lists[] = { "modules.builtin", "modules.dep" };
    for (size_t l = 0; l < 2; l++)
        listed = (path_join(path, sizeof(path), modules, lists[l]) && file_mentions(path, needles, found, count)) ||
                 listed;
    missing[0] = links[0] = '\0';
    if (!registered && !listed)
        return -1;

    size_t pos = 0, lpos = 0, at = 0;
    bool cut = false;
    for (size_t i = 0; i < sizeof(XT_NEEDS) / sizeof(XT_NEEDS[0]); i++) {
        bool there = text_has_line(XT_NEEDS[i].target ? targets : matches, XT_NEEDS[i].name);
        for (size_t m = 0; m < 2 && XT_NEEDS[i].modules[m]; m++, at++)
            there = there || found[at];
        if (there || (XT_NEEDS[i].when == XT_MASQ && !cfg_global.ip_masq))
            continue;
        char *out = XT_NEEDS[i].when == XT_LINKS ? links : missing;
        size_t *p = XT_NEEDS[i].when == XT_LINKS ? &lpos : &pos;
        size_t room = XT_NEEDS[i].when == XT_LINKS ? links_max : max;
        *p = str_append(out, *p, *p ? "; " : "", room, &cut);
        *p = str_append(out, *p, XT_NEEDS[i].name, room, &cut);
        *p = str_append(out, *p, XT_NEEDS[i].target ? " target (" : " match (", room, &cut);
        *p = str_append(out, *p, XT_NEEDS[i].modules[0], room, &cut);
        *p = str_append(out, *p, ", ", room, &cut);
        *p = str_append(out, *p, XT_NEEDS[i].config, room, &cut);
        *p = str_append(out, *p, ")", room, &cut);
    }
    return missing[0] ? 0 : 1;
}

bool kernel_module_listed(const char *modules, const char *name, bool *listed) {
    char needle[64], path[MAX_PATH];
    bool cut = false, found[1] = { false };
    str_append(needle, str_append(needle, str_append(needle, 0, "/", sizeof(needle), &cut), name, sizeof(needle), &cut),
               ".ko", sizeof(needle), &cut);
    const char *needles[1] = { needle };
    *listed = false;
    static const char *const lists[] = { "modules.builtin", "modules.dep" };
    for (size_t l = 0; l < 2 && !cut; l++)
        *listed = (path_join(path, sizeof(path), modules, lists[l]) && file_mentions(path, needles, found, 1)) || *listed;
    return found[0];
}

bool running_kernel_modules(char out[MAX_PATH]) {
    char release[128];
    int n = read_file("/proc/sys/kernel/osrelease", release, sizeof(release));
    while (n > 0 && (release[n - 1] == '\n' || release[n - 1] == ' '))
        release[--n] = '\0';
    if (n <= 0)
        return false;
    static const char *const roots[] = { "/lib/modules", "/usr/lib/modules" };
    for (size_t i = 0; i < 2; i++)
        if (path_join(out, MAX_PATH, roots[i], release) && path_is_directory(out))
            return true;
    return path_join(out, MAX_PATH, roots[0], release);
}

int nft_kernel_check(const container_network *net, char *said, size_t max) {
    said[0] = '\0';
    static char text[FIREWALL_TEXT_MAX];
    if (!plain_ifname(cfg_global.bridge) || !nft_setup_text(net, text, sizeof(text)) ||
        !path_executable(tool_path_nft()))
        return -1;
    const char *check[] = { "nft", "--check", "-f", "-", NULL };
    return run_cmd_input_capture(tool_path_nft(), check, text, said, max) == 0 ? 1 : 0;
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
        { "filter", "LIGHTBOX-USER" }, { "filter", "LIGHTBOX-LINKS" }, { "filter", "LIGHTBOX-EGRESS" },
        { "filter", "LIGHTBOX-OUTSIDE" }, { "filter", "LIGHTBOX-INPUT" },
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
    if (run_cmd_input(tool_path_iptables_restore(), restore, text, false) != 0) {
        /* what of the kernel's the rules needed, where that is what failed */
        char modules[MAX_PATH];
        static char missing[512], links[256];
        if (running_kernel_modules(modules) &&
            iptables_kernel_missing("/proc/net", modules, missing, sizeof(missing), links, sizeof(links)) == 0) {
            print_str(STDERR, "Error: setup's iptables rules could not be put in: the kernel has no ");
            print_str(STDERR, missing);
            print_str(STDERR, ".\nfirewall_backend = nftables in lightbox.conf needs none of them, and nf_tables' bridge family\n"
                              "instead; lightbox doctor checks the kernel for either\n");
            lc_kernel_exit(failure_status);
        }
        die("Error: setup's iptables rules could not be put in. They need iptables with connection tracking,\n"
            "the addrtype match and the REJECT and MASQUERADE targets; lightbox doctor checks the kernel for them");
    }

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
    /* --net outside: what containers send the host itself, at the top of
     * INPUT, before the host's own rules */
    const char *has_input[] = { "iptables", "-C", "INPUT", "-j", "LIGHTBOX-INPUT", NULL };
    const char *ins_input[] = { "iptables", "-I", "INPUT", "1", "-j", "LIGHTBOX-INPUT", NULL };
    iptables_idempotent(has_input, ins_input);

    int old = forget_old_rules(net);
    if (old > 0) {
        char digits[16];
        fmt_int(digits, old);
        print_str(STDOUT, "Removed ");
        print_str(STDOUT, digits);
        print_str(STDOUT, " firewall rules that an earlier lightbox put straight into FORWARD and POSTROUTING;\n"
                          "a running container with links has its link rules back when it is started again\n");
    }
    print_str(STDOUT, "Firewall rules are in LIGHTBOX-FORWARD, LIGHTBOX-LINKS, LIGHTBOX-POSTROUTING, and for\n"
                      "--net outside LIGHTBOX-INPUT, LIGHTBOX-EGRESS and LIGHTBOX-OUTSIDE; rules of this\n"
                      "host's that are to decide first go in LIGHTBOX-USER\n");
}

/* Whether this setup took away what lightbox had made with the other
 * firewall backend: the running containers' links and --net outside rules
 * went with it, and setup puts them back in the one it made. */
static bool backend_switched;

/* The chains of containers' --net outside, flushed and taken away. */
static void forget_egress_chains(void) {
    static char rules[65536];
    const char *list[] = { "iptables", "-S", NULL };
    if (run_cmd_capture_quiet(tool_path_iptables(), list, rules, sizeof(rules)) != 0)
        return;
    for (char *line = rules; *line; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        bool last = *end == '\0';
        *end = '\0';
        if (lc_string_starts_with(line, lc_string_length(line), "-N ", 3) && egress_chain_ok(line + 3)) {
            const char *flush[] = { "iptables", "-F", line + 3, NULL };
            const char *drop[] = { "iptables", "-X", line + 3, NULL };
            (void)run_cmd_quiet(tool_path_iptables(), flush);
            (void)run_cmd_quiet(tool_path_iptables(), drop);
        }
        line = last ? end : end + 1;
    }
}

/*
 * With firewall_backend = nftables: what lightbox put in iptables taken out,
 * as Docker takes out its iptables rules when it starts with nftables. The
 * host's LIGHTBOX-USER stays, and the jump to it. The chain of a running
 * container's links is taken out when the container stops.
 */
static void forget_iptables_chains(const container_network *net, bool teardown) {
    if (!path_exists(tool_path_iptables()))
        return;
    int old = forget_old_rules(net);
    bool forward = iptables_chain_exists("filter", "LIGHTBOX-FORWARD");
    bool links = iptables_chain_exists("filter", "LIGHTBOX-LINKS");
    bool post = iptables_chain_exists("nat", "LIGHTBOX-POSTROUTING");
    bool input = iptables_chain_exists("filter", "LIGHTBOX-INPUT");
    bool egress = iptables_chain_exists("filter", "LIGHTBOX-EGRESS");
    bool outside = iptables_chain_exists("filter", "LIGHTBOX-OUTSIDE");
    if (forward || links || post || input || egress || outside) {
        const char *jump[] = { "iptables", "-D", "FORWARD", "-j", "LIGHTBOX-FORWARD", NULL };
        const char *in_jump[] = { "iptables", "-D", "INPUT", "-j", "LIGHTBOX-INPUT", NULL };
        const char *nat_jump[] = { "iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "LIGHTBOX-POSTROUTING", NULL };
        (void)iptables_delete_all(jump);
        (void)iptables_delete_all(in_jump);
        (void)iptables_delete_all(nat_jump);
        static const struct { const char *table, *chain; } ours[] = {
            { "filter", "LIGHTBOX-FORWARD" }, { "filter", "LIGHTBOX-INPUT" }, { "filter", "LIGHTBOX-LINKS" },
            { "filter", "LIGHTBOX-EGRESS" }, { "filter", "LIGHTBOX-OUTSIDE" }, { "nat", "LIGHTBOX-POSTROUTING" },
        };
        /* All flushed before any goes: LIGHTBOX-FORWARD jumps to LIGHTBOX-LINKS,
         * and the chain of a container's --net outside to LIGHTBOX-OUTSIDE.
         * Those chains go too, so that LIGHTBOX-OUTSIDE can; a stop finds
         * them gone. */
        for (size_t i = 0; i < sizeof(ours) / sizeof(ours[0]); i++) {
            const char *step[] = { "iptables", "-t", ours[i].table, "-F", ours[i].chain, NULL };
            (void)run_cmd_quiet(tool_path_iptables(), step);
        }
        forget_egress_chains();
        for (size_t i = 0; i < sizeof(ours) / sizeof(ours[0]); i++) {
            const char *step[] = { "iptables", "-t", ours[i].table, "-X", ours[i].chain, NULL };
            (void)run_cmd_quiet(tool_path_iptables(), step);
        }
        backend_switched = !teardown;
        print_str(STDOUT, teardown ? "Removed lightbox's iptables chains\n"
                                   : "Removed the iptables chains that lightbox made with firewall_backend = iptables.\n"
                                     "LIGHTBOX-USER is this host's and stays; its rules still run in FORWARD\n");
    }
    if (old > 0)
        print_str(STDOUT, "Removed the firewall rules that an earlier lightbox put straight into FORWARD and POSTROUTING\n");
}

/* With firewall_backend = iptables: the tables of nftables taken away. */
static void forget_nft_tables(void) {
    if (!path_exists(tool_path_nft()))
        return;
    static char tables[4096];
    const char *list[] = { "nft", "list", "tables", NULL };
    if (run_cmd_capture_quiet(tool_path_nft(), list, tables, sizeof(tables)) != 0)
        return;
    bool ip = false, bridge = false;
    for (char *line = tables; *line; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        bool last = *end == '\0';
        *end = '\0';
        ip = ip || streq(line, "table ip lightbox");
        bridge = bridge || streq(line, "table bridge lightbox");
        line = last ? end : end + 1;
    }
    if (!ip && !bridge)
        return;
    const char *text = ip && bridge ? "delete table ip lightbox\ndelete table bridge lightbox\n"
                     : ip ? "delete table ip lightbox\n" : "delete table bridge lightbox\n";
    const char *nft[] = { "nft", "-f", "-", NULL };
    if (run_cmd_input(tool_path_nft(), nft, text, false) != 0)
        print_str(STDERR, "Warning: the nftables tables that lightbox made with firewall_backend = nftables\n"
                          "could not be removed\n");
    else {
        backend_switched = true;
        print_str(STDOUT, "Removed the nftables tables that lightbox made with firewall_backend = nftables\n");
    }
}

/* What drops what lightbox's nftables rules accept, said: an accept in one
 * table does not get a packet past another that drops it. */
static void warn_forward_drops(void) {
    static char drops[1024];
    forward_drops_on_host(drops, sizeof(drops));
    if (!drops[0])
        return;
    print_str(STDOUT, "Warning: on this host forwarded packets that nothing accepts are dropped by:\n  ");
    print_str(STDOUT, drops);
    print_str(STDOUT, "\nand those are dropped there whatever lightbox's nftables rules accept, so containers\n"
                      "reach this host and nothing beyond it. As Docker asks of its nftables backend,\n"
                      "set their policy to accept (iptables -P FORWARD ACCEPT for iptables), or accept the\n"
                      "bridge's traffic in them\n");
}

/*
 * firewall_backend = nftables: lightbox's two tables, in one transaction,
 * and nothing of lightbox's left in iptables.
 */
static void nft_firewall_setup(const container_network *net) {
    require_tool("nft", tool_path_nft());
    if (!plain_ifname(cfg_global.bridge))
        die2("Error: bridge in lightbox.conf is not an interface name nft can be given: ", cfg_global.bridge);
    static char text[FIREWALL_TEXT_MAX];
    if (!nft_setup_text(net, text, sizeof(text)))
        die("Error: setup's firewall rules are too long");
    const char *nft[] = { "nft", "-f", "-", NULL };
    if (run_cmd_input(tool_path_nft(), nft, text, false) != 0)
        die("Error: setup's nftables rules could not be put in. They need nf_tables with NAT,\n"
            "masquerading, connection tracking and the bridge family (CONFIG_NF_TABLES_BRIDGE)");
    forget_iptables_chains(net, false);
    print_str(STDOUT, "Firewall rules are in the nftables tables ip lightbox and bridge lightbox. To accept\n"
                      "what they drop, give it the mark of bridge_accept_fwmark in a chain of this host's\n"
                      "that comes before theirs\n");
    warn_forward_drops();
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
    lc_kernel_exit(failure_status);
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

static bool forwarding_on(void) {
    char forwarding[8];
    return read_file("/proc/sys/net/ipv4/ip_forward", forwarding, sizeof(forwarding)) > 0 && forwarding[0] == '1';
}

/* Forwarding is a part of lightbox's host network only where lightbox makes
 * the rules that say what is forwarded. With firewall = false it makes none:
 * forwarding is then this host's own, to turn on with the host's rules or to
 * leave off, and lightbox neither turns it on nor waits for it. */
static bool forwarding_wanted(void) {
    return cfg_global.ip_forward && cfg_global.firewall;
}

bool host_forwarding_left_off(void) {
    return cfg_global.ip_forward && !cfg_global.firewall && !forwarding_on();
}

/* With nftables, forwarding that is needed is on already, as Docker has it:
 * lightbox would have no DROP policy to turn it on with. */
static void require_forwarding_for_nftables(void) {
    if (cfg_global.firewall_backend == FIREWALL_NFTABLES && forwarding_wanted() && !forwarding_on())
        die("Error: IPv4 forwarding is off. With firewall_backend = nftables lightbox does not turn it\n"
            "on, as Docker does not: turn it on with rules of this host's against forwarding between\n"
            "its other interfaces (sysctl -w net.ipv4.ip_forward=1), or set ip_forward = false in\n"
            "lightbox.conf, and containers reach this host and nothing beyond it");
}

/* <run_dir>/.forwarding: what setup changed of forwarding, for teardown to
 * say. No container is called that: a name has no dot. */
static void forwarding_record_path(char out[MAX_PATH]) {
    path_join_or_die(out, MAX_PATH, cfg_global.run_dir, ".forwarding");
}

/*
 * The bridge, the firewall rules and forwarding, which setup makes and start
 * makes again when a reboot took them. Under the store's lock.
 */
static void host_network_setup(const container_network *net) {
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;
    require_forwarding_for_nftables();
    {
        const char *br = cfg_global.bridge;
        rtnl nl;
        int rc = rtnl_open(&nl);
        if (rc < 0)
            die_errno("no netlink socket to make the bridge with", "", rc);
        int index = rtnl_link_get(&nl, br, NULL, 0);
        if (index == -LB_ENODEV) {
            print_str(STDOUT, "Creating bridge ");
            print_str(STDOUT, br);
            print_str(STDOUT, "...\n");
            if ((rc = rtnl_bridge_add(&nl, br)) < 0)
                die_errno("cannot make the bridge ", br, rc);
            if ((index = rtnl_link_get(&nl, br, NULL, 0)) < 0)
                die_errno("cannot find the bridge it made, ", br, index);
            if ((rc = rtnl_addr_add(&nl, index, net->gateway, net->prefix)) < 0)
                die_errno("cannot give its address to the bridge ", br, rc);
            if ((rc = rtnl_link_up(&nl, br)) < 0)
                die_errno("cannot bring up the bridge ", br, rc);
        } else if (index < 0) {
            die_errno("cannot look for the bridge ", br, index);
        } else {
            print_str(STDOUT, "Bridge ");
            print_str(STDOUT, br);
            print_str(STDOUT, " already exists, skipping\n");
        }
        rtnl_close(&nl);
    }

    if (!cfg_global.firewall) {
        print_str(STDOUT, "firewall = false in lightbox.conf: no firewall rules were made\n");
    } else if (nftables) {
        nft_firewall_setup(net);
    } else {
        firewall_setup(net);
        forget_nft_tables();
    }

    /*
     * Forwarding, as Docker does it: when setup is the one that turns it on,
     * the FORWARD policy becomes DROP first, so that the host forwards what a
     * rule accepts and nothing else. A host that had forwarding on already
     * keeps its policy, and ip_forward_no_drop keeps it in any case. What
     * was changed goes on record, for teardown to say.
     *
     * With firewall = false lightbox has made no rule, and turning forwarding
     * on would have this host forward between all its interfaces with nothing
     * of lightbox's to say what: it is left as it is, and that is said.
     */
    bool was_on = forwarding_on();
    if (!was_on && cfg_global.ip_forward && !cfg_global.firewall) {
        print_str(STDOUT, "Warning: IPv4 forwarding is off, and firewall = false in lightbox.conf: lightbox makes\n"
                          "no rule that says what this host forwards, so it leaves forwarding as it is.\n"
                          "Containers reach this host and nothing beyond it until forwarding is on, with rules\n"
                          "of this host's (sysctl -w net.ipv4.ip_forward=1)\n");
    } else if (!was_on && cfg_global.ip_forward && !nftables) {
        bool drop = !cfg_global.ip_forward_no_drop;
        if (drop) {
            const char *policy[] = { "iptables", "-P", "FORWARD", "DROP", NULL };
            require_cmd(tool_path_iptables(), policy);
            print_str(STDOUT, "IPv4 forwarding was off. It is on, and the FORWARD policy is DROP: this host\n"
                              "forwards what a rule accepts and nothing else (ip_forward_no_drop = true\n"
                              "in lightbox.conf leaves the policy as it is)\n");
        } else {
            print_str(STDOUT, "IPv4 forwarding was off, and is on\n");
        }
        require_write_file("/proc/sys/net/ipv4/ip_forward", "1");
        char record[MAX_PATH];
        forwarding_record_path(record);
        ensure_private_dir(cfg_global.run_dir);
        if (write_file_volatile(record, drop ? "on drop\n" : "on\n") != 0)
            print_str(STDERR, "Warning: what setup changed of forwarding could not be recorded\n");
    } else if (!was_on) {
        print_str(STDOUT, "Warning: IPv4 forwarding is off, and ip_forward = false in lightbox.conf:\n"
                          "containers reach this host and nothing beyond it\n");
    }
}

/*
 * The link rules of every container that runs, put in again: after a
 * firewall's reload or flush took them, as podman network reload puts back
 * its containers' rules, or after a start made the network again. A
 * container that a command is working on is left to it: a start puts its
 * links in itself, and a stop takes them out. except: the container of the
 * command that asks, NULL for none. How many could not be put back.
 */
int put_back_running_links(const char *except) {
    if (!cfg_global.firewall)
        return 0;           /* no container with links starts */
    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    static container_config config;
    bool more = false;
    int failed = 0;
    int count = list_containers(names, MAX_LISTED, &more);
    for (int i = 0; i < count; i++) {
        if (except && streq(names[i], except))
            continue;
        int32_t lock = container_lock_try(names[i]);
        if (lock < 0) {
            print_str(STDERR, "Note: a lightbox command is working on container '");
            print_str(STDERR, names[i]);
            print_str(STDERR, "': its links are left to it; if they are not there when it is done,\n"
                              "lightbox reload puts them back\n");
            continue;
        }
        if (is_running(names[i])) {
            const char *wrong = container_config_load(names[i], &config);
            if (wrong) {
                print_str(STDERR, "Error: the configuration of running container '");
                print_str(STDERR, names[i]);
                print_str(STDERR, "' cannot be read, so its links are not put back: ");
                print_str(STDERR, wrong);
                lc_print_char(STDERR, '\n');
                failed++;
            } else {
                if (config.nlinks > 0) {
                    if (firewall_add_links(names[i], &config) == 0) {
                        print_str(STDOUT, "The links of container '");
                        print_str(STDOUT, names[i]);
                        print_str(STDOUT, "' are in again\n");
                    } else {
                        failed++;
                    }
                }
                char ip[IPV4_TEXT_MAX], mode[NET_MODE_TEXT_MAX];
                net_mode_text(mode, config.net, config.proxy_port);
                if (!net_has_rules(config.net)) {
                    /* nothing to put back */
                } else if (read_container_ip(names[i], ip, sizeof(ip)) != 0 ||
                           firewall_add_egress(names[i], ip, &config) != 0) {
                    print_str(STDERR, "Error: the --net ");
                    print_str(STDERR, mode);
                    print_str(STDERR, " rules of running container '");
                    print_str(STDERR, names[i]);
                    print_str(STDERR, "' are not in again\n");
                    failed++;
                } else {
                    print_str(STDOUT, "The --net ");
                    print_str(STDOUT, mode);
                    print_str(STDOUT, " rules of container '");
                    print_str(STDOUT, names[i]);
                    print_str(STDOUT, "' are in again\n");
                }
            }
        }
        lc_kernel_close_file(lock);
    }
    if (more) {
        print_str(STDERR, "Error: there are more containers than lightbox can look at; the links of some are not put back\n");
        failed++;
    }
    return failed;
}

/* setup, and with reload what a firewall's reload took: setup's part again,
 * as setup makes it, and the links of the containers that run */
static void setup_or_reload(bool reload) {
    const char *command = reload ? "reload" : "setup";
    require_root(command);
    bool nftables = cfg_global.firewall_backend == FIREWALL_NFTABLES;
    if (cfg_global.firewall)
        require_tool(nftables ? "nft" : "iptables", nftables ? tool_path_nft() : tool_path_iptables());

    /* Before anything on the host changes: the bridge gets an address of a
     * network that the settings do describe, forwarding is on where it has
     * to be, */
    container_network net;
    container_network_load_or_die(&net);
    require_forwarding_for_nftables();
    /* and a host without cgroup v2 cannot run containers, so setup stops
     * here and leaves no bridge behind. */
    ensure_cgroup2_root();

    print_str(STDOUT, reload ? "Putting lightbox's host network in again...\n" : "Setting up host networking...\n");

    ensure_private_dir(cfg_global.lightbox_dir);
    ensure_private_dir(cfg_global.container_dir);
    /* gone again after a reboot, when start makes it anew */
    ensure_private_dir(cfg_global.run_dir);

    /* one setup at a time, and no create while the bridge is being made */
    (void)store_lock();
    host_network_setup(&net);
    int failed = reload || backend_switched ? put_back_running_links(NULL) : 0;

    if (!nftables && !bridge_traffic_is_filtered())
        print_str(STDOUT,
            "Note: br_netfilter is not filtering bridged traffic on this host. Containers\n"
            "are kept apart at the bridge, so that needs nothing. A container created with\n"
            "--link will not start until it does:\n"
            "  modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1\n");

    if (failed) {
        print_str(STDERR, "Error: the links or --net rules of some running containers are not in again\n");
        lc_kernel_exit(failure_status);
    }
    print_str(STDOUT, "Host networking ready\n");
}

void cmd_setup(void) {
    setup_or_reload(false);
}

void cmd_reload(int argc, char **argv) {
    if (argc > 0)
        die2(argv[0][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[0]);
    setup_or_reload(true);
}

/* ─── After a reboot, and teardown ──────────────────────────────────────── */

/* The bridge, as /proc/net/dev lists the interfaces of this network
 * namespace: no process, and not the namespace that sysfs was mounted in. */
static bool bridge_present(void) {
    static char dev[65536];
    if (read_file("/proc/net/dev", dev, sizeof(dev)) <= 0)
        return false;
    size_t blen = lc_string_length(cfg_global.bridge);
    for (const char *line = dev; *line; ) {
        while (*line == ' ')
            line++;
        if (lc_string_starts_with(line, lc_string_length(line), cfg_global.bridge, blen) && line[blen] == ':')
            return true;
        while (*line && *line != '\n')
            line++;
        if (*line)
            line++;
    }
    return false;
}

/* lightbox's firewall rules: the jumps to LIGHTBOX-FORWARD and
 * LIGHTBOX-INPUT with iptables; with nftables, looked at with one process,
 * both tables and the chain of --net proxy, which the setup that made it
 * made with all of 0.8's others, and a setup before that did not. A flush by
 * a firewall service that loads its own rules takes those as well. */
static bool firewall_present(void) {
    if (!cfg_global.firewall)
        return true;
    if (cfg_global.firewall_backend == FIREWALL_NFTABLES) {
        static char chains[65536];
        const char *list[] = { "nft", "list", "chains", NULL };
        if (run_cmd_capture_quiet(tool_path_nft(), list, chains, sizeof(chains)) != 0)
            return false;
        bool in_ip = false, ip = false, egress = false, bridge = false;
        for (char *line = chains; *line; ) {
            char *end = line;
            while (*end && *end != '\n') end++;
            bool last = *end == '\0';
            *end = '\0';
            if (lc_string_starts_with(line, lc_string_length(line), "table ", 6)) {
                in_ip = streq(line, "table ip lightbox {");
                ip = ip || in_ip;
                bridge = bridge || streq(line, "table bridge lightbox {");
            } else if (in_ip && streq(line, "\tchain egress_proxy {")) {
                egress = true;
            }
            line = last ? end : end + 1;
        }
        return ip && egress && bridge;
    }
    const char *jump[] = { "iptables", "-C", "FORWARD", "-j", "LIGHTBOX-FORWARD", NULL };
    const char *in_jump[] = { "iptables", "-C", "INPUT", "-j", "LIGHTBOX-INPUT", NULL };
    return iptables_check(jump) == 0 && iptables_check(in_jump) == 0;
}

static bool host_network_ready(void) {
    return bridge_present() && (!forwarding_wanted() || forwarding_on()) && firewall_present();
}

const char *host_network_missing(void) {
    static char missing[96];
    size_t pos = 0;
    bool cut = false;
    missing[0] = '\0';
    if (!bridge_present())
        pos = str_append(missing, pos, "the bridge", sizeof(missing), &cut);
    if (lb_sys_geteuid() == 0 && !firewall_present())
        pos = str_append(missing, pos, pos ? ", the firewall rules" : "the firewall rules", sizeof(missing), &cut);
    /* what a start makes again: with nftables forwarding is this host's to
     * turn on, and doctor has a check of its own for it */
    if (forwarding_wanted() && cfg_global.firewall_backend != FIREWALL_NFTABLES && !forwarding_on())
        str_append(missing, pos, pos ? ", forwarding" : "forwarding", sizeof(missing), &cut);
    return missing[0] ? missing : NULL;
}

void ensure_host_network(const char *starting) {
    if (host_network_ready())
        return;
    container_network net;
    container_network_load_or_die(&net);
    /* as setup, one at a time; and whoever waited finds it made */
    int32_t lock = store_lock();
    if (!host_network_ready()) {
        print_str(STDOUT, "lightbox's host network is not all there, as after a reboot: making it again\n");
        host_network_setup(&net);
        /* what took setup's rules took those of the links too */
        (void)put_back_running_links(starting);     /* each has said why, if it could not */
    }
    store_unlock(lock);
}

void ensure_cgroup2_for_start(void) {
    struct lb_statfs sfs;
    if (lb_sys_statfs(cfg_global.cgroup_root, &sfs) == 0 && sfs.f_type == LB_CGROUP2_SUPER_MAGIC)
        return;
    /* as setup, and one at a time: whoever waited finds it mounted */
    int32_t lock = store_lock();
    ensure_cgroup2_root();
    store_unlock(lock);
}

/* LIGHTBOX-USER is the host's, made by lightbox: taken away with its jump
 * when it has no rule, and left with them when it has. */
static void forget_user_chain(void) {
    if (!path_exists(tool_path_iptables()) || !iptables_chain_exists("filter", "LIGHTBOX-USER"))
        return;
    static char rules[4096];
    const char *list[] = { "iptables", "-S", "LIGHTBOX-USER", NULL };
    if (run_cmd_capture_quiet(tool_path_iptables(), list, rules, sizeof(rules)) != 0 ||
        !streq(rules, "-N LIGHTBOX-USER\n")) {
        print_str(STDOUT, "LIGHTBOX-USER has rules of this host's, and stays, with the jump to it from FORWARD\n");
        return;
    }
    const char *jump[] = { "iptables", "-D", "FORWARD", "-j", "LIGHTBOX-USER", NULL };
    const char *drop[] = { "iptables", "-X", "LIGHTBOX-USER", NULL };
    (void)iptables_delete_all(jump);
    if (run_cmd_quiet(tool_path_iptables(), drop) == 0)
        print_str(STDOUT, "Removed LIGHTBOX-USER, which had no rule\n");
}

void teardown_host(void) {
    container_network net;
    container_network_load_or_die(&net);
    print_str(STDOUT, "Taking lightbox's host network away...\n");

    /* the firewall, whichever backend made it */
    forget_iptables_chains(&net, true);
    forget_user_chain();
    forget_nft_tables();

    if (bridge_present()) {
        rtnl nl;
        int rc = rtnl_open(&nl);
        if (rc == 0) {
            rc = rtnl_link_delete(&nl, cfg_global.bridge);
            rtnl_close(&nl);
        }
        if (rc < 0 && rc != -LB_ENODEV)
            die_errno("cannot remove the bridge ", cfg_global.bridge, rc);
        print_str(STDOUT, "Removed bridge ");
        print_str(STDOUT, cfg_global.bridge);
        lc_print_char(STDOUT, '\n');
    }

    /* cgroup_base, which start made; never the hierarchy itself */
    if (!streq(cfg_global.cgroup_base, cfg_global.cgroup_root) && path_exists(cfg_global.cgroup_base)) {
        if (lc_kernel_unlinkat(AT_FDCWD, cfg_global.cgroup_base, AT_REMOVEDIR) == 0) {
            print_str(STDOUT, "Removed ");
            print_str(STDOUT, cfg_global.cgroup_base);
            lc_print_char(STDOUT, '\n');
        } else {
            print_str(STDERR, "Warning: cannot remove ");
            print_str(STDERR, cfg_global.cgroup_base);
            print_str(STDERR, "; a cgroup is left in it\n");
        }
    }

    /* Forwarding and the FORWARD policy stay as they are: something else on
     * this host may forward by now, and turning it off would cut that off,
     * as an ACCEPT policy with forwarding on would open it. */
    char record[MAX_PATH], changed[16];
    forwarding_record_path(record);
    if (read_file(record, changed, sizeof(changed)) > 0) {
        bool drop = streq(changed, "on drop\n");
        print_str(STDOUT, drop ? "setup turned IPv4 forwarding on and set the FORWARD policy to DROP. Both stay,\n"
                               : "setup turned IPv4 forwarding on. It stays on,\n");
        print_str(STDOUT, "as something else on this host may forward by now. If nothing does:\n");
        print_str(STDOUT, drop ? "  sysctl -w net.ipv4.ip_forward=0 && iptables -P FORWARD ACCEPT\n"
                               : "  sysctl -w net.ipv4.ip_forward=0\n");
        lc_kernel_unlinkat(AT_FDCWD, record, 0);
    }
    /* run_dir, which setup made, when nothing is left in it */
    (void)lc_kernel_unlinkat(AT_FDCWD, cfg_global.run_dir, AT_REMOVEDIR);

    print_str(STDOUT, "lightbox's host network is taken away; setup, or a start, makes it again\n");
}
