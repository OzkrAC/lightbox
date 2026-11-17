#include "lightbox.h"

/*
 * rtnetlink: what lightbox asks of the kernel's configuration of interfaces,
 * addresses and routes, over a netlink socket, where until 0.7 it ran ip and
 * nsenter (ROADMAP 7.2). Each request is one message; the kernel answers it
 * before sendto returns, with an acknowledgement or an errno, or with what
 * was asked for.
 *
 * A message is a header, the header of its kind (an interface's, an
 * address's or a route's) and attributes: a length, a type and a value,
 * each starting at a multiple of 4 bytes. A nested attribute holds others.
 */

#define RTNL_REQUEST_MAX 512        /* the longest request, the veth pair's, is about 100 bytes */
#define RTNL_REPLY_MAX   32768      /* the most the kernel puts into one read of a dump */
#define RTNL_NEST_MAX    4

static uint32_t align4(uint32_t n) { return (n + 3u) & ~3u; }

struct rtnl_req {
    uint32_t words[RTNL_REQUEST_MAX / 4];   /* the message; words, so that its headers are aligned */
    uint32_t len;
    uint32_t nest[RTNL_NEST_MAX];           /* where each open nested attribute starts */
    int      depth;
    bool     cut;                           /* it did not fit, and is not sent */
};

static uint8_t *req_bytes(struct rtnl_req *r) { return (uint8_t *)r->words; }

static void req_raw(struct rtnl_req *r, const void *data, uint32_t len) {
    uint32_t end = align4(r->len + len);
    if (r->cut || len > RTNL_REQUEST_MAX || end > RTNL_REQUEST_MAX) {
        r->cut = true;
        return;
    }
    lc_bytes_copy(req_bytes(r) + r->len, data, len);
    lc_bytes_fill(req_bytes(r) + r->len + len, 0, end - r->len - len);
    r->len = end;
}

static void req_begin(struct rtnl_req *r, uint16_t type, uint16_t flags, const void *head, uint32_t head_len) {
    r->len = 0;
    r->depth = 0;
    r->cut = false;
    struct lb_nlmsghdr h = { .type = type, .flags = (uint16_t)(LB_NLM_F_REQUEST | flags) };
    req_raw(r, &h, sizeof(h));
    req_raw(r, head, head_len);
}

static void req_attr(struct rtnl_req *r, uint16_t type, const void *data, uint32_t len) {
    if (len > 0xffffu - sizeof(struct lb_rtattr)) {
        r->cut = true;
        return;
    }
    struct lb_rtattr a = { .len = (uint16_t)(sizeof(a) + len), .type = type };
    req_raw(r, &a, sizeof(a));
    req_raw(r, data, len);
}

/* a name, with its end, as ip gives one */
static void req_string(struct rtnl_req *r, uint16_t type, const char *s) {
    req_attr(r, type, s, (uint32_t)lc_string_length(s) + 1);
}

/* text without its end, as ip gives an alias */
static void req_text(struct rtnl_req *r, uint16_t type, const char *s) {
    req_attr(r, type, s, (uint32_t)lc_string_length(s));
}

static void req_u32(struct rtnl_req *r, uint16_t type, uint32_t value) {
    req_attr(r, type, &value, sizeof(value));
}

static void req_u8(struct rtnl_req *r, uint16_t type, uint8_t value) {
    req_attr(r, type, &value, sizeof(value));
}

/* an IPv4 address, in the order of its bytes on the wire */
static void req_ipv4(struct rtnl_req *r, uint16_t type, uint32_t addr) {
    uint8_t b[4] = { (uint8_t)(addr >> 24), (uint8_t)(addr >> 16), (uint8_t)(addr >> 8), (uint8_t)addr };
    req_attr(r, type, b, sizeof(b));
}

static void req_nest(struct rtnl_req *r, uint16_t type) {
    if (r->depth == RTNL_NEST_MAX) {
        r->cut = true;
        return;
    }
    r->nest[r->depth++] = r->len;
    struct lb_rtattr a = { .len = 0, .type = type };
    req_raw(r, &a, sizeof(a));
}

/* the nested attribute's length: all that was put in since it was opened */
static void req_nest_end(struct rtnl_req *r) {
    if (r->depth == 0) {
        r->cut = true;
        return;
    }
    uint32_t at = r->nest[--r->depth];
    if (r->cut || r->len - at > 0xffffu)
        return;
    uint16_t len = (uint16_t)(r->len - at);
    lc_bytes_copy(req_bytes(r) + at, &len, sizeof(len));
}

/* ─── Answers ───────────────────────────────────────────────────────────── */

/* What reads an answer that is not an acknowledgement: 0, or minus an errno. */
typedef int (*rtnl_reader)(uint16_t type, const uint8_t *payload, uint32_t len, void *ctx);

static uint32_t reply_words[RTNL_REPLY_MAX / 4];

/*
 * Send the request and read what answers it: 0 for an acknowledgement or the
 * end of a dump, minus the errno the kernel refused it with, or what the
 * reader said of an answer. Answers to an earlier request, by their sequence
 * number, are passed over.
 */
static int rtnl_talk(rtnl *nl, struct rtnl_req *r, rtnl_reader read, void *ctx) {
    if (r->cut || r->depth != 0)
        return -LB_EINVAL;
    struct lb_nlmsghdr h;
    lc_bytes_copy(&h, req_bytes(r), sizeof(h));
    h.len = r->len;
    h.seq = ++nl->seq;
    lc_bytes_copy(req_bytes(r), &h, sizeof(h));
    bool one_answer = !(h.flags & LB_NLM_F_ACK) && (h.flags & LB_NLM_F_DUMP) != LB_NLM_F_DUMP;

    struct lb_sockaddr_nl kernel = { .family = LB_AF_NETLINK };
    lc_sysret sent;
    do
        sent = lb_sys_sendto(nl->fd, r->words, r->len, 0, &kernel, sizeof(kernel));
    while (sent == -LB_EINTR);
    if (sent < 0)
        return (int)sent;

    const uint8_t *reply = (const uint8_t *)reply_words;
    int result = 0;
    for (;;) {
        lc_sysret got;
        do
            got = lb_sys_recvfrom(nl->fd, reply_words, sizeof(reply_words), 0);
        while (got == -LB_EINTR);
        if (got < 0)
            return (int)got;
        if (got == 0)
            return -LB_EINVAL;
        uint32_t end = (uint32_t)got, at = 0;
        while (end - at >= sizeof(struct lb_nlmsghdr)) {
            struct lb_nlmsghdr m;
            lc_bytes_copy(&m, reply + at, sizeof(m));
            if (m.len < sizeof(m) || m.len > end - at)
                return -LB_EINVAL;      /* an answer cut short */
            const uint8_t *payload = reply + at + sizeof(m);
            uint32_t len = m.len - (uint32_t)sizeof(m);
            at = align4(m.len) > end - at ? end : at + align4(m.len);
            if (m.seq != h.seq)
                continue;
            if (m.type == LB_NLMSG_ERROR || m.type == LB_NLMSG_DONE) {
                int32_t err = 0;
                if (len >= sizeof(err))
                    lc_bytes_copy(&err, payload, sizeof(err));
                return err < 0 ? (int)err : result;
            }
            if (read && result == 0)
                result = read(m.type, payload, len, ctx);
            if (one_answer && !(m.flags & LB_NLM_F_MULTI))
                return result;
        }
    }
}

/* The value of the first attribute of this type among len bytes of them, and
 * its length in *alen; NULL when there is none. */
static const uint8_t *attr_find(const uint8_t *attrs, uint32_t len, uint16_t type, uint32_t *alen) {
    uint32_t at = 0;
    while (len - at >= sizeof(struct lb_rtattr)) {
        struct lb_rtattr a;
        lc_bytes_copy(&a, attrs + at, sizeof(a));
        if (a.len < sizeof(a) || a.len > len - at)
            return NULL;
        if ((a.type & 0x3fffu) == type) {      /* without the nested and byte-order bits */
            *alen = a.len - (uint32_t)sizeof(a);
            return attrs + at + sizeof(a);
        }
        if (align4(a.len) > len - at)
            return NULL;
        at += align4(a.len);
    }
    return NULL;
}

/* Text of an attribute, with or without its end, into out; false when there
 * is none or it does not fit. */
static bool attr_text(const uint8_t *attrs, uint32_t len, uint16_t type, char *out, size_t max) {
    uint32_t alen = 0;
    const uint8_t *v = attr_find(attrs, len, type, &alen);
    if (!v || max == 0)
        return false;
    while (alen > 0 && v[alen - 1] == '\0')
        alen--;
    if (alen >= max)
        return false;
    lc_bytes_copy(out, v, alen);
    out[alen] = '\0';
    return true;
}

static bool attr_u32(const uint8_t *attrs, uint32_t len, uint16_t type, uint32_t *value) {
    uint32_t alen = 0;
    const uint8_t *v = attr_find(attrs, len, type, &alen);
    if (!v || alen < sizeof(*value))
        return false;
    lc_bytes_copy(value, v, sizeof(*value));
    return true;
}

/* ─── Interfaces ────────────────────────────────────────────────────────── */

int rtnl_open(rtnl *nl) {
    lc_sysret fd = lb_sys_socket(LB_AF_NETLINK, LB_SOCK_RAW | LB_SOCK_CLOEXEC, LB_NETLINK_ROUTE);
    nl->fd = fd < 0 ? -1 : (int32_t)fd;
    nl->seq = 0;
    return fd < 0 ? (int)fd : 0;
}

void rtnl_close(rtnl *nl) {
    if (nl->fd >= 0)
        lc_kernel_close_file(nl->fd);
    nl->fd = -1;
}

/* A request about one interface: by its name, or with NULL by its index. */
static void link_request(struct rtnl_req *r, uint16_t type, uint16_t flags, const char *ifname, int index,
                         uint32_t up) {
    struct lb_ifinfomsg ifi = { .index = index, .flags = up, .change = up };
    req_begin(r, type, flags, &ifi, sizeof(ifi));
    if (ifname)
        req_string(r, LB_IFLA_IFNAME, ifname);
}

struct link_found {
    int     index;
    char   *alias;
    size_t  alias_max;
    char   *name;
    size_t  name_max;
};

static int read_link(uint16_t type, const uint8_t *payload, uint32_t len, void *ctx) {
    struct link_found *f = ctx;
    struct lb_ifinfomsg ifi;
    if (type != LB_RTM_NEWLINK || len < sizeof(ifi))
        return -LB_EINVAL;
    lc_bytes_copy(&ifi, payload, sizeof(ifi));
    const uint8_t *attrs = payload + align4(sizeof(ifi));
    uint32_t alen = len - align4(sizeof(ifi));
    if (f->alias && !attr_text(attrs, alen, LB_IFLA_IFALIAS, f->alias, f->alias_max))
        f->alias[0] = '\0';
    if (f->name && !attr_text(attrs, alen, LB_IFLA_IFNAME, f->name, f->name_max))
        return -LB_EINVAL;
    f->index = ifi.index;
    return 0;
}

int rtnl_link_get(rtnl *nl, const char *ifname, char *alias, size_t alias_max) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_GETLINK, 0, ifname, 0, 0);
    struct link_found f = { .index = 0, .alias = alias_max ? alias : NULL, .alias_max = alias_max };
    if (f.alias)
        f.alias[0] = '\0';
    int rc = rtnl_talk(nl, &r, read_link, &f);
    if (rc < 0)
        return rc;
    return f.index > 0 ? f.index : -LB_ENODEV;
}

int rtnl_link_name(rtnl *nl, int index, char out[IFNAME_TEXT_MAX]) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_GETLINK, 0, NULL, index, 0);
    struct link_found f = { .index = 0, .name = out, .name_max = IFNAME_TEXT_MAX };
    int rc = rtnl_talk(nl, &r, read_link, &f);
    return rc < 0 ? rc : f.index > 0 ? 0 : -LB_ENODEV;
}

static const uint16_t CREATE_NEW = LB_NLM_F_ACK | LB_NLM_F_CREATE | LB_NLM_F_EXCL;

/* ip link add <ifname> type veth peer name <peer> netns <pid> */
int rtnl_veth_add(rtnl *nl, const char *ifname, const char *peer, int peer_pid) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_NEWLINK, CREATE_NEW, ifname, 0, 0);
    req_nest(&r, LB_IFLA_LINKINFO);
    req_string(&r, LB_IFLA_INFO_KIND, "veth");
    req_nest(&r, LB_IFLA_INFO_DATA);
    req_nest(&r, LB_VETH_INFO_PEER);
    struct lb_ifinfomsg peer_ifi = { .index = 0 };    /* the peer's own header, then its attributes */
    req_raw(&r, &peer_ifi, sizeof(peer_ifi));
    req_string(&r, LB_IFLA_IFNAME, peer);
    req_u32(&r, LB_IFLA_NET_NS_PID, (uint32_t)peer_pid);
    req_nest_end(&r);
    req_nest_end(&r);
    req_nest_end(&r);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ip link add name <ifname> type bridge */
int rtnl_bridge_add(rtnl *nl, const char *ifname) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_NEWLINK, CREATE_NEW, ifname, 0, 0);
    req_nest(&r, LB_IFLA_LINKINFO);
    req_string(&r, LB_IFLA_INFO_KIND, "bridge");
    req_nest_end(&r);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ip link set dev <ifname> alias <alias> master <index>: one request, in
 * which the kernel sets the alias before it makes the interface a port. */
int rtnl_link_attach(rtnl *nl, const char *ifname, const char *alias, int master) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_NEWLINK, LB_NLM_F_ACK, ifname, 0, 0);
    req_text(&r, LB_IFLA_IFALIAS, alias);
    req_u32(&r, LB_IFLA_MASTER, (uint32_t)master);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ip link set dev <ifname> type bridge_slave isolated on: the bridge's
 * setting of its port, which the bridge has to be the master of already */
int rtnl_port_isolate(rtnl *nl, const char *ifname) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_NEWLINK, LB_NLM_F_ACK, ifname, 0, 0);
    req_nest(&r, LB_IFLA_LINKINFO);
    req_string(&r, LB_IFLA_INFO_SLAVE_KIND, "bridge");
    req_nest(&r, LB_IFLA_INFO_SLAVE_DATA);
    req_u8(&r, LB_IFLA_BRPORT_ISOLATED, 1);
    req_nest_end(&r);
    req_nest_end(&r);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ip link set <ifname> up */
int rtnl_link_up(rtnl *nl, const char *ifname) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_NEWLINK, LB_NLM_F_ACK, ifname, 0, LB_IFF_UP);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ip link delete <ifname>: a veth goes with its peer */
int rtnl_link_delete(rtnl *nl, const char *ifname) {
    struct rtnl_req r;
    link_request(&r, LB_RTM_DELLINK, LB_NLM_F_ACK, ifname, 0, 0);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ─── Addresses and routes ──────────────────────────────────────────────── */

/* ip addr add <addr>/<prefix> dev <index> */
int rtnl_addr_add(rtnl *nl, int index, uint32_t addr, int prefix) {
    struct rtnl_req r;
    struct lb_ifaddrmsg ifa = {
        .family = LB_AF_INET, .prefixlen = (uint8_t)prefix, .scope = LB_RT_SCOPE_UNIVERSE, .index = (uint32_t)index,
    };
    req_begin(&r, LB_RTM_NEWADDR, CREATE_NEW, &ifa, sizeof(ifa));
    req_ipv4(&r, LB_IFA_LOCAL, addr);
    req_ipv4(&r, LB_IFA_ADDRESS, addr);
    return rtnl_talk(nl, &r, NULL, NULL);
}

/* ip route add default via <gateway> dev <index> */
int rtnl_default_route_add(rtnl *nl, uint32_t gateway, int index) {
    struct rtnl_req r;
    struct lb_rtmsg rt = {
        .family = LB_AF_INET, .table = LB_RT_TABLE_MAIN, .protocol = LB_RTPROT_BOOT,
        .scope = LB_RT_SCOPE_UNIVERSE, .type = LB_RTN_UNICAST,
    };
    req_begin(&r, LB_RTM_NEWROUTE, CREATE_NEW, &rt, sizeof(rt));
    req_ipv4(&r, LB_RTA_GATEWAY, gateway);
    req_u32(&r, LB_RTA_OIF, (uint32_t)index);
    return rtnl_talk(nl, &r, NULL, NULL);
}

static int read_route(uint16_t type, const uint8_t *payload, uint32_t len, void *ctx) {
    int *index = ctx;
    struct lb_rtmsg rt;
    if (type != LB_RTM_NEWROUTE || len < sizeof(rt) || *index > 0)
        return 0;
    lc_bytes_copy(&rt, payload, sizeof(rt));
    const uint8_t *attrs = payload + align4(sizeof(rt));
    uint32_t alen = len - align4(sizeof(rt));
    uint32_t table = rt.table, oif = 0;
    (void)attr_u32(attrs, alen, LB_RTA_TABLE, &table);     /* a table past 255 is named only here */
    if (rt.family == LB_AF_INET && rt.dst_len == 0 && rt.type == LB_RTN_UNICAST && table == LB_RT_TABLE_MAIN &&
        attr_u32(attrs, alen, LB_RTA_OIF, &oif) && oif > 0 && oif <= 0x7fffffffu)
        *index = (int)oif;
    return 0;
}

/* ip route show default: the interface of the main table's first default
 * route that names one; 0 when none does */
int rtnl_default_route_index(rtnl *nl) {
    struct rtnl_req r;
    struct lb_rtmsg rt = { .family = LB_AF_INET };
    req_begin(&r, LB_RTM_GETROUTE, LB_NLM_F_DUMP, &rt, sizeof(rt));
    int index = 0;
    int rc = rtnl_talk(nl, &r, read_route, &index);
    return rc < 0 ? rc : index;
}

/* ─── The container's side ──────────────────────────────────────────────── */

/*
 * What init does in the container's network namespace, where the start put
 * eth0: bring it up, give it its address and route through the bridge. No
 * process enters the namespace from the host for it. 0, or -1 once what
 * failed has been said.
 */
int container_interface_up(uint32_t addr, int prefix, uint32_t gateway) {
    rtnl nl;
    const char *step = "cannot open a netlink socket for ";
    int rc = rtnl_open(&nl);
    if (rc == 0) {
        int index = rtnl_link_get(&nl, CONTAINER_IFNAME, NULL, 0);
        step = NULL;
        if (index < 0) {
            rc = index;
            step = "cannot find ";
        } else if ((rc = rtnl_link_up(&nl, CONTAINER_IFNAME)) < 0) {
            step = "cannot bring up ";
        } else if ((rc = rtnl_addr_add(&nl, index, addr, prefix)) < 0) {
            step = "cannot give its address to ";
        } else if ((rc = rtnl_default_route_add(&nl, gateway, index)) < 0) {
            step = "cannot add the default route through ";
        }
        rtnl_close(&nl);
    }
    if (!step)
        return 0;
    char digits[16];
    fmt_int(digits, -rc);
    print_str(STDERR, "Error: ");
    print_str(STDERR, step);
    print_str(STDERR, CONTAINER_IFNAME " in the container (errno ");
    print_str(STDERR, digits);
    print_str(STDERR, ")\n");
    return -1;
}
