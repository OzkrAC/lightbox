#include <lightc/syscall.h>
#include <lightc/types.h>
#include <lightc/memory.h>
#include <lightc/socket.h>

#include "lightbox.h"
#include "lightbox_sys.h"
#include "lightbox_seccomp.h"

/*
 * The relay of a box's published ports (ROADMAP N.1, by the maintainer's
 * word of 2026-11-25).
 *
 * start makes a TCP socket of the host's that listens for each port -p gave
 * the box, as root, so that a port below 1024 can be had and one that is in
 * use is found before the box runs anything. It forks the relay into a cgroup
 * below the box's, so that the box's limits hold for it, and the box's end,
 * by whatever end, ends it with the rest of the cgroup. The relay then:
 *
 *   - goes into the box's network namespace, so that every socket it makes
 *     after that is the box's: it connects to the box's port on the box's
 *     loopback, and a relay that something made do otherwise reaches what
 *     the box reaches and no more, under the box's own rules;
 *   - becomes nobody, with no capability and none to be had, and not
 *     dumpable;
 *   - takes its buffers, and then a seccomp filter of the calls it makes and
 *     no other: socket of AF_INET and its one type alone, and no open, mmap,
 *     kill, setns or execve;
 *   - says to start that it is ready, and copies bytes both ways for each
 *     connection, and reads none of them.
 *
 * The kernel is not asked to send loopback's connections to the box, which it
 * does only with route_localnet, which let a LAN's machines reach a host's
 * loopback services in Kubernetes (CVE-2020-8558). A box sees each connection
 * come from its own loopback.
 */

#define RELAY_CONNS   64            /* connections at once; more wait to be taken */
#define RELAY_BUF     16384         /* bytes of one direction of one connection */
#define RELAY_BACKLOG 128

/* An address as lightc's sockets take it, from parse_ipv4's order */
static lc_socket_address relay_address(uint32_t addr, uint16_t port) {
    return (lc_socket_address){ .family = LC_AF_INET, .port = lc_host_to_network_16(port),
                                .addr = lc_host_to_network_32(addr) };
}

lc_sysret relay_listen(uint32_t addr, uint16_t port) {
    lc_result made = lc_socket_create(LC_SOCK_STREAM | LB_SOCK_NONBLOCK | LB_SOCK_CLOEXEC);
    if (made.error)
        return -made.error;
    int32_t fd = (int32_t)made.value;
    lc_socket_address at = relay_address(addr, port);
    lc_result done = lc_socket_set_reuse_address(fd);
    if (!done.error)
        done = lc_socket_bind(fd, &at);
    if (!done.error)
        done = lc_socket_listen(fd, RELAY_BACKLOG);
    if (done.error) {
        lc_socket_close(fd);
        return -done.error;
    }
    return fd;
}

int relay_port_of(int32_t fd) {
    lc_socket_address at = { 0 };
    uint32_t len = sizeof(at);
    if (lb_sys_getsockname(fd, &at, &len) < 0)
        return -1;
    return lc_network_to_host_16(at.port);
}

/* One direction's bytes: what this side sent that the other has not had
 * yet, buf[off..len). */
struct relay_side {
    int32_t  fd;
    uint32_t len, off;
    bool     eof;           /* it sends no more */
    bool     shut;          /* it was told that no more comes */
    uint8_t *buf;
};

/* side 0 is the one that connected to the host's port, side 1 the box's */
struct relay_conn {
    bool used;
    bool connecting;        /* side 1's connect is under way */
    struct relay_side side[2];
};

static struct relay_conn conns[RELAY_CONNS];
static struct lb_pollfd fds[MAX_PORTS + 2 * RELAY_CONNS];
static int whose[MAX_PORTS + 2 * RELAY_CONNS];      /* -1 - listener, or 2 * connection + side */

static void relay_close(struct relay_conn *c) {
    for (int k = 0; k < 2; k++)
        lc_kernel_close_file(c->side[k].fd);
    c->used = false;
}

/* A connection on a listener of the box's port box_port, where one is free. */
static void relay_take(int32_t listener, uint16_t box_port) {
    lc_sysret a = lb_sys_accept4(listener, LB_SOCK_NONBLOCK | LB_SOCK_CLOEXEC);
    if (a < 0)
        return;
    struct relay_conn *c = NULL;
    for (int i = 0; i < RELAY_CONNS && !c; i++)
        if (!conns[i].used)
            c = &conns[i];
    lc_result made = c ? lc_socket_create((int32_t)LB_SECCOMP_RELAY_SOCKET_TYPE) : (lc_result){ .error = LB_EAGAIN };
    if (made.error) {
        lc_kernel_close_file((int32_t)a);
        return;
    }
    int32_t b = (int32_t)made.value;
    lc_socket_address to = relay_address(LC_INADDR_LOOPBACK, box_port);
    lc_result connected = lc_socket_connect(b, &to);
    if (connected.error && connected.error != LB_EINPROGRESS) {
        lc_kernel_close_file((int32_t)a);
        lc_kernel_close_file(b);
        return;
    }
    uint8_t *bufs[2] = { c->side[0].buf, c->side[1].buf };
    *c = (struct relay_conn){ .used = true, .connecting = connected.error != 0 };
    for (int k = 0; k < 2; k++)
        c->side[k] = (struct relay_side){ .fd = k ? b : (int32_t)a, .buf = bufs[k] };
}

/* What a side's descriptor said: read what it sent, and write to it what the
 * other sent. False once the connection is closed. */
static bool relay_side_ready(struct relay_conn *c, int k, int16_t said) {
    struct relay_side *me = &c->side[k], *other = &c->side[1 - k];
    if (c->connecting) {
        if (k == 1 && (said & (LB_POLLOUT | LB_POLLERR | LB_POLLHUP))) {
            int32_t err = 0;
            uint32_t len = sizeof(err);
            if (lb_sys_getsockopt(me->fd, LC_SOL_SOCKET, LB_SO_ERROR, &err, &len) < 0 || err != 0) {
                relay_close(c);
                return false;
            }
            c->connecting = false;
        } else if (k == 0 && (said & LB_POLLERR)) {
            relay_close(c);
            return false;
        }
        return true;
    }
    if (said & LB_POLLERR) {
        relay_close(c);
        return false;
    }
    if ((said & (LB_POLLIN | LB_POLLHUP)) && !me->eof && me->len == 0) {
        lc_sysret n = lc_kernel_read_bytes(me->fd, me->buf, RELAY_BUF);
        if (n > 0) {
            me->len = (uint32_t)n;
            me->off = 0;
        } else if (n == 0) {
            me->eof = true;
        } else if (n != -LB_EAGAIN && n != -LB_EINTR) {
            relay_close(c);
            return false;
        }
    }
    if ((said & LB_POLLOUT) && other->len > other->off) {
        lc_sysret n = lc_kernel_write_bytes(me->fd, other->buf + other->off, other->len - other->off);
        if (n > 0) {
            other->off += (uint32_t)n;
            if (other->off == other->len)
                other->len = other->off = 0;
        } else if (n != -LB_EAGAIN && n != -LB_EINTR) {
            relay_close(c);
            return false;
        }
    }
    return true;
}

/* A side that sends no more, and whose last bytes the other has, is said to
 * the other as the end of what it gets; once both have ended, it is closed. */
static void relay_settle(struct relay_conn *c) {
    if (!c->used || c->connecting)
        return;
    for (int k = 0; k < 2; k++) {
        struct relay_side *me = &c->side[k], *other = &c->side[1 - k];
        if (me->eof && me->len == 0 && !other->shut) {
            (void)lc_socket_shutdown(other->fd, LC_SHUT_WRITE);
            other->shut = true;
        }
    }
    if (c->side[0].eof && c->side[1].eof && c->side[0].len == 0 && c->side[1].len == 0)
        relay_close(c);
}

/* nobody, with no capability and none to be had; as an ordinary user, as
 * the unit cases run it, the ids it has */
static bool relay_drop(void) {
    if (lb_sys_geteuid() != 0)
        return true;
    for (int cap = 0; cap < 64; cap++) {
        lc_sysret held = lc_kernel_prctl(LB_PR_CAPBSET_READ, (uint64_t)cap, 0, 0, 0);
        if (held < 0)
            break;
        if (held == 1 && lc_kernel_prctl(LB_PR_CAPBSET_DROP, (uint64_t)cap, 0, 0, 0) < 0)
            return false;
    }
    if (lc_kernel_setgroups(0, NULL) < 0 || lc_kernel_setgid(NOBODY_ID) < 0 || lc_kernel_setuid(NOBODY_ID) < 0)
        return false;
    struct lb_cap_header hdr = { LB_CAPABILITY_VERSION_3, 0 };
    struct lb_cap_data sets[LB_CAPABILITY_WORDS] = { 0 };
    return lb_sys_capset(&hdr, sets) == 0 &&
           lc_kernel_prctl(LB_PR_CAP_AMBIENT, LB_PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == 0;
}

[[noreturn]] void relay_run(const int32_t *listeners, const uint16_t *box_ports, int n, int32_t netns, int32_t ready) {
    /* a peer that went away is an error of the write, and not the relay's end */
    uint64_t pipe_only = (uint64_t)1 << (LB_SIGPIPE - 1);
    lc_kernel_set_signal_mask(LC_SIG_SETMASK, &pipe_only, NULL);
    if (n < 1 || n > MAX_PORTS)
        lc_kernel_exit(1);

    /* the box's network, for every socket made from here on */
    if (netns >= 0) {
        if (lc_kernel_setns(netns, CLONE_NEWNET) < 0)
            lc_kernel_exit(1);
        lc_kernel_close_file(netns);
    }
    if (!relay_drop() || lc_kernel_prctl(LB_PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        lc_kernel_exit(1);
    lc_result_ptr pages = lc_allocate_pages((size_t)RELAY_CONNS * 2 * RELAY_BUF / LC_PAGE_SIZE);
    if (lc_ptr_is_err(pages))
        lc_kernel_exit(1);
    for (int i = 0; i < RELAY_CONNS; i++)
        for (int k = 0; k < 2; k++)
            conns[i].side[k].buf = (uint8_t *)pages.value + ((size_t)i * 2 + (size_t)k) * RELAY_BUF;
    static struct lb_sock_filter filter[LB_SECCOMP_RELAY_PROG_LEN];
    struct lb_sock_fprog prog = { .len = (uint16_t)lb_seccomp_build_relay(filter), .filter = filter };
    if (prog.len != LB_SECCOMP_RELAY_PROG_LEN || lc_kernel_prctl(LB_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        lc_kernel_prctl(LB_PR_SET_SECCOMP, LB_SECCOMP_MODE_FILTER, (uint64_t)&prog, 0, 0) < 0)
        lc_kernel_exit(1);
    if (lc_kernel_write_bytes(ready, "R", 1) != 1)
        lc_kernel_exit(1);
    lc_kernel_close_file(ready);

    for (;;) {
        size_t count = 0;
        bool room = false;
        for (int i = 0; i < RELAY_CONNS && !room; i++)
            room = !conns[i].used;
        for (int i = 0; i < n; i++) {
            /* with no room, a connection waits in the listener's queue */
            fds[count] = (struct lb_pollfd){ .fd = room ? listeners[i] : -1, .events = LB_POLLIN };
            whose[count++] = -1 - i;
        }
        for (int i = 0; i < RELAY_CONNS; i++) {
            struct relay_conn *c = &conns[i];
            if (!c->used)
                continue;
            for (int k = 0; k < 2; k++) {
                const struct relay_side *me = &c->side[k], *other = &c->side[1 - k];
                int16_t want = 0;
                if (c->connecting) {
                    want = k == 1 ? LB_POLLOUT : 0;
                } else {
                    if (!me->eof && me->len == 0)
                        want |= LB_POLLIN;
                    if (other->len > other->off)
                        want |= LB_POLLOUT;
                }
                /* a side that is asked for nothing is not looked at, so that
                 * a hang-up the kernel says of it does not come back at once */
                fds[count] = (struct lb_pollfd){ .fd = want ? me->fd : -1, .events = want };
                whose[count++] = 2 * i + k;
            }
        }
        lc_sysret ready_count = lb_sys_ppoll(fds, count, NULL);
        if (ready_count == -LB_EINTR)
            continue;
        if (ready_count < 0)
            lc_kernel_exit(1);
        for (size_t f = 0; f < count; f++) {
            if (fds[f].fd < 0 || !fds[f].revents)
                continue;
            if (whose[f] < 0) {
                int l = -1 - whose[f];
                relay_take(listeners[l], box_ports[l]);
                continue;
            }
            struct relay_conn *c = &conns[whose[f] / 2];
            int k = whose[f] % 2;
            /* closed by its other side's events, before this one's */
            if (!c->used || c->side[k].fd != fds[f].fd)
                continue;
            (void)relay_side_ready(c, k, fds[f].revents);
        }
        for (int i = 0; i < RELAY_CONNS; i++)
            relay_settle(&conns[i]);
    }
}
