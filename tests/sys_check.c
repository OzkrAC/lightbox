/*
 * Compile-only check of lightbox_sys.h, lightbox_seccomp.h and
 * lightbox_devices.h against the kernel's own headers.
 *
 * lightbox is freestanding and carries a few syscall numbers, constants and
 * structure layouts of its own, and its seccomp table lists numbers for two
 * architectures. A wrong one does not fail to build; it calls or denies a
 * different syscall, or reads the wrong bytes. This file makes it fail to build.
 *
 *   make check-sys
 *
 * compiles it with the native compiler and with every cross compiler it finds
 * (aarch64-linux-gnu-gcc, x86_64-linux-gnu-gcc). Nothing is linked or run.
 *
 * Only kernel headers are included here. What can be checked only next to the
 * C library's headers is in sys_check_net.c.
 */

#define LIGHTBOX_SYS_CHECK 1

#include <stddef.h>
#include <stdint.h>

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/poll.h>
#include <asm/siginfo.h>
#include <asm/signal.h>
#include <asm/statfs.h>
#include <asm/termbits.h>
#include <asm/termios.h>
#include <asm/unistd.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <linux/major.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/memfd.h>
#include <linux/time.h>
#include <linux/mount.h>
#include <linux/netlink.h>
#include <linux/openat2.h>
#include <linux/prctl.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/sockios.h>
#include <linux/stat.h>
#include <linux/veth.h>

#include "../lightbox_sys.h"
#include "../lightbox_seccomp.h"
#include "../lightbox_devices.h"

#define SAME_NR(name) \
    _Static_assert(LB_SYS_##name == __NR_##name, \
                   "LB_SYS_" #name " differs from the kernel's __NR_" #name)

SAME_NR(fsync);
SAME_NR(fchdir);
SAME_NR(capget);
SAME_NR(capset);
SAME_NR(statfs);
SAME_NR(chroot);
SAME_NR(renameat);
SAME_NR(ppoll);
SAME_NR(close_range);
SAME_NR(pidfd_open);
SAME_NR(getrandom);

/* --ttl's clock (ROADMAP 8.8) */
_Static_assert(LB_CLOCK_BOOTTIME == CLOCK_BOOTTIME, "LB_CLOCK_BOOTTIME is not CLOCK_BOOTTIME");
SAME_NR(open_tree);
SAME_NR(openat2);
SAME_NR(fcntl);
SAME_NR(flock);
SAME_NR(geteuid);
SAME_NR(getuid);
SAME_NR(memfd_create);
SAME_NR(execveat);
SAME_NR(mount_setattr);
SAME_NR(move_mount);
SAME_NR(pidfd_send_signal);
SAME_NR(statx);
SAME_NR(fgetxattr);
SAME_NR(flistxattr);
SAME_NR(fsetxattr);
SAME_NR(linkat);
SAME_NR(utimensat);
SAME_NR(fchmod);
SAME_NR(umask);
SAME_NR(faccessat);
SAME_NR(bpf);

#define SAME_VALUE(ours, kernels) \
    _Static_assert((ours) == (kernels), #ours " differs from the kernel's " #kernels)

SAME_VALUE(LB_EPERM, EPERM);
SAME_VALUE(LB_ENOENT, ENOENT);
SAME_VALUE(LB_ENODEV, ENODEV);
SAME_VALUE(LB_ESRCH, ESRCH);
SAME_VALUE(LB_EINTR, EINTR);
SAME_VALUE(LB_EIO, EIO);
SAME_VALUE(LB_ENOMEM, ENOMEM);
SAME_VALUE(LB_EEXIST, EEXIST);
SAME_VALUE(LB_EACCES, EACCES);
SAME_VALUE(LB_ENOTDIR, ENOTDIR);
SAME_VALUE(LB_EISDIR, EISDIR);
SAME_VALUE(LB_ENOTEMPTY, ENOTEMPTY);
SAME_VALUE(LB_ELOOP, ELOOP);
SAME_VALUE(LB_S_IFREG, S_IFREG);
SAME_VALUE(LB_S_IFMT, S_IFMT);
SAME_VALUE(LB_S_IFDIR, S_IFDIR);
SAME_VALUE(LB_S_IFLNK, S_IFLNK);
SAME_VALUE(LB_S_IFCHR, S_IFCHR);
SAME_VALUE(LB_S_IFBLK, S_IFBLK);
SAME_VALUE(LB_S_IFIFO, S_IFIFO);
SAME_VALUE(LB_S_IFSOCK, S_IFSOCK);
SAME_VALUE(LB_STATX_NLINK, STATX_NLINK);
SAME_VALUE(LB_STATX_MTIME, STATX_MTIME);
SAME_VALUE(LB_STATX_SIZE, STATX_SIZE);
SAME_VALUE(LB_ERANGE, ERANGE);
SAME_VALUE(LB_ENODATA, ENODATA);
SAME_VALUE(LB_EOPNOTSUPP, EOPNOTSUPP);
SAME_VALUE(LB_AT_EMPTY_PATH, AT_EMPTY_PATH);
SAME_VALUE(LB_O_EXCL, O_EXCL);
SAME_VALUE(LB_LOCK_SH, LOCK_SH);
SAME_VALUE(LB_LOCK_EX, LOCK_EX);
SAME_VALUE(LB_LOCK_NB, LOCK_NB);
SAME_VALUE(LB_RESOLVE_IN_ROOT, RESOLVE_IN_ROOT);
SAME_VALUE(LB_OPEN_TREE_CLONE, OPEN_TREE_CLONE);
SAME_VALUE(LB_OPEN_TREE_CLOEXEC, OPEN_TREE_CLOEXEC);
SAME_VALUE(LB_MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_F_EMPTY_PATH);
SAME_VALUE(LB_MOVE_MOUNT_T_SYMLINKS, MOVE_MOUNT_T_SYMLINKS);
SAME_VALUE(LB_EBUSY, EBUSY);
SAME_VALUE(LB_EINVAL, EINVAL);
SAME_VALUE(LB_ENOSYS, ENOSYS);
SAME_VALUE(LB_MFD_CLOEXEC, MFD_CLOEXEC);
SAME_VALUE(LB_MFD_ALLOW_SEALING, MFD_ALLOW_SEALING);
SAME_VALUE(LB_MFD_EXEC, MFD_EXEC);
SAME_VALUE(LB_F_ADD_SEALS, F_ADD_SEALS);
SAME_VALUE(LB_F_GET_SEALS, F_GET_SEALS);
SAME_VALUE(LB_F_SEAL_SEAL, F_SEAL_SEAL);
SAME_VALUE(LB_F_SEAL_SHRINK, F_SEAL_SHRINK);
SAME_VALUE(LB_F_SEAL_GROW, F_SEAL_GROW);
SAME_VALUE(LB_F_SEAL_WRITE, F_SEAL_WRITE);
SAME_VALUE(LB_MOUNT_ATTR_RDONLY, MOUNT_ATTR_RDONLY);
SAME_VALUE(LB_MOUNT_ATTR_NOSUID, MOUNT_ATTR_NOSUID);
SAME_VALUE(LB_MOUNT_ATTR_NODEV, MOUNT_ATTR_NODEV);
SAME_VALUE(LB_MOUNT_ATTR_IDMAP, MOUNT_ATTR_IDMAP);
SAME_VALUE(LB_SIGPIPE, SIGPIPE);
SAME_VALUE(LB_SIGCONT, SIGCONT);
SAME_VALUE(LB_SIGTTOU, SIGTTOU);
SAME_VALUE(LB_SIGWINCH, SIGWINCH);
SAME_VALUE(LB_EAGAIN, EAGAIN);
SAME_VALUE(LB_POLLOUT, POLLOUT);
SAME_VALUE(LB_TCGETS, TCGETS);
SAME_VALUE(LB_TCSETS, TCSETS);
SAME_VALUE(LB_TIOCSCTTY, TIOCSCTTY);
SAME_VALUE(LB_TIOCGWINSZ, TIOCGWINSZ);
SAME_VALUE(LB_TIOCSWINSZ, TIOCSWINSZ);
SAME_VALUE(LB_TIOCSPTLCK, TIOCSPTLCK);
SAME_VALUE(LB_TIOCGPTPEER, TIOCGPTPEER);
SAME_VALUE(LB_O_NOCTTY, O_NOCTTY);
SAME_VALUE(LB_F_GETFL, F_GETFL);
SAME_VALUE(LB_F_SETFL, F_SETFL);
SAME_VALUE(LB_IGNBRK, IGNBRK);
SAME_VALUE(LB_BRKINT, BRKINT);
SAME_VALUE(LB_PARMRK, PARMRK);
SAME_VALUE(LB_ISTRIP, ISTRIP);
SAME_VALUE(LB_INLCR, INLCR);
SAME_VALUE(LB_IGNCR, IGNCR);
SAME_VALUE(LB_ICRNL, ICRNL);
SAME_VALUE(LB_IXON, IXON);
SAME_VALUE(LB_OPOST, OPOST);
SAME_VALUE(LB_ISIG, ISIG);
SAME_VALUE(LB_ICANON, ICANON);
SAME_VALUE(LB_ECHO, ECHO);
SAME_VALUE(LB_ECHONL, ECHONL);
SAME_VALUE(LB_IEXTEN, IEXTEN);
SAME_VALUE(LB_CSIZE, CSIZE);
SAME_VALUE(LB_CS8, CS8);
SAME_VALUE(LB_PARENB, PARENB);
SAME_VALUE(LB_VTIME, VTIME);
SAME_VALUE(LB_VMIN, VMIN);
SAME_VALUE(LB_SI_QUEUE, SI_QUEUE);
SAME_VALUE(LB_POLLIN, POLLIN);
SAME_VALUE(LB_POLLERR, POLLERR);
SAME_VALUE(LB_POLLHUP, POLLHUP);
SAME_VALUE(LB_SIOCGIFFLAGS, SIOCGIFFLAGS);
SAME_VALUE(LB_SIOCSIFFLAGS, SIOCSIFFLAGS);
SAME_VALUE(LB_S_IFMT, S_IFMT);
SAME_VALUE(LB_S_IFDIR, S_IFDIR);
SAME_VALUE(LB_STATX_TYPE, STATX_TYPE);
SAME_VALUE(LB_STATX_INO, STATX_INO);
SAME_VALUE(LB_STATX_MODE, STATX_MODE);
SAME_VALUE(LB_STATX_UID, STATX_UID);
SAME_VALUE(LB_STATX_GID, STATX_GID);
SAME_VALUE(LB_STATX_ATTR_MOUNT_ROOT, STATX_ATTR_MOUNT_ROOT);
SAME_VALUE(LB_CGROUP_SUPER_MAGIC, CGROUP_SUPER_MAGIC);
SAME_VALUE(LB_CGROUP2_SUPER_MAGIC, CGROUP2_SUPER_MAGIC);

SAME_VALUE(LB_PR_SET_KEEPCAPS, PR_SET_KEEPCAPS);
SAME_VALUE(LB_PR_SET_DUMPABLE, PR_SET_DUMPABLE);
SAME_VALUE(LB_PR_SET_NAME, PR_SET_NAME);
SAME_VALUE(LB_PR_SET_SECCOMP, PR_SET_SECCOMP);
SAME_VALUE(LB_PR_CAPBSET_READ, PR_CAPBSET_READ);
SAME_VALUE(LB_PR_CAPBSET_DROP, PR_CAPBSET_DROP);
SAME_VALUE(LB_PR_SET_NO_NEW_PRIVS, PR_SET_NO_NEW_PRIVS);
SAME_VALUE(LB_PR_CAP_AMBIENT, PR_CAP_AMBIENT);
SAME_VALUE(LB_PR_CAP_AMBIENT_CLEAR_ALL, PR_CAP_AMBIENT_CLEAR_ALL);

SAME_VALUE(LB_CAP_CHOWN, CAP_CHOWN);
SAME_VALUE(LB_CAP_DAC_OVERRIDE, CAP_DAC_OVERRIDE);
SAME_VALUE(LB_CAP_FOWNER, CAP_FOWNER);
SAME_VALUE(LB_CAP_FSETID, CAP_FSETID);
SAME_VALUE(LB_CAP_KILL, CAP_KILL);
SAME_VALUE(LB_CAP_SETGID, CAP_SETGID);
SAME_VALUE(LB_CAP_SETUID, CAP_SETUID);
SAME_VALUE(LB_CAP_SETPCAP, CAP_SETPCAP);
SAME_VALUE(LB_CAP_NET_BIND_SERVICE, CAP_NET_BIND_SERVICE);
SAME_VALUE(LB_CAP_SYS_CHROOT, CAP_SYS_CHROOT);
SAME_VALUE(LB_CAP_AUDIT_WRITE, CAP_AUDIT_WRITE);
SAME_VALUE(LB_CAP_SETFCAP, CAP_SETFCAP);
SAME_VALUE(LB_CAPABILITY_VERSION_3, _LINUX_CAPABILITY_VERSION_3);
SAME_VALUE(LB_CAPABILITY_WORDS, _LINUX_CAPABILITY_U32S_3);

/* The flags statfs reports for a mount are passed back to mount(2) as they
 * are, so each must be the bit mount(2) takes for the same thing. */
SAME_VALUE(LB_ST_RDONLY, MS_RDONLY);
SAME_VALUE(LB_ST_NOSUID, MS_NOSUID);
SAME_VALUE(LB_ST_NODEV, MS_NODEV);
SAME_VALUE(LB_ST_NOEXEC, MS_NOEXEC);
SAME_VALUE(LB_MS_NOATIME, MS_NOATIME);
SAME_VALUE(LB_MS_NODIRATIME, MS_NODIRATIME);
SAME_VALUE(LB_MS_RELATIME, MS_RELATIME);
SAME_VALUE(LB_MS_STRICTATIME, MS_STRICTATIME);

#define SAME_SIZE(ours, kernels) \
    _Static_assert(sizeof(struct ours) == sizeof(struct kernels), \
                   "struct " #ours " is not the size of the kernel's struct " #kernels)

#define SAME_FIELD(ours, kernels, field) \
    _Static_assert(offsetof(struct ours, field) == offsetof(struct kernels, field) && \
                   sizeof(((struct ours *)0)->field) == sizeof(((struct kernels *)0)->field), \
                   "struct " #ours "." #field " does not match the kernel's struct " #kernels)

SAME_SIZE(lb_statfs, statfs);
SAME_FIELD(lb_statfs, statfs, f_type);
SAME_FIELD(lb_statfs, statfs, f_flags);

SAME_SIZE(lb_statx, statx);
SAME_FIELD(lb_statx, statx, stx_mask);
SAME_FIELD(lb_statx, statx, stx_attributes);
SAME_FIELD(lb_statx, statx, stx_uid);
SAME_FIELD(lb_statx, statx, stx_gid);
SAME_FIELD(lb_statx, statx, stx_mode);
SAME_FIELD(lb_statx, statx, stx_attributes_mask);
SAME_FIELD(lb_statx, statx, stx_dev_major);
SAME_FIELD(lb_statx, statx, stx_dev_minor);
SAME_FIELD(lb_statx, statx, stx_mnt_id);
SAME_FIELD(lb_statx, statx, stx_nlink);
SAME_FIELD(lb_statx, statx, stx_ino);
SAME_FIELD(lb_statx, statx, stx_size);
SAME_FIELD(lb_statx, statx, stx_rdev_major);
SAME_FIELD(lb_statx, statx, stx_rdev_minor);
/* stx_mtime is a struct of the kernel's, which lightbox has as its two numbers */
_Static_assert(offsetof(struct lb_statx, stx_mtime_sec) == offsetof(struct statx, stx_mtime.tv_sec) &&
               offsetof(struct lb_statx, stx_mtime_nsec) == offsetof(struct statx, stx_mtime.tv_nsec) &&
               sizeof(((struct lb_statx *)0)->stx_mtime_sec) == sizeof(((struct statx *)0)->stx_mtime.tv_sec) &&
               sizeof(((struct lb_statx *)0)->stx_mtime_nsec) == sizeof(((struct statx *)0)->stx_mtime.tv_nsec),
               "struct lb_statx's mtime does not match the kernel's struct statx");

/* siginfo_t is a typedef, and its fields past the first three are macros
 * into a union: compared one by one. */
#define SAME_SIGINFO(ours, kernels) \
    _Static_assert(offsetof(struct lb_siginfo_queue, ours) == offsetof(siginfo_t, kernels) && \
                   sizeof(((struct lb_siginfo_queue *)0)->ours) == sizeof(((siginfo_t *)0)->kernels), \
                   "struct lb_siginfo_queue." #ours " does not match the kernel's siginfo_t." #kernels)
_Static_assert(sizeof(struct lb_siginfo_queue) == sizeof(siginfo_t),
               "struct lb_siginfo_queue is not the size of the kernel's siginfo_t");
SAME_SIGINFO(signo, si_signo);
SAME_SIGINFO(err, si_errno);
SAME_SIGINFO(code, si_code);
SAME_SIGINFO(pid, si_pid);
SAME_SIGINFO(uid, si_uid);
SAME_SIGINFO(value, si_int);

SAME_SIZE(lb_termios, termios);
_Static_assert(offsetof(struct lb_termios, iflag) == offsetof(struct termios, c_iflag) &&
               offsetof(struct lb_termios, oflag) == offsetof(struct termios, c_oflag) &&
               offsetof(struct lb_termios, cflag) == offsetof(struct termios, c_cflag) &&
               offsetof(struct lb_termios, lflag) == offsetof(struct termios, c_lflag) &&
               offsetof(struct lb_termios, line) == offsetof(struct termios, c_line) &&
               offsetof(struct lb_termios, cc) == offsetof(struct termios, c_cc) &&
               sizeof(((struct lb_termios *)0)->cc) == sizeof(((struct termios *)0)->c_cc),
               "struct lb_termios does not match the kernel's struct termios");
SAME_SIZE(lb_winsize, winsize);
_Static_assert(offsetof(struct lb_winsize, row) == offsetof(struct winsize, ws_row) &&
               offsetof(struct lb_winsize, col) == offsetof(struct winsize, ws_col),
               "struct lb_winsize does not match the kernel's struct winsize");

SAME_SIZE(lb_mount_attr, mount_attr);
SAME_FIELD(lb_mount_attr, mount_attr, attr_set);
SAME_FIELD(lb_mount_attr, mount_attr, attr_clr);

/* rtnetlink. AF_NETLINK, SOCK_RAW and SOCK_CLOEXEC, which the kernel's
 * headers do not have, are in sys_check_net.c. */
SAME_VALUE(LB_NETLINK_ROUTE, NETLINK_ROUTE);
SAME_VALUE(LB_NLMSG_ERROR, NLMSG_ERROR);
SAME_VALUE(LB_NLMSG_DONE, NLMSG_DONE);
SAME_VALUE(LB_NLM_F_REQUEST, NLM_F_REQUEST);
SAME_VALUE(LB_NLM_F_MULTI, NLM_F_MULTI);
SAME_VALUE(LB_NLM_F_ACK, NLM_F_ACK);
SAME_VALUE(LB_NLM_F_EXCL, NLM_F_EXCL);
SAME_VALUE(LB_NLM_F_CREATE, NLM_F_CREATE);
SAME_VALUE(LB_NLM_F_DUMP, NLM_F_DUMP);
SAME_VALUE(LB_RTM_NEWLINK, RTM_NEWLINK);
SAME_VALUE(LB_RTM_DELLINK, RTM_DELLINK);
SAME_VALUE(LB_RTM_GETLINK, RTM_GETLINK);
SAME_VALUE(LB_RTM_NEWADDR, RTM_NEWADDR);
SAME_VALUE(LB_RTM_NEWROUTE, RTM_NEWROUTE);
SAME_VALUE(LB_RTM_GETROUTE, RTM_GETROUTE);
SAME_VALUE(LB_IFLA_IFNAME, IFLA_IFNAME);
SAME_VALUE(LB_IFLA_MASTER, IFLA_MASTER);
SAME_VALUE(LB_IFLA_LINKINFO, IFLA_LINKINFO);
SAME_VALUE(LB_IFLA_NET_NS_PID, IFLA_NET_NS_PID);
SAME_VALUE(LB_IFLA_IFALIAS, IFLA_IFALIAS);
SAME_VALUE(LB_IFLA_INFO_KIND, IFLA_INFO_KIND);
SAME_VALUE(LB_IFLA_INFO_DATA, IFLA_INFO_DATA);
SAME_VALUE(LB_IFLA_INFO_SLAVE_KIND, IFLA_INFO_SLAVE_KIND);
SAME_VALUE(LB_IFLA_INFO_SLAVE_DATA, IFLA_INFO_SLAVE_DATA);
SAME_VALUE(LB_IFLA_BRPORT_ISOLATED, IFLA_BRPORT_ISOLATED);
SAME_VALUE(LB_VETH_INFO_PEER, VETH_INFO_PEER);
SAME_VALUE(LB_IFA_ADDRESS, IFA_ADDRESS);
SAME_VALUE(LB_IFA_LOCAL, IFA_LOCAL);
SAME_VALUE(LB_RTA_OIF, RTA_OIF);
SAME_VALUE(LB_RTA_GATEWAY, RTA_GATEWAY);
SAME_VALUE(LB_RTA_TABLE, RTA_TABLE);
SAME_VALUE(LB_RT_TABLE_MAIN, RT_TABLE_MAIN);
SAME_VALUE(LB_RTPROT_BOOT, RTPROT_BOOT);
SAME_VALUE(LB_RT_SCOPE_UNIVERSE, RT_SCOPE_UNIVERSE);
SAME_VALUE(LB_RTN_UNICAST, RTN_UNICAST);

/* the same layout under other names */
#define SAME_MEMBER(ours, ofield, kernels, kfield) \
    _Static_assert(offsetof(struct ours, ofield) == offsetof(struct kernels, kfield) && \
                   sizeof(((struct ours *)0)->ofield) == sizeof(((struct kernels *)0)->kfield), \
                   "struct " #ours "." #ofield " does not match the kernel's struct " #kernels "." #kfield)

SAME_SIZE(lb_nlmsghdr, nlmsghdr);
SAME_MEMBER(lb_nlmsghdr, len, nlmsghdr, nlmsg_len);
SAME_MEMBER(lb_nlmsghdr, type, nlmsghdr, nlmsg_type);
SAME_MEMBER(lb_nlmsghdr, flags, nlmsghdr, nlmsg_flags);
SAME_MEMBER(lb_nlmsghdr, seq, nlmsghdr, nlmsg_seq);
SAME_MEMBER(lb_nlmsghdr, pid, nlmsghdr, nlmsg_pid);
SAME_SIZE(lb_nlmsgerr, nlmsgerr);
SAME_MEMBER(lb_nlmsgerr, error, nlmsgerr, error);
SAME_MEMBER(lb_nlmsgerr, msg, nlmsgerr, msg);
SAME_SIZE(lb_rtattr, rtattr);
SAME_MEMBER(lb_rtattr, len, rtattr, rta_len);
SAME_MEMBER(lb_rtattr, type, rtattr, rta_type);
SAME_SIZE(lb_ifinfomsg, ifinfomsg);
SAME_MEMBER(lb_ifinfomsg, family, ifinfomsg, ifi_family);
SAME_MEMBER(lb_ifinfomsg, type, ifinfomsg, ifi_type);
SAME_MEMBER(lb_ifinfomsg, index, ifinfomsg, ifi_index);
SAME_MEMBER(lb_ifinfomsg, flags, ifinfomsg, ifi_flags);
SAME_MEMBER(lb_ifinfomsg, change, ifinfomsg, ifi_change);
SAME_SIZE(lb_ifaddrmsg, ifaddrmsg);
SAME_MEMBER(lb_ifaddrmsg, family, ifaddrmsg, ifa_family);
SAME_MEMBER(lb_ifaddrmsg, prefixlen, ifaddrmsg, ifa_prefixlen);
SAME_MEMBER(lb_ifaddrmsg, flags, ifaddrmsg, ifa_flags);
SAME_MEMBER(lb_ifaddrmsg, scope, ifaddrmsg, ifa_scope);
SAME_MEMBER(lb_ifaddrmsg, index, ifaddrmsg, ifa_index);
SAME_SIZE(lb_rtmsg, rtmsg);
SAME_MEMBER(lb_rtmsg, family, rtmsg, rtm_family);
SAME_MEMBER(lb_rtmsg, dst_len, rtmsg, rtm_dst_len);
SAME_MEMBER(lb_rtmsg, src_len, rtmsg, rtm_src_len);
SAME_MEMBER(lb_rtmsg, tos, rtmsg, rtm_tos);
SAME_MEMBER(lb_rtmsg, table, rtmsg, rtm_table);
SAME_MEMBER(lb_rtmsg, protocol, rtmsg, rtm_protocol);
SAME_MEMBER(lb_rtmsg, scope, rtmsg, rtm_scope);
SAME_MEMBER(lb_rtmsg, type, rtmsg, rtm_type);
SAME_MEMBER(lb_rtmsg, flags, rtmsg, rtm_flags);
SAME_SIZE(lb_sockaddr_nl, sockaddr_nl);
SAME_MEMBER(lb_sockaddr_nl, family, sockaddr_nl, nl_family);
SAME_MEMBER(lb_sockaddr_nl, pid, sockaddr_nl, nl_pid);
SAME_MEMBER(lb_sockaddr_nl, groups, sockaddr_nl, nl_groups);

SAME_SIZE(lb_open_how, open_how);
SAME_FIELD(lb_open_how, open_how, flags);
SAME_FIELD(lb_open_how, open_how, mode);
SAME_FIELD(lb_open_how, open_how, resolve);

SAME_SIZE(lb_pollfd, pollfd);
SAME_FIELD(lb_pollfd, pollfd, fd);
SAME_FIELD(lb_pollfd, pollfd, events);
SAME_FIELD(lb_pollfd, pollfd, revents);

SAME_SIZE(lb_cap_header, __user_cap_header_struct);
SAME_FIELD(lb_cap_header, __user_cap_header_struct, version);
SAME_FIELD(lb_cap_header, __user_cap_header_struct, pid);
SAME_SIZE(lb_cap_data, __user_cap_data_struct);
SAME_FIELD(lb_cap_data, __user_cap_data_struct, effective);
SAME_FIELD(lb_cap_data, __user_cap_data_struct, permitted);
SAME_FIELD(lb_cap_data, __user_cap_data_struct, inheritable);

/* ─── lightbox_seccomp.h ────────────────────────────────────────────────── */

/* Every row of the deny table holds the kernel's number for its name, on the
 * architecture this file is being compiled for. */
#if defined(__x86_64__)
#define ROW_NR(x86_64, aarch64) (x86_64)
#else
#define ROW_NR(x86_64, aarch64) (aarch64)
#endif

#define CHECK_ROW(name, x86_64, aarch64, err) \
    _Static_assert(ROW_NR(x86_64, aarch64) == __NR_##name, \
                   "lightbox_seccomp.h: wrong number for " #name);
LB_SECCOMP_DENY(CHECK_ROW)

/* The x86_64-only rows: right on x86_64, and really absent everywhere else. If
 * the kernel's headers define __NR_<name>, NR_TEXT(__NR_<name>) is its digits;
 * if they do not, it is the name itself. */
#define NR_TEXT_(token) #token
#define NR_TEXT(token)  NR_TEXT_(token)

#if defined(__x86_64__)
#define CHECK_ROW_X86_64(name, nr, err) \
    _Static_assert((nr) == __NR_##name, "lightbox_seccomp.h: wrong x86_64 number for " #name);
#else
#define CHECK_ROW_X86_64(name, nr, err) \
    _Static_assert(sizeof(NR_TEXT(__NR_##name)) == sizeof("__NR_" #name), \
                   "lightbox_seccomp.h: " #name " exists on this architecture; move it to LB_SECCOMP_DENY");
#endif
LB_SECCOMP_DENY_X86_64(CHECK_ROW_X86_64)

/* the mode table, as the deny table */
#define CHECK_MODE_ROW(name, x86_64, aarch64, mode, flags) CHECK_ROW(name, x86_64, aarch64, 0)
LB_SECCOMP_MODE(CHECK_MODE_ROW)
#define CHECK_MODE_ROW_X86_64(name, nr, mode, flags) CHECK_ROW_X86_64(name, nr, 0)
LB_SECCOMP_MODE_X86_64(CHECK_MODE_ROW_X86_64)
/* the allow table, as the deny table */
#define CHECK_ALLOW_ROW(name, x86_64, aarch64) CHECK_ROW(name, x86_64, aarch64, 0)
LB_SECCOMP_ALLOW(CHECK_ALLOW_ROW)
#define CHECK_ALLOW_ROW_X86_64(name, nr) CHECK_ROW_X86_64(name, nr, 0)
LB_SECCOMP_ALLOW_X86_64(CHECK_ALLOW_ROW_X86_64)
#if defined(__x86_64__)
SAME_VALUE(LB_SECCOMP_NR_SOCKET, LB_SECCOMP_NR_SOCKET_X86_64);
SAME_VALUE(LB_SECCOMP_NR_SOCKETPAIR, LB_SECCOMP_NR_SOCKETPAIR_X86_64);
#else
SAME_VALUE(LB_SECCOMP_NR_SOCKET, LB_SECCOMP_NR_SOCKET_AARCH64);
SAME_VALUE(LB_SECCOMP_NR_SOCKETPAIR, LB_SECCOMP_NR_SOCKETPAIR_AARCH64);
#endif
SAME_VALUE(LB_SECCOMP_NR_SOCKET, __NR_socket);
SAME_VALUE(LB_SECCOMP_NR_SOCKETPAIR, __NR_socketpair);
SAME_VALUE(LB_SC_EAFNOSUPPORT, EAFNOSUPPORT);

SAME_VALUE(LB_SECCOMP_SUID_SGID, S_ISUID | S_ISGID);
SAME_VALUE(LB_SECCOMP_CREATE_FLAGS, O_CREAT | __O_TMPFILE);

SAME_VALUE(LB_SECCOMP_NR_CLONE, __NR_clone);
SAME_VALUE(LB_SC_EPERM, EPERM);
SAME_VALUE(LB_SC_ENOSYS, ENOSYS);

#if defined(__x86_64__)
SAME_VALUE(LB_SECCOMP_AUDIT_ARCH, AUDIT_ARCH_X86_64);
SAME_VALUE(LB_X32_SYSCALL_BIT, __X32_SYSCALL_BIT);
#else
SAME_VALUE(LB_SECCOMP_AUDIT_ARCH, AUDIT_ARCH_AARCH64);
#endif
SAME_VALUE(LB_AUDIT_ARCH_X86_64, AUDIT_ARCH_X86_64);
SAME_VALUE(LB_AUDIT_ARCH_AARCH64, AUDIT_ARCH_AARCH64);

SAME_VALUE(LB_SECCOMP_MODE_FILTER, SECCOMP_MODE_FILTER);
SAME_VALUE(LB_SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_PROCESS);
SAME_VALUE(LB_SECCOMP_RET_ERRNO, SECCOMP_RET_ERRNO);
SAME_VALUE(LB_SECCOMP_RET_ALLOW, SECCOMP_RET_ALLOW);
/* an errno travels in the low 16 bits of the return value */
SAME_VALUE(0xffffU, SECCOMP_RET_DATA);

SAME_VALUE(LB_BPF_LD_W_ABS, BPF_LD | BPF_W | BPF_ABS);
SAME_VALUE(LB_BPF_JEQ_K, BPF_JMP | BPF_JEQ | BPF_K);
SAME_VALUE(LB_BPF_JGE_K, BPF_JMP | BPF_JGE | BPF_K);
SAME_VALUE(LB_BPF_JSET_K, BPF_JMP | BPF_JSET | BPF_K);
SAME_VALUE(LB_BPF_RET_K, BPF_RET | BPF_K);

SAME_VALUE(LB_SECCOMP_DATA_NR, offsetof(struct seccomp_data, nr));
SAME_VALUE(LB_SECCOMP_DATA_ARCH, offsetof(struct seccomp_data, arch));
SAME_VALUE(LB_SECCOMP_DATA_ARG0_LO, offsetof(struct seccomp_data, args));
SAME_VALUE(LB_SECCOMP_DATA_ARG_LO(1), offsetof(struct seccomp_data, args[1]));
SAME_VALUE(LB_SECCOMP_DATA_ARG_LO(2), offsetof(struct seccomp_data, args[2]));
SAME_VALUE(LB_SECCOMP_DATA_ARG_LO(3), offsetof(struct seccomp_data, args[3]));

SAME_VALUE(LB_SECCOMP_CLONE_NS_FLAGS,
           CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
           CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET);
/* CLONE_NEWTIME is left out of that mask because it overlaps the exit signal */
SAME_VALUE(CLONE_NEWTIME & ~CSIGNAL, 0);

SAME_SIZE(lb_sock_filter, sock_filter);
SAME_FIELD(lb_sock_filter, sock_filter, code);
SAME_FIELD(lb_sock_filter, sock_filter, jt);
SAME_FIELD(lb_sock_filter, sock_filter, jf);
SAME_FIELD(lb_sock_filter, sock_filter, k);

SAME_SIZE(lb_sock_fprog, sock_fprog);
SAME_FIELD(lb_sock_fprog, sock_fprog, len);
SAME_FIELD(lb_sock_fprog, sock_fprog, filter);

/* ─── The device program (lightbox_devices.h) and bpf(2) ────────────────── */

SAME_VALUE(LB_BPF_PROG_LOAD, BPF_PROG_LOAD);
SAME_VALUE(LB_BPF_PROG_ATTACH, BPF_PROG_ATTACH);
SAME_VALUE(LB_BPF_PROG_TYPE_CGROUP_DEVICE, BPF_PROG_TYPE_CGROUP_DEVICE);
SAME_VALUE(LB_BPF_CGROUP_DEVICE, BPF_CGROUP_DEVICE);
SAME_VALUE(LB_BPF_OBJ_NAME_LEN, BPF_OBJ_NAME_LEN);

SAME_VALUE(LB_DEVCG_ACC_MKNOD, BPF_DEVCG_ACC_MKNOD);
SAME_VALUE(LB_DEVCG_ACC_READ, BPF_DEVCG_ACC_READ);
SAME_VALUE(LB_DEVCG_ACC_WRITE, BPF_DEVCG_ACC_WRITE);
SAME_VALUE(LB_DEVCG_DEV_BLOCK, BPF_DEVCG_DEV_BLOCK);
SAME_VALUE(LB_DEVCG_DEV_CHAR, BPF_DEVCG_DEV_CHAR);
SAME_VALUE(LB_DEVCG_CTX_ACCESS_TYPE, offsetof(struct bpf_cgroup_dev_ctx, access_type));
SAME_VALUE(LB_DEVCG_CTX_MAJOR, offsetof(struct bpf_cgroup_dev_ctx, major));
SAME_VALUE(LB_DEVCG_CTX_MINOR, offsetof(struct bpf_cgroup_dev_ctx, minor));
SAME_VALUE(LB_DEVCG_CTX_MINOR + 4, sizeof(struct bpf_cgroup_dev_ctx));

SAME_VALUE(LB_EBPF_LDX_MEM_W, BPF_LDX | BPF_MEM | BPF_W);
SAME_VALUE(LB_EBPF_ALU64_MOV_K, BPF_ALU64 | BPF_MOV | BPF_K);
SAME_VALUE(LB_EBPF_ALU64_MOV_X, BPF_ALU64 | BPF_MOV | BPF_X);
SAME_VALUE(LB_EBPF_ALU64_AND_K, BPF_ALU64 | BPF_AND | BPF_K);
SAME_VALUE(LB_EBPF_ALU64_RSH_K, BPF_ALU64 | BPF_RSH | BPF_K);
SAME_VALUE(LB_EBPF_JMP_JNE_K, BPF_JMP | BPF_JNE | BPF_K);
SAME_VALUE(LB_EBPF_JMP_JLT_K, BPF_JMP | BPF_JLT | BPF_K);
SAME_VALUE(LB_EBPF_JMP_JGT_K, BPF_JMP | BPF_JGT | BPF_K);
SAME_VALUE(LB_EBPF_JMP_JSET_K, BPF_JMP | BPF_JSET | BPF_K);
SAME_VALUE(LB_EBPF_JMP_EXIT, BPF_JMP | BPF_EXIT);

/* The registers' nibbles are bit-fields, which offsetof cannot see:
 * tests/devices_filter.c reads them back through the kernel's struct. */
SAME_SIZE(lb_ebpf_insn, bpf_insn);
SAME_FIELD(lb_ebpf_insn, bpf_insn, code);
SAME_FIELD(lb_ebpf_insn, bpf_insn, off);
SAME_FIELD(lb_ebpf_insn, bpf_insn, imm);

/* the two parts of union bpf_attr that lightbox fills */
#define SAME_ATTR(ours, field) \
    _Static_assert(offsetof(struct ours, field) == offsetof(union bpf_attr, field) && \
                   sizeof(((struct ours *)0)->field) == sizeof(((union bpf_attr *)0)->field), \
                   "struct " #ours "." #field " does not match the kernel's union bpf_attr")

SAME_ATTR(lb_bpf_prog_load, prog_type);
SAME_ATTR(lb_bpf_prog_load, insn_cnt);
SAME_ATTR(lb_bpf_prog_load, insns);
SAME_ATTR(lb_bpf_prog_load, license);
SAME_ATTR(lb_bpf_prog_load, log_level);
SAME_ATTR(lb_bpf_prog_load, log_size);
SAME_ATTR(lb_bpf_prog_load, log_buf);
SAME_ATTR(lb_bpf_prog_load, kern_version);
SAME_ATTR(lb_bpf_prog_load, prog_flags);
SAME_ATTR(lb_bpf_prog_load, prog_name);
SAME_VALUE(sizeof(struct lb_bpf_prog_load), offsetof(union bpf_attr, prog_name) + BPF_OBJ_NAME_LEN);
SAME_ATTR(lb_bpf_prog_attach, target_fd);
SAME_ATTR(lb_bpf_prog_attach, attach_bpf_fd);
SAME_ATTR(lb_bpf_prog_attach, attach_type);
SAME_ATTR(lb_bpf_prog_attach, attach_flags);
SAME_VALUE(sizeof(struct lb_bpf_prog_attach), offsetof(union bpf_attr, attach_flags) + 4);

SAME_VALUE(LB_DEV_MEM_MAJOR, MEM_MAJOR);
SAME_VALUE(LB_DEV_TTYAUX_MAJOR, TTYAUX_MAJOR);
SAME_VALUE(LB_DEV_PTS_MAJOR, UNIX98_PTY_SLAVE_MAJOR);
SAME_VALUE(LB_DEV_PTS_MAJORS, UNIX98_PTY_MAJOR_COUNT);
