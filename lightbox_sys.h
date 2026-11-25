#ifndef LIGHTBOX_SYS_H
#define LIGHTBOX_SYS_H

/*
 * Private syscall numbers, kernel constants and thin wrappers for the calls
 * lightc does not wrap yet.
 *
 * This is the only place in lightbox that may hold a raw syscall number.
 * tests/sys_check.c and tests/sys_check_net.c compare every number, constant
 * and structure layout here with the kernel's own headers for x86_64 and
 * aarch64 (make check-sys), so a wrong value fails the build instead of
 * calling a different syscall.
 *
 * Delete an entry when lightc ships the wrapper for it.
 */

#ifdef LIGHTBOX_SYS_CHECK
/* tests/sys_check.c: numbers and layouts only, compiled without lightc. */
#include <stdint.h>
#else
#include <lightc/syscall.h>
#include <lightc/types.h>
#endif

/* ─── Syscall numbers ───────────────────────────────────────────────────── */

#if defined(__x86_64__)
#define LB_SYS_fcntl      72
#define LB_SYS_flock      73
#define LB_SYS_fsync      74
#define LB_SYS_fchdir     81
#define LB_SYS_fchmod     91
#define LB_SYS_umask      95
#define LB_SYS_getuid     102
#define LB_SYS_geteuid    107
#define LB_SYS_capget     125
#define LB_SYS_capset     126
#define LB_SYS_statfs     137
#define LB_SYS_fstatfs    138
#define LB_SYS_chroot     161
#define LB_SYS_fsetxattr  190
#define LB_SYS_fgetxattr  193
#define LB_SYS_flistxattr 196
#define LB_SYS_renameat   264
#define LB_SYS_linkat     265
#define LB_SYS_ppoll      271
#define LB_SYS_utimensat  280
#define LB_SYS_memfd_create 319
#define LB_SYS_getrandom  318
#define LB_SYS_execveat   322
#define LB_SYS_bpf        321
#define LB_SYS_statx      332
#define LB_SYS_faccessat  269
#define LB_SYS_pidfd_send_signal 424
#define LB_SYS_open_tree  428
#define LB_SYS_move_mount 429
#define LB_SYS_pidfd_open 434
#define LB_SYS_close_range 436
#define LB_SYS_openat2    437
#define LB_SYS_mount_setattr 442
#elif defined(__aarch64__)
#define LB_SYS_fsetxattr  7
#define LB_SYS_fgetxattr  10
#define LB_SYS_flistxattr 13
#define LB_SYS_fcntl      25
#define LB_SYS_flock      32
#define LB_SYS_linkat     37
#define LB_SYS_renameat   38
#define LB_SYS_statfs     43
#define LB_SYS_fstatfs    44
#define LB_SYS_fchdir     50
#define LB_SYS_chroot     51
#define LB_SYS_fchmod     52
#define LB_SYS_ppoll      73
#define LB_SYS_fsync      82
#define LB_SYS_utimensat  88
#define LB_SYS_capget     90
#define LB_SYS_capset     91
#define LB_SYS_umask      166
#define LB_SYS_getuid     174
#define LB_SYS_geteuid    175
#define LB_SYS_memfd_create 279
#define LB_SYS_getrandom  278
#define LB_SYS_execveat   281
#define LB_SYS_bpf        280
#define LB_SYS_statx      291
#define LB_SYS_faccessat  48
#define LB_SYS_pidfd_send_signal 424
#define LB_SYS_open_tree  428
#define LB_SYS_move_mount 429
#define LB_SYS_pidfd_open 434
#define LB_SYS_close_range 436
#define LB_SYS_openat2    437
#define LB_SYS_mount_setattr 442
#else
#error "lightbox supports x86_64 and aarch64 only"
#endif

/* ─── Kernel constants (the same on both architectures) ─────────────────── */

/* CLOCK_BOOTTIME: CLOCK_MONOTONIC with the time the system was suspended,
 * for a lifetime that counts as a clock on the wall does */
#define LB_CLOCK_BOOTTIME 7

#define LB_EPERM                  1
#define LB_ENOENT                 2
#define LB_ESRCH                  3
#define LB_EINTR                  4
#define LB_EIO                    5
#define LB_EAGAIN                 11
#define LB_ENOMEM                 12
#define LB_EACCES                 13
#define LB_EBUSY                  16
#define LB_EEXIST                 17
#define LB_ENODEV                 19
#define LB_EINVAL                 22
#define LB_ENOSYS                 38
#define LB_ENOTDIR                20
#define LB_EISDIR                 21
#define LB_ERANGE                 34
#define LB_ENAMETOOLONG           36
#define LB_ENOTEMPTY              39
#define LB_ELOOP                  40
#define LB_ENODATA                61
#define LB_EOPNOTSUPP             95

/* The signals lightbox names that lightc does not (asm/signal.h) */
#define LB_SIGPIPE                13
#define LB_SIGCONT                18
#define LB_SIGTTOU                22
#define LB_SIGWINCH               28
#define LB_SIGSYS                 31

/* si_code of a signal that was queued with a value (asm-generic/siginfo.h) */
#define LB_SI_QUEUE               (-1)

/* What ppoll(2) is asked to wait for, and what it reports (asm-generic/poll.h).
 * A pipe whose other end was closed reports POLLHUP, with or without POLLIN. */
#define LB_POLLIN                 0x0001
#define LB_POLLOUT                0x0004
#define LB_POLLERR                0x0008
#define LB_POLLHUP                0x0010

#define LB_S_IFMT                 0170000
#define LB_S_IFIFO                0010000
#define LB_S_IFCHR                0020000
#define LB_S_IFDIR                0040000
#define LB_S_IFBLK                0060000
#define LB_S_IFREG                0100000
#define LB_S_IFLNK                0120000
#define LB_S_IFSOCK               0140000

/* statx of the file a descriptor is open on, given an empty path (linux/fcntl.h) */
#define LB_AT_EMPTY_PATH          0x1000

/* utimensat(2): a time that is left as it is, in the place of its
 * nanoseconds (the C library's bits/stat.h; the kernel's headers for programs
 * do not name it) */
#define LB_UTIME_OMIT             ((1L << 30) - 2L)

#define LB_STATX_TYPE             0x00000001U
#define LB_STATX_INO              0x00000100U
#define LB_STATX_MODE             0x00000002U
#define LB_STATX_NLINK            0x00000004U
#define LB_STATX_MTIME            0x00000040U
#define LB_STATX_SIZE             0x00000200U
#define LB_STATX_UID              0x00000008U
#define LB_STATX_GID              0x00000010U
#define LB_STATX_ATTR_MOUNT_ROOT  0x00002000U   /* reported since Linux 5.8 */

#define LB_CGROUP_SUPER_MAGIC     0x0027e0eb    /* a cgroup v1 hierarchy */
#define LB_CGROUP2_SUPER_MAGIC    0x63677270

/* f_flags of statfs: what the mount at a path carries. Each of these four is
 * the bit mount(2) takes for the same thing (MS_RDONLY and so on). */
#define LB_ST_RDONLY              1
#define LB_ST_NOSUID              2
#define LB_ST_NODEV               4
#define LB_ST_NOEXEC              8
/* How a mount keeps access times: in statfs's f_flags, and as mount(2) takes
 * them; noatime and nodiratime have the same bits in both, relatime not. */
#define LB_ST_NOATIME             1024
#define LB_ST_NODIRATIME          2048
#define LB_ST_RELATIME            4096
#define LB_MS_NOATIME             1024
#define LB_MS_NODIRATIME          2048
#define LB_MS_RELATIME            (1 << 21)
#define LB_MS_STRICTATIME         (1 << 24)

/* Terminals (asm-generic/ioctls.h, termbits.h, fcntl.h).
 *
 * TIOCGPTPEER opens the other end of a pseudo-terminal from the descriptor of
 * the one end, without a path for anything to stand in. */
#define LB_TCGETS                     0x5401
#define LB_TCSETS                     0x5402
#define LB_TIOCSCTTY                  0x540E
#define LB_TIOCGWINSZ                 0x5413
#define LB_TIOCSWINSZ                 0x5414
#define LB_TIOCSPTLCK                 0x40045431
#define LB_TIOCGPTPEER                0x5441

#define LB_O_NOCTTY                   0400
#define LB_F_GETFL                    3
#define LB_F_SETFL                    4

/* what "raw" takes away from a terminal's modes, and the two characters it sets */
#define LB_IGNBRK                     0x001
#define LB_BRKINT                     0x002
#define LB_PARMRK                     0x008
#define LB_ISTRIP                     0x020
#define LB_INLCR                      0x040
#define LB_IGNCR                      0x080
#define LB_ICRNL                      0x100
#define LB_IXON                       0x400
#define LB_OPOST                      0x01
#define LB_ISIG                       0x00001
#define LB_ICANON                     0x00002
#define LB_ECHO                       0x00008
#define LB_ECHONL                     0x00040
#define LB_IEXTEN                     0x08000
#define LB_CSIZE                      0x00000030
#define LB_CS8                        0x00000030
#define LB_PARENB                     0x00000100
#define LB_VTIME                      5
#define LB_VMIN                       6

/* memfd_create(2) (linux/memfd.h). MFD_EXEC, Linux 6.3, says that the file
 * is meant to be executed; an older kernel does not know the flag. */
#define LB_MFD_CLOEXEC                0x0001U
#define LB_MFD_ALLOW_SEALING          0x0002U
#define LB_MFD_EXEC                   0x0010U

/* fcntl(2) on a memfd: its seals (linux/fcntl.h). Once F_SEAL_SEAL is set
 * the others cannot be taken off again, by anyone. */
#define LB_F_ADD_SEALS                1033
#define LB_F_GET_SEALS                1034
#define LB_F_SEAL_SEAL                0x0001
#define LB_F_SEAL_SHRINK              0x0002
#define LB_F_SEAL_GROW                0x0004
#define LB_F_SEAL_WRITE               0x0008

/* mount_setattr(2), Linux 5.12 (linux/mount.h): read-only, and the flags of
 * an idmapped mount, whose files show the ids of a user namespace */
#define LB_MOUNT_ATTR_RDONLY          0x00000001
#define LB_MOUNT_ATTR_NOSUID          0x00000002
#define LB_MOUNT_ATTR_NODEV           0x00000004
#define LB_MOUNT_ATTR_IDMAP           0x00100000

/* flock(2) (asm-generic/fcntl.h). A lock belongs to the open file, and is
 * gone when the last descriptor of that open file is closed. */
#define LB_LOCK_SH                    1
#define LB_LOCK_EX                    2
#define LB_LOCK_NB                    4

/* open(2): fail if the file is there already, and a descriptor that only
 * names a file, for which the right to pass its directory is enough
 * (asm-generic/fcntl.h); the open flags lightbox uses that lightc does not
 * name */
#define LB_O_EXCL                     0200
#define LB_O_PATH                     010000000

/* openat2(2), Linux 5.6 (linux/openat2.h): look a path up as if the directory
 * it starts from were the root. A link to "/x" then leads to x in that
 * directory, and ".." does not lead out of it. */
#define LB_RESOLVE_IN_ROOT            0x10

/* open_tree(2) and move_mount(2), Linux 5.2 (linux/mount.h). A cloned tree
 * is a copy of a mount that is attached nowhere yet; move_mount attaches it. */
#define LB_OPEN_TREE_CLONE            1
#define LB_OPEN_TREE_CLOEXEC          02000000      /* O_CLOEXEC */
#define LB_MOVE_MOUNT_F_EMPTY_PATH    0x00000004    /* the tree is the descriptor itself */
#define LB_MOVE_MOUNT_T_SYMLINKS      0x00000010    /* follow a link at the end of the target */

/* clone(2) and unshare(2): the namespace that lightc does not name yet
 * (linux/sched.h; ROADMAP U.4) */
#define LB_CLONE_NEWCGROUP            0x02000000

/* prctl(2) requests (linux/prctl.h) */
#define LB_PR_SET_DUMPABLE            4
#define LB_PR_SET_KEEPCAPS            8
#define LB_PR_SET_NAME                15
#define LB_PR_SET_SECCOMP             22
#define LB_PR_CAPBSET_READ            23
#define LB_PR_CAPBSET_DROP            24
#define LB_PR_SET_NO_NEW_PRIVS        38
#define LB_PR_CAP_AMBIENT             47
#define LB_PR_CAP_AMBIENT_CLEAR_ALL   4

/* The capabilities a sandboxed container keeps (linux/capability.h) */
#define LB_CAP_CHOWN              0
#define LB_CAP_DAC_OVERRIDE       1
#define LB_CAP_FOWNER             3
#define LB_CAP_FSETID             4
#define LB_CAP_KILL               5
#define LB_CAP_SETGID             6
#define LB_CAP_SETUID             7
#define LB_CAP_SETPCAP            8
#define LB_CAP_NET_BIND_SERVICE   10
#define LB_CAP_SYS_CHROOT         18
#define LB_CAP_AUDIT_WRITE        29
#define LB_CAP_SETFCAP            31

/* capget(2) and capset(2), version 3: each set is two 32-bit words */
#define LB_CAPABILITY_VERSION_3   0x20080522
#define LB_CAPABILITY_WORDS       2

/* A socket to carry interface requests, and the two requests that read and
 * write an interface's flags (sys/socket.h, linux/sockios.h, linux/if.h). */
#define LB_AF_INET                2
#define LB_SOCK_DGRAM             2
#define LB_SIOCGIFFLAGS           0x8913
#define LB_SIOCSIFFLAGS           0x8914
#define LB_IFF_UP                 0x1

/* rtnetlink: a socket to the kernel's configuration of interfaces, addresses
 * and routes, the requests lightbox makes of it and the attributes they carry
 * (linux/netlink.h, rtnetlink.h, if_link.h, veth.h, if_addr.h). */
#define LB_AF_NETLINK             16
#define LB_SOCK_RAW               3
#define LB_SOCK_CLOEXEC           0x80000
#define LB_NETLINK_ROUTE          0

#define LB_NLMSG_ERROR            2
#define LB_NLMSG_DONE             3
#define LB_NLM_F_REQUEST          0x001
#define LB_NLM_F_MULTI            0x002
#define LB_NLM_F_ACK              0x004
#define LB_NLM_F_EXCL             0x200
#define LB_NLM_F_CREATE           0x400
#define LB_NLM_F_DUMP             0x300

#define LB_RTM_NEWLINK            16
#define LB_RTM_DELLINK            17
#define LB_RTM_GETLINK            18
#define LB_RTM_NEWADDR            20
#define LB_RTM_NEWROUTE           24
#define LB_RTM_GETROUTE           26

#define LB_IFLA_IFNAME            3
#define LB_IFLA_MASTER            10
#define LB_IFLA_LINKINFO          18
#define LB_IFLA_NET_NS_PID        19
#define LB_IFLA_IFALIAS           20
#define LB_IFLA_INFO_KIND         1
#define LB_IFLA_INFO_DATA         2
#define LB_IFLA_INFO_SLAVE_KIND   4
#define LB_IFLA_INFO_SLAVE_DATA   5
#define LB_IFLA_BRPORT_ISOLATED   33
#define LB_VETH_INFO_PEER         1

#define LB_IFA_ADDRESS            1
#define LB_IFA_LOCAL              2

#define LB_RTA_OIF                4
#define LB_RTA_GATEWAY            5
#define LB_RTA_TABLE              15
#define LB_RT_TABLE_MAIN          254
#define LB_RTPROT_BOOT            3
#define LB_RT_SCOPE_UNIVERSE      0
#define LB_RTN_UNICAST            1

/* ─── Structures ────────────────────────────────────────────────────────── */

/* rtnetlink's headers: of a message, of an error the kernel answers with, of
 * an attribute, and of the three kinds of request; and the address of the
 * kernel's end (linux/netlink.h, rtnetlink.h, if_link.h, if_addr.h). Every
 * header and attribute starts at a multiple of 4 bytes. */
struct lb_nlmsghdr {
    uint32_t len;
    uint16_t type;
    uint16_t flags;
    uint32_t seq;
    uint32_t pid;
};

struct lb_nlmsgerr {
    int32_t            error;       /* 0 for an acknowledgement, or minus an errno */
    struct lb_nlmsghdr msg;         /* the header of the request it answers */
};

struct lb_rtattr {
    uint16_t len;                   /* with these 4 bytes, and without the padding after */
    uint16_t type;
};

struct lb_ifinfomsg {
    uint8_t  family;
    uint8_t  pad;
    uint16_t type;
    int32_t  index;
    uint32_t flags;
    uint32_t change;
};

struct lb_ifaddrmsg {
    uint8_t  family;
    uint8_t  prefixlen;
    uint8_t  flags;
    uint8_t  scope;
    uint32_t index;
};

struct lb_rtmsg {
    uint8_t  family;
    uint8_t  dst_len;
    uint8_t  src_len;
    uint8_t  tos;
    uint8_t  table;
    uint8_t  protocol;
    uint8_t  scope;
    uint8_t  type;
    uint32_t flags;
};

struct lb_sockaddr_nl {
    uint16_t family;
    uint16_t pad;
    uint32_t pid;                   /* 0: the kernel */
    uint32_t groups;
};

/* struct __user_cap_header_struct and __user_cap_data_struct (linux/capability.h) */
struct lb_cap_header {
    uint32_t version;
    int32_t  pid;
};

struct lb_cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

/* siginfo_t (asm-generic/siginfo.h) as a signal queued with a value fills
 * it: the three numbers every signal has, then who sent it and the value. */
struct lb_siginfo_queue {
    int32_t  signo;
    int32_t  err;
    int32_t  code;
    int32_t  pad0;
    int32_t  pid;
    uint32_t uid;
    int32_t  value;
    uint8_t  pad1[100];
};

/* struct termios, as TCGETS and TCSETS take it, and struct winsize
 * (asm-generic/termbits.h, termios.h) */
struct lb_termios {
    uint32_t iflag;
    uint32_t oflag;
    uint32_t cflag;
    uint32_t lflag;
    uint8_t  line;
    uint8_t  cc[19];
};

struct lb_winsize {
    uint16_t row;
    uint16_t col;
    uint16_t xpixel;
    uint16_t ypixel;
};

/* struct mount_attr (linux/mount.h) */
struct lb_mount_attr {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

/* union bpf_attr (linux/bpf.h) as BPF_PROG_LOAD reads it, to the program's
 * name; the kernel takes the rest of the union as zero */
struct lb_bpf_prog_load {
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns;             /* the instructions' address */
    uint64_t license;           /* a string's address */
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf;
    uint32_t kern_version;
    uint32_t prog_flags;
    char     prog_name[16];
};

/* union bpf_attr as BPF_PROG_ATTACH reads it, to its flags */
struct lb_bpf_prog_attach {
    uint32_t target_fd;         /* the cgroup's directory */
    uint32_t attach_bpf_fd;     /* the program */
    uint32_t attach_type;
    uint32_t attach_flags;
};

/* struct open_how (linux/openat2.h) */
struct lb_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

/* struct pollfd (asm-generic/poll.h) */
struct lb_pollfd {
    int32_t fd;
    int16_t events;
    int16_t revents;
};

/* struct ifreq (linux/if.h), as the two flag requests use it: the interface's
 * name and its flags. The rest of the kernel's union is padding here. */
struct lb_ifreq_flags {
    char    name[16];
    int16_t flags;
    char    pad[22];
};

/* struct statfs as the 64-bit kernels lay it out (asm-generic/statfs.h). */
struct lb_statfs {
    int64_t  f_type;
    int64_t  f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    int32_t  f_fsid[2];
    int64_t  f_namelen;
    int64_t  f_frsize;
    int64_t  f_flags;
    int64_t  f_spare[4];
};

/* struct statx (linux/stat.h). Fields lightbox does not read are padding. */
struct lb_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t stx_pad0;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    uint64_t stx_times[6];          /* atime, btime and ctime */
    int64_t  stx_mtime_sec;         /* stx_mtime.tv_sec */
    uint32_t stx_mtime_nsec;        /* stx_mtime.tv_nsec */
    int32_t  stx_mtime_pad;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t stx_spare[13];
};

/* ─── Wrappers ──────────────────────────────────────────────────────────── */

#ifndef LIGHTBOX_SYS_CHECK

/* Like lightc's own wrappers, these return 0 or a positive value on success
 * and a negative errno on failure. */

static inline lc_sysret lb_sys_fsync(int32_t fd) {
    return lc_syscall1(LB_SYS_fsync, fd);
}

static inline lc_sysret lb_sys_renameat(int32_t olddirfd, const char *oldpath,
                                        int32_t newdirfd, const char *newpath) {
    return lc_syscall4(LB_SYS_renameat, olddirfd, (int64_t)oldpath,
                       newdirfd, (int64_t)newpath);
}

static inline lc_sysret lb_sys_fchdir(int32_t fd) {
    return lc_syscall1(LB_SYS_fchdir, fd);
}

static inline lc_sysret lb_sys_chroot(const char *path) {
    return lc_syscall1(LB_SYS_chroot, (int64_t)path);
}

/* data points at LB_CAPABILITY_WORDS entries */
static inline lc_sysret lb_sys_capget(struct lb_cap_header *header, struct lb_cap_data *data) {
    return lc_syscall2(LB_SYS_capget, (int64_t)header, (int64_t)data);
}

static inline lc_sysret lb_sys_capset(struct lb_cap_header *header, const struct lb_cap_data *data) {
    return lc_syscall2(LB_SYS_capset, (int64_t)header, (int64_t)data);
}

/* socket(2). The number is lightc's own, which its library uses too. */
static inline lc_sysret lb_sys_socket(int32_t domain, int32_t type, int32_t protocol) {
    return lc_syscall3(SYS_socket, domain, type, protocol);
}

/* sendto(2) and recvfrom(2), with lightc's numbers too; recvfrom without the
 * sender's address, which for rtnetlink is always the kernel. */
static inline lc_sysret lb_sys_sendto(int32_t fd, const void *buf, uint64_t len, int32_t flags,
                                      const void *addr, uint32_t addrlen) {
    return lc_syscall6(SYS_sendto, fd, (int64_t)buf, (int64_t)len, flags, (int64_t)addr, addrlen);
}

static inline lc_sysret lb_sys_recvfrom(int32_t fd, void *buf, uint64_t len, int32_t flags) {
    return lc_syscall6(SYS_recvfrom, fd, (int64_t)buf, (int64_t)len, flags, 0, 0);
}

/* ppoll(2) with the caller's signal mask left as it is: wait until one of the
 * descriptors has something, or for as long as timeout says. The number of
 * descriptors that have something, 0 when the time ran out. */
static inline lc_sysret lb_sys_ppoll(struct lb_pollfd *fds, uint64_t count, lc_timespec *timeout) {
    return lc_syscall5(LB_SYS_ppoll, (int64_t)fds, (int64_t)count, (int64_t)timeout, 0, 0);
}

/* pidfd_open(2), Linux 5.3: a descriptor for a process, which stays that
 * process's whatever becomes of its number, and reads as ready when it ends */
/* getrandom(2), Linux 3.17: from the kernel's pool, which is ready once the
 * system is up */
static inline lc_sysret lb_sys_getrandom(void *buf, uint64_t len, uint32_t flags) {
    return lc_syscall3(LB_SYS_getrandom, (int64_t)(uintptr_t)buf, (int64_t)len, flags);
}

static inline lc_sysret lb_sys_pidfd_open(int32_t pid, uint32_t flags) {
    return lc_syscall2(LB_SYS_pidfd_open, pid, flags);
}

/* pidfd_send_signal(2), Linux 5.1. info may be NULL, for a plain signal. */
static inline lc_sysret lb_sys_pidfd_send_signal(int32_t pidfd, int32_t sig,
                                                 const struct lb_siginfo_queue *info, uint32_t flags) {
    return lc_syscall4(LB_SYS_pidfd_send_signal, pidfd, sig, (int64_t)info, flags);
}

static inline lc_sysret lb_sys_flock(int32_t fd, int32_t operation) {
    return lc_syscall2(LB_SYS_flock, fd, operation);
}

static inline lc_sysret lb_sys_geteuid(void) {
    return lc_syscall0(LB_SYS_geteuid);
}

static inline lc_sysret lb_sys_getuid(void) {
    return lc_syscall0(LB_SYS_getuid);
}

static inline lc_sysret lb_sys_fcntl(int32_t fd, int32_t request, uint64_t argument) {
    return lc_syscall3(LB_SYS_fcntl, fd, request, (int64_t)argument);
}

static inline lc_sysret lb_sys_memfd_create(const char *name, uint32_t flags) {
    return lc_syscall2(LB_SYS_memfd_create, (int64_t)name, flags);
}

/* execveat(2): execute the file a descriptor is open on, with an empty path
 * and LB_AT_EMPTY_PATH */
static inline lc_sysret lb_sys_execveat(int32_t dirfd, const char *path, char *const argv[],
                                        char *const envp[], int32_t flags) {
    return lc_syscall5(LB_SYS_execveat, dirfd, (int64_t)path, (int64_t)argv, (int64_t)envp, flags);
}

static inline lc_sysret lb_sys_mount_setattr(int32_t dirfd, const char *path, uint32_t flags,
                                             const struct lb_mount_attr *attr) {
    return lc_syscall5(LB_SYS_mount_setattr, dirfd, (int64_t)path, flags, (int64_t)attr,
                       (int64_t)sizeof(*attr));
}

static inline lc_sysret lb_sys_openat2(int32_t dirfd, const char *path, const struct lb_open_how *how) {
    return lc_syscall4(LB_SYS_openat2, dirfd, (int64_t)path, (int64_t)how, (int64_t)sizeof(*how));
}

static inline lc_sysret lb_sys_open_tree(int32_t dirfd, const char *path, uint32_t flags) {
    return lc_syscall3(LB_SYS_open_tree, dirfd, (int64_t)path, flags);
}

static inline lc_sysret lb_sys_move_mount(int32_t from_dirfd, const char *from_path,
                                          int32_t to_dirfd, const char *to_path, uint32_t flags) {
    return lc_syscall5(LB_SYS_move_mount, from_dirfd, (int64_t)from_path,
                       to_dirfd, (int64_t)to_path, flags);
}

/* bpf(2), with one of the two layouts above */
static inline lc_sysret lb_sys_bpf(int32_t cmd, void *attr, uint32_t size) {
    return lc_syscall3(LB_SYS_bpf, cmd, (int64_t)attr, size);
}

/* close_range(2), Linux 5.9: close every descriptor from first to last */
static inline lc_sysret lb_sys_close_range(uint32_t first, uint32_t last, uint32_t flags) {
    return lc_syscall3(LB_SYS_close_range, first, last, flags);
}

/* faccessat without flags: what kernels before 5.8, which have no
 * faccessat2, answer with. */
static inline lc_sysret lb_sys_faccessat(int32_t dirfd, const char *path, int32_t mode) {
    return lc_syscall3(LB_SYS_faccessat, dirfd, (int64_t)path, mode);
}

/* The names of a file's extended attributes, each with its NUL, and the
 * value of one: the length, which is all that is given with size 0. */
static inline lc_sysret lb_sys_flistxattr(int32_t fd, char *list, size_t size) {
    return lc_syscall3(LB_SYS_flistxattr, fd, (int64_t)list, (int64_t)size);
}

static inline lc_sysret lb_sys_fgetxattr(int32_t fd, const char *name, void *value, size_t size) {
    return lc_syscall4(LB_SYS_fgetxattr, fd, (int64_t)name, (int64_t)value, (int64_t)size);
}

static inline lc_sysret lb_sys_fsetxattr(int32_t fd, const char *name, const void *value, size_t size) {
    return lc_syscall5(LB_SYS_fsetxattr, fd, (int64_t)name, (int64_t)value, (int64_t)size, 0);
}

/* A second name for a file. Without flags a link at the end of the old name
 * is not followed: the link itself gets the name. */
static inline lc_sysret lb_sys_linkat(int32_t olddirfd, const char *oldpath,
                                      int32_t newdirfd, const char *newpath, int32_t flags) {
    return lc_syscall5(LB_SYS_linkat, olddirfd, (int64_t)oldpath, newdirfd, (int64_t)newpath, flags);
}

/* The two times of a file, of its last reading and of its last change: by
 * its name, or with no name the file the descriptor is open on. */
static inline lc_sysret lb_sys_utimensat(int32_t dirfd, const char *path, const lc_timespec times[2],
                                         int32_t flags) {
    return lc_syscall4(LB_SYS_utimensat, dirfd, (int64_t)path, (int64_t)times, flags);
}

static inline lc_sysret lb_sys_fchmod(int32_t fd, uint32_t mode) {
    return lc_syscall2(LB_SYS_fchmod, fd, mode);
}

/* The bits a new file's mode never has, for this process: what they were. */
static inline lc_sysret lb_sys_umask(uint32_t mask) {
    return lc_syscall1(LB_SYS_umask, mask);
}

static inline lc_sysret lb_sys_statfs(const char *path, struct lb_statfs *buf) {
    return lc_syscall2(LB_SYS_statfs, (int64_t)path, (int64_t)buf);
}

/* the same of what a descriptor is open on, one of open_tree's among them */
static inline lc_sysret lb_sys_fstatfs(int32_t fd, struct lb_statfs *buf) {
    return lc_syscall2(LB_SYS_fstatfs, fd, (int64_t)buf);
}

static inline lc_sysret lb_sys_statx(int32_t dirfd, const char *path, int32_t flags,
                                     uint32_t mask, struct lb_statx *buf) {
    return lc_syscall5(LB_SYS_statx, dirfd, (int64_t)path, flags, mask, (int64_t)buf);
}

#endif /* LIGHTBOX_SYS_CHECK */

#endif
