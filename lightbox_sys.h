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
#define LB_SYS_fsync      74
#define LB_SYS_fchdir     81
#define LB_SYS_capget     125
#define LB_SYS_capset     126
#define LB_SYS_statfs     137
#define LB_SYS_chroot     161
#define LB_SYS_renameat   264
#define LB_SYS_ppoll      271
#define LB_SYS_statx      332
#elif defined(__aarch64__)
#define LB_SYS_renameat   38
#define LB_SYS_statfs     43
#define LB_SYS_fchdir     50
#define LB_SYS_chroot     51
#define LB_SYS_ppoll      73
#define LB_SYS_fsync      82
#define LB_SYS_capget     90
#define LB_SYS_capset     91
#define LB_SYS_statx      291
#else
#error "lightbox supports x86_64 and aarch64 only"
#endif

/* ─── Kernel constants (the same on both architectures) ─────────────────── */

#define LB_ENOENT                 2
#define LB_ESRCH                  3
#define LB_EINTR                  4
#define LB_EEXIST                 17

/* The one signal lightbox names that lightc does not (asm/signal.h) */
#define LB_SIGPIPE                13

/* What ppoll(2) is asked to wait for, and what it reports (asm-generic/poll.h).
 * A pipe whose other end was closed reports POLLHUP, with or without POLLIN. */
#define LB_POLLIN                 0x0001
#define LB_POLLERR                0x0008
#define LB_POLLHUP                0x0010

#define LB_S_IFMT                 0170000
#define LB_S_IFDIR                0040000

#define LB_STATX_TYPE             0x00000001U
#define LB_STATX_MODE             0x00000002U
#define LB_STATX_ATTR_MOUNT_ROOT  0x00002000U   /* reported since Linux 5.8 */

#define LB_CGROUP_SUPER_MAGIC     0x0027e0eb    /* a cgroup v1 hierarchy */
#define LB_CGROUP2_SUPER_MAGIC    0x63677270

/* f_flags of statfs: what the mount at a path carries. Each of these four is
 * the bit mount(2) takes for the same thing (MS_RDONLY and so on). */
#define LB_ST_RDONLY              1
#define LB_ST_NOSUID              2
#define LB_ST_NODEV               4
#define LB_ST_NOEXEC              8

/* prctl(2) requests (linux/prctl.h) */
#define LB_PR_SET_KEEPCAPS            8
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

/* ─── Structures ────────────────────────────────────────────────────────── */

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
    uint64_t stx_times[8];          /* atime, btime, ctime, mtime */
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

/* ppoll(2) with the caller's signal mask left as it is: wait until one of the
 * descriptors has something, or for as long as timeout says. The number of
 * descriptors that have something, 0 when the time ran out. */
static inline lc_sysret lb_sys_ppoll(struct lb_pollfd *fds, uint64_t count, lc_timespec *timeout) {
    return lc_syscall5(LB_SYS_ppoll, (int64_t)fds, (int64_t)count, (int64_t)timeout, 0, 0);
}

static inline lc_sysret lb_sys_statfs(const char *path, struct lb_statfs *buf) {
    return lc_syscall2(LB_SYS_statfs, (int64_t)path, (int64_t)buf);
}

static inline lc_sysret lb_sys_statx(int32_t dirfd, const char *path, int32_t flags,
                                     uint32_t mask, struct lb_statx *buf) {
    return lc_syscall5(LB_SYS_statx, dirfd, (int64_t)path, flags, mask, (int64_t)buf);
}

#endif /* LIGHTBOX_SYS_CHECK */

#endif
