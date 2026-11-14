#ifndef LIGHTBOX_SYS_H
#define LIGHTBOX_SYS_H

/*
 * Private syscall numbers, kernel constants and thin wrappers for the calls
 * lightc does not wrap yet.
 *
 * This is the only place in lightbox that may hold a raw syscall number.
 * tests/sys_check.c compares every number, constant and structure layout here
 * with the kernel's own headers for x86_64 and aarch64 (make check-sys), so a
 * wrong value fails the build instead of calling a different syscall.
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
#define LB_SYS_mount      165   /* lightc before its 0a.4 has 40 (sendfile) here */
#define LB_SYS_renameat   264
#define LB_SYS_statx      332
#elif defined(__aarch64__)
#define LB_SYS_renameat   38
#define LB_SYS_mount      40
#define LB_SYS_statfs     43
#define LB_SYS_fchdir     50
#define LB_SYS_chroot     51
#define LB_SYS_fsync      82
#define LB_SYS_capget     90
#define LB_SYS_capset     91
#define LB_SYS_statx      291
#else
#error "lightbox supports x86_64 and aarch64 only"
#endif

/* ─── Kernel constants (the same on both architectures) ─────────────────── */

#define LB_ENOENT                 2
#define LB_EINTR  4
#define LB_ESRCH                  3

#define LB_S_IFMT                 0170000
#define LB_S_IFDIR                0040000

#define LB_STATX_TYPE             0x00000001U
#define LB_STATX_MODE             0x00000002U
#define LB_STATX_ATTR_MOUNT_ROOT  0x00002000U   /* reported since Linux 5.8 */

#define LB_CGROUP_SUPER_MAGIC     0x0027e0eb    /* a cgroup v1 hierarchy */
#define LB_CGROUP2_SUPER_MAGIC    0x63677270

/* ─── Structures ────────────────────────────────────────────────────────── */

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

static inline lc_sysret lb_sys_capget(void *header, void *data) {
    return lc_syscall2(LB_SYS_capget, (int64_t)header, (int64_t)data);
}

static inline lc_sysret lb_sys_capset(void *header, const void *data) {
    return lc_syscall2(LB_SYS_capset, (int64_t)header, (int64_t)data);
}

/* mount(2) with lightbox's own number, so the call is right whichever lightc
 * release the build uses. */
static inline lc_sysret lb_sys_mount(const char *source, const char *target,
                                     const char *fstype, uint64_t flags,
                                     const void *data) {
    return lc_syscall5(LB_SYS_mount, (int64_t)source, (int64_t)target,
                       (int64_t)fstype, (int64_t)flags, (int64_t)data);
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
