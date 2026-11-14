/*
 * Compile-only check of lightbox_sys.h against the kernel's own headers.
 *
 * lightbox is freestanding and carries a few syscall numbers, constants and
 * structure layouts of its own. A wrong one does not fail to build; it calls a
 * different syscall or reads the wrong bytes. This file makes it fail to build.
 *
 *   make check-sys
 *
 * compiles it with the native compiler and with every cross compiler it finds
 * (aarch64-linux-gnu-gcc, x86_64-linux-gnu-gcc). Nothing is linked or run.
 */

#define LIGHTBOX_SYS_CHECK 1

#include <stddef.h>
#include <stdint.h>

#include <asm/errno.h>
#include <asm/statfs.h>
#include <asm/unistd.h>
#include <linux/magic.h>
#include <linux/stat.h>

#include "../lightbox_sys.h"

#define SAME_NR(name) \
    _Static_assert(LB_SYS_##name == __NR_##name, \
                   "LB_SYS_" #name " differs from the kernel's __NR_" #name)

SAME_NR(fsync);
SAME_NR(fchdir);
SAME_NR(capget);
SAME_NR(capset);
SAME_NR(statfs);
SAME_NR(chroot);
SAME_NR(mount);
SAME_NR(renameat);
SAME_NR(statx);

#define SAME_VALUE(ours, kernels) \
    _Static_assert((ours) == (kernels), #ours " differs from the kernel's " #kernels)

SAME_VALUE(LB_ENOENT, ENOENT);
SAME_VALUE(LB_ESRCH, ESRCH);
SAME_VALUE(LB_S_IFMT, S_IFMT);
SAME_VALUE(LB_S_IFDIR, S_IFDIR);
SAME_VALUE(LB_STATX_TYPE, STATX_TYPE);
SAME_VALUE(LB_STATX_MODE, STATX_MODE);
SAME_VALUE(LB_STATX_ATTR_MOUNT_ROOT, STATX_ATTR_MOUNT_ROOT);
SAME_VALUE(LB_CGROUP_SUPER_MAGIC, CGROUP_SUPER_MAGIC);
SAME_VALUE(LB_CGROUP2_SUPER_MAGIC, CGROUP2_SUPER_MAGIC);

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
SAME_FIELD(lb_statx, statx, stx_mode);
SAME_FIELD(lb_statx, statx, stx_attributes_mask);
SAME_FIELD(lb_statx, statx, stx_dev_major);
SAME_FIELD(lb_statx, statx, stx_dev_minor);
SAME_FIELD(lb_statx, statx, stx_mnt_id);
