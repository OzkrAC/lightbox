/*
 * The part of the check of lightbox_sys.h that needs the C library's headers:
 * the kernel's linux/if.h, which has struct ifreq, includes sys/socket.h.
 * tests/sys_check.c takes the kernel's own definitions of things the C library
 * also defines, so the two cannot share a file.
 *
 *   make check-sys
 *
 * compiles both. Nothing is linked or run.
 */

#define LIGHTBOX_SYS_CHECK 1
#define _GNU_SOURCE 1      /* the C library names statfs's ST_ flags of access times only so */

#include <stddef.h>
#include <stdint.h>

#include <linux/if.h>
#include <sys/statvfs.h>

#include "../lightbox_sys.h"

#define SAME_VALUE(ours, theirs) \
    _Static_assert((ours) == (theirs), #ours " differs from " #theirs)

SAME_VALUE(LB_AF_INET, AF_INET);

/* statfs's flags of access times, which only the C library's headers name */
SAME_VALUE(LB_ST_NOATIME, ST_NOATIME);
SAME_VALUE(LB_ST_NODIRATIME, ST_NODIRATIME);
SAME_VALUE(LB_ST_RELATIME, ST_RELATIME);
SAME_VALUE(LB_SOCK_DGRAM, SOCK_DGRAM);
SAME_VALUE(LB_AF_NETLINK, AF_NETLINK);
SAME_VALUE(LB_SOCK_RAW, SOCK_RAW);
SAME_VALUE(LB_SOCK_CLOEXEC, SOCK_CLOEXEC);
SAME_VALUE(LB_IFF_UP, IFF_UP);

/* struct lb_ifreq_flags against struct ifreq: the size the kernel copies, and
 * the two members the flag requests read and write. */
SAME_VALUE(sizeof(struct lb_ifreq_flags), sizeof(struct ifreq));
SAME_VALUE(offsetof(struct lb_ifreq_flags, name), offsetof(struct ifreq, ifr_name));
SAME_VALUE(sizeof(((struct lb_ifreq_flags *)0)->name), sizeof(((struct ifreq *)0)->ifr_name));
SAME_VALUE(offsetof(struct lb_ifreq_flags, flags), offsetof(struct ifreq, ifr_flags));
SAME_VALUE(sizeof(((struct lb_ifreq_flags *)0)->flags), sizeof(((struct ifreq *)0)->ifr_flags));
