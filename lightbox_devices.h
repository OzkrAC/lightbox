/*
 * lightbox_devices.h: the devices a container has, as one table, and the
 * cgroup device program that lets it open those and nothing else (ROADMAP 8.4).
 *
 * Init gives a container a /dev of its own: a tmpfs with the host's nodes of
 * LB_DEV_BOUND bound onto empty files, and a devpts of its own, whose ptmx and
 * terminals are LB_DEV_PTY. lb_devices_build() turns both tables into an eBPF
 * program of type BPF_PROG_TYPE_CGROUP_DEVICE, which start attaches to the
 * container's cgroup. The kernel then asks it before any process of the
 * container opens or makes a block or character device: one whose numbers
 * are in a row is opened with the access the row gives, and every other is
 * refused with EPERM, wherever its node is and whoever made it. No device is
 * made: mknod of one is refused for every number. The kernel lets overlayfs
 * make its whiteouts, character devices 0:0, without asking.
 *
 * Nothing here is taken on trust:
 *   tests/sys_check.c       compares the constants and layouts below with the
 *                           kernel's headers, for both architectures
 *   tests/devices_filter.c  interprets the program and checks its verdict for
 *                           every kind of device, access and number it tries
 *   tests/lifecycle.sh      opens devices in containers, which needs root
 *
 * This header needs no lightc and no C library, so the tests can include it.
 */

#ifndef LIGHTBOX_DEVICES_H
#define LIGHTBOX_DEVICES_H

#include <stddef.h>
#include <stdint.h>

/* Both targets are little-endian, which the registers of an instruction
 * rely on (see LB_EBPF_REGS). */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "an eBPF instruction holds its destination register in the low four bits");

/* ─── Kernel constants (linux/bpf.h, linux/bpf_common.h) ────────────────── */

/* bpf(2) commands, the program type and its attach type */
#define LB_BPF_PROG_LOAD             5
#define LB_BPF_PROG_ATTACH           8
#define LB_BPF_PROG_TYPE_CGROUP_DEVICE 15
#define LB_BPF_CGROUP_DEVICE         6
#define LB_BPF_OBJ_NAME_LEN          16

/* struct bpf_cgroup_dev_ctx, what the program is given: the access in the
 * high half of access_type and the kind of device in the low one, then the
 * device's numbers */
#define LB_DEVCG_CTX_ACCESS_TYPE     0
#define LB_DEVCG_CTX_MAJOR           4
#define LB_DEVCG_CTX_MINOR           8
#define LB_DEVCG_ACC_MKNOD           1
#define LB_DEVCG_ACC_READ            2
#define LB_DEVCG_ACC_WRITE           4
#define LB_DEVCG_DEV_BLOCK           1
#define LB_DEVCG_DEV_CHAR            2

/* the largest minor number, MINORMASK of linux/kdev_t.h: 20 bits */
#define LB_DEV_MINOR_MAX             0xfffffU

/* majors (linux/major.h): memory devices, ttys of their own, and the
 * terminals of a devpts, which have eight */
#define LB_DEV_MEM_MAJOR             1
#define LB_DEV_TTYAUX_MAJOR          5
#define LB_DEV_PTS_MAJOR             136
#define LB_DEV_PTS_MAJORS            8

/* eBPF: class | operation | source */
#define LB_EBPF_LDX_MEM_W            0x61   /* dst = *(u32 *)(src + off) */
#define LB_EBPF_ALU64_MOV_K          0xb7   /* dst = imm */
#define LB_EBPF_ALU64_MOV_X          0xbf   /* dst = src */
#define LB_EBPF_ALU64_AND_K          0x57   /* dst &= imm */
#define LB_EBPF_ALU64_RSH_K          0x77   /* dst >>= imm */
#define LB_EBPF_JMP_JNE_K            0x55   /* if dst != imm: pc += off */
#define LB_EBPF_JMP_JLT_K            0xa5   /* if dst < imm, unsigned */
#define LB_EBPF_JMP_JGT_K            0x25   /* if dst > imm, unsigned */
#define LB_EBPF_JMP_JSET_K           0x45   /* if dst & imm */
#define LB_EBPF_JMP_EXIT             0x95   /* return r0 */

struct lb_ebpf_insn {
    uint8_t code;
    uint8_t regs;       /* the destination in the low four bits, the source in the high */
    int16_t off;
    int32_t imm;
};

#define LB_EBPF_REGS(dst, src) ((uint8_t)((dst) | ((src) << 4)))

/* ─── The tables ────────────────────────────────────────────────────────── */

/* the access a row gives */
#define LB_DEV_R   LB_DEVCG_ACC_READ
#define LB_DEV_RW  (LB_DEVCG_ACC_READ | LB_DEVCG_ACC_WRITE)

/*
 * The host's character devices that init binds into a container's /dev, by
 * name: what they are on every Linux (Documentation/admin-guide/devices.txt),
 * the mode of the file they are bound onto, and the access a container has.
 * random and urandom are read-only, as their mounts are; a read-only mount
 * alone does not keep a device from being written.
 *
 *   X(name, major, minor, mode, access)
 */
#define LB_DEV_BOUND(X) \
    X(null,     LB_DEV_MEM_MAJOR,    3, 0666, LB_DEV_RW) \
    X(zero,     LB_DEV_MEM_MAJOR,    5, 0666, LB_DEV_RW) \
    X(full,     LB_DEV_MEM_MAJOR,    7, 0666, LB_DEV_RW) \
    X(random,   LB_DEV_MEM_MAJOR,    8, 0444, LB_DEV_R) \
    X(urandom,  LB_DEV_MEM_MAJOR,    9, 0444, LB_DEV_R) \
    X(tty,      LB_DEV_TTYAUX_MAJOR, 0, 0666, LB_DEV_RW)

/*
 * The container's own devpts: its ptmx, which /dev/ptmx links to, and the
 * terminals it hands out, of eight majors and any minor.
 *
 *   X(name, first major, last major, first minor, last minor, access)
 */
#define LB_DEV_PTY(X) \
    X(ptmx, LB_DEV_TTYAUX_MAJOR, LB_DEV_TTYAUX_MAJOR, 2, 2, LB_DEV_RW) \
    X(pts,  LB_DEV_PTS_MAJOR, LB_DEV_PTS_MAJOR + LB_DEV_PTS_MAJORS - 1, 0, LB_DEV_MINOR_MAX, LB_DEV_RW)

struct lb_dev_row {
    uint32_t major_first, major_last;
    uint32_t minor_first, minor_last;
    uint32_t access;
};

#define LB_DEV_BOUND_ROW(name, major, minor, mode, access) { major, major, minor, minor, access },
#define LB_DEV_PTY_ROW(name, major_first, major_last, minor_first, minor_last, access) \
    { major_first, major_last, minor_first, minor_last, access },

static const struct lb_dev_row LB_DEV_TABLE[] = {
    LB_DEV_BOUND(LB_DEV_BOUND_ROW)
    LB_DEV_PTY(LB_DEV_PTY_ROW)
};

#undef LB_DEV_BOUND_ROW
#undef LB_DEV_PTY_ROW

#define LB_DEV_TABLE_LEN (sizeof(LB_DEV_TABLE) / sizeof(LB_DEV_TABLE[0]))

/* ─── The program ───────────────────────────────────────────────────────── */

/* Instructions: six to read the context, one for the kind of device, seven
 * per row and two to refuse. lb_devices_build() writes exactly this many. */
#define LB_DEV_PROG_HEAD  7
#define LB_DEV_ROW_INSNS  7
#define LB_DEV_PROG_LEN   (LB_DEV_PROG_HEAD + LB_DEV_ROW_INSNS * LB_DEV_TABLE_LEN + 2)

_Static_assert(LB_DEV_PROG_LEN < 4096, "the jumps of the program are 16 bits");

/* The numbers of a row are compared as immediates, which the kernel widens
 * to 64 bits with their sign: each has to be below 2^31. */
#define LB_DEV_NUMBER_OK(x) ((uint32_t)(x) < 0x80000000U)

/* One instruction at prog[*n]. */
static inline void lb_ebpf_put(struct lb_ebpf_insn *prog, size_t *n, uint8_t code,
                               uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
    prog[*n] = (struct lb_ebpf_insn){ code, LB_EBPF_REGS(dst, src), off, imm };
    (*n)++;
}

/* A jump to the instruction at target: its offset counts from the
 * instruction after it. */
static inline void lb_ebpf_jump(struct lb_ebpf_insn *prog, size_t *n, uint8_t code,
                                uint8_t dst, size_t target, uint32_t imm) {
    lb_ebpf_put(prog, n, code, dst, 0, (int16_t)((int32_t)target - (int32_t)*n - 1), (int32_t)imm);
}

/*
 * Write the program into prog, which holds LB_DEV_PROG_LEN instructions, and
 * return how many were written. r1 is the context; the program keeps the
 * access in r2, the kind of device in r3 and its numbers in r4 and r5, and
 * returns 1 to allow and 0 to refuse. Every number it compares with is below
 * 2^31, so the kernel's widening of an immediate to 64 bits keeps it.
 */
static inline size_t lb_devices_build(struct lb_ebpf_insn *prog) {
    size_t n = 0;
    const size_t deny = LB_DEV_PROG_LEN - 2;   /* where the refusal is */

    lb_ebpf_put(prog, &n, LB_EBPF_LDX_MEM_W, 2, 1, LB_DEVCG_CTX_ACCESS_TYPE, 0);
    lb_ebpf_put(prog, &n, LB_EBPF_ALU64_MOV_X, 3, 2, 0, 0);
    lb_ebpf_put(prog, &n, LB_EBPF_ALU64_AND_K, 3, 0, 0, 0xffff);
    lb_ebpf_put(prog, &n, LB_EBPF_ALU64_RSH_K, 2, 0, 0, 16);
    lb_ebpf_put(prog, &n, LB_EBPF_LDX_MEM_W, 4, 1, LB_DEVCG_CTX_MAJOR, 0);
    lb_ebpf_put(prog, &n, LB_EBPF_LDX_MEM_W, 5, 1, LB_DEVCG_CTX_MINOR, 0);

    /* no block device at all */
    lb_ebpf_jump(prog, &n, LB_EBPF_JMP_JNE_K, 3, deny, LB_DEVCG_DEV_CHAR);

    /* a row: its majors, its minors, and no access it does not give, mknod
     * among them; past any of them the next row */
    for (size_t i = 0; i < LB_DEV_TABLE_LEN; i++) {
        const struct lb_dev_row *row = &LB_DEV_TABLE[i];
        const size_t next = n + LB_DEV_ROW_INSNS;
        lb_ebpf_jump(prog, &n, LB_EBPF_JMP_JLT_K, 4, next, row->major_first);
        lb_ebpf_jump(prog, &n, LB_EBPF_JMP_JGT_K, 4, next, row->major_last);
        lb_ebpf_jump(prog, &n, LB_EBPF_JMP_JLT_K, 5, next, row->minor_first);
        lb_ebpf_jump(prog, &n, LB_EBPF_JMP_JGT_K, 5, next, row->minor_last);
        lb_ebpf_jump(prog, &n, LB_EBPF_JMP_JSET_K, 2, next,
                     (LB_DEVCG_ACC_MKNOD | LB_DEVCG_ACC_READ | LB_DEVCG_ACC_WRITE) & ~row->access);
        lb_ebpf_put(prog, &n, LB_EBPF_ALU64_MOV_K, 0, 0, 0, 1);
        lb_ebpf_put(prog, &n, LB_EBPF_JMP_EXIT, 0, 0, 0, 0);
    }

    lb_ebpf_put(prog, &n, LB_EBPF_ALU64_MOV_K, 0, 0, 0, 0);
    lb_ebpf_put(prog, &n, LB_EBPF_JMP_EXIT, 0, 0, 0, 0);
    return n;
}

#endif /* LIGHTBOX_DEVICES_H */
