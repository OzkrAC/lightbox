/*
 * lightbox_seccomp.h: the seccomp profile, as one table and one BPF program.
 *
 * The profile is a deny-list. Each row of the table names a syscall, gives its
 * number on x86_64 and on aarch64, and the errno a sandboxed caller gets.
 * lb_seccomp_build() turns the rows for the target architecture into the
 * program lightbox installs.
 *
 * Nothing here is taken on trust:
 *   tests/sys_check.c       compares every number and constant below with the
 *                           kernel's headers, for both architectures
 *   tests/seccomp_filter.c  interprets the program of each architecture and
 *                           checks its verdict for every syscall number
 *   tests/seccomp_profile.c installs the program and calls the syscalls
 *
 * This header needs no lightc and no C library, so the tests can include it.
 */

#ifndef LIGHTBOX_SECCOMP_H
#define LIGHTBOX_SECCOMP_H

#include <stddef.h>
#include <stdint.h>

/*
 * The architecture the program is built for: the one being compiled, unless a
 * test asks for another by defining LB_SECCOMP_TARGET_X86_64 or
 * LB_SECCOMP_TARGET_AARCH64 itself.
 */
#if !defined(LB_SECCOMP_TARGET_X86_64) && !defined(LB_SECCOMP_TARGET_AARCH64)
#  if defined(__x86_64__)
#    define LB_SECCOMP_TARGET_X86_64 1
#  elif defined(__aarch64__)
#    define LB_SECCOMP_TARGET_AARCH64 1
#  else
#    error "lightbox_seccomp.h has no syscall numbers for this architecture"
#  endif
#endif

/* Both targets are little-endian, which LB_SECCOMP_DATA_ARG0_LO relies on. */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "the seccomp program reads the low word of a 64-bit argument");

/* ─── Kernel constants ──────────────────────────────────────────────────── */

#define LB_SECCOMP_MODE_FILTER       2

#define LB_SECCOMP_RET_KILL_PROCESS  0x80000000U
#define LB_SECCOMP_RET_ERRNO         0x00050000U
#define LB_SECCOMP_RET_ALLOW         0x7fff0000U

#define LB_AUDIT_ARCH_X86_64         0xc000003eU
#define LB_AUDIT_ARCH_AARCH64        0xc00000b7U

/* classic BPF: class | size or operation | source */
#define LB_BPF_LD_W_ABS              0x20   /* A = 32-bit word at offset k */
#define LB_BPF_JEQ_K                 0x15   /* A == k */
#define LB_BPF_JGE_K                 0x35   /* A >= k, unsigned */
#define LB_BPF_JSET_K                0x45   /* A & k */
#define LB_BPF_RET_K                 0x06   /* return k */

/* offsets in struct seccomp_data */
#define LB_SECCOMP_DATA_NR           0
#define LB_SECCOMP_DATA_ARCH         4
#define LB_SECCOMP_DATA_ARG0_LO      16     /* low 32 bits of args[0] */

/* x86_64 only: x32 calls report AUDIT_ARCH_X86_64 and carry this bit. */
#define LB_X32_SYSCALL_BIT           0x40000000U

/* CLONE_NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID and NEWNET.
 * CLONE_NEWTIME is not a clone() flag: its bit belongs to the exit signal. */
#define LB_SECCOMP_CLONE_NS_FLAGS    0x7e020000U

#define LB_SECCOMP_NR_CLONE_X86_64   56
#define LB_SECCOMP_NR_CLONE_AARCH64  220

#define LB_SC_EPERM                  1
#define LB_SC_ENOSYS                 38

struct lb_sock_filter {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct lb_sock_fprog {
    uint16_t               len;
    struct lb_sock_filter *filter;
};

/* ─── The table ─────────────────────────────────────────────────────────── */

/*
 * Docker's default deny list. Almost every row answers EPERM. clone3 answers
 * ENOSYS: its flags sit behind a pointer the filter cannot read, so it cannot
 * be allowed selectively, and ENOSYS is the one answer that makes a C library
 * fall back to clone. With EPERM, glibc 2.34 and later cannot create a thread.
 *
 * Not in the table on purpose: mount and pivot_root, which container setup
 * uses before the capabilities that permit them are dropped.
 *
 *   X(name, number on x86_64, number on aarch64, errno)
 */
#define LB_SECCOMP_DENY(X) \
    X(acct,               163,   89, LB_SC_EPERM) \
    X(add_key,            248,  217, LB_SC_EPERM) \
    X(bpf,                321,  280, LB_SC_EPERM) \
    X(clock_adjtime,      305,  266, LB_SC_EPERM) \
    X(clock_settime,      227,  112, LB_SC_EPERM) \
    X(delete_module,      176,  106, LB_SC_EPERM) \
    X(finit_module,       313,  273, LB_SC_EPERM) \
    X(get_mempolicy,      239,  236, LB_SC_EPERM) \
    X(io_uring_setup,     425,  425, LB_SC_EPERM) \
    X(io_uring_enter,     426,  426, LB_SC_EPERM) \
    X(io_uring_register,  427,  427, LB_SC_EPERM) \
    X(init_module,        175,  105, LB_SC_EPERM) \
    X(kcmp,               312,  272, LB_SC_EPERM) \
    X(kexec_file_load,    320,  294, LB_SC_EPERM) \
    X(kexec_load,         246,  104, LB_SC_EPERM) \
    X(keyctl,             250,  219, LB_SC_EPERM) \
    X(lookup_dcookie,     212,   18, LB_SC_EPERM) \
    X(mbind,              237,  235, LB_SC_EPERM) \
    X(migrate_pages,      256,  238, LB_SC_EPERM) \
    X(move_mount,         429,  429, LB_SC_EPERM) \
    X(move_pages,         279,  239, LB_SC_EPERM) \
    X(name_to_handle_at,  303,  264, LB_SC_EPERM) \
    X(nfsservctl,         180,   42, LB_SC_EPERM) \
    X(open_by_handle_at,  304,  265, LB_SC_EPERM) \
    X(open_tree,          428,  428, LB_SC_EPERM) \
    X(perf_event_open,    298,  241, LB_SC_EPERM) \
    X(personality,        135,   92, LB_SC_EPERM) \
    X(process_vm_readv,   310,  270, LB_SC_EPERM) \
    X(process_vm_writev,  311,  271, LB_SC_EPERM) \
    X(ptrace,             101,  117, LB_SC_EPERM) \
    X(quotactl,           179,   60, LB_SC_EPERM) \
    X(reboot,             169,  142, LB_SC_EPERM) \
    X(request_key,        249,  218, LB_SC_EPERM) \
    X(set_mempolicy,      238,  237, LB_SC_EPERM) \
    X(setns,              308,  268, LB_SC_EPERM) \
    X(settimeofday,       164,  170, LB_SC_EPERM) \
    X(swapon,             167,  224, LB_SC_EPERM) \
    X(swapoff,            168,  225, LB_SC_EPERM) \
    X(umount2,            166,   39, LB_SC_EPERM) \
    X(unshare,            272,   97, LB_SC_EPERM) \
    X(userfaultfd,        323,  282, LB_SC_EPERM) \
    X(clone3,             435,  435, LB_SC_ENOSYS) \
    X(mount_setattr,      442,  442, LB_SC_EPERM) \
    X(fsopen,             430,  430, LB_SC_EPERM) \
    X(fsconfig,           431,  431, LB_SC_EPERM) \
    X(fsmount,            432,  432, LB_SC_EPERM) \
    X(fspick,             433,  433, LB_SC_EPERM)

/*
 * Syscalls only x86_64 has. tests/sys_check.c fails the aarch64 build if the
 * kernel's aarch64 headers ever define one of them.
 *
 *   X(name, number on x86_64, errno)
 */
#define LB_SECCOMP_DENY_X86_64(X) \
    X(create_module,      174, LB_SC_EPERM) \
    X(get_kernel_syms,    177, LB_SC_EPERM) \
    X(ioperm,             173, LB_SC_EPERM) \
    X(iopl,               172, LB_SC_EPERM) \
    X(query_module,       178, LB_SC_EPERM) \
    X(_sysctl,            156, LB_SC_EPERM) \
    X(sysfs,              139, LB_SC_EPERM) \
    X(uselib,             134, LB_SC_EPERM) \
    X(ustat,              136, LB_SC_EPERM)

/* ─── The rows and the program for the target ───────────────────────────── */

struct lb_seccomp_deny {
    uint32_t nr;
    uint16_t err;   /* the errno the caller sees */
};

#if defined(LB_SECCOMP_TARGET_X86_64)
#  define LB_SECCOMP_AUDIT_ARCH   LB_AUDIT_ARCH_X86_64
#  define LB_SECCOMP_NR_CLONE     LB_SECCOMP_NR_CLONE_X86_64
#  define LB_SECCOMP_PROG_HEAD    6
#  define LB_SC_ROW(name, x86_64, aarch64, err)  { x86_64, err },
#  define LB_SC_ROW_X86_64(name, nr, err)        { nr, err },
#else
#  define LB_SECCOMP_AUDIT_ARCH   LB_AUDIT_ARCH_AARCH64
#  define LB_SECCOMP_NR_CLONE     LB_SECCOMP_NR_CLONE_AARCH64
#  define LB_SECCOMP_PROG_HEAD    4
#  define LB_SC_ROW(name, x86_64, aarch64, err)  { aarch64, err },
#  define LB_SC_ROW_X86_64(name, nr, err)
#endif

static const struct lb_seccomp_deny LB_SECCOMP_TABLE[] = {
    LB_SECCOMP_DENY(LB_SC_ROW)
    LB_SECCOMP_DENY_X86_64(LB_SC_ROW_X86_64)
};

#undef LB_SC_ROW
#undef LB_SC_ROW_X86_64

#define LB_SECCOMP_TABLE_LEN (sizeof(LB_SECCOMP_TABLE) / sizeof(LB_SECCOMP_TABLE[0]))

/* Instructions in the program: the head, two per row, five for clone and the
 * final allow. lb_seccomp_build() writes exactly this many. */
#define LB_SECCOMP_PROG_LEN (LB_SECCOMP_PROG_HEAD + 2 * LB_SECCOMP_TABLE_LEN + 5)

_Static_assert(LB_SECCOMP_PROG_LEN <= 4096, "the kernel accepts at most 4096 BPF instructions");

/*
 * Write the program into prog, which holds LB_SECCOMP_PROG_LEN instructions,
 * and return how many were written. No jump is longer than three instructions,
 * so the table can grow without any offset overflowing its 8 bits.
 */
static inline size_t lb_seccomp_build(struct lb_sock_filter *prog) {
    size_t n = 0;

#define LB_STMT(op, value) \
    prog[n++] = (struct lb_sock_filter){ (op), 0, 0, (value) }
#define LB_JUMP(op, value, if_true, if_false) \
    prog[n++] = (struct lb_sock_filter){ (op), (if_true), (if_false), (value) }

    /* A syscall made through another ABI of this machine (i386 on x86_64,
     * AArch32 on aarch64) has other numbers: kill the process. */
    LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARCH);
    LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_AUDIT_ARCH, 1, 0);
    LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_KILL_PROCESS);

    LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_NR);

#if defined(LB_SECCOMP_TARGET_X86_64)
    /* x32 calls pass the architecture check with bit 30 set in the number,
     * so no row below would match them: refuse the whole range. */
    LB_JUMP(LB_BPF_JGE_K, LB_X32_SYSCALL_BIT, 0, 1);
    LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM);
#endif

    for (size_t i = 0; i < LB_SECCOMP_TABLE_LEN; i++) {
        LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_TABLE[i].nr, 0, 1);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SECCOMP_TABLE[i].err);
    }

    /* clone may create processes and threads but not namespaces, which is
     * what denying unshare, setns and clone3 above is for. Its flags are the
     * first argument on both targets. */
    LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_NR_CLONE, 0, 3);
    LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARG0_LO);
    LB_JUMP(LB_BPF_JSET_K, LB_SECCOMP_CLONE_NS_FLAGS, 0, 1);
    LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM);

    LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ALLOW);

#undef LB_STMT
#undef LB_JUMP

    return n;
}

#endif /* LIGHTBOX_SECCOMP_H */
