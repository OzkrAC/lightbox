/*
 * Interprets lightbox's seccomp program and checks its verdict for every
 * syscall number (ROADMAP 2.4).
 *
 * The program is built for the architecture named at compile time,
 *
 *   cc -DLB_SECCOMP_TARGET_X86_64  tests/seccomp_filter.c
 *   cc -DLB_SECCOMP_TARGET_AARCH64 tests/seccomp_filter.c
 *
 * and is interpreted here, not installed. That lets one machine check both
 * programs, the aarch64 one included, without an emulator. It checks the
 * program's logic. That the numbers in the table are the kernel's is what
 * tests/sys_check.c checks, and that the kernel accepts and applies the
 * program is what tests/seccomp_profile.c checks on the machine it runs on.
 *
 * An ordinary hosted program: it needs a C library and nothing of lightc.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lightbox_seccomp.h"

#if defined(LB_SECCOMP_TARGET_X86_64)
#define TARGET       "x86_64"
#define OTHER_ARCH   LB_AUDIT_ARCH_AARCH64
#else
#define TARGET       "aarch64"
#define OTHER_ARCH   LB_AUDIT_ARCH_X86_64
#endif

#define AUDIT_ARCH_I386  0x40000003U
#define AUDIT_ARCH_ARM   0x40000028U

#define NR_LIMIT 1024   /* well above the highest syscall number of either target */

/* What the kernel hands a filter; the layout of struct seccomp_data. */
struct data {
    uint32_t nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
};

static struct lb_sock_filter prog[LB_SECCOMP_PROG_LEN];
static size_t prog_len;
static unsigned long verdicts, failures;

static void fail(const char *what, const struct data *d, uint32_t got, uint32_t want) {
    failures++;
    if (failures <= 20)
        printf("  %s: arch %#x nr %u arg0 %#llx: verdict %#x, expected %#x\n", what,
               d->arch, d->nr, (unsigned long long)d->args[0], got, want);
}

/* A classic-BPF interpreter for the five instructions the program uses.
 * Anything else, a read outside the data or a jump past the end is an error. */
static uint32_t run(const struct data *d) {
    uint32_t a = 0;
    for (size_t pc = 0; pc < prog_len; pc++) {
        const struct lb_sock_filter *in = &prog[pc];
        switch (in->code) {
        case LB_BPF_LD_W_ABS:
            if (in->k > sizeof(*d) - sizeof(a)) {
                printf("  instruction %zu reads offset %u, outside the data\n", pc, in->k);
                exit(1);
            }
            memcpy(&a, (const char *)d + in->k, sizeof(a));
            break;
        case LB_BPF_JEQ_K:  pc += (a == in->k) ? in->jt : in->jf; break;
        case LB_BPF_JGE_K:  pc += (a >= in->k) ? in->jt : in->jf; break;
        case LB_BPF_JSET_K: pc += (a & in->k)  ? in->jt : in->jf; break;
        case LB_BPF_RET_K:  return in->k;
        default:
            printf("  instruction %zu has opcode %#x, which this check does not know\n", pc, in->code);
            exit(1);
        }
    }
    printf("  the program ran past its last instruction\n");
    exit(1);
}

static void expect(const char *what, const struct data *d, uint32_t want) {
    uint32_t got = run(d);
    verdicts++;
    if (got != want)
        fail(what, d, got, want);
}

/* The errno the table documents for nr, or 0 when it has no row. */
static uint32_t table_errno(uint32_t nr) {
    for (size_t i = 0; i < LB_SECCOMP_TABLE_LEN; i++)
        if (LB_SECCOMP_TABLE[i].nr == nr)
            return LB_SECCOMP_TABLE[i].err;
    return 0;
}

#define DENY(err) (LB_SECCOMP_RET_ERRNO | (err))

int main(void) {
    prog_len = lb_seccomp_build(prog);
    if (prog_len != LB_SECCOMP_PROG_LEN) {
        printf("  %s: built %zu instructions, LB_SECCOMP_PROG_LEN says %zu\n",
               TARGET, prog_len, (size_t)LB_SECCOMP_PROG_LEN);
        return 1;
    }

    /* the table itself: no number twice, every errno a real one */
    for (size_t i = 0; i < LB_SECCOMP_TABLE_LEN; i++) {
        const struct lb_seccomp_deny *row = &LB_SECCOMP_TABLE[i];
        if (row->nr >= NR_LIMIT || row->err == 0 || row->err > 4095) {
            printf("  row %zu (nr %u, errno %u) is out of range\n", i, row->nr, row->err);
            failures++;
        }
        if (row->nr == LB_SECCOMP_NR_CLONE) {
            printf("  clone has a row; it is filtered by its flags instead\n");
            failures++;
        }
        for (size_t j = 0; j < i; j++)
            if (LB_SECCOMP_TABLE[j].nr == row->nr) {
                printf("  number %u is in the table twice\n", row->nr);
                failures++;
            }
    }

    struct data d;

    /* another ABI: killed, whatever the number */
    static const uint32_t foreign[] = { OTHER_ARCH, AUDIT_ARCH_I386, AUDIT_ARCH_ARM, 0 };
    for (size_t f = 0; f < sizeof(foreign) / sizeof(foreign[0]); f++)
        for (uint32_t nr = 0; nr < NR_LIMIT; nr++) {
            d = (struct data){ .nr = nr, .arch = foreign[f] };
            expect("foreign architecture", &d, LB_SECCOMP_RET_KILL_PROCESS);
        }

    /* this ABI: a row answers its errno, everything else is allowed */
    for (uint32_t nr = 0; nr < NR_LIMIT; nr++) {
        uint32_t err = table_errno(nr);
        d = (struct data){ .nr = nr, .arch = LB_SECCOMP_AUDIT_ARCH };
        expect(err ? "table row" : "allowed syscall", &d, err ? DENY(err) : LB_SECCOMP_RET_ALLOW);
        /* arguments do not change the answer, except for clone below */
        if (nr != LB_SECCOMP_NR_CLONE) {
            d.args[0] = UINT64_MAX;
            expect(err ? "table row with arguments" : "allowed syscall with arguments", &d,
                   err ? DENY(err) : LB_SECCOMP_RET_ALLOW);
        }
    }

    /* the x32 range: refused on x86_64, where it exists; no special case elsewhere */
    for (uint32_t nr = 0; nr < NR_LIMIT; nr++) {
        d = (struct data){ .nr = LB_X32_SYSCALL_BIT | nr, .arch = LB_SECCOMP_AUDIT_ARCH };
#if defined(LB_SECCOMP_TARGET_X86_64)
        expect("x32 number", &d, DENY(LB_SC_EPERM));
#else
        expect("number with bit 30", &d, LB_SECCOMP_RET_ALLOW);
#endif
    }
#if defined(LB_SECCOMP_TARGET_X86_64)
    d = (struct data){ .nr = UINT32_MAX, .arch = LB_SECCOMP_AUDIT_ARCH };
    expect("number -1", &d, DENY(LB_SC_EPERM));
#endif

    /* clone: every namespace flag is refused, alone or with others */
    static const uint64_t ns_flags[] = {
        0x00020000 /* NEWNS */,  0x02000000 /* NEWCGROUP */, 0x04000000 /* NEWUTS */,
        0x08000000 /* NEWIPC */, 0x10000000 /* NEWUSER */,   0x20000000 /* NEWPID */,
        0x40000000 /* NEWNET */,
    };
    static const uint64_t harmless[] = {
        0,                       /* nothing */
        17,                      /* SIGCHLD: fork */
        0x00004111,              /* CLONE_VM | CLONE_VFORK | SIGCHLD: vfork, posix_spawn */
        0x003d0f00,              /* what pthread_create passes */
        0x000000ff,              /* any exit signal, including bit 7 */
        0x81fdffff,              /* every flag that is not a namespace flag */
        0xffffffff00000000ULL,   /* bits above the 32 the kernel reads */
    };
    for (size_t h = 0; h < sizeof(harmless) / sizeof(harmless[0]); h++) {
        d = (struct data){ .nr = LB_SECCOMP_NR_CLONE, .arch = LB_SECCOMP_AUDIT_ARCH, .args = { harmless[h] } };
        expect("clone without a namespace flag", &d, LB_SECCOMP_RET_ALLOW);
        for (size_t f = 0; f < sizeof(ns_flags) / sizeof(ns_flags[0]); f++) {
            d.args[0] = harmless[h] | ns_flags[f];
            expect("clone with a namespace flag", &d, DENY(LB_SC_EPERM));
        }
    }
    d = (struct data){ .nr = LB_SECCOMP_NR_CLONE, .arch = LB_SECCOMP_AUDIT_ARCH, .args = { LB_SECCOMP_CLONE_NS_FLAGS } };
    expect("clone with all namespace flags", &d, DENY(LB_SC_EPERM));
    /* the flags are the first argument only */
    d = (struct data){ .nr = LB_SECCOMP_NR_CLONE, .arch = LB_SECCOMP_AUDIT_ARCH,
                       .args = { 17, LB_SECCOMP_CLONE_NS_FLAGS, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX } };
    expect("clone with namespace bits in other arguments", &d, LB_SECCOMP_RET_ALLOW);

    printf("  %s: %zu instructions, %zu table rows, %lu verdicts checked, %lu wrong\n",
           TARGET, prog_len, (size_t)LB_SECCOMP_TABLE_LEN, verdicts, failures);
    return failures ? 1 : 0;
}
