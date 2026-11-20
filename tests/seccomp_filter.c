/*
 * Interprets lightbox's two seccomp programs, the deny-list and the
 * allow-list, and checks their verdict for every syscall number (ROADMAP 2.4
 * and 8.3); for the calls that set a mode, their verdict for every bit of the
 * mode and for the flags of an open (8.2); and for socket and socketpair,
 * the allow-list's for every family.
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

#if defined(LB_SECCOMP_TARGET_X86_64)
#define O_DIRECTORY_BIT 0200000U
#else
#define O_DIRECTORY_BIT 040000U
#endif
#define O_CREAT_BIT     0100U
#define O_EXCL_BIT      0200U
#define O_TMPFILE_BITS  (020000000U | O_DIRECTORY_BIT)

/* What the kernel hands a filter; the layout of struct seccomp_data. */
struct data {
    uint32_t nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
};

static struct lb_sock_filter prog[LB_SECCOMP_PROG_MAX];
static size_t prog_len;
static int allow_mode;          /* the program being checked is the allow-list */
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

/* The row of the mode table for nr, or NULL. */
static const struct lb_seccomp_mode *mode_row(uint32_t nr) {
    for (size_t i = 0; i < LB_SECCOMP_MODE_TABLE_LEN; i++)
        if (LB_SECCOMP_MODE_TABLE[i].nr == nr)
            return &LB_SECCOMP_MODE_TABLE[i];
    return NULL;
}

/* A call of a mode row: the mode in its argument, flags in its flags
 * argument when it has one, and fill in every other argument. */
static struct data mode_call(const struct lb_seccomp_mode *row, uint64_t mode, uint64_t flags, uint64_t fill) {
    struct data d = { .nr = row->nr, .arch = LB_SECCOMP_AUDIT_ARCH };
    for (int i = 0; i < 6; i++)
        d.args[i] = fill;
    d.args[row->mode_arg] = mode;
    if (row->flags_arg >= 0)
        d.args[row->flags_arg] = flags;
    return d;
}

/* The errno the table documents for nr, or 0 when it has no row. */
static uint32_t table_errno(uint32_t nr) {
    for (size_t i = 0; i < LB_SECCOMP_TABLE_LEN; i++)
        if (LB_SECCOMP_TABLE[i].nr == nr)
            return LB_SECCOMP_TABLE[i].err;
    return 0;
}

#define DENY(err) (LB_SECCOMP_RET_ERRNO | (err))

static int in_allow_table(uint32_t nr) {
    for (size_t i = 0; i < LB_SECCOMP_ALLOW_TABLE_LEN; i++)
        if (LB_SECCOMP_ALLOW_TABLE[i] == nr)
            return 1;
    return 0;
}

static int is_socket_call(uint32_t nr) {
    return nr == LB_SECCOMP_NR_SOCKET || nr == LB_SECCOMP_NR_SOCKETPAIR;
}

/* What the program answers nr with when every argument is 0. */
static uint32_t verdict_without_arguments(uint32_t nr) {
    uint32_t err = table_errno(nr);
    if (err)
        return DENY(err);
    if (!allow_mode || mode_row(nr) || nr == LB_SECCOMP_NR_CLONE || in_allow_table(nr))
        return LB_SECCOMP_RET_ALLOW;
    if (is_socket_call(nr))
        return DENY(LB_SC_EAFNOSUPPORT);     /* family 0, AF_UNSPEC */
    return DENY(LB_SC_ENOSYS);
}

/* The tables, once: no number twice or in two of them, every errno a real one. */
static void check_tables(void) {
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

    /* the mode table: numbers apart from every other row, arguments that are */
    for (size_t i = 0; i < LB_SECCOMP_MODE_TABLE_LEN; i++) {
        const struct lb_seccomp_mode *row = &LB_SECCOMP_MODE_TABLE[i];
        if (row->nr >= NR_LIMIT || row->mode_arg > 5 || row->flags_arg > 5 || row->flags_arg < -1 ||
            row->flags_arg == (int8_t)row->mode_arg) {
            printf("  mode row %zu (nr %u, mode argument %u, flags argument %d) is out of range\n",
                   i, row->nr, row->mode_arg, row->flags_arg);
            failures++;
        }
        if (row->nr == LB_SECCOMP_NR_CLONE || table_errno(row->nr)) {
            printf("  number %u is in the mode table and in another row\n", row->nr);
            failures++;
        }
        for (size_t j = 0; j < i; j++)
            if (LB_SECCOMP_MODE_TABLE[j].nr == row->nr) {
                printf("  number %u is in the mode table twice\n", row->nr);
                failures++;
            }
    }

    /* the allow table: none of the calls that have rules of their own */
    for (size_t i = 0; i < LB_SECCOMP_ALLOW_TABLE_LEN; i++) {
        uint32_t nr = LB_SECCOMP_ALLOW_TABLE[i];
        if (nr >= NR_LIMIT || table_errno(nr) || mode_row(nr) || nr == LB_SECCOMP_NR_CLONE || is_socket_call(nr)) {
            printf("  number %u of the allow table is out of range or has a rule of its own\n", nr);
            failures++;
        }
        for (size_t j = 0; j < i; j++)
            if (LB_SECCOMP_ALLOW_TABLE[j] == nr) {
                printf("  number %u is in the allow table twice\n", nr);
                failures++;
            }
    }
}

/* One of the two programs, built and interpreted. */
static void check_program(int allow) {
    allow_mode = allow;
    const char *which = allow ? "allow-list" : "deny-list";
    size_t want = allow ? LB_SECCOMP_ALLOW_PROG_LEN : LB_SECCOMP_PROG_LEN;
    prog_len = allow ? lb_seccomp_build_allow(prog) : lb_seccomp_build(prog);
    if (prog_len != want) {
        printf("  %s %s: built %zu instructions, its length says %zu\n", TARGET, which, prog_len, want);
        failures++;
        return;
    }
    unsigned long verdicts_before = verdicts, failures_before = failures;

    struct data d;

    /* another ABI: killed, whatever the number */
    static const uint32_t foreign[] = { OTHER_ARCH, AUDIT_ARCH_I386, AUDIT_ARCH_ARM, 0 };
    for (size_t f = 0; f < sizeof(foreign) / sizeof(foreign[0]); f++)
        for (uint32_t nr = 0; nr < NR_LIMIT; nr++) {
            d = (struct data){ .nr = nr, .arch = foreign[f] };
            expect("foreign architecture", &d, LB_SECCOMP_RET_KILL_PROCESS);
        }

    /* this ABI: a row answers its errno; everything else is allowed by
     * the deny-list, and by the allow-list if it names it, and answered
     * ENOSYS if not */
    for (uint32_t nr = 0; nr < NR_LIMIT; nr++) {
        uint32_t want_verdict = verdict_without_arguments(nr);
        d = (struct data){ .nr = nr, .arch = LB_SECCOMP_AUDIT_ARCH };
        expect("a syscall", &d, want_verdict);
        /* arguments do not change the answer, except for clone, the mode
         * rows and, in the allow-list, socket and socketpair below */
        if (nr != LB_SECCOMP_NR_CLONE && !mode_row(nr) && !(allow_mode && is_socket_call(nr))) {
            for (int i = 0; i < 6; i++)
                d.args[i] = UINT64_MAX;
            expect("a syscall with arguments", &d, want_verdict);
        }
    }

    /* the x32 range: refused on x86_64, where it exists; no special case elsewhere */
    for (uint32_t nr = 0; nr < NR_LIMIT; nr++) {
        d = (struct data){ .nr = LB_X32_SYSCALL_BIT | nr, .arch = LB_SECCOMP_AUDIT_ARCH };
#if defined(LB_SECCOMP_TARGET_X86_64)
        expect("x32 number", &d, DENY(LB_SC_EPERM));
#else
        expect("number with bit 30", &d, allow_mode ? DENY(LB_SC_ENOSYS) : LB_SECCOMP_RET_ALLOW);
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

    /* the calls that set a mode: refused for the setuid or the setgid bit, by
     * itself or with others, in the mode argument and nowhere else */
    for (size_t i = 0; i < LB_SECCOMP_MODE_TABLE_LEN; i++) {
        const struct lb_seccomp_mode *row = &LB_SECCOMP_MODE_TABLE[i];
        const uint64_t create = O_CREAT_BIT;
        for (uint32_t bit = 0; bit < 64; bit++) {
            d = mode_call(row, 1ULL << bit, create, 0);
            /* the kernel reads 16 bits of a mode; the filter its low word */
            expect(bit == 10 || bit == 11 ? "mode bit refused" : "mode bit allowed", &d,
                   bit == 10 || bit == 11 ? DENY(LB_SC_EPERM) : LB_SECCOMP_RET_ALLOW);
        }
        static const uint64_t refused[] = { 04000, 02000, 06000, 04755, 02755, 06755, 07777,
                                            0x100000000ULL | 04000, UINT64_MAX };
        static const uint64_t allowed[] = { 0, 0644, 0755, 01777, 0777 | 01000 | 0170000,
                                            0xffffffff00000000ULL | 0755, UINT64_MAX & ~06000ULL };
        for (size_t m = 0; m < sizeof(refused) / sizeof(refused[0]); m++) {
            d = mode_call(row, refused[m], create, 0);
            expect("a mode with a setuid or setgid bit", &d, DENY(LB_SC_EPERM));
        }
        for (size_t m = 0; m < sizeof(allowed) / sizeof(allowed[0]); m++) {
            d = mode_call(row, allowed[m], create, 0);
            expect("a mode without either bit", &d, LB_SECCOMP_RET_ALLOW);
        }
        /* the bits in every other argument do not count */
        d = mode_call(row, 0755, create, UINT64_MAX);
        expect("the bits in other arguments", &d, LB_SECCOMP_RET_ALLOW);

        if (row->flags_arg < 0)
            continue;
        /* an open uses its mode only with O_CREAT or O_TMPFILE */
        static const uint64_t making[] = { O_CREAT_BIT, O_CREAT_BIT | O_EXCL_BIT | 1, O_TMPFILE_BITS | 1,
                                           020000000U, 0xffffffffU, UINT64_MAX };
        static const uint64_t not_making[] = { 0, 1, 2, 01000 | 1, O_DIRECTORY_BIT, 04000,
                                               0xffffffffU & ~LB_SECCOMP_CREATE_FLAGS,
                                               (uint64_t)O_CREAT_BIT << 32, (uint64_t)020000000U << 32 };
        for (size_t f = 0; f < sizeof(making) / sizeof(making[0]); f++) {
            d = mode_call(row, 04755, making[f], 0);
            expect("an open that makes a file, with a setuid mode", &d, DENY(LB_SC_EPERM));
            d = mode_call(row, 0644, making[f], 0);
            expect("an open that makes a file, with a plain mode", &d, LB_SECCOMP_RET_ALLOW);
        }
        for (size_t f = 0; f < sizeof(not_making) / sizeof(not_making[0]); f++) {
            d = mode_call(row, 07777, not_making[f], UINT64_MAX);
            expect("an open that makes nothing, whatever the mode", &d, LB_SECCOMP_RET_ALLOW);
        }
    }

    /* the allow-list's socket and socketpair: their families, the first
     * argument and its low word, and EAFNOSUPPORT for any other */
    if (allow_mode) {
        static const struct { uint32_t nr; const uint32_t *af; size_t naf; } sockets[] = {
            { LB_SECCOMP_NR_SOCKET, LB_SECCOMP_SOCKET_FAMILY_TABLE, LB_SECCOMP_SOCKET_FAMILY_LEN },
            { LB_SECCOMP_NR_SOCKETPAIR, LB_SECCOMP_SOCKETPAIR_FAMILY_TABLE, LB_SECCOMP_SOCKETPAIR_FAMILY_LEN },
        };
        for (size_t s = 0; s < 2; s++) {
            for (uint64_t af = 0; af < 256; af++) {
                int listed = 0;
                for (size_t f = 0; f < sockets[s].naf; f++)
                    listed |= sockets[s].af[f] == af;
                d = (struct data){ .nr = sockets[s].nr, .arch = LB_SECCOMP_AUDIT_ARCH,
                                   .args = { af, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX } };
                expect(listed ? "a family it takes" : "a family it does not take", &d,
                       listed ? LB_SECCOMP_RET_ALLOW : DENY(LB_SC_EAFNOSUPPORT));
                /* the kernel reads an int: the high word does not count */
                d.args[0] = af | 0xffffffff00000000ULL;
                expect("a family with a high word", &d,
                       listed ? LB_SECCOMP_RET_ALLOW : DENY(LB_SC_EAFNOSUPPORT));
            }
            static const uint64_t others[] = { 0xffffffffU, 0x80000000U, 0x100U | 1, 0x10000U | 2 };
            for (size_t o = 0; o < sizeof(others) / sizeof(others[0]); o++) {
                d = (struct data){ .nr = sockets[s].nr, .arch = LB_SECCOMP_AUDIT_ARCH, .args = { others[o] } };
                expect("a family out of range", &d, DENY(LB_SC_EAFNOSUPPORT));
            }
            /* a family it takes in another argument does not count */
            d = (struct data){ .nr = sockets[s].nr, .arch = LB_SECCOMP_AUDIT_ARCH,
                               .args = { 40, sockets[s].af[0], sockets[s].af[0], sockets[s].af[0] } };
            expect("a family in another argument", &d, DENY(LB_SC_EAFNOSUPPORT));
        }
    }

    printf("  %s %s: %zu instructions, %zu table rows, %zu mode rows%s, %lu verdicts checked, %lu wrong\n",
           TARGET, which, prog_len, (size_t)LB_SECCOMP_TABLE_LEN, (size_t)LB_SECCOMP_MODE_TABLE_LEN,
           allow ? ", the allowed calls and the families of a socket" : "",
           verdicts - verdicts_before, failures - failures_before);
}

int main(void) {
    check_tables();
    check_program(0);
    check_program(1);
    return failures ? 1 : 0;
}
