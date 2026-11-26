/*
 * Interprets lightbox's cgroup device program (ROADMAP 8.4) and checks it:
 * that it is one the kernel's verifier has no reason to refuse, and its
 * verdict for every kind of device, every access and a range of numbers.
 *
 *   cc tests/devices_filter.c && ./a.out
 *
 * The program is the same on both architectures. It is interpreted here and
 * not loaded, which needs root; tests/lifecycle.sh opens devices in
 * containers, where the kernel runs it. That the constants are the kernel's
 * is what tests/sys_check.c checks, but for the order of the two registers in
 * an instruction's byte, a bit-field, which is read back here through the
 * kernel's own struct bpf_insn.
 *
 * Besides the verdicts the tables give, a few are fixed here by hand, so that
 * a wrong row is seen too: /dev/mem, /dev/kmsg and /dev/console are refused,
 * /dev/null is not, and no device can be made.
 *
 * The same again for the program of a container given devices with --device
 * (ROADMAP G.1), with the rows of a box with a GPU after the table's: those
 * devices open with the access each row gives, no other does, none is made,
 * and a row a container may not be given builds no program.
 *
 * An ordinary hosted program: it needs a C library and nothing of lightc.
 */

#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../lightbox_devices.h"

static struct lb_ebpf_insn prog[LB_DEV_PROG_MAX];
static size_t prog_len;
static const struct lb_dev_row *extra_rows;
static size_t extra_count;
static unsigned long verdicts, failures;

static void fail(const char *what) {
    if (failures < 20)
        printf("  %s\n", what);
    failures++;
}

/* The checks a verifier makes that matter here: known instructions only,
 * jumps forward and inside the program, the context read where and as wide
 * as the kernel allows, registers written before they are read, and every
 * path ending in an exit with r0 set. The program has no loop, so walking it
 * from the top with the set of written registers settles each path. */
static void check_shape(void) {
    struct bpf_insn kernels[LB_DEV_PROG_MAX];
    memcpy(kernels, prog, sizeof(kernels));
    for (size_t i = 0; i < prog_len; i++) {
        const struct lb_ebpf_insn *in = &prog[i];
        if (kernels[i].dst_reg != (in->regs & 15) || kernels[i].src_reg != (in->regs >> 4)) {
            fail("the registers of an instruction are not where the kernel's struct bpf_insn has them");
            return;
        }
    }

    /* written[i]: the registers written on every path to instruction i */
    uint16_t written[LB_DEV_PROG_MAX + 1];
    int reached[LB_DEV_PROG_MAX + 1] = { 0 };
    for (size_t i = 0; i <= LB_DEV_PROG_MAX; i++)
        written[i] = 0xffff;
    written[0] = 1u << 1;       /* r1: the context */
    reached[0] = 1;
    for (size_t i = 0; i < prog_len; i++) {
        if (!reached[i])
            continue;
        const struct lb_ebpf_insn *in = &prog[i];
        unsigned dst = in->regs & 15, src = in->regs >> 4;
        uint16_t w = written[i];
        int falls = 1;
        size_t jump = (size_t)-1;
        switch (in->code) {
        case LB_EBPF_LDX_MEM_W:
            if (src != 1 || !(w & (1u << 1)) || in->off < 0 || in->off % 4 || in->off + 4 > 12)
                fail("a read of the context the kernel would not allow");
            w |= (uint16_t)(1u << dst);
            break;
        case LB_EBPF_ALU64_MOV_X:
            if (!(w & (1u << src)))
                fail("a register is read before it is written");
            w |= (uint16_t)(1u << dst);
            break;
        case LB_EBPF_ALU64_MOV_K:
            w |= (uint16_t)(1u << dst);
            break;
        case LB_EBPF_ALU64_AND_K:
        case LB_EBPF_ALU64_RSH_K:
            if (!(w & (1u << dst)))
                fail("a register is read before it is written");
            break;
        case LB_EBPF_JMP_JNE_K:
        case LB_EBPF_JMP_JLT_K:
        case LB_EBPF_JMP_JGT_K:
        case LB_EBPF_JMP_JSET_K:
            if (!(w & (1u << dst)))
                fail("a register is compared before it is written");
            if (in->off < 0 || i + 1 + (size_t)in->off >= prog_len)
                fail("a jump goes back or out of the program");
            else
                jump = i + 1 + (size_t)in->off;
            break;
        case LB_EBPF_JMP_EXIT:
            if (!(w & 1u))
                fail("the program exits without r0 set");
            falls = 0;
            break;
        default:
            fail("an instruction the interpreter does not know");
            return;
        }
        if (in->code != LB_EBPF_JMP_EXIT && (dst > 10 || src > 10 || dst == 10))
            fail("a register that is not one, or the frame pointer written");
        if (falls) {
            if (i + 1 >= prog_len) {
                fail("the program runs off its end");
                continue;
            }
            written[i + 1] &= w;
            reached[i + 1] = 1;
        }
        if (jump != (size_t)-1) {
            written[jump] &= w;
            reached[jump] = 1;
        }
    }
    for (size_t i = 0; i < prog_len; i++)
        if (!reached[i])
            fail("an instruction no path reaches, which the verifier refuses");
}

/* What the program returns for one request. */
static uint64_t run(uint32_t kind, uint32_t access, uint32_t major, uint32_t minor) {
    uint32_t ctx[3] = { (access << 16) | kind, major, minor };
    uint64_t r[11] = { 0 };
    for (size_t pc = 0; pc < prog_len; pc++) {
        const struct lb_ebpf_insn *in = &prog[pc];
        unsigned dst = in->regs & 15, src = in->regs >> 4;
        uint64_t imm = (uint64_t)(int64_t)in->imm;      /* widened with its sign, as the kernel does */
        int taken = 0;
        switch (in->code) {
        case LB_EBPF_LDX_MEM_W:   r[dst] = ctx[in->off / 4]; break;
        case LB_EBPF_ALU64_MOV_X: r[dst] = r[src]; break;
        case LB_EBPF_ALU64_MOV_K: r[dst] = imm; break;
        case LB_EBPF_ALU64_AND_K: r[dst] &= imm; break;
        case LB_EBPF_ALU64_RSH_K: r[dst] >>= imm; break;
        case LB_EBPF_JMP_JNE_K:   taken = r[dst] != imm; break;
        case LB_EBPF_JMP_JLT_K:   taken = r[dst] < imm; break;
        case LB_EBPF_JMP_JGT_K:   taken = r[dst] > imm; break;
        case LB_EBPF_JMP_JSET_K:  taken = (r[dst] & imm) != 0; break;
        case LB_EBPF_JMP_EXIT:    return r[0];
        default:                  return 2;
        }
        if (taken)
            pc += (size_t)in->off;
    }
    return 3;
}

/* What the tables, and the rows given, say of one request. */
static int allowed(uint32_t kind, uint32_t access, uint32_t major, uint32_t minor) {
    if (kind != LB_DEVCG_DEV_CHAR)
        return 0;
    for (size_t i = 0; i < LB_DEV_TABLE_LEN + extra_count; i++) {
        const struct lb_dev_row *row = i < LB_DEV_TABLE_LEN ? &LB_DEV_TABLE[i] : &extra_rows[i - LB_DEV_TABLE_LEN];
        if (major >= row->major_first && major <= row->major_last &&
            minor >= row->minor_first && minor <= row->minor_last && !(access & ~row->access))
            return 1;
    }
    return 0;
}

static void expect(const char *what, uint32_t kind, uint32_t access, uint32_t major, uint32_t minor, int want) {
    uint64_t got = run(kind, access, major, minor);
    verdicts++;
    if (got != (uint64_t)want) {
        char line[200];
        snprintf(line, sizeof(line), "%s: kind %u, access %u, %u:%u: got %llu, want %d",
                 what, kind, access, major, minor, (unsigned long long)got, want);
        fail(line);
    }
}

/* Every kind and access, majors past the highest row and minors at the
 * edges of each, against what the tables and the rows given say. */
static void check_all(void) {
    check_shape();
    static const uint32_t far[] = { 511, 1000, 4095, 4096, 0x7fffffffU, 0x80000000U, 0xffffffffU };
    static const uint32_t minors_far[] = { LB_DEV_MINOR_MAX, LB_DEV_MINOR_MAX + 1, 0x7fffffffU,
                                           0x80000000U, 0xffffffffU };
    for (uint32_t kind = 0; kind < 4; kind++)
        for (uint32_t access = 0; access < 8; access++) {
            for (uint32_t major = 0; major < 300 + sizeof(far) / sizeof(far[0]); major++) {
                uint32_t mj = major < 300 ? major : far[major - 300];
                for (uint32_t minor = 0; minor < 300 + sizeof(minors_far) / sizeof(minors_far[0]); minor++) {
                    uint32_t mn = minor < 300 ? minor : minors_far[minor - 300];
                    expect("the tables", kind, access, mj, mn, allowed(kind, access, mj, mn));
                }
            }
        }
}

int main(void) {
    prog_len = lb_devices_build(prog);
    if (prog_len != LB_DEV_PROG_LEN) {
        printf("  built %zu instructions, its length says %zu\n", prog_len, (size_t)LB_DEV_PROG_LEN);
        return 1;
    }
    for (size_t i = 0; i < LB_DEV_TABLE_LEN; i++) {
        const struct lb_dev_row *row = &LB_DEV_TABLE[i];
        if (!LB_DEV_NUMBER_OK(row->major_last) || !LB_DEV_NUMBER_OK(row->minor_last) ||
            row->major_first > row->major_last || row->minor_first > row->minor_last ||
            row->minor_last > LB_DEV_MINOR_MAX || !row->access ||
            (row->access & ~(uint32_t)(LB_DEVCG_ACC_READ | LB_DEVCG_ACC_WRITE)))
            fail("a row is out of range, or gives mknod");
    }
    check_all();

    /* by hand */
    const uint32_t C = LB_DEVCG_DEV_CHAR, B = LB_DEVCG_DEV_BLOCK;
    const uint32_t R = LB_DEVCG_ACC_READ, W = LB_DEVCG_ACC_WRITE, M = LB_DEVCG_ACC_MKNOD;
    expect("/dev/null read and written", C, R | W, 1, 3, 1);
    expect("/dev/zero read", C, R, 1, 5, 1);
    expect("/dev/full written", C, W, 1, 7, 1);
    expect("/dev/urandom read", C, R, 1, 9, 1);
    expect("/dev/urandom written", C, W, 1, 9, 0);
    expect("/dev/random written", C, R | W, 1, 8, 0);
    expect("/dev/tty", C, R | W, 5, 0, 1);
    expect("/dev/console", C, R | W, 5, 1, 0);
    expect("/dev/pts/ptmx", C, R | W, 5, 2, 1);
    expect("/dev/pts/0", C, R | W, 136, 0, 1);
    expect("a terminal of the eighth major", C, R | W, 143, 1048575, 1);
    expect("past the terminals' majors", C, R | W, 144, 0, 0);
    expect("a pty master of the old kind", C, R | W, 128, 0, 0);
    expect("/dev/mem", C, R, 1, 1, 0);
    expect("/dev/kmem", C, R, 1, 2, 0);
    expect("/dev/port", C, R, 1, 4, 0);
    expect("/dev/kmsg", C, R, 1, 11, 0);
    expect("/dev/tty0", C, R | W, 4, 0, 0);
    expect("/dev/net/tun", C, R | W, 10, 200, 0);
    expect("/dev/fuse", C, R | W, 10, 229, 0);
    expect("/dev/loop0", B, R | W, 7, 0, 0);
    expect("/dev/sda", B, R, 8, 0, 0);
    expect("a block device of /dev/null's numbers", B, R, 1, 3, 0);
    expect("mknod of /dev/null", C, M, 1, 3, 0);
    expect("mknod of a terminal", C, M, 136, 0, 0);
    expect("mknod of 0:0, which the kernel never asks for", C, M, 0, 0, 0);
    expect("mknod of a block device", B, M, 7, 0, 0);
    printf("  %zu instructions, %zu rows, %lu verdicts checked, %lu wrong\n",
           prog_len, (size_t)LB_DEV_TABLE_LEN, verdicts, failures);

    /* A box with a GPU (ROADMAP G.1): a render node, NVIDIA's control node, a
     * major the kernel gives at boot, as nvidia-uvm's, and /dev/fuse read alone */
    static const struct lb_dev_row gpu[] = {
        { 226, 226, 128, 128, LB_DEV_RW },
        { 195, 195, 255, 255, LB_DEV_RW },
        { 511, 511, 0, 1, LB_DEV_RW },
        { 10, 10, 229, 229, LB_DEV_R },
    };
    extra_rows = gpu;
    extra_count = sizeof(gpu) / sizeof(gpu[0]);
    unsigned long before = verdicts;
    prog_len = lb_devices_build_with(prog, gpu, extra_count);
    if (prog_len != LB_DEV_PROG_LEN_FOR(extra_count)) {
        printf("  built %zu instructions with rows given, its length says %zu\n", prog_len,
               (size_t)LB_DEV_PROG_LEN_FOR(extra_count));
        return 1;
    }
    check_all();
    expect("a render node given", C, R | W, 226, 128, 1);
    expect("the render node after it", C, R | W, 226, 129, 0);
    expect("a card node", C, R | W, 226, 0, 0);
    expect("nvidiactl given", C, R | W, 195, 255, 1);
    expect("nvidia-modeset", C, R | W, 195, 254, 0);
    expect("nvidia-uvm-tools given", C, R | W, 511, 1, 1);
    expect("past nvidia-uvm's minors", C, R | W, 511, 2, 0);
    expect("/dev/fuse given to read, read", C, R, 10, 229, 1);
    expect("/dev/fuse given to read, written", C, W, 10, 229, 0);
    expect("mknod of a device given", C, M, 226, 128, 0);
    expect("a block device of a render node's numbers", B, R | W, 226, 128, 0);
    expect("/dev/null still", C, R | W, 1, 3, 1);
    expect("/dev/mem still not", C, R, 1, 1, 0);
    printf("  with %zu rows given: %zu instructions, %lu verdicts checked\n", extra_count, prog_len, verdicts - before);

    /* rows a container may not be given build nothing, nor do too many */
    static const struct lb_dev_row bad[] = {
        { 226, 226, 128, 128, LB_DEV_RW | LB_DEVCG_ACC_MKNOD },
        { 226, 226, 128, 128, 0 },
        { 0x80000000U, 0x80000000U, 0, 0, LB_DEV_RW },
        { 226, 226, 0, LB_DEV_MINOR_MAX + 1, LB_DEV_RW },
        { 227, 226, 0, 0, LB_DEV_RW },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        if (lb_devices_build_with(prog, &bad[i], 1) != 0)
            fail("a row that may not be given built a program");
    static struct lb_dev_row many[LB_DEV_EXTRA_MAX + 1];
    for (size_t i = 0; i <= LB_DEV_EXTRA_MAX; i++)
        many[i] = (struct lb_dev_row){ 226, 226, 128 + (uint32_t)i, 128 + (uint32_t)i, LB_DEV_RW };
    if (lb_devices_build_with(prog, many, LB_DEV_EXTRA_MAX) != LB_DEV_PROG_MAX)
        fail("the most rows a container may be given did not build a program of LB_DEV_PROG_MAX");
    if (lb_devices_build_with(prog, many, LB_DEV_EXTRA_MAX + 1) != 0)
        fail("more rows than a container may be given built a program");
    printf("  %zu instructions at the most; %lu wrong in all\n", (size_t)LB_DEV_PROG_MAX, failures);
    return failures ? 1 : 0;
}
