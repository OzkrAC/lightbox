/*
 * Seccomp profile harness (ROADMAP 0.5).
 *
 * Built from lightbox.c itself, so it exercises the real apply_seccomp() and
 * the real deny table, not a copy. Needs no privileges: an unprivileged
 * process may install a filter once it has set no_new_privs.
 *
 *   seccomp_profile run <program> [args...]
 *       Install the profile, then execute the program under it.
 *
 *   seccomp_profile probe
 *       Call every syscall of the deny table before and after installing the
 *       profile and print what each returned. tests/seccomp_cases.sh reads it.
 *
 * It prints one line per table row, then what the x32 range (x86_64 only), a
 * clone with a namespace flag and a plain clone returned:
 *
 *   deny <nr> <documented errno> <returned before> <returned after>
 *   x32 <returned before> <returned after>
 *   clone_newuser <returned before> <returned after>
 *   clone_plain <returned before> <returned after>
 *
 * Probes pass -1 for every argument. A denied syscall never runs, and one that
 * does run (before the profile, or because the profile missed it) fails on the
 * invalid argument without doing anything: a bad pointer, descriptor or flag.
 */

#define main lightbox_main
#include "../lightbox.c"
#undef main

#define X32_SYSCALL_BIT   0x40000000
#define NR_PERSONALITY    135
#define PERSONALITY_QUERY 0xffffffff   /* returns the persona, changes nothing */
#define CLONE_NEWUSER_FLAG 0x10000000
#define SIGCHLD_NR        17

#define KILLED INT64_MIN   /* the probing child was killed by the filter */

static void put(const char *s) { print_str(STDOUT, s); }

static void put_num(int64_t v) {
    if (v == KILLED) { put("killed"); return; }
    char buf[16];
    fmt_int(buf, (int)v);
    put(buf);
}

static int64_t probe_nr(int64_t nr) {
    return lc_syscall6(nr, -1, -1, -1, -1, -1, -1);
}

#if defined(__x86_64__)
static int64_t probe_x32(void) {
    return lc_syscall6(X32_SYSCALL_BIT | NR_PERSONALITY, PERSONALITY_QUERY, 0, 0, 0, 0, 0);
}
#endif

/* clone with the given flags. 1 when a child was created (it exits at once),
 * otherwise the negative errno. */
static int64_t probe_clone(int64_t flags) {
    lc_sysret pid = lc_syscall5(SYS_clone, flags | SIGCHLD_NR, 0, 0, 0, 0);
    if (pid == 0)
        lc_kernel_exit(0);
    if (pid < 0)
        return pid;
    int32_t status;
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    return 1;
}

static int64_t probe_clone_newuser(void) { return probe_clone(CLONE_NEWUSER_FLAG); }
static int64_t probe_clone_plain(void)   { return probe_clone(0); }

/* Run a probe in a child, so that a filter which kills instead of returning an
 * errno is reported and does not end the harness. */
static int64_t in_child(int64_t (*probe)(void)) {
    int pipefd[2];
    if (lc_kernel_create_pipe(pipefd, 0) < 0)
        die("seccomp_profile: pipe failed");
    lc_sysret pid = lc_kernel_fork();
    if (pid < 0)
        die("seccomp_profile: fork failed");
    if (pid == 0) {
        int64_t r = probe();
        lc_kernel_write_bytes(pipefd[1], &r, sizeof(r));
        lc_kernel_exit(0);
    }
    lc_kernel_close_file(pipefd[1]);
    int64_t result = KILLED;
    int32_t status = 0;
    lc_sysret got = lc_kernel_read_bytes(pipefd[0], &result, sizeof(result));
    lc_kernel_close_file(pipefd[0]);
    lc_kernel_wait_for_child((int32_t)pid, &status, 0);
    if (got != (lc_sysret)sizeof(result) || (status & 0x7f) != 0)
        return KILLED;
    return result;
}

static void install_profile(void) {
    if (lc_kernel_prctl(LB_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("seccomp_profile: failed to set no_new_privs");
    apply_seccomp();
}

static void cmd_probe(void) {
    static int64_t before[LB_SECCOMP_TABLE_LEN];
    size_t n = LB_SECCOMP_TABLE_LEN;

    for (size_t i = 0; i < n; i++)
        before[i] = probe_nr(LB_SECCOMP_TABLE[i].nr);
#if defined(__x86_64__)
    int64_t x32_before = probe_x32();
#endif
    int64_t clone_before = in_child(probe_clone_newuser);
    int64_t plain_before = in_child(probe_clone_plain);

    install_profile();

    /* deny <nr> <documented errno> <returned before> <returned after> */
    for (size_t i = 0; i < n; i++) {
        put("deny ");   put_num(LB_SECCOMP_TABLE[i].nr);
        put(" ");       put_num(LB_SECCOMP_TABLE[i].err);
        put(" ");       put_num(before[i]);
        put(" ");       put_num(probe_nr(LB_SECCOMP_TABLE[i].nr));
        put("\n");
    }
#if defined(__x86_64__)
    put("x32 ");            put_num(x32_before);
    put(" ");               put_num(in_child(probe_x32));
    put("\n");
#endif
    put("clone_newuser ");  put_num(clone_before);
    put(" ");               put_num(in_child(probe_clone_newuser));
    put("\n");
    put("clone_plain ");    put_num(plain_before);
    put(" ");               put_num(in_child(probe_clone_plain));
    put("\n");
}

int main(int argc, char **argv, char **envp) {
    if (argc >= 3 && streq(argv[1], "run")) {
        install_profile();
        lc_kernel_execute(argv[2], argv + 2, envp);
        die2("seccomp_profile: failed to execute ", argv[2]);
    }
    if (argc == 2 && streq(argv[1], "probe")) {
        cmd_probe();
        return 0;
    }
    die("usage: seccomp_profile run <program> [args...] | seccomp_profile probe");
}
