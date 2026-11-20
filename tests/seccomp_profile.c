/*
 * Seccomp profile harness (ROADMAP 0.5).
 *
 * Built from lightbox.c itself, so it exercises the real apply_seccomp() and
 * the real deny table, not a copy. Needs no privileges: an unprivileged
 * process may install a filter once it has set no_new_privs.
 *
 * Each command takes --allow first for the allow-list (ROADMAP 8.3); without
 * it, the deny-list.
 *
 *   seccomp_profile run [--allow] <program> [args...]
 *       Install the profile, then execute the program under it.
 *
 *   seccomp_profile probe [--allow]
 *       Call every syscall of the deny table before and after installing the
 *       profile and print what each returned. tests/seccomp_cases.sh reads it.
 *
 *   seccomp_profile modes [--allow] <dir>
 *       Make the calls that set a file's mode, with the setuid or setgid bit
 *       and without, on fresh paths in <dir>/before and then, under the
 *       profile, in <dir>/after, and print what each returned:
 *
 *         mode <call> refused|allowed <returned before> <returned after>
 *
 *       a line for the call with a setuid or setgid bit and one for it with a
 *       plain mode, where the second word is what the profile is to do with
 *       it. 0 is success.
 *       The two directories have to exist and be empty.
 *
 * It prints one line per table row, then what the x32 range (x86_64 only), a
 * clone with a namespace flag and a plain clone returned:
 *
 *   deny <nr> <documented errno> <returned before> <returned after>
 *   x32 <returned before> <returned after>
 *   clone_newuser <returned before> <returned after>
 *   clone_plain <returned before> <returned after>
 *
 * and with --allow, for a call the allow-list does not name (vhangup), a
 * number past every table, and socket and socketpair of some families:
 *
 *   unlisted <returned before> <returned after>
 *   past <returned before> <returned after>
 *   socket <family> <returned before> <returned after>
 *   socketpair <family> <returned before> <returned after>
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

static bool allow_list;     /* --allow */

static void install_profile(void) {
    if (lc_kernel_prctl(LB_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("seccomp_profile: failed to set no_new_privs");
    apply_seccomp(allow_list);
}

/* ─── What only the allow-list does ─────────────────────────────────────── */

#if defined(__x86_64__)
#define NR_VHANGUP     153
#define NR_SOCKET       41
#define NR_SOCKETPAIR   53
#else
#define NR_VHANGUP      58
#define NR_SOCKET      198
#define NR_SOCKETPAIR  199
#endif
#define NR_PAST        1000     /* past every table and every syscall */
#define SOCK_STREAM_   1
#define SOCK_DGRAM_    2

/* the families probed: four it takes, and AF_PACKET, AF_ALG and AF_VSOCK */
static const int SOCKET_FAMILIES[] = { 1, 2, 10, 16, 17, 38, 40 };
#define NSOCKET_FAMILIES (int)(sizeof(SOCKET_FAMILIES) / sizeof(SOCKET_FAMILIES[0]))
static const int SOCKETPAIR_FAMILIES[] = { 1, 2 };
#define NSOCKETPAIR_FAMILIES (int)(sizeof(SOCKETPAIR_FAMILIES) / sizeof(SOCKETPAIR_FAMILIES[0]))

/* a descriptor is success, and closed */
static int64_t opened(int64_t rc) {
    if (rc < 0)
        return rc;
    lc_kernel_close_file((int32_t)rc);
    return 0;
}

static int64_t probe_socket(int family) {
    return opened(lc_syscall6(NR_SOCKET, family, family == 16 ? SOCK_DGRAM_ : SOCK_STREAM_ | O_CLOEXEC, 0, 0, 0, 0));
}

static int64_t probe_socketpair(int family) {
    int32_t fds[2];
    int64_t rc = lc_syscall6(NR_SOCKETPAIR, family, SOCK_STREAM_ | O_CLOEXEC, 0, (int64_t)fds, 0, 0);
    if (rc == 0) {
        lc_kernel_close_file(fds[0]);
        lc_kernel_close_file(fds[1]);
    }
    return rc;
}

static void put_pair(const char *what, int64_t before, int64_t after) {
    put(what);  put(" ");
    put_num(before);
    put(" ");   put_num(after);
    put("\n");
}

/* ─── The calls that set a mode ───────────────────────────────────────────── */

/* Not in lightc; the numbers of the kernel's headers, as tests/sys_check.c
 * holds those of the table to them. */
#if defined(__x86_64__)
#define NR_FCHMOD  91
#define NR_CHMOD   90
#define NR_CREAT   85
#define NR_MKDIR   83
#define NR_MKNOD  133
#else
#define NR_FCHMOD  52
#endif
#define MODE_S_IFREG   0100000
#define MODE_O_TMPFILE (020000000 | O_DIRECTORY)

/* <base>/<name><tag> */
static const char *mode_path(char *buf, size_t size, const char *base, const char *name, const char *tag) {
    bool cut = false;
    size_t pos = str_append(buf, 0, base, size, &cut);
    pos = str_append(buf, pos, "/", size, &cut);
    pos = str_append(buf, pos, name, size, &cut);
    str_append(buf, pos, tag, size, &cut);
    return buf;
}

/* A call with all six arguments, those it does not take 0: a filter that
 * looked for the mode in another argument would find nothing there. */
static int64_t sc(int64_t nr, int64_t a, int64_t b, int64_t c, int64_t d) {
    return lc_syscall6(nr, a, b, c, d, 0, 0);
}

/* a descriptor's result is success; it is closed */
static int64_t done(int64_t rc) {
    if (rc >= 0) {
        lc_kernel_close_file((int32_t)rc);
        return 0;
    }
    return rc;
}

/* a file of mode 0644 at path, as the profile lets anything make one */
static int64_t plain_file(const char *path) {
    return done(sc(SYS_openat, AT_FDCWD, (int64_t)path, O_CREAT | O_WRONLY | O_CLOEXEC, 0644));
}

enum { M_FCHMOD, M_FCHMODAT, M_FCHMODAT2, M_MKNODAT, M_OPENAT, M_OPENAT_TMPFILE, M_OPENAT_EXISTING,
       M_MKDIRAT,
#if defined(__x86_64__)
       M_CHMOD, M_CREAT, M_MKNOD, M_OPEN, M_OPEN_EXISTING, M_MKDIR,
#endif
       M_CALLS };

static const char *const MODE_CALL_NAMES[M_CALLS] = {
    "fchmod", "fchmodat", "fchmodat2", "mknodat", "openat-create", "openat-tmpfile", "openat-existing",
    "mkdirat",
#if defined(__x86_64__)
    "chmod", "creat", "mknod", "open-create", "open-existing", "mkdir",
#endif
};

/* One call with mode, on a fresh path under base named for the call and
 * tag: its result, 0 for success. */
static int64_t mode_call(int call, int64_t mode, const char *base, const char *tag) {
    char path[MAX_PATH];
    mode_path(path, sizeof(path), base, MODE_CALL_NAMES[call], tag);
    int64_t rc = 0;
    switch (call) {
    case M_FCHMOD:
        rc = sc(SYS_openat, AT_FDCWD, (int64_t)path, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
        if (rc >= 0) {
            int64_t fd = rc;
            rc = sc(NR_FCHMOD, fd, mode, 0, 0);
            lc_kernel_close_file((int32_t)fd);
        }
        return rc;
    case M_FCHMODAT:
        rc = plain_file(path);
        return rc < 0 ? rc : sc(SYS_fchmodat, AT_FDCWD, (int64_t)path, mode, 0);
    case M_FCHMODAT2:
        rc = plain_file(path);
        return rc < 0 ? rc : sc(SYS_fchmodat2, AT_FDCWD, (int64_t)path, mode, 0);
    case M_MKNODAT:
        return sc(SYS_mknodat, AT_FDCWD, (int64_t)path, MODE_S_IFREG | mode, 0);
    case M_OPENAT:
        return done(sc(SYS_openat, AT_FDCWD, (int64_t)path, O_CREAT | O_WRONLY | O_CLOEXEC, mode));
    case M_OPENAT_TMPFILE:
        return done(sc(SYS_openat, AT_FDCWD, (int64_t)base, MODE_O_TMPFILE | O_WRONLY | O_CLOEXEC, mode));
    case M_OPENAT_EXISTING:
        rc = plain_file(path);
        return rc < 0 ? rc : done(sc(SYS_openat, AT_FDCWD, (int64_t)path, O_RDONLY | O_CLOEXEC, mode));
    case M_MKDIRAT:
        return sc(SYS_mkdirat, AT_FDCWD, (int64_t)path, mode, 0);
#if defined(__x86_64__)
    case M_CHMOD:
        rc = plain_file(path);
        return rc < 0 ? rc : sc(NR_CHMOD, (int64_t)path, mode, 0, 0);
    case M_CREAT:
        return done(sc(NR_CREAT, (int64_t)path, mode, 0, 0));
    case M_MKNOD:
        return sc(NR_MKNOD, (int64_t)path, MODE_S_IFREG | mode, 0, 0);
    case M_OPEN:
        return done(sc(SYS_open, (int64_t)path, O_CREAT | O_WRONLY | O_CLOEXEC, mode, 0));
    case M_OPEN_EXISTING:
        rc = plain_file(path);
        return rc < 0 ? rc : done(sc(SYS_open, (int64_t)path, O_RDONLY | O_CLOEXEC, mode, 0));
    case M_MKDIR:
        return sc(NR_MKDIR, (int64_t)path, mode, 0, 0);
#endif
    default:
        return -LB_EINVAL;
    }
}

/* The profile is to refuse a call with the setuid or setgid bit, but not an
 * open that makes nothing, which uses no mode, nor a mkdir, whose mode the
 * kernel takes neither bit from. */
static bool mode_refused(int call) {
    switch (call) {
    case M_OPENAT_EXISTING:
    case M_MKDIRAT:
#if defined(__x86_64__)
    case M_OPEN_EXISTING:
    case M_MKDIR:
#endif
        return false;
    default:
        return true;
    }
}

static void cmd_modes(const char *dir) {
    char before[MAX_PATH], after[MAX_PATH];
    bool cut = false;
    str_append(before, str_append(before, 0, dir, sizeof(before), &cut), "/before", sizeof(before), &cut);
    str_append(after, str_append(after, 0, dir, sizeof(after), &cut), "/after", sizeof(after), &cut);

    /* each call with a mode of the two bits, setuid or setgid by turns, and
     * with a plain one: a filter that read another argument than the mode's
     * gets one of the two wrong, whatever that argument holds */
    static int64_t was[M_CALLS][2];
    for (int c = 0; c < M_CALLS; c++) {
        was[c][0] = mode_call(c, c % 2 ? 02755 : 04755, before, "-bits");
        was[c][1] = mode_call(c, 0755, before, "-plain");
    }

    install_profile();

    for (int c = 0; c < M_CALLS; c++) {
        int64_t bits = mode_call(c, c % 2 ? 02755 : 04755, after, "-bits");
        int64_t plain = mode_call(c, 0755, after, "-plain");
        put("mode ");   put(MODE_CALL_NAMES[c]);
        put(mode_refused(c) ? " refused " : " allowed ");
        put_num(was[c][0]);
        put(" ");       put_num(bits);
        put("\nmode ");  put(MODE_CALL_NAMES[c]);
        put(" allowed ");
        put_num(was[c][1]);
        put(" ");       put_num(plain);
        put("\n");
    }
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
    int64_t unlisted_before = lc_syscall6(NR_VHANGUP, 0, 0, 0, 0, 0, 0);
    int64_t past_before = lc_syscall6(NR_PAST, 0, 0, 0, 0, 0, 0);
    int64_t socket_before[NSOCKET_FAMILIES], socketpair_before[NSOCKETPAIR_FAMILIES];
    for (int i = 0; i < NSOCKET_FAMILIES; i++)
        socket_before[i] = probe_socket(SOCKET_FAMILIES[i]);
    for (int i = 0; i < NSOCKETPAIR_FAMILIES; i++)
        socketpair_before[i] = probe_socketpair(SOCKETPAIR_FAMILIES[i]);

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
    if (!allow_list)
        return;
    put_pair("unlisted", unlisted_before, lc_syscall6(NR_VHANGUP, 0, 0, 0, 0, 0, 0));
    put_pair("past", past_before, lc_syscall6(NR_PAST, 0, 0, 0, 0, 0, 0));
    char what[32];
    for (int i = 0; i < NSOCKET_FAMILIES; i++) {
        char digits[16];
        fmt_int(digits, SOCKET_FAMILIES[i]);
        bool cut = false;
        str_append(what, str_append(what, 0, "socket ", sizeof(what), &cut), digits, sizeof(what), &cut);
        put_pair(what, socket_before[i], probe_socket(SOCKET_FAMILIES[i]));
    }
    for (int i = 0; i < NSOCKETPAIR_FAMILIES; i++) {
        char digits[16];
        fmt_int(digits, SOCKETPAIR_FAMILIES[i]);
        bool cut = false;
        str_append(what, str_append(what, 0, "socketpair ", sizeof(what), &cut), digits, sizeof(what), &cut);
        put_pair(what, socketpair_before[i], probe_socketpair(SOCKETPAIR_FAMILIES[i]));
    }
}

int main(int argc, char **argv, char **envp) {
    /* the command, then --allow */
    if (argc >= 3 && streq(argv[2], "--allow")) {
        allow_list = true;
        argv[2] = argv[1];
        argv++;
        argc--;
    }
    if (argc >= 3 && streq(argv[1], "run")) {
        install_profile();
        lc_kernel_execute(argv[2], argv + 2, envp);
        die2("seccomp_profile: failed to execute ", argv[2]);
    }
    if (argc == 2 && streq(argv[1], "probe")) {
        cmd_probe();
        return 0;
    }
    if (argc == 3 && streq(argv[1], "modes")) {
        cmd_modes(argv[2]);
        return 0;
    }
    die("usage: seccomp_profile run|probe|modes [--allow] [<program> [args...] | <dir>]");
}
