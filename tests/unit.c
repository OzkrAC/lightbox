/*
 * Unit harness (ROADMAP 3.1).
 *
 * Calls lightbox's own helpers from the command line, so tests/unit_cases.sh
 * can drive them with real programs. Built from lightbox.c itself, like the
 * seccomp harness, so it runs the code lightbox runs and not a copy.
 *
 *   unit run     <program> [args...]          run_cmd
 *   unit quiet   <program> [args...]          run_cmd_quiet
 *   unit capture <size> <program> [args...]   run_cmd_capture, into <size> bytes
 *   unit status  <wait status>                exit_code_from_status
 *   unit mount   <source> <target> <fstype> <flags> <data>     do_mount
 *   unit mkdirs  <path>                       make_dirs
 *   unit loopback                             loopback_up
 *   unit caps                                 drop_capabilities, then this process's own sets
 *   unit sandbox <program> [args...]          apply_sandbox, then the program in its place
 *   unit maskproc                             mask_proc_paths
 *   unit noipv6  <pid>                        netns_disable_ipv6
 *   unit seconds <text>                       parse_seconds
 *   unit streams <file>                       reserve_standard_streams, then the number
 *                                             the next descriptor gets, written to <file>
 *   unit init    <how> confined|open <seconds> <hook script | -> <log file | -> [<grace>]
 *                                             the two sides of a start, see below
 *   unit stop    <pid> <seconds>              ask_init_to_stop, then wait as stop does:
 *                                             "asked" or "gone", then "ended" or "still there"
 *   unit pids    <file>                       each_listed_pid: a line for each, then the count
 *   unit volspec <spec>                       parse_volume_spec: "<src> -> <dst> ro|rw",
 *                                             or "invalid: <what is wrong>"
 *   unit volumes <root> <spec>... [-- <probe>...]
 *                                             the volumes as init takes and attaches them, see below
 *   unit sealed [words...]                    run_sealed, as exec begins: then what this process
 *                                             runs from, its seals, its name, its words, and
 *                                             whether its own binary can be opened for writing
 *   unit sealed-readonly [words...]           the same from readonly_clone, the way exec takes
 *                                             where an executable memfd is refused
 *   unit nameservers <resolv.conf>            name_servers_of: a line for each, then the count
 *   unit dnslist <text>                       name_servers_listed: the same for the dns setting
 *   unit userspec <text>                      parse_user_spec: "name <n>", "uid <n>",
 *                                             "uid <n> gid <m>" or "invalid"
 *   unit identity <passwd> <group> <exec's options...>
 *                                             resolve_identity for those options, from the two
 *                                             files: "uid <n> gid <m> name <x> home <h> groups ..."
 *   unit command <passwd> <group> <exec's options and command...>
 *                                             the same, and then run_command in the harness's
 *                                             place, without taking the identity on
 *
 * For mount, "-" stands for an argument that is not given, and the flags are
 * names joined by commas: ro, nosuid, nodev, noexec, remount, bind, rec,
 * private.
 *
 * Each prints "result <n>" on stdout once the helper has returned; capture
 * prints "captured <text>" after it. The harness itself exits 0, so a case
 * reads the helper's verdict from the output and not from the exit status.
 *
 * init clones a real init into a PID namespace of its own, without a
 * container around it, and plays the command that starts it: init_begin and
 * init_main on one side, init_spawn, init_go, await_report and init_abandon
 * on the other, as cmd_start uses them. It needs the right to make a PID
 * namespace, which the root of a user namespace has. <how> is what the
 * command does:
 *
 *   whole           both bytes, and waits <seconds> for the hook
 *   late-first-byte the same, after a second in which it sends nothing and
 *                   prints "init waits", or "init went ahead" if init
 *                   reported in that second
 *   no-first-byte   closes its pipes without sending the first byte
 *   deaf            closes its end of the report pipe before the first byte
 *   no-second-byte  closes its pipes once init has reported that it is ready
 *   leave           as whole, and then ends like a start that worked: it
 *                   prints "left" and leaves init running
 *
 * With a log file, init gets /dev/null and that file as its standard streams
 * once it is ready, as in a container; with "-" it keeps the harness's.
 * <grace> is how many seconds init gives its processes when a SIGTERM comes
 * without a number of its own; 10 when it is not given.
 *
 * volumes does to <root> what init does to a container's root filesystem,
 * as far as volumes go: open_volume for each spec, pivot_root into <root>,
 * the old root taken away, attach_volumes. It then prints "attached" and
 * answers each probe from inside: "cat:<path>" with the file's text,
 * "ls:<path>" with a line for each entry, "write:<path>" with "written" or
 * "refused". It needs a mount namespace to itself, since the pivot moves the
 * root of every process in it, and <root> on a mount of that namespace.
 *
 * It prints what it sees, a line each: "init <pid>", "ready", "hook <exit
 * status>", "hook-timeout", "closed", "signal <n>" and "abandoned" when one of
 * the signals a start holds back arrives. Then, unless init is expected to
 * end by itself, "sent SIGTERM"; and "init-exit <status>", or "init-stays"
 * when init is still there five seconds later.
 */

#define main lightbox_main
#include "../lightbox.c"
#undef main

static void put(const char *s) { print_str(STDOUT, s); }

static void put_result(int result) {
    char buf[16];
    fmt_int(buf, result);
    put("result ");
    put(buf);
    put("\n");
}

static uint64_t mount_flags_named(const char *names) {
    static const struct { const char *name; uint64_t flag; } known[] = {
        { "ro", MS_RDONLY }, { "nosuid", MS_NOSUID }, { "nodev", MS_NODEV }, { "noexec", MS_NOEXEC },
        { "remount", MS_REMOUNT }, { "bind", MS_BIND }, { "rec", MS_REC }, { "private", MS_PRIVATE },
    };
    uint64_t flags = 0;
    if (streq(names, "-"))
        return 0;
    for (const char *p = names; *p; ) {
        char word[16];
        size_t len = 0;
        while (p[len] && p[len] != ',') len++;
        if (len >= sizeof(word))
            die2("unit: unknown mount flag in ", names);
        lc_bytes_copy(word, p, len);
        word[len] = '\0';
        bool found = false;
        for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
            if (streq(word, known[i].name)) { flags |= known[i].flag; found = true; }
        }
        if (!found)
            die2("unit: unknown mount flag: ", word);
        p += len;
        if (*p == ',') p++;
    }
    return flags;
}

static const char *given(const char *arg) { return streq(arg, "-") ? NULL : arg; }

/* The lines of /proc/self/status that say what this process may do. */
static void put_own_privileges(void) {
    static char status[8192];
    if (read_file("/proc/self/status", status, sizeof(status)) <= 0)
        die("unit: cannot read /proc/self/status");
    for (char *line = status; *line; ) {
        char *end = line;
        while (*end && *end != '\n') end++;
        char after = *end;
        *end = '\0';
        size_t len = lc_string_length(line);
        if (lc_string_starts_with(line, len, "Cap", 3) ||
            lc_string_starts_with(line, len, "NoNewPrivs:", 11) ||
            lc_string_starts_with(line, len, "Seccomp:", 8)) {
            put(line);
            put("\n");
        }
        line = after ? end + 1 : end;
    }
}

static void put_number(const char *label, int number) {
    char buf[16];
    fmt_int(buf, number);
    put(label);
    put(" ");
    put(buf);
    put("\n");
}

/* What init is in the harness: all of a container's init but the container. */
static int unit_init_child(void *arg) {
    const struct child_args *ca = (const struct child_args *)arg;
    init_begin(ca);
    return init_main(ca);
}

/* Give init five seconds to end. */
static bool unit_init_ended(struct init_link *link, int32_t *status) {
    for (int i = 0; i < 100; i++) {
        if (lc_kernel_wait_for_child(link->pid, status, WNOHANG) == link->pid) {
            link->pid = -1;
            return true;
        }
        lc_timespec nap = { .seconds = 0, .nanoseconds = 50000000 };
        lc_kernel_sleep(&nap);
    }
    return false;
}

static void unit_close(int32_t *fd) {
    lc_kernel_close_file(*fd);
    *fd = -1;
}

static void put_pid(int pid) {
    char buf[16];
    fmt_int(buf, pid);
    put(buf);
    put("\n");
}

static void unit_init(const char *how, bool confined, int seconds, const char *script, const char *log,
                      int grace) {
    int32_t signal_fd = hold_signals();
    if (signal_fd < 0)
        die("unit: cannot hold signals back");

    int32_t null_fd = -1, log_fd = -1;
    if (log && !open_container_streams(log, &null_fd, &log_fd))
        die2("unit: cannot open ", log);

    struct init_link link = INIT_LINK_NONE;
    struct child_args ca = {
        .starter_signals = signal_fd,
        .null_fd = null_fd,
        .log_fd = log_fd,
        .name = "unit",
        .root = "/",
        .hook = script,
        .stop_grace = grace,
        .privileged = !confined,
    };
    const char *failed = init_spawn(&link, &ca, CLONE_NEWPID, unit_init_child);
    close_container_streams(&null_fd, &log_fd);
    if (failed) {
        init_abandon(&link);
        die2("unit: ", failed);
    }
    put_number("init", link.pid);

    bool ends_by_itself = false;
    bool ready = false;
    struct start_report report = { 0, 0 };
    int stop_signal = 0;

    if (streq(how, "late-first-byte")) {
        /* the command is still setting up the cgroup and the network: init
         * must not have built anything, let alone say that it is ready */
        if (await_report(link.report_rd, signal_fd, 1, &report, &stop_signal) == AWAIT_TIMEOUT)
            put("init waits\n");
        else
            put("init went ahead\n");
    }

    if (streq(how, "no-first-byte")) {
        unit_close(&link.go_wr);
        ends_by_itself = true;
    } else {
        if (streq(how, "deaf")) {
            unit_close(&link.report_rd);
            ends_by_itself = true;
        }
        if (!init_go(&link))
            put("the first byte could not be sent\n");
    }

    if (link.report_rd >= 0 && link.go_wr >= 0) {
        switch (await_report(link.report_rd, signal_fd, 5, &report, &stop_signal)) {
            case AWAIT_REPORT:
                ready = report.what == START_READY;
                put(ready ? "ready\n" : "a report that is not START_READY\n");
                break;
            case AWAIT_CLOSED:
                put("closed\n");
                ends_by_itself = true;
                break;
            case AWAIT_TIMEOUT:
                put("not ready within 5 seconds\n");
                break;
            case AWAIT_SIGNAL:
                put_number("signal", stop_signal);
                init_abandon(&link);
                put("abandoned\n");
                return;
            case AWAIT_FAILED:
            default:
                put("the wait failed\n");
                break;
        }
    }

    if (ready && streq(how, "no-second-byte")) {
        unit_close(&link.go_wr);
        ends_by_itself = true;
    } else if (ready) {
        if (!init_go(&link))
            put("the second byte could not be sent\n");
        switch (await_report(link.report_rd, signal_fd, seconds, &report, &stop_signal)) {
            case AWAIT_REPORT:
                if (report.what == START_HOOK_DONE)
                    put_number("hook", report.status);
                else
                    put("a report that is not START_HOOK_DONE\n");
                ends_by_itself = report.status != 0;
                break;
            case AWAIT_CLOSED:
                put("closed\n");
                ends_by_itself = true;
                break;
            case AWAIT_TIMEOUT:
                put("hook-timeout\n");
                break;
            case AWAIT_SIGNAL:
                put_number("signal", stop_signal);
                init_abandon(&link);
                put("abandoned\n");
                return;
            case AWAIT_FAILED:
            default:
                put("the wait failed\n");
                break;
        }
    }

    if (streq(how, "leave") && !ends_by_itself) {
        init_link_close(&link);
        put("left\n");
        return;
    }

    if (!ends_by_itself) {
        lc_kernel_send_signal(link.pid, SIGTERM);
        put("sent SIGTERM\n");
    }
    int32_t status = 0;
    if (unit_init_ended(&link, &status))
        put_number("init-exit", exit_code_from_status(status));
    else
        put("init-stays\n");
    init_abandon(&link);
}

/* One look at the new root from inside it. */
static void unit_probe(const char *probe) {
    size_t len = lc_string_length(probe);
    put(probe);
    if (lc_string_starts_with(probe, len, "cat:", 4)) {
        static char text[512];
        put(" = ");
        put(read_file(probe + 4, text, sizeof(text)) >= 0 ? text : "(cannot be read)\n");
    } else if (lc_string_starts_with(probe, len, "write:", 6)) {
        lc_sysret fd = lc_kernel_open_file(probe + 6, O_WRONLY | O_CREAT, 0644);
        put(fd >= 0 ? " = written\n" : " = refused\n");
        if (fd >= 0)
            lc_kernel_close_file((int32_t)fd);
    } else if (lc_string_starts_with(probe, len, "ls:", 3)) {
        put(" =\n");
        lc_sysret fd = lc_kernel_open_file(probe + 3, O_RDONLY | O_DIRECTORY, 0);
        static char entries[4096];
        for (;;) {
            lc_sysret n = fd < 0 ? 0 : lc_kernel_read_directory((int32_t)fd, entries, sizeof(entries));
            if (n <= 0)
                break;
            for (lc_sysret pos = 0; pos < n; ) {
                uint16_t reclen;
                lc_bytes_copy(&reclen, entries + pos + 16, sizeof(reclen));
                const char *name = entries + pos + 19;
                if (!streq(name, ".") && !streq(name, "..")) {
                    put("  ");
                    put(name);
                    put("\n");
                }
                if (reclen == 0)
                    break;
                pos += reclen;
            }
        }
        if (fd >= 0)
            lc_kernel_close_file((int32_t)fd);
    } else {
        put(" is not a probe\n");
    }
}

static void put_int(int number) {
    char buf[16];
    fmt_int(buf, number);
    put(buf);
}

/* What the process that run_sealed returns in is running from. */
static void unit_report_sealed(int argc, char **argv) {
    static char link[256];
    lc_sysret n = lc_kernel_readlinkat(AT_FDCWD, "/proc/self/exe", link, sizeof(link) - 1);
    link[n > 0 ? n : 0] = '\0';
    put("exe ");
    put(link);
    put("\n");

    lc_sysret fd = lc_kernel_open_file("/proc/self/exe", O_RDONLY | O_CLOEXEC, 0);
    lc_sysret seals = fd >= 0 ? lb_sys_fcntl((int32_t)fd, LB_F_GET_SEALS, 0) : -1;
    if (fd >= 0)
        lc_kernel_close_file((int32_t)fd);
    /* the seals as the kernel numbers them, for the case to compare with what it expects:
     * 1 no more seals, 2 no shrinking, 4 no growing, 8 no writing */
    put("seals ");
    if (seals >= 0)
        put_int((int)seals);
    else
        put("none");
    put("\n");

    struct lb_statfs fs;
    put(lb_sys_statfs("/proc/self/exe", &fs) >= 0 && (fs.f_flags & LB_ST_RDONLY) ? "mount read-only\n" : "mount writable\n");
    put(runs_sealed() ? "sealed yes\n" : "sealed no\n");

    static char name[64];
    if (read_file("/proc/self/comm", name, sizeof(name)) > 0) {
        put("name ");
        put(name);
    }
    put("words");
    for (int i = 2; i < argc; i++) {
        put(" [");
        put(argv[i]);
        put("]");
    }
    put("\n");
    const char *kept = env_get(caller_env, "KEPT");
    put("kept ");
    put(kept ? kept : "(not in the environment)");
    put("\n");

    /* the binary this process runs, as another process would reach it */
    fd = lc_kernel_open_file("/proc/self/exe", O_WRONLY, 0);
    if (fd < 0) {
        put("write refused at open\n");
    } else {
        put(lc_kernel_write_bytes((int32_t)fd, "x", 1) == 1 ? "write DONE\n" : "write refused\n");
        lc_kernel_close_file((int32_t)fd);
    }
}

/* exec's own parsing and resolving, with the account files where the case
 * put them instead of in a container. */
static void unit_request(int argc, char **argv, struct exec_request *req, struct identity *id) {
    static const char *const shell[] = { "/bin/sh", NULL };
    int command = parse_exec_options(argc, argv, 4, req);
    req->argv = command < argc ? (const char *const *)(uintptr_t)(argv + command) : shell;
    request_term(req);
    resolve_identity(req, argv[2], argv[3], id);
}

int main(int argc, char **argv, char **envp) {
    caller_argv = argv;
    caller_env = envp;
    if (argc >= 3 && streq(argv[1], "run")) {
        put_result(run_cmd(argv[2], (const char *const *)(argv + 2)));
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "quiet")) {
        put_result(run_cmd_quiet(argv[2], (const char *const *)(argv + 2)));
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "capture")) {
        static char captured[4096];
        int size = parse_int(argv[2]);
        if (size < 1 || size > (int)sizeof(captured))
            die("unit: capture size must be 1 to 4096");
        put_result(run_cmd_capture(argv[3], (const char *const *)(argv + 3), captured, (size_t)size));
        put("captured ");
        put(captured);
        put("\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "status")) {
        put_result(exit_code_from_status(parse_int(argv[2])));
        return 0;
    }
    if (argc == 7 && streq(argv[1], "mount")) {
        put_result(do_mount(given(argv[2]), argv[3], given(argv[4]), mount_flags_named(argv[5]), given(argv[6])));
        return 0;
    }
    if (argc == 3 && streq(argv[1], "mkdirs")) {
        put_result(make_dirs(argv[2]));
        return 0;
    }
    if (argc == 2 && streq(argv[1], "loopback")) {
        put_result(loopback_up());
        return 0;
    }
    if (argc == 2 && streq(argv[1], "caps")) {
        drop_capabilities();
        put_own_privileges();
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "sandbox")) {
        apply_sandbox();
        exec_program(argv[2], (const char *const *)(argv + 2), TOOL_ENV);
        die2("unit: cannot execute ", argv[2]);
    }
    if (argc == 2 && streq(argv[1], "maskproc")) {
        mask_proc_paths();
        put_result(0);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "noipv6")) {
        put_result(netns_disable_ipv6(parse_int(argv[2])));
        return 0;
    }
    if (argc == 3 && streq(argv[1], "seconds")) {
        int seconds = -1;
        bool ok = parse_seconds(argv[2], &seconds);
        put_result(ok ? seconds : -1);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "streams")) {
        /* whatever of 0, 1 and 2 the caller left closed: the file must not land there */
        reserve_standard_streams();
        lc_sysret fd = lc_kernel_open_file(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            return 1;
        char digits[16];
        int len = fmt_int(digits, (int)fd);
        lc_kernel_write_bytes((int32_t)fd, digits, (size_t)len);
        lc_kernel_close_file((int32_t)fd);
        return 0;
    }
    if ((argc == 7 || argc == 8) && streq(argv[1], "init")) {
        int seconds = 0, grace = STOP_TIMEOUT_DEFAULT;
        bool confined = streq(argv[3], "confined");
        if ((!confined && !streq(argv[3], "open")) || !parse_seconds(argv[4], &seconds) ||
            (argc == 8 && !parse_seconds(argv[7], &grace)))
            die("unit: init <how> confined|open <seconds> <hook script | -> <log file | -> [<grace>]");
        unit_init(argv[2], confined, seconds, given(argv[5]), given(argv[6]), grace);
        return 0;
    }
    if (argc == 4 && streq(argv[1], "stop")) {
        int seconds = 0;
        if (!parse_seconds(argv[3], &seconds))
            die("unit: stop <pid> <seconds>");
        lc_sysret pidfd = lb_sys_pidfd_open(parse_int(argv[2]), 0);
        if (pidfd < 0)
            die2("unit: no process ", argv[2]);
        put(ask_init_to_stop((int32_t)pidfd, seconds) ? "asked\n" : "gone\n");
        put(readable_within((int32_t)pidfd, (int64_t)seconds * 1000 + STOP_MARGIN_MS) ? "ended\n" : "still there\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "volspec")) {
        volume_spec vol = {0};
        const char *wrong = parse_volume_spec(argv[2], &vol);
        if (wrong) {
            put("invalid: ");
            put(wrong);
        } else {
            put(vol.src);
            put(" -> ");
            put(vol.dst);
            put(vol.ro ? " ro" : " rw");
        }
        put("\n");
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "volumes")) {
        static struct volume_mount volumes[MAX_VOLS];
        const char *root = argv[2];
        int count = 0, i = 3;

        require_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        for (; i < argc && !streq(argv[i], "--"); i++) {
            if (count == MAX_VOLS)
                die("unit: too many volumes");
            open_volume(argv[i], &volumes[count++]);
        }

        /* into the root as build_container goes into a container's */
        require_mount(root, root, NULL, MS_BIND | MS_REC, NULL);
        if (lc_kernel_chdir(root) < 0)
            die2("unit: cannot change to ", root);
        lc_kernel_mkdirat(AT_FDCWD, ".old_root", 0755);
        if (lc_kernel_pivot_root(".", ".old_root") < 0)
            die("unit: pivot_root failed");
        cleanup_old_root_or_die();
        lc_kernel_chdir("/");

        attach_volumes(volumes, count);
        put("attached\n");
        for (i++; i < argc; i++)
            unit_probe(argv[i]);
        return 0;
    }
    if (argc >= 2 && streq(argv[1], "sealed")) {
        run_sealed();
        unit_report_sealed(argc, argv);
        return 0;
    }
    if (argc >= 2 && streq(argv[1], "sealed-readonly")) {
        if (!runs_sealed()) {
            lc_sysret clone = readonly_clone();
            if (clone < 0)
                die("unit: no read-only clone of the binary");
            lb_sys_execveat((int32_t)clone, "", argv, envp, LB_AT_EMPTY_PATH);
            die("unit: the read-only clone could not be executed");
        }
        unit_report_sealed(argc, argv);
        return 0;
    }
    if (argc == 3 && (streq(argv[1], "nameservers") || streq(argv[1], "dnslist"))) {
        char found[MAX_DNS][16];
        int count = streq(argv[1], "dnslist") ? name_servers_listed(argv[2], found)
                                              : name_servers_of(argv[2], found);
        for (int i = 0; i < count; i++) {
            put(found[i]);
            put("\n");
        }
        put_result(count);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "userspec")) {
        struct exec_request req = { .as = AS_ROOT, .gid = -1 };
        if (!parse_user_spec(argv[2], &req)) {
            put("invalid\n");
        } else if (req.as == AS_NAME) {
            put("name ");
            put(req.user);
            put("\n");
        } else {
            put("uid ");
            put_int(req.uid);
            if (req.gid >= 0) {
                put(" gid ");
                put_int(req.gid);
            }
            put("\n");
        }
        return 0;
    }
    if (argc >= 4 && (streq(argv[1], "identity") || streq(argv[1], "command"))) {
        struct exec_request req = { .as = AS_ROOT, .gid = -1 };
        static struct identity id;
        unit_request(argc, argv, &req, &id);
        if (streq(argv[1], "command"))
            run_command(&req, &id);
        put("uid ");
        put_int(id.uid);
        put(" gid ");
        put_int(id.gid);
        put(" name ");
        put(id.name[0] ? id.name : "-");
        put(" home ");
        put(id.home[0] ? id.home : "-");
        put(" groups");
        for (int i = 0; i < id.ngroups; i++) {
            put(" ");
            put_int((int)id.groups[i]);
        }
        put("\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "pids")) {
        put_result(each_listed_pid(argv[2], put_pid));
        return 0;
    }
    die("usage: unit run|quiet <program> [args...] | unit capture <size> <program> [args...] | unit status <n>\n"
        "       unit mount <source> <target> <fstype> <flags> <data> | unit mkdirs <path> | unit loopback\n"
        "       unit caps | unit sandbox <program> [args...] | unit maskproc | unit noipv6 <pid>\n"
        "       unit seconds <text> | unit streams <file> | unit init <how> confined|open <seconds> <hook script | -> <log file | -> [<grace>]\n"
        "       unit stop <pid> <seconds> | unit pids <file> | unit userspec <text>\n"
        "       unit volspec <spec> | unit volumes <root> <spec>... [-- <probe>...]\n"
        "       unit nameservers <resolv.conf> | unit dnslist <text>\n"
        "       unit sealed [words...] | unit sealed-readonly [words...]\n"
        "       unit identity|command <passwd> <group> <exec's options...>");
}
