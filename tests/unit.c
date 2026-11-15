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
 *   unit init    <how> confined|open <seconds> <hook script | ->
 *                                             the two sides of a start, see below
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

static void unit_init(const char *how, bool confined, int seconds, const char *script) {
    int32_t signal_fd = hold_signals();
    if (signal_fd < 0)
        die("unit: cannot hold signals back");

    struct init_link link = INIT_LINK_NONE;
    struct child_args ca = {
        .starter_signals = signal_fd,
        .name = "unit",
        .root = "/",
        .hook = script,
        .privileged = !confined,
    };
    const char *failed = init_spawn(&link, &ca, CLONE_NEWPID, unit_init_child);
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

int main(int argc, char **argv) {
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
    if (argc == 6 && streq(argv[1], "init")) {
        int seconds = 0;
        bool confined = streq(argv[3], "confined");
        if ((!confined && !streq(argv[3], "open")) || !parse_seconds(argv[4], &seconds))
            die("unit: init <how> confined|open <seconds> <hook script | ->");
        unit_init(argv[2], confined, seconds, given(argv[5]));
        return 0;
    }
    die("usage: unit run|quiet <program> [args...] | unit capture <size> <program> [args...] | unit status <n>\n"
        "       unit mount <source> <target> <fstype> <flags> <data> | unit mkdirs <path> | unit loopback\n"
        "       unit caps | unit sandbox <program> [args...] | unit maskproc | unit noipv6 <pid>\n"
        "       unit seconds <text> | unit init <how> confined|open <seconds> <hook script | ->");
}
