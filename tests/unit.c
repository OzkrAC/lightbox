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
 *
 * For mount, "-" stands for an argument that is not given, and the flags are
 * names joined by commas: ro, nosuid, nodev, noexec, remount, bind, rec,
 * private.
 *
 * Each prints "result <n>" on stdout once the helper has returned; capture
 * prints "captured <text>" after it. The harness itself exits 0, so a case
 * reads the helper's verdict from the output and not from the exit status.
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
    die("usage: unit run|quiet <program> [args...] | unit capture <size> <program> [args...] | unit status <n>\n"
        "       unit mount <source> <target> <fstype> <flags> <data> | unit mkdirs <path> | unit loopback");
}
