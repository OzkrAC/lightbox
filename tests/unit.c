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
    die("usage: unit run|quiet <program> [args...] | unit capture <size> <program> [args...] | unit status <n>");
}
