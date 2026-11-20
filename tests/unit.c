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
 *   unit input   <text> <program> [args...]   run_cmd_input, with <text> as its input; then
 *                                             "left open <n>": descriptors it left open
 *   unit names <name>                         host_port_name and link_chain_name, a line each
 *   unit owner <name> <alias>                 port_owner_of_alias: ours or foreign
 *   unit subid <subuid text> <subgid text> [<uid>:<gid>...]
 *                                             subid_ranges of lightbox's lines, "range <start> <count>"
 *                                             each or "bad line <n>", then userns_choose with those
 *                                             ranges taken: "chose <uid> <gid>" or "none: <why>"
 *   unit userns-start <text>                  userns_start_ok: "ok <n>" or "refused"
 *   unit volume-maps <uid> <gid> <uid_start> <gid_start>
 *                                             volume_maps for a source of uid and gid: its two lines,
 *                                             "uid_map <line>" and "gid_map <line>", or "plain"
 *   unit userns-volume <uid_start> <gid_start> <src:dst>
 *                                             open_userns_volume of a container with that range, as
 *                                             start takes it, attached at dst in this mount namespace:
 *                                             "attached", or "refused: <why>"
 *   unit port owner|remove <ifname> <name>    host_port_owner: absent, ours, foreign or unknown;
 *                                             remove_own_port: "result <n>"
 *   unit rtnl <request> [args...]             one rtnetlink request, "result <n>" or what it found:
 *                                             index <ifname>; alias <ifname>; name <index>;
 *                                             veth <ifname> <peer> <pid>; bridge <ifname>;
 *                                             attach <ifname> <alias> <bridge>; isolate <ifname>;
 *                                             up <ifname>; delete <ifname>;
 *                                             addr <ifname> <address> <prefix>; route <gateway> <ifname>;
 *                                             wan (the default route's interface, or none);
 *                                             inside <address> <prefix> <gateway> (container_interface_up)
 *   unit chain <text>                         link_chain_ok: ok or refused
 *   unit firewall links <name> [<link>...]    firewall_links_text for a container with those links;
 *                                             links-into-64 gives it 64 bytes to write into
 *   unit firewall setup <subnet> <gw> <bridge> <ip_masq>
 *                                             firewall_setup_text for that network
 *   unit firewall nft-setup <subnet> <gw> <bridge> <ip_masq> [<fwmark>]
 *                                             nft_setup_text, with bridge_accept_fwmark if given
 *   unit firewall nft-record <name> [<link>...]
 *                                             nft_links_record for a container with those links
 *   unit nftlinks add|remove <record>         nft_links_text for that record, or "refused"; a line
 *                                             it would take lies right after the record's end
 *   unit fwmark <text>                        parse_fwmark: lines "mark <m>", "mask <k>", "as <text>",
 *                                             or "refused"
 *   unit portname <text>                      host_port_ok: ok or refused
 *   unit kernel <release>                     kernel_release_at_least the floor: "yes <major>.<minor>",
 *                                             "no <major>.<minor>", or "unreadable"
 *   unit config-source <given> <env> <etc> <home>
 *                                             config_source_of, "-" for no --config or no
 *                                             variable, 1 or 0 for a file in /etc or $HOME:
 *                                             given, env, etc, home or none
 *   unit dropping <listing>                   forward_drop_chains of what "nft list chains"
 *                                             printed: how many, and their names
 *   unit status  <wait status>                exit_code_from_status
 *   unit mount   <source> <target> <fstype> <flags> <data>     do_mount
 *   unit mkdirs  <path>                       make_dirs
 *   unit loopback                             loopback_up
 *   unit caps                                 drop_capabilities, then this process's own sets
 *   unit sandbox <program> [args...]          apply_sandbox, then the program in its place
 *   unit maskproc                             mask_proc_paths
 *   unit noipv6  <pid>                        netns_disable_ipv6
 *   unit seconds <text>                       parse_seconds
 *   unit number  <text> <min> <max>           parse_number: the number, or "refused"
 *   unit limit   mem|pids|cpu|oom <text>      the check that an option, a setting and a .conf
 *                                             share: "ok", for cpu "quota <n>", for oom
 *                                             "score <n>"; or "refused"
 *   unit text copy   <size> <text>            str_copy into <size> bytes
 *   unit text append <size> <a> <b>           str_append of <b> after <a>
 *   unit text join   <size> <a> <b>           path_join
 *                                             each: "whole <text>", or "cut <what is there>"
 *   unit config <dir> <name> [nodefaults]     container_config_load of <dir>/<name>/.conf: a line
 *                                             for each value, or "refused: <why>"; nodefaults
 *                                             is a lightbox.conf whose default_* are all unusable
 *   unit config-write <dir> <name> [<field>=<value>...]
 *                                             container_config_save of a configuration with these
 *                                             values put in unchecked, as no command would: mem,
 *                                             pids, cpu, io, link, and src and dst for a volume.
 *                                             "written", or "refused: <why>"
 *   unit streams <file>                       reserve_standard_streams, then the number
 *                                             the next descriptor gets, written to <file>
 *   unit init    <how> confined|open <seconds> <hook script | -> <log file | -> [<grace>]
 *                                             the two sides of a start, see below
 *   unit stop    <pid> <seconds>              ask_init_to_stop, then wait as stop does:
 *                                             "asked" or "gone", then "ended" or "still there"
 *   unit pids    <file>                       each_listed_pid: a line for each, then the count
 *   unit remove  <file>                       remove_file_durably
 *   unit record  <run_dir> <name> <state>     record_container_state, which makes run_dir and the
 *                                             container's directory in it when they are missing
 *   unit reconcile <container_dir> <run_dir> <name>
 *                                             reconcile, as start, stop and rm call it for a
 *                                             container that ended without a stop: "cleared" or
 *                                             "nothing", then "state <what is on record now>"
 *   unit volspec <spec>                       parse_volume_spec: "<src> -> <dst> ro|rw",
 *                                             or "invalid: <what is wrong>"
 *   unit volumes <root> <spec>... [-- <probe>...]
 *                                             the volumes as init takes and attaches them, see below
 *   unit sealed [words...]                    run_sealed, as exec begins: then what this process
 *                                             runs from, its seals, its name, its words, and
 *                                             whether its own binary can be opened for writing
 *   unit sealed-readonly [words...]           the same from readonly_clone, the way exec takes
 *                                             where an executable memfd is refused
 *   unit relay <ptmx> -- <command...>         what exec does about a command's standard streams,
 *                                             without a container: see below
 *   unit controllers <listed> <mem> <pids> <swap|-> <io|->
 *                                             controllers_check for a container with those
 *                                             limits and a cgroup.controllers of <listed>:
 *                                             "have <controller>..." after the warnings, on
 *                                             standard error, or "refused: <why>"
 *   unit address <text>                       parse_ipv4: the address as format_ipv4 writes it,
 *                                             or "refused"
 *   unit network <subnet> <gw> [<address>...] container_network_parse: "subnet <net>/<bits>
 *                                             broadcast <b> gateway <g>", or "<setting> <what is
 *                                             wrong>"; then for each address "<address>: " and
 *                                             what address_with_prefix gives, or why
 *                                             address_unusable refuses it
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
 * once it is ready, as in a container; with "-" it keeps the harness's. When
 * UNIT_EXIT names a file, init has it as the record of how it ends, as in a
 * container, and writes its exit status there as its last act.
 * <grace> is how many seconds init gives its processes when a SIGTERM comes
 * without a number of its own; 10 when it is not given.
 *
 * relay runs a command the way exec does once it is in a container: a first
 * process as the one that ran exec, which keeps the terminal's modes and
 * attends to a second, the worker, which gives the command a pseudo-terminal
 * from <ptmx>, or pipes, or its own streams, and carries them until the
 * command ends. The harness ends with the command's exit status.
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

/* How many descriptors this process has open, from /proc/self/fd: its
 * entries, as getdents64 gives them, but for "." and "..". The record's
 * length is at byte 16 and its name at 19. */
static int open_descriptors(void) {
    enum { RECLEN_AT = 16, NAME_AT = 19 };
    lc_sysret fd = lc_kernel_open_file("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    char buf[4096];
    int count = 0;
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        for (lc_sysret pos = 0; pos < n; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + RECLEN_AT, sizeof(reclen));
            if (reclen == 0)
                break;
            if (buf[pos + NAME_AT] != '.')
                count++;
            pos += reclen;
        }
    }
    lc_kernel_close_file((int32_t)fd);
    return count;
}

static void put_result(int result) {
    char buf[16];
    fmt_int(buf, result);
    put("result ");
    put(buf);
    put("\n");
}

static int number_arg(const char *text) {
    int number;
    if (!parse_int_in(text, INT32_MIN, INT32_MAX, &number))
        die2("unit: not a number: ", text);
    return number;
}

/* "<label> <number>" */
static void put_number(const char *label, int number) {
    char buf[16];
    fmt_int(buf, number);
    put(label);
    put(" ");
    put(buf);
    put("\n");
}

static void put_line(const char *label, const char *text) {
    put(label);
    put(text);
    put("\n");
}

static uint32_t ipv4_arg(const char *text) {
    uint32_t addr;
    if (!parse_ipv4(text, &addr))
        die2("unit: not an IPv4 address: ", text);
    return addr;
}

/* "unit rtnl <request> [args...]" */
static int unit_rtnl(int argc, char **argv) {
    const char *op = argv[0];
    if (argc == 4 && streq(op, "inside")) {
        put_result(container_interface_up(ipv4_arg(argv[1]), number_arg(argv[2]), ipv4_arg(argv[3])));
        return 0;
    }
    rtnl nl;
    int rc = rtnl_open(&nl);
    if (rc < 0) {
        put_result(rc);
        return 0;
    }
    char text[256];
    if (argc == 2 && streq(op, "index")) {
        rc = rtnl_link_get(&nl, argv[1], NULL, 0);
        if (rc > 0) { put_number("index", rc); rc = 0; }
    } else if (argc == 2 && streq(op, "alias")) {
        rc = rtnl_link_get(&nl, argv[1], text, sizeof(text));
        if (rc > 0) { put_line("alias ", text); rc = 0; }
    } else if (argc == 2 && streq(op, "name")) {
        char name[IFNAME_TEXT_MAX];
        rc = rtnl_link_name(&nl, number_arg(argv[1]), name);
        if (rc == 0) put_line("name ", name);
    } else if (argc == 4 && streq(op, "veth")) {
        rc = rtnl_veth_add(&nl, argv[1], argv[2], number_arg(argv[3]));
    } else if (argc == 2 && streq(op, "bridge")) {
        rc = rtnl_bridge_add(&nl, argv[1]);
    } else if (argc == 4 && streq(op, "attach")) {
        int master = rtnl_link_get(&nl, argv[3], NULL, 0);
        rc = master < 0 ? master : rtnl_link_attach(&nl, argv[1], argv[2], master);
    } else if (argc == 2 && streq(op, "isolate")) {
        rc = rtnl_port_isolate(&nl, argv[1]);
    } else if (argc == 2 && streq(op, "up")) {
        rc = rtnl_link_up(&nl, argv[1]);
    } else if (argc == 2 && streq(op, "delete")) {
        rc = rtnl_link_delete(&nl, argv[1]);
    } else if (argc == 4 && streq(op, "addr")) {
        int index = rtnl_link_get(&nl, argv[1], NULL, 0);
        rc = index < 0 ? index : rtnl_addr_add(&nl, index, ipv4_arg(argv[2]), number_arg(argv[3]));
    } else if (argc == 3 && streq(op, "route")) {
        int index = rtnl_link_get(&nl, argv[2], NULL, 0);
        rc = index < 0 ? index : rtnl_default_route_add(&nl, ipv4_arg(argv[1]), index);
    } else if (argc == 1 && streq(op, "wan")) {
        char name[IFNAME_TEXT_MAX];
        rc = rtnl_default_route_index(&nl);
        if (rc == 0) put("wan none\n");
        else if (rc > 0 && (rc = rtnl_link_name(&nl, rc, name)) == 0) put_line("wan ", name);
    } else {
        rtnl_close(&nl);
        die("unit: rtnl index|alias|name|veth|bridge|attach|isolate|up|delete|addr|route|wan|inside ...");
    }
    rtnl_close(&nl);
    put_result(rc);
    return 0;
}

/* a text helper's verdict and what it left in the buffer */
static void put_text(bool whole, const char *text) {
    put_line(whole ? "whole " : "cut ", text);
}

static void put_config(const container_config *config) {
    put_number("version", config->version);
    put_line("mem ", config->mem);
    put_line("pids ", config->pids);
    put_line("cpu ", config->cpu);
    put_number("oom_score", config->oom_score);
    put_number("privileged", config->privileged);
    put_number("readonly", config->read_only);
    put_line("seccomp ", config->seccomp_allow ? "allow" : "deny");
    put_line("io ", config->io[0] ? config->io : "-");
    put_line("swap ", config->swap[0] ? config->swap : "-");
    put_line("base ", config->base[0] ? config->base : "-");
    if (config->userns) {
        char u[11], g[11];
        format_u32(u, config->uid_start);
        format_u32(g, config->gid_start);
        put("userns ");
        put(u);
        put_line(" ", g);
    } else {
        put("userns -\n");
    }
    for (int i = 0; i < config->nvols; i++) {
        put("vol ");
        put(config->vols[i].src);
        put(" -> ");
        put(config->vols[i].dst);
        put(config->vols[i].ro ? " ro\n" : " rw\n");
    }
    for (int i = 0; i < config->nlinks; i++)
        put_line("link ", config->links[i]);
}

/* A field of a configuration set to a value as it is, however long it is
 * allowed to be and whatever is in it. */
static void set_unchecked(container_config *config, const char *assignment) {
    static const char *const fields[] = { "mem=", "pids=", "cpu=", "io=", "link=", "src=", "dst=", "swap=" };
    size_t which = 0, len = 0;
    for (; which < sizeof(fields) / sizeof(fields[0]); which++) {
        len = lc_string_length(fields[which]);
        if (lc_string_starts_with(assignment, lc_string_length(assignment), fields[which], len))
            break;
    }
    const char *value = assignment + len;
    bool fits = false;
    switch (which) {
        case 0: fits = str_copy(config->mem, value, sizeof(config->mem)); break;
        case 1: fits = str_copy(config->pids, value, sizeof(config->pids)); break;
        case 2: fits = str_copy(config->cpu, value, sizeof(config->cpu)); break;
        case 3: fits = str_copy(config->io, value, sizeof(config->io)); break;
        case 4: fits = config->nlinks < MAX_LINKS &&
                       str_copy(config->links[config->nlinks], value, sizeof(config->links[0]));
                config->nlinks++;
                break;
        case 5: fits = config->nvols < MAX_VOLS &&
                       str_copy(config->vols[config->nvols].src, value, MAX_PATH);
                break;
        case 6: fits = config->nvols < MAX_VOLS &&
                       str_copy(config->vols[config->nvols].dst, value, MAX_PATH);
                config->nvols++;
                break;
        case 7: fits = str_copy(config->swap, value, sizeof(config->swap)); break;
        default: break;
    }
    if (!fits)
        die2("unit: cannot set ", assignment);
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

/* What init is in the harness: all of a container's init but the container. */
static int unit_init_child(void *arg) {
    const struct child_args *ca = (const struct child_args *)arg;
    init_begin(ca);
    return init_ends(ca, init_main(ca));
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

    int32_t null_fd = -1, log_fd = -1, exit_fd = -1;
    if (log && !open_container_streams(log, &null_fd, &log_fd))
        die2("unit: cannot open ", log);
    const char *exit_record = env_get(caller_env, "UNIT_EXIT");
    if (exit_record && (exit_fd = open_exit_record(exit_record)) < 0)
        die2("unit: cannot open ", exit_record);

    struct init_link link = INIT_LINK_NONE;
    struct child_args ca = {
        .starter_signals = signal_fd,
        .null_fd = null_fd,
        .log_fd = log_fd,
        .exit_fd = exit_fd,
        .name = "unit",
        .root = "/",
        .hook = script,
        .stop_grace = grace,
        .privileged = !confined,
    };
    const char *failed = init_spawn(&link, &ca, CLONE_NEWPID, unit_init_child);
    close_container_streams(&null_fd, &log_fd);
    if (exit_fd >= 0)
        lc_kernel_close_file(exit_fd);
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
        int size = number_arg(argv[2]);
        if (size < 1 || size > (int)sizeof(captured))
            die("unit: capture size must be 1 to 4096");
        put_result(run_cmd_capture(argv[3], (const char *const *)(argv + 3), captured, (size_t)size));
        put("captured ");
        put(captured);
        put("\n");
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "input")) {
        int before = open_descriptors();
        put_result(run_cmd_input(argv[3], (const char *const *)(argv + 3), argv[2], false));
        put_number("left open", open_descriptors() - before);
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "subid")) {
        static subid_range uids[SUBID_RANGES_MAX], gids[SUBID_RANGES_MAX];
        static uint32_t taken[64][2];
        int line = 0, nu, ng;
        nu = subid_ranges(argv[2], USERNS_OWNER, uids, SUBID_RANGES_MAX, &line);
        if (nu < 0) {
            put_number("bad uid line", line);
            return 0;
        }
        ng = subid_ranges(argv[3], USERNS_OWNER, gids, SUBID_RANGES_MAX, &line);
        if (ng < 0) {
            put_number("bad gid line", line);
            return 0;
        }
        for (int i = 0; i < nu; i++) {
            char s[11], c[11];
            format_u32(s, uids[i].start);
            format_u32(c, uids[i].count);
            put("uid range ");
            put(s);
            put_line(" ", c);
        }
        int ntaken = 0;
        for (int i = 4; i < argc && ntaken < 64; i++, ntaken++) {
            char *colon = argv[i];
            while (*colon && *colon != ':') colon++;
            if (!*colon)
                die("unit: subid ... <uid>:<gid>");
            *colon = '\0';
            if (!parse_u32_text(argv[i], &taken[ntaken][0]) || !parse_u32_text(colon + 1, &taken[ntaken][1]))
                die("unit: subid ... <uid>:<gid>");
        }
        uint32_t u = 0, g = 0;
        const char *why = userns_choose(uids, nu, gids, ng, (const uint32_t (*)[2])taken, ntaken, &u, &g);
        if (why) {
            put_line("none: ", why);
        } else {
            char su[11], sg[11];
            format_u32(su, u);
            format_u32(sg, g);
            put("chose ");
            put(su);
            put_line(" ", sg);
        }
        return 0;
    }
    if (argc == 3 && streq(argv[1], "userns-start")) {
        uint32_t start = 0;
        if (userns_start_ok(argv[2], &start)) {
            char s[11];
            format_u32(s, start);
            put_line("ok ", s);
        } else {
            put("refused\n");
        }
        return 0;
    }
    if (argc == 6 && streq(argv[1], "volume-maps")) {
        uint32_t ids[4];
        for (int i = 0; i < 4; i++)
            if (!parse_u32_text(argv[2 + i], &ids[i]))
                die2("unit: not a number: ", argv[2 + i]);
        id_map uids, gids;
        if (!volume_maps(ids[0], ids[1], ids[2], ids[3], &uids, &gids)) {
            put("plain\n");
            return 0;
        }
        char line[ID_MAP_LINE_MAX];
        id_map_line(line, &uids);
        put("uid_map ");
        put(line);
        id_map_line(line, &gids);
        put("gid_map ");
        put(line);
        return 0;
    }
    if (argc == 5 && streq(argv[1], "userns-volume")) {
        uint32_t uid_start, gid_start;
        static volume_spec spec;
        if (!parse_u32_text(argv[2], &uid_start) || !parse_u32_text(argv[3], &gid_start))
            die("unit: a first uid and gid are numbers");
        if (parse_volume_spec(argv[4], &spec) != NULL)
            die2("unit: not a volume: ", argv[4]);
        struct volume_mount vol;
        const char *wrong = open_userns_volume(&spec, uid_start, gid_start, &vol);
        if (wrong) {
            put_line("refused: ", wrong);
            return 0;
        }
        int rc = attach_tree(vol.tree, spec.dst);
        if (rc < 0) {
            char digits[16];
            fmt_int(digits, -rc);
            put_line("not attached, errno ", digits);
            return 1;
        }
        put("attached\n");
        return 0;
    }
    if (argc == 4 && streq(argv[1], "owner")) {
        port_owner owner = port_owner_of_alias(argv[3], argv[2]);
        put(owner == PORT_OURS ? "ours\n" : owner == PORT_FOREIGN ? "foreign\n" : "other\n");
        return 0;
    }
    if (argc == 5 && streq(argv[1], "port") && streq(argv[2], "owner")) {
        port_owner owner = host_port_owner(argv[3], argv[4]);
        put(owner == PORT_OURS ? "ours\n" : owner == PORT_FOREIGN ? "foreign\n" :
            owner == PORT_ABSENT ? "absent\n" : "unknown\n");
        return 0;
    }
    if (argc == 5 && streq(argv[1], "port") && streq(argv[2], "remove")) {
        put_result(remove_own_port(argv[3], argv[4]));
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "rtnl"))
        return unit_rtnl(argc - 2, argv + 2);
    if (argc == 3 && streq(argv[1], "chain")) {
        put(link_chain_ok(argv[2]) ? "ok\n" : "refused\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "names")) {
        char port[IFNAME_TEXT_MAX], chain[IFNAME_TEXT_MAX];
        host_port_name(argv[2], port);
        link_chain_name(argv[2], chain);
        put_line("", port);
        put_line("", chain);
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "firewall")) {
        static char text[FIREWALL_TEXT_MAX];
        static container_config config;
        bool fits = false;
        cfg_global_init();
        if (streq(argv[2], "links") || streq(argv[2], "links-into-64")) {
            container_config_init(&config);
            for (int i = 4; i < argc && config.nlinks < MAX_LINKS; i++)
                if (!str_copy(config.links[config.nlinks++], argv[i], sizeof(config.links[0])))
                    die("unit: a link that is too long");
            fits = firewall_links_text(argv[3], &config, text, streq(argv[2], "links") ? sizeof(text) : 64);
        } else if (streq(argv[2], "setup") && argc == 7) {
            container_network net;
            const char *setting;
            if (container_network_parse(argv[3], argv[4], &net, &setting) != NULL ||
                !str_copy(cfg_global.bridge, argv[5], sizeof(cfg_global.bridge)))
                die("unit: firewall setup <subnet> <gw> <bridge> <true|false>");
            cfg_global.ip_masq = streq(argv[6], "true");
            fits = firewall_setup_text(&net, text, sizeof(text));
        } else if (streq(argv[2], "nft-setup") && (argc == 7 || argc == 8)) {
            container_network net;
            const char *setting;
            if (container_network_parse(argv[3], argv[4], &net, &setting) != NULL ||
                !str_copy(cfg_global.bridge, argv[5], sizeof(cfg_global.bridge)))
                die("unit: firewall nft-setup <subnet> <gw> <bridge> <true|false> [<fwmark>]");
            cfg_global.ip_masq = streq(argv[6], "true");
            if (argc == 8) {
                if (!parse_fwmark(argv[7], &cfg_global.accept_fwmark, &cfg_global.accept_fwmask))
                    die("unit: a fwmark that parse_fwmark refuses");
                cfg_global.accept_fwmark_set = true;
            }
            fits = nft_setup_text(&net, text, sizeof(text));
        } else if (streq(argv[2], "nft-record")) {
            container_config_init(&config);
            for (int i = 4; i < argc && config.nlinks < MAX_LINKS; i++)
                if (!str_copy(config.links[config.nlinks++], argv[i], sizeof(config.links[0])))
                    die("unit: a link that is too long");
            fits = nft_links_record(argv[3], &config, text, sizeof(text));
        } else {
            die("unit: firewall links <name> [<link>...] | firewall setup <subnet> <gw> <bridge> <true|false>");
        }
        put(fits ? text : "too long\n");
        return 0;
    }
    if (argc == 4 && streq(argv[1], "nftlinks")) {
        /* the record, and right after its end a line lightbox would take:
         * a parser that reads past the end takes it */
        static char record[FIREWALL_TEXT_MAX], text[FIREWALL_TEXT_MAX];
        static const char beyond[] = "vb-111111111111 vb-222222222222\n";
        size_t len = lc_string_length(argv[3]);
        if (len + 1 + sizeof(beyond) > sizeof(record))
            die("unit: nftlinks add|remove <record>");
        lc_bytes_copy(record, argv[3], len + 1);
        lc_bytes_copy(record + len + 1, beyond, sizeof(beyond));
        put(nft_links_text(record, streq(argv[2], "remove"), text, sizeof(text)) ? text : "refused\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "fwmark")) {
        uint32_t mark, mask;
        if (!parse_fwmark(argv[2], &mark, &mask)) {
            put("refused\n");
            return 0;
        }
        char text[24], m[24], k[24];
        fwmark_text(text, mark, mask);
        fwmark_text(m, mark, 0xffffffffu);
        fwmark_text(k, mask, 0xffffffffu);
        put_line("mark ", m);
        put_line("mask ", k);
        put_line("as ", text);
        return 0;
    }
    if (argc == 6 && streq(argv[1], "config-source")) {
        static const char *const names[] = { "given", "env", "etc", "home", "none" };
        config_source source = config_source_of(streq(argv[2], "-") ? NULL : argv[2],
                                                streq(argv[3], "-") ? NULL : argv[3],
                                                streq(argv[4], "1"), streq(argv[5], "1"));
        put_line("", names[source]);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "kernel")) {
        int major, minor;
        bool ok = kernel_release_at_least(argv[2], KERNEL_FLOOR_MAJOR, KERNEL_FLOOR_MINOR, &major, &minor);
        if (major < 0) {
            put("unreadable\n");
            return 0;
        }
        char a[16], b[16];
        fmt_int(a, major);
        fmt_int(b, minor);
        put(ok ? "yes " : "no ");
        put(a);
        put(".");
        put_line("", b);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "portname")) {
        put(host_port_ok(argv[2]) ? "ok\n" : "refused\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "dropping")) {
        static char listing[65536], chains[1024];
        if (!str_copy(listing, argv[2], sizeof(listing)))
            die("unit: dropping <listing>");
        put_number("chains", (int)forward_drop_chains(listing, chains, sizeof(chains)));
        put_line("", chains);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "status")) {
        put_result(exit_code_from_status(number_arg(argv[2])));
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
        apply_sandbox(false);
        exec_program(argv[2], (const char *const *)(argv + 2), TOOL_ENV);
        die2("unit: cannot execute ", argv[2]);
    }
    if (argc == 2 && streq(argv[1], "maskproc")) {
        mask_proc_paths();
        put_result(0);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "noipv6")) {
        put_result(netns_disable_ipv6(number_arg(argv[2])));
        return 0;
    }
    if (argc == 3 && streq(argv[1], "seconds")) {
        int seconds = -1;
        bool ok = parse_seconds(argv[2], &seconds);
        put_result(ok ? seconds : -1);
        return 0;
    }
    if (argc == 5 && streq(argv[1], "number")) {
        int64_t min, max, number;
        if (!parse_number(argv[3], INT64_MIN, INT64_MAX, &min) ||
            !parse_number(argv[4], INT64_MIN, INT64_MAX, &max))
            die("unit: number <text> <min> <max>");
        if (!parse_number(argv[2], min, max, &number)) {
            put("refused\n");
            return 0;
        }
        /* in two halves: the harness prints ints */
        if (number < 0) put("-");
        uint64_t magnitude = number < 0 ? 0 - (uint64_t)number : (uint64_t)number;
        char digits[24];
        int at = (int)sizeof(digits);
        digits[--at] = '\0';
        do { digits[--at] = (char)('0' + magnitude % 10); magnitude /= 10; } while (magnitude);
        put_line("", digits + at);
        return 0;
    }
    if (argc == 4 && streq(argv[1], "limit")) {
        int number = 0;
        if (streq(argv[2], "mem"))
            put(mem_limit_ok(argv[3]) ? "ok\n" : "refused\n");
        else if (streq(argv[2], "swap"))
            put(swap_limit_ok(argv[3]) ? "ok\n" : "refused\n");
        else if (streq(argv[2], "io"))
            put(io_limit_ok(argv[3]) ? "ok\n" : "refused\n");
        else if (streq(argv[2], "pids"))
            put(pids_limit_ok(argv[3]) ? "ok\n" : "refused\n");
        else if (streq(argv[2], "cpu") && parse_cpu_limit(argv[3], &number))
            put_number("quota", number);
        else if (streq(argv[2], "oom") && parse_oom_score(argv[3], &number))
            put_number("score", number);
        else
            put("refused\n");
        return 0;
    }
    if (argc == 7 && streq(argv[1], "controllers")) {
        static container_config config;
        container_config_init(&config);
        if (!str_copy(config.mem, argv[3], sizeof(config.mem)) ||
            !str_copy(config.pids, argv[4], sizeof(config.pids)) ||
            !str_copy(config.swap, streq(argv[5], "-") ? "" : argv[5], sizeof(config.swap)) ||
            !str_copy(config.io, streq(argv[6], "-") ? "" : argv[6], sizeof(config.io)) ||
            !str_copy(config.cpu, "1", sizeof(config.cpu)))
            die("unit: controllers <listed> <mem> <pids> <swap|-> <io|->");
        bool have[CTL_COUNT];
        const char *lacking = controllers_check(argv[2], &config, have);
        if (lacking) {
            put_line("refused: ", lacking);
            return 0;
        }
        put("have");
        for (int i = 0; i < CTL_COUNT; i++) {
            if (have[i]) {
                put(" ");
                put(CONTROLLER_NAMES[i]);
            }
        }
        put("\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "address")) {
        uint32_t addr;
        char text[IPV4_TEXT_MAX];
        if (!parse_ipv4(argv[2], &addr)) {
            put("refused\n");
            return 0;
        }
        format_ipv4(text, addr);
        put(text);
        put("\n");
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "network")) {
        container_network net;
        const char *setting;
        const char *wrong = container_network_parse(argv[2], argv[3], &net, &setting);
        if (wrong) {
            put(setting);
            put(" ");
            put(wrong);
            put("\n");
            return 0;
        }
        char text[CIDR_TEXT_MAX];
        subnet_text(text, &net);
        put("subnet ");
        put(text);
        format_ipv4(text, net.broadcast);
        put(" broadcast ");
        put(text);
        format_ipv4(text, net.gateway);
        put(" gateway ");
        put(text);
        put("\n");
        for (int i = 4; i < argc; i++) {
            uint32_t addr;
            put(argv[i]);
            put(": ");
            const char *why = parse_ipv4(argv[i], &addr) ? address_unusable(&net, addr) : "not an address";
            if (!why)
                address_with_prefix(text, addr, &net);
            put(why ? why : text);
            put("\n");
        }
        return 0;
    }
    if (argc >= 5 && streq(argv[1], "text")) {
        static char buf[4096];
        int size = number_arg(argv[3]);
        if (size < 1 || size > (int)sizeof(buf))
            die("unit: text size must be 1 to 4096");
        lc_bytes_fill(buf, 'x', sizeof(buf));       /* so that what was not written shows */
        buf[size - 1] = '\0';
        if (argc == 5 && streq(argv[2], "copy")) {
            put_text(str_copy(buf, argv[4], (size_t)size), buf);
        } else if (argc == 6 && streq(argv[2], "append")) {
            bool cut = false;
            size_t pos = str_append(buf, 0, argv[4], (size_t)size, &cut);
            if (cut)
                die("unit: text append: the first text has to fit");
            str_append(buf, pos, argv[5], (size_t)size, &cut);
            put_text(!cut, buf);
        } else if (argc == 6 && streq(argv[2], "join")) {
            put_text(path_join(buf, (size_t)size, argv[4], argv[5]), buf);
        } else {
            die("unit: text copy|append|join");
        }
        return 0;
    }
    if ((argc == 4 || argc == 5) && streq(argv[1], "config")) {
        static container_config config;
        cfg_global_init();
        if (argc == 5) {
            cfg_global.default_mem[0] = cfg_global.default_pids[0] = cfg_global.default_cpu[0] = '\0';
            cfg_global.default_oom_ok = false;
        }
        str_copy_or_die(cfg_global.container_dir, argv[2], MAX_PATH, "the directory");
        const char *wrong = container_config_load(argv[3], &config);
        if (wrong)
            put_line("refused: ", wrong);
        else
            put_config(&config);
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "config-write")) {
        static container_config config;
        cfg_global_init();
        str_copy_or_die(cfg_global.container_dir, argv[2], MAX_PATH, "the directory");
        container_config_init(&config);
        if (container_config_fill_defaults(&config) != NULL)
            die("unit: no defaults");
        for (int i = 4; i < argc; i++)
            set_unchecked(&config, argv[i]);
        const char *wrong = container_config_save(argv[3], &config);
        put_line(wrong ? "refused: " : "written", wrong ? wrong : "");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "remove")) {
        put_result(remove_file_durably(argv[2]));
        return 0;
    }
    if (argc == 5 && streq(argv[1], "record")) {
        char text[32];
        bool cut = false;
        cfg_global_init();
        str_copy_or_die(cfg_global.run_dir, argv[2], MAX_PATH, "the directory");
        size_t pos = str_append(text, 0, argv[4], sizeof(text), &cut);
        str_append(text, pos, "\n", sizeof(text), &cut);
        if (cut)
            die("unit: record <run_dir> <name> <state>");
        put_result(record_container_state(argv[3], text));
        return 0;
    }
    if (argc == 5 && streq(argv[1], "reconcile")) {
        char state[32];
        cfg_global_init();
        str_copy_or_die(cfg_global.container_dir, argv[2], MAX_PATH, "the directory");
        str_copy_or_die(cfg_global.run_dir, argv[3], MAX_PATH, "the directory");
        /* a cgroup tree that is not there: the container has nothing in it */
        path_join_or_die(cfg_global.cgroup_base, MAX_PATH, argv[3], "no-cgroups");
        put(reconcile(argv[4]) ? "cleared\n" : "nothing\n");
        get_container_state(argv[4], state, sizeof(state));
        put_line("state ", state);
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
        lc_sysret pidfd = lb_sys_pidfd_open(number_arg(argv[2]), 0);
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
        static volume_spec specs[MAX_VOLS];
        const char *root = argv[2];
        int count = 0, i = 3;

        require_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        for (; i < argc && !streq(argv[i], "--"); i++) {
            if (count == MAX_VOLS)
                die("unit: too many volumes");
            if (parse_volume_spec(argv[i], &specs[count]) != NULL)
                die2("unit: not a volume: ", argv[i]);
            open_volume(&specs[count], &volumes[count]);
            count++;
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
    if (argc >= 5 && streq(argv[1], "relay") && streq(argv[3], "--")) {
        struct lb_termios modes;
        bool restore = lc_kernel_device_control(STDIN, LB_TCGETS, &modes) >= 0;
        int32_t signal_fd = hold_relay_signals();
        if (signal_fd < 0)
            die("unit: cannot hold signals back");

        lc_sysret worker = lc_kernel_fork();
        if (worker < 0)
            die("unit: fork failed");
        if (worker == 0) {
            lc_kernel_close_file(signal_fd);
            static struct exec_streams streams;
            prepare_streams(&streams, argv[2], (int)lc_kernel_getuid(), -1);
            int32_t worker_signals = hold_relay_signals();
            lc_sysret command = lc_kernel_fork();
            if (command < 0 || worker_signals < 0)
                die("unit: cannot start the command");
            if (command == 0) {
                take_streams(&streams);
                exec_program(argv[4], (const char *const *)(uintptr_t)(argv + 4), (const char *const *)(uintptr_t)envp);
                die2("unit: cannot execute ", argv[4]);
            }
            lc_kernel_exit(exit_code_from_status(serve_command(&streams, (int32_t)command, worker_signals)));
        }

        return finish_exec((int32_t)worker, signal_fd, restore ? &modes : NULL);
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
        "       unit relay <ptmx> -- <command...>\n"
        "       unit identity|command <passwd> <group> <exec's options...>");
}
