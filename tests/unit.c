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
 *   unit firewall egress <name> <ip> [<dns>...]
 *                                             firewall_egress_text for a container of --net outside
 *   unit firewall nft-egress <ip> [<dns>...]  nft_egress_record for it
 *   unit firewall both <name> <ip> <dns> <link>
 *                                             what a start gives iptables-restore for a container
 *                                             of --net outside with that name server and link
 *   unit nftegress add|remove <record>        nft_egress_text for that record, or "refused"
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
 *   unit tool-sandbox <program> [args...]     sandbox_host_tool, then the program in its place
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
 *   unit sha256 <file> [<piece>]              the SHA-256 of a file, given to sha256_update in
 *                                             pieces of at most that many bytes, 65536 without
 *                                             one: its 64 hex digits
 *   unit sha256-name <text>                   sha256_hex_ok: ok or refused
 *   unit tar <dir> <archive> [overlay] [<uid_start> <gid_start>]
 *                                             tar_write_tree of what is in <dir> into the file
 *                                             <archive>, as an overlay's upper directory with
 *                                             "overlay" and with ids less the two starts: lines
 *                                             "entries <n>", "sockets <n>", "attributes-left <n>",
 *                                             "bytes <n>" and "sha256 <digest>" of the archive;
 *                                             or "failed: <entry>: <why>" and status 1
 *   unit tar-one <dir> <name> <as> <archive> [plain] [root] [nosetid]
 *                                             tar_write_one of <name> in <dir>, as <as>, with
 *                                             lightbox cp's options: "entries <n>", or "failed: ..."
 *   unit untar-copy <archive> <dir> [nosetid] [owner <uid> <gid>]
 *                                             tar_read_tree into <dir> as lightbox cp unpacks:
 *                                             "entries <n>" and "devices <n>", or "failed: ..."
 *   unit untar <archive> <dir> [tree|upper|upper-user [<uid_start> <gid_start> [<piece>]]]
 *                                             tar_read_tree of the file <archive> into <dir>: as
 *                                             one tree, or as an overlay's upper directory, root's
 *                                             or one mounted with userxattr; with ids the two
 *                                             starts more; the archive given in pieces of at most
 *                                             <piece> bytes. Lines "entries <n>", "devices <n>",
 *                                             "attributes-left <n>", "bytes <n>" and
 *                                             "sha256 <digest>" of what was read; or
 *                                             "failed: <entry>: <why>" and status 1
 *   unit json-read <file> [<path>...]         json_check of the file's text, of which a byte more
 *                                             than is read is taken: "ok", or "refused:
 *                                             <line>:<column>: <why>" and status 1. Then json_at
 *                                             for each path, written as RFC 6901 has one: "none",
 *                                             "other case", or the value's kind and what it says:
 *                                             "string <text>", "number <as written>" with " whole"
 *                                             after one json_whole takes, "true", "false", "null",
 *                                             and "array <count>" or "object <count>" with a line
 *                                             "  <kind>" or "  <name>: <kind>" for each of what
 *                                             is in it, which json_first and json_next give
 *   unit json-text <file> <path> <size>       json_text of the value at a path into <size> bytes:
 *                                             "<length> <text>", or "none"
 *   unit json-is <file> <path> <text>         json_text_is of it: same or other
 *   unit image-base <lightbox_dir> <image> <count>
 *                                             image_open of the image in a directory, and image_base
 *                                             of its first <count> layers, with lightbox's files in
 *                                             <lightbox_dir>: "took <id>" or "found <id>", and
 *                                             "entries <n>", "devices <n>" of what was unpacked; what
 *                                             is no image, or cannot be unpacked, is said as import
 *                                             says it, with status 1
 *   unit overlay-options <lightbox_dir> <id> <upper> <work>
 *                                             overlay_options of a snapshot: the options, or
 *                                             "refused" and status 1
 *   unit overlay-whole <dir>                  overlay_upper_whole: "whole", "not whole: <path>"
 *                                             with status 1, or "cannot read" with status 2
 *   unit monitor <record>                     init_spawn_monitored with a child that waits to be
 *                                             killed, which it then is: whether it is the
 *                                             command's child, a zombie until the command is done,
 *                                             what the monitor wrote to record, whether it reaped
 *   unit monitor-ttl <record> <duration>      the same with that --ttl and no grace, and a child
 *                                             that never ends: what the monitor wrote, and when
 *   unit gpu <root>                           gpu_devices under root: "<host> -> <path>" a line
 *                                             each, or "more than <n>" with status 1
 *   unit nvidia <root>                        nvidia_libraries under root: "version <v>", then
 *                                             "file <host> <name>[ bin]" and "link <name> <target>"
 *                                             lines; "none", or "missing <name>" with status 1
 *   unit musl <rootfs>                        root_has_musl: "musl" or "not musl"
 *   unit gidmap <gid_start> [<group>...]      userns_gid_map_text: the gid map of a container of
 *                                             --userns with its devices' groups, or "refused"
 *   unit devgroups <file>                     gid_map_device_groups of a gid_map's text: the gids
 *                                             inside of the devices' groups, a line each
 *   unit cgroup2-root <store> <cgroup_root>   ensure_cgroup2_for_start with the store's lock in
 *                                             <store>: what it says, then "cgroup2"; or its error
 *   unit firewall-kernel <proc_net> <modules> true|false
 *                                             iptables_kernel_missing with ip_masq as given:
 *                                             "all there", "missing: <what>" with status 1, or
 *                                             "not known" with status 2; then "links: <what>"
 *                                             where a container with --link lacks something
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

/* a number of 64 bits on a line of its own: the harness prints ints */
static void put_int64(int64_t number) {
    if (number < 0) put("-");
    uint64_t magnitude = number < 0 ? 0 - (uint64_t)number : (uint64_t)number;
    char digits[24];
    int at = (int)sizeof(digits);
    digits[--at] = '\0';
    do { digits[--at] = (char)('0' + magnitude % 10); magnitude /= 10; } while (magnitude);
    put_line("", digits + at);
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
    char mode[NET_MODE_TEXT_MAX];
    net_mode_text(mode, config->net, config->proxy_port);
    put_line("net ", mode);
    put(config->ndns ? "dns " : "dns -");
    for (int i = 0; i < config->ndns; i++) {
        if (i)
            put(",");
        put(config->dns[i]);
    }
    put("\n");
    put_line("io ", config->io[0] ? config->io : "-");
    put_line("swap ", config->swap[0] ? config->swap : "-");
    put_line("base ", config->base[0] ? config->base : "-");
    if (config->ttl[0]) {
        put("ttl ");
        put(config->ttl);
        put(" ");
        put_int64(config->ttl_ms);
    } else {
        put("ttl -\n");
    }
    put_line("id ", config->id[0] ? config->id : "-");
    put_line("profile ", config->profile == PROFILE_AGENT ? "agent" : "-");
    put_line("workdir ", config->workdir[0] ? config->workdir : "-");
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
    static const char *const fields[] = { "mem=", "pids=", "cpu=", "io=", "link=", "src=", "dst=", "swap=", "ttl=", "id=", "profile=", "workdir=" };
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
        /* the text as it is, and what it means when it is a duration */
        case 8: fits = str_copy(config->ttl, value, sizeof(config->ttl));
                if (!parse_duration_ms(value, &config->ttl_ms))
                    config->ttl_ms = 0;
                break;
        case 9: fits = str_copy(config->id, value, sizeof(config->id)); break;
        /* agent, the one profile there is */
        case 10: config->profile = PROFILE_AGENT; fits = streq(value, "agent"); break;
        case 11: fits = str_copy(config->workdir, value, sizeof(config->workdir)); break;
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
/* A child for the monitor to clone: it waits to be killed. */
static int unit_sleeper(void *arg) {
    (void)arg;
    for (;;) {
        lc_timespec long_time = { .seconds = 3600, .nanoseconds = 0 };
        lc_kernel_sleep(&long_time);
    }
    return 0;
}

/* What the monitor saw, into the file that the name is (ROADMAP M.1): the
 * exit code of its child, and the descriptors it holds. */
static void unit_monitor_ended(const char *record, int32_t pid, const char *started, int32_t status, bool expired,
                               int32_t log_fd) {
    (void)log_fd;
    (void)pid;
    (void)started;
    char text[256], digits[16];
    bool cut = false;
    fmt_int(digits, exit_code_from_status(status));
    size_t pos = str_append(text, 0, "status ", sizeof(text), &cut);
    pos = str_append(text, pos, digits, sizeof(text), &cut);
    if (expired)
        pos = str_append(text, pos, " expired", sizeof(text), &cut);
    pos = str_append(text, pos, " fds", sizeof(text), &cut);
    lc_sysret dir = lc_kernel_open_file("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    char buf[2048];
    lc_sysret n = dir < 0 ? -1 : lc_kernel_read_directory((int32_t)dir, buf, sizeof(buf));
    for (lc_sysret at = 0; n > 0 && at < n; ) {
        uint16_t reclen;
        lc_bytes_copy(&reclen, buf + at + 16, sizeof(reclen));
        if (reclen == 0)
            break;
        const char *entry = buf + at + 19;
        at += reclen;
        int fd;
        if (entry[0] == '.' || !parse_int_in(entry, 0, 1 << 20, &fd) || fd == (int)dir)
            continue;
        pos = str_append(text, pos, " ", sizeof(text), &cut);
        pos = str_append(text, pos, entry, sizeof(text), &cut);
    }
    str_append(text, pos, "\n", sizeof(text), &cut);
    (void)write_file(record, text);
}

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

/* "unit tar": the archive into a file, hashed and counted on its way */
struct unit_tar_sink {
    int32_t    fd;
    sha256_ctx hash;
    uint64_t   bytes;
};

static int unit_tar_write(void *to, const void *data, size_t len) {
    struct unit_tar_sink *sink = to;
    sha256_update(&sink->hash, data, len);
    sink->bytes += len;
    return lc_kernel_write_all(sink->fd, data, len) < 0 ? -1 : 0;
}

/* "unit untar": the archive from a file, in pieces of no more than a length.
 * "unit untar-held": the same, and the first read, which is made in the
 * process that unpacks once it is held to what unpacking needs (ROADMAP
 * I.12), looks at that: with "descriptors", how many it has open of the
 * first 1024, which statx, one of its calls, tells, and the archive cannot
 * be read unless they are three; with "call", a call that the reader never
 * makes, getpid, which its filter ends it at. */
struct unit_tar_source {
    int32_t  fd;
    uint32_t piece;
    int      probe;     /* 0, or 1 descriptors, 2 a call */
    bool     probed;
};

/* set by "untar-held" for "untar" */
static struct unit_tar_source *unit_source;

static int64_t unit_tar_read(void *from, void *data, size_t len) {
    struct unit_tar_source *source = from;
    if (source->probe && !source->probed) {
        source->probed = true;
        if (source->probe == 2)
            (void)lc_kernel_get_process_id();
        int open = 0;
        for (int32_t fd = 0; fd < 1024; fd++) {
            struct lb_statx st;
            if (lb_sys_statx(fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE, &st) == 0)
                open++;
        }
        if (open != 3)
            return -1;
    }
    return lc_kernel_read_retry(source->fd, data, source->piece && source->piece < len ? source->piece : len);
}

/* "unit json-read" and the two beside it: a file's text, checked, or the refusal said and status 1 */
static char unit_json_bytes[JSON_TEXT_MAX + 1];
static char unit_json_string[65536];

static json_value unit_json_root(const char *path) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY, 0);
    if (fd < 0)
        die2("unit: cannot open ", path);
    lc_sysret len = lc_kernel_read_all((int32_t)fd, unit_json_bytes, sizeof(unit_json_bytes));
    if (len < 0)
        die2("unit: cannot read ", path);
    json_value root;
    json_refusal why;
    if (json_check(unit_json_bytes, (size_t)len, &root, &why) != 0) {
        char line[16], column[16];
        fmt_int(line, (int)why.line);
        fmt_int(column, (int)why.column);
        put("refused: ");
        put(line);
        put(":");
        put(column);
        put(": ");
        put(why.why ? why.why : "(no reason given)");
        put("\n");
        lc_kernel_exit(1);
    }
    return root;
}

static const char *unit_json_kind(json_value v) {
    switch (json_kind_of(v)) {
    case JSON_NULL:   return "null";
    case JSON_FALSE:  return "false";
    case JSON_TRUE:   return "true";
    case JSON_NUMBER: return "number";
    case JSON_STRING: return "string";
    case JSON_ARRAY:  return "array";
    case JSON_OBJECT: return "object";
    }
    return "(no kind)";
}

static void unit_json_put(json_value v) {
    json_kind kind = json_kind_of(v);
    put(unit_json_kind(v));
    if (kind == JSON_STRING) {
        put(" ");
        put(json_text(v, unit_json_string, sizeof(unit_json_string)) < 0 ? "(cannot be given)" : unit_json_string);
    } else if (kind == JSON_NUMBER) {
        uint64_t whole;
        put(" ");
        (void)lc_kernel_write_all(STDOUT, v.text, v.len);
        if (json_whole(v, &whole)) {
            /* and the number it took is the one that is written */
            char digits[24];
            int at = (int)sizeof(digits);
            digits[--at] = '\0';
            do { digits[--at] = (char)('0' + whole % 10); whole /= 10; } while (whole);
            size_t len = sizeof(digits) - 1 - (size_t)at;
            put(len != v.len || lc_bytes_compare(digits + at, v.text, len) != 0 ? " whole, but another number"
                                                                                : " whole");
        }
    } else if (kind == JSON_ARRAY || kind == JSON_OBJECT) {
        put(" ");
        put_int64((int64_t)json_count(v));
        json_item item;
        for (bool more = json_first(v, &item); more; more = json_next(&item)) {
            put("  ");
            if (item.named) {
                put(json_text(item.name, unit_json_string, sizeof(unit_json_string)) < 0 ? "(cannot be given)"
                                                                                         : unit_json_string);
                put(": ");
            }
            put_line("", unit_json_kind(item.value));
        }
        return;
    }
    put("\n");
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
        } else if (streq(argv[2], "egress") && argc >= 5) {
            container_config_init(&config);
            config.net = NET_OUTSIDE;
            for (int i = 5; i < argc && config.ndns < MAX_DNS; i++)
                if (!str_copy(config.dns[config.ndns++], argv[i], sizeof(config.dns[0])))
                    die("unit: a name server that is too long");
            fits = firewall_egress_text(argv[3], argv[4], "", &config, text, sizeof(text));
        } else if (streq(argv[2], "egress-proxy") && argc == 7) {
            int64_t port;
            container_config_init(&config);
            config.net = NET_PROXY;
            if (!parse_number(argv[6], 0, 99999, &port))
                die("unit: firewall egress-proxy <name> <ip> <gw> <port>");
            config.proxy_port = (int)port;
            fits = firewall_egress_text(argv[3], argv[4], argv[5], &config, text, sizeof(text));
        } else if (streq(argv[2], "both") && argc == 7) {
            static char links_text[FIREWALL_TEXT_MAX], egress_text[FIREWALL_TEXT_MAX];
            container_config_init(&config);
            config.net = NET_OUTSIDE;
            config.ndns = 1;
            config.nlinks = 1;
            if (!str_copy(config.dns[0], argv[5], sizeof(config.dns[0])) ||
                !str_copy(config.links[0], argv[6], sizeof(config.links[0])))
                die("unit: firewall both <name> <ip> <dns> <link>");
            fits = firewall_links_text(argv[3], &config, links_text, sizeof(links_text)) &&
                   firewall_egress_text(argv[3], argv[4], "", &config, egress_text, sizeof(egress_text)) &&
                   firewall_rules_text(false, links_text, egress_text, text, sizeof(text));
        } else if (streq(argv[2], "nft-egress")) {
            container_config_init(&config);
            config.net = NET_OUTSIDE;
            for (int i = 4; i < argc && config.ndns < MAX_DNS; i++)
                if (!str_copy(config.dns[config.ndns++], argv[i], sizeof(config.dns[0])))
                    die("unit: a name server that is too long");
            fits = nft_egress_record("unit", argv[3], "", &config, text, sizeof(text));
        } else if (streq(argv[2], "nft-egress-proxy") && argc == 7) {
            int64_t port;
            container_config_init(&config);
            config.net = NET_PROXY;
            if (!parse_number(argv[6], 0, 99999, &port))
                die("unit: firewall nft-egress-proxy <name> <ip> <gw> <port>");
            config.proxy_port = (int)port;
            fits = nft_egress_record(argv[3], argv[4], argv[5], &config, text, sizeof(text));
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
    if (argc == 4 && streq(argv[1], "nftegress")) {
        static char text[FIREWALL_TEXT_MAX];
        put(nft_egress_text(argv[3], streq(argv[2], "remove"), text, sizeof(text)) ? text : "refused\n");
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
    if (argc >= 3 && streq(argv[1], "tool-sandbox")) {
        sandbox_host_tool(argv[2]);
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
        put_int64(number);
        return 0;
    }
    /* keeper <file>: exec --timeout's worker ending its cgroup without
     * cgroup.kill, with a file of PIDs standing in for cgroup.procs */
    if (argc == 3 && streq(argv[1], "keeper")) {
        lc_sysret fd = lc_kernel_open_file(argv[2], O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0)
            die2("unit: cannot open ", argv[2]);
        struct exec_keeper k = { .kill_fd = -1, .procs_fd = (int32_t)fd, .caller_fd = -1, .deadline = 0 };
        keeper_end(&k);
    }
    /* runner <text>: is the run that a .runner of this text names there? */
    if (argc == 3 && streq(argv[1], "runner")) {
        put(runner_alive(argv[2]) ? "alive\n" : "gone\n");
        return 0;
    }
    /* json <hex>: the bytes the hex digits are, as a JSON string of the
     * audit log; "-" for none */
    if (argc == 3 && streq(argv[1], "json")) {
        static char bytes[4096], quoted[JSON_QUOTED_MAX(sizeof(bytes)) + 2];
        size_t n = 0;
        for (const char *h = streq(argv[2], "-") ? "" : argv[2]; h[0] && h[1] && n < sizeof(bytes); h += 2) {
            int hi = h[0] <= '9' ? h[0] - '0' : h[0] - 'a' + 10;
            int lo = h[1] <= '9' ? h[1] - '0' : h[1] - 'a' + 10;
            bytes[n++] = (char)(hi * 16 + lo);
        }
        size_t counted = json_quote(NULL, bytes, n);
        size_t len = json_quote(quoted, bytes, n);
        if (counted != len || len > JSON_QUOTED_MAX(n))
            die("unit: json_quote counted a length that it did not write, or above its bound");
        quoted[len++] = '\n';
        (void)lc_kernel_write_all(STDOUT, quoted, len);
        return 0;
    }
    /* utc <seconds> <nanoseconds>: a time as the audit log writes it */
    if (argc == 4 && streq(argv[1], "utc")) {
        int64_t parts[2];
        for (int i = 0; i < 2; i++) {
            const char *t = argv[2 + i];
            bool minus = t[0] == '-';
            int64_t v = 0;
            for (t += minus; *t; t++)
                v = v * 10 + (*t - '0');
            parts[i] = minus ? -v : v;
        }
        char out[UTC_TEXT_LEN + 1];
        format_utc(out, parts[0], parts[1]);
        put_line("", out);
        return 0;
    }
    /* auditline start <box> <box_id|-> <exec_id> <via> <uid> <loginuid> <user|-> <workdir|->
     *           <timeout|-> <number of env> <env>... [argv...]
     * auditline end <box> <box_id|-> <exec_id> <status> <ms> <yes|no>:
     * the line, with "T" for the time */
    if (argc >= 3 && streq(argv[1], "auditline")) {
        static char line[1 << 20];
        size_t len = 0, counted = 0;
#define DASH(i) (streq(argv[i], "-") ? NULL : argv[i])
        if (streq(argv[2], "start") && argc >= 13) {
            int nenv = 0;
            for (const char *t = argv[12]; *t; t++)
                nenv = nenv * 10 + (*t - '0');
            if (13 + nenv > argc)
                die("unit: fewer env than counted");
            struct audit_start a = {
                .box = argv[3], .box_id = DASH(4), .exec_id = argv[5], .via = argv[6],
                .uid = 0, .loginuid = -1, .user = DASH(9), .workdir = DASH(10), .timeout = DASH(11),
                .env = (const char *const *)(argv + 13), .nenv = nenv,
                .argv = (const char *const *)(argv + 13 + nenv),
            };
            for (int k = 0; k < 2; k++) {
                const char *t = argv[7 + k];
                bool minus = t[0] == '-';
                int64_t v = 0;
                for (t += minus; *t; t++)
                    v = v * 10 + (*t - '0');
                if (k == 0) a.uid = minus ? -v : v; else a.loginuid = minus ? -v : v;
            }
            counted = audit_start_line(NULL, &a, "T");
            len = audit_start_line(line, &a, "T");
        } else if (streq(argv[2], "end") && argc == 9) {
            int status = 0;
            int64_t ms = 0;
            for (const char *t = argv[6]; *t; t++)
                status = status * 10 + (*t - '0');
            for (const char *t = argv[7]; *t; t++)
                ms = ms * 10 + (*t - '0');
            struct audit_end e = { .box = argv[3], .box_id = DASH(4), .exec_id = argv[5],
                                   .status = status, .duration_ms = ms, .timed_out = streq(argv[8], "yes") };
            counted = audit_end_line(NULL, &e, "T");
            len = audit_end_line(line, &e, "T");
        } else {
            die("unit: auditline start ... or auditline end ...");
        }
#undef DASH
        if (counted != len)
            die("unit: an audit line is not as long as counted");
        (void)lc_kernel_write_all(STDOUT, line, len);
        return 0;
    }
    /* auditfilter <box> <piece> <file>: the lines of the file about the box,
     * read in pieces of that many bytes */
    if (argc == 5 && streq(argv[1], "auditfilter")) {
        int piece = 0;
        for (const char *t = argv[3]; *t; t++)
            piece = piece * 10 + (*t - '0');
        static char buf[4096], kept[4096 + NAME_MAX_LEN + 16];
        if (piece < 1 || piece > (int)sizeof(buf))
            die("unit: a piece of 1 to 4096 bytes");
        lc_sysret fd = lc_kernel_open_file(argv[4], O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0)
            die2("unit: cannot open ", argv[4]);
        struct audit_filter f;
        audit_filter_start(&f, argv[2]);
        for (;;) {
            lc_sysret n = lc_kernel_read_retry((int32_t)fd, buf, (size_t)piece);
            if (n <= 0)
                break;
            size_t len = audit_filter(&f, buf, (size_t)n, kept);
            (void)lc_kernel_write_all(STDOUT, kept, len);
        }
        return 0;
    }
    if (argc == 3 && streq(argv[1], "duration")) {
        int64_t ms;
        if (parse_duration_ms(argv[2], &ms))
            put_int64(ms);
        else
            put("refused\n");
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
    if (argc == 4 && streq(argv[1], "monitor-ttl")) {
        /* the same with a --ttl of argv[3] ms and no grace, and a child that
         * never ends by itself: the monitor ends it, a margin past the deadline */
        static container_config config;
        if (!parse_duration_ms(argv[3], &config.ttl_ms))
            return 2;
        struct init_link link = INIT_LINK_NONE;
        struct child_args ca = { .null_fd = -1, .log_fd = -1, .exit_fd = -1, .starter_signals = -1, .name = argv[2],
                                 .config = &config, .stop_grace = 0 };
        int64_t began = boottime_ms();
        const char *failed = init_spawn_monitored(&link, &ca, 0, unit_sleeper, unit_monitor_ended);
        if (failed)
            die2("unit: ", failed);
        link.pid = -1;
        init_link_close(&link);
        for (int i = 0; i < 200 && !path_exists(argv[2]); i++) {
            lc_timespec tenth = { .seconds = 0, .nanoseconds = 100000000 };
            lc_kernel_sleep(&tenth);
        }
        static char text[256];
        put(read_file(argv[2], text, sizeof(text)) > 0 ? text : "the monitor said nothing\n");
        char ms[24];
        fmt_int(ms, (int)(boottime_ms() - began));
        put_line("after ms ", ms);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "monitor")) {
        /* init_spawn_monitored with a child that waits to be killed */
        struct init_link link = INIT_LINK_NONE;
        struct child_args ca = { .null_fd = -1, .log_fd = -1, .exit_fd = -1, .starter_signals = -1, .name = argv[2] };
        const char *failed = init_spawn_monitored(&link, &ca, 0, unit_sleeper, unit_monitor_ended);
        if (failed)
            die2("unit: ", failed);
        int32_t status;
        put(lc_kernel_wait_for_child(link.pid, &status, WNOHANG) == -10 /* ECHILD */ ? "not the command's child\n"
                                                                                   : "the command's child\n");
        (void)lb_sys_pidfd_send_signal(link.pidfd, SIGKILL, NULL, 0);
        struct lb_pollfd one = { .fd = link.pidfd, .events = LB_POLLIN, .revents = 0 };
        lc_timespec limit = { .seconds = 5, .nanoseconds = 0 };
        put(lb_sys_ppoll(&one, 1, &limit) == 1 ? "ended, as its pidfd says\n" : "not ended\n");
        /* not reaped while the command holds the control pipe: the pid is still init's */
        char path[64], stat[256];
        if (proc_pid_path(path, sizeof(path), link.pid, "/stat") && read_file(path, stat, sizeof(stat)) > 0) {
            const char *paren = stat;
            for (const char *p = stat; *p; p++)
                if (*p == ')')
                    paren = p;
            put(paren[1] == ' ' && paren[2] == 'Z' ? "a zombie until the command is done\n" : "not a zombie\n");
        } else {
            put("gone before the command was done\n");
        }
        int32_t pid = link.pid;
        link.pid = -1;
        init_link_close(&link);
        for (int i = 0; i < 50 && !path_exists(argv[2]); i++) {
            lc_timespec tenth = { .seconds = 0, .nanoseconds = 100000000 };
            lc_kernel_sleep(&tenth);
        }
        static char text[256];
        put(read_file(argv[2], text, sizeof(text)) > 0 ? text : "the monitor said nothing\n");
        put(proc_pid_path(path, sizeof(path), pid, "/stat") && path_exists(path) ? "still there\n" : "reaped\n");
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
    /* relay <pty> [<duration>] -- <command>: with a duration, the deadline of
     * exec's --timeout, after which the worker is killed and "relay: timed
     * out" is the last line on standard output */
    bool limited = argc >= 6 && streq(argv[1], "relay") && streq(argv[4], "--");
    if ((argc >= 5 && streq(argv[1], "relay") && streq(argv[3], "--")) || limited) {
        int64_t limit_ms = 0;
        if (limited && !parse_duration_ms(argv[3], &limit_ms))
            die2("unit: not a duration: ", argv[3]);
        int64_t deadline = limited ? monotonic_ms() + limit_ms : 0;
        char **command_argv = argv + (limited ? 5 : 4);
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
                exec_program(command_argv[0], (const char *const *)(uintptr_t)command_argv,
                             (const char *const *)(uintptr_t)envp);
                die2("unit: cannot execute ", command_argv[0]);
            }
            lc_kernel_exit(exit_code_from_status(serve_command(&streams, (int32_t)command, worker_signals, NULL)));
        }

        bool timed_out;
        int code = finish_exec((int32_t)worker, signal_fd, restore ? &modes : NULL, NULL, deadline, &timed_out);
        if (timed_out)
            put_line("relay: ", "timed out");
        return code;
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
    if ((argc == 3 || argc == 4) && streq(argv[1], "sha256")) {
        static uint8_t piece[65536];
        int size = (int)sizeof(piece);
        if (argc == 4 && !parse_int_in(argv[3], 1, (int)sizeof(piece), &size))
            die("unit: a piece is 1 to 65536 bytes");
        lc_sysret fd = lc_kernel_open_file(argv[2], O_RDONLY, 0);
        if (fd < 0)
            die2("unit: cannot open ", argv[2]);
        sha256_ctx ctx;
        sha256_init(&ctx);
        for (;;) {
            lc_sysret n = lc_kernel_read_retry((int32_t)fd, piece, (size_t)size);
            if (n < 0)
                die2("unit: cannot read ", argv[2]);
            if (n == 0)
                break;
            sha256_update(&ctx, piece, (size_t)n);
        }
        uint8_t digest[SHA256_BYTES];
        char hex[SHA256_HEX + 1];
        sha256_final(&ctx, digest);
        sha256_hex(digest, hex);
        /* what sha256_hex writes is what sha256_hex_ok takes */
        if (!sha256_hex_ok(hex))
            die("unit: sha256_hex wrote what sha256_hex_ok refuses");
        put(hex);
        put("\n");
        return 0;
    }
    if (argc >= 4 && argc <= 7 && streq(argv[1], "tar")) {
        static tar_writer w;
        static struct unit_tar_sink to;
        int at = 4;
        if (at < argc && streq(argv[at], "overlay")) {
            w.overlay = true;
            at++;
        }
        if (at != argc && (at + 2 != argc || !parse_u32_text(argv[at], &w.uid_start) ||
                           !parse_u32_text(argv[at + 1], &w.gid_start)))
            die("usage: unit tar <dir> <archive> [overlay] [<uid_start> <gid_start>]");
        lc_sysret dirfd = lc_kernel_open_file(argv[2], O_RDONLY | O_DIRECTORY, 0);
        if (dirfd < 0)
            die2("unit: cannot open the directory ", argv[2]);
        lc_sysret out = lc_kernel_open_file(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out < 0)
            die2("unit: cannot write ", argv[3]);
        to.fd = (int32_t)out;
        sha256_init(&to.hash);
        w.sink = unit_tar_write;
        w.to = &to;
        if (tar_write_tree(&w, (int32_t)dirfd) != 0) {
            put("failed: ");
            put(w.failed_at);
            put(": ");
            put(w.failure ? w.failure : "(no reason given)");
            put("\n");
            return 1;
        }
        uint8_t digest[SHA256_BYTES];
        char hex[SHA256_HEX + 1];
        sha256_final(&to.hash, digest);
        sha256_hex(digest, hex);
        put("entries ");
        put_int64((int64_t)w.entries);
        put("sockets ");
        put_int64((int64_t)w.sockets);
        put("attributes-left ");
        put_int64((int64_t)w.attributes_left);
        put("bytes ");
        put_int64((int64_t)to.bytes);
        put_line("sha256 ", hex);
        return 0;
    }
    if (argc == 5 && streq(argv[1], "untar-held")) {
        static struct unit_tar_source from;
        static char *again[5];
        if (!streq(argv[2], "descriptors") && !streq(argv[2], "call"))
            die("usage: unit untar-held descriptors|call <archive> <dir>");
        from.probe = streq(argv[2], "descriptors") ? 1 : 2;
        unit_source = &from;
        again[0] = argv[0], again[1] = "untar", again[2] = argv[3], again[3] = argv[4], again[4] = NULL;
        argv = again;
        argc = 4;
    }
    if (argc >= 6 && streq(argv[1], "tar-one")) {
        static tar_writer w;
        static struct unit_tar_sink to;
        for (int i = 6; i < argc; i++) {
            if (streq(argv[i], "plain"))
                w.plain = true;
            else if (streq(argv[i], "root"))
                w.owners_root = true;
            else if (streq(argv[i], "nosetid"))
                w.no_setid = true;
            else
                die("usage: unit tar-one <dir> <name> <as> <archive> [plain] [root] [nosetid]");
        }
        lc_sysret dirfd = lc_kernel_open_file(argv[2], O_RDONLY | O_DIRECTORY, 0);
        lc_sysret out = lc_kernel_open_file(argv[5], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dirfd < 0 || out < 0)
            die("unit: cannot open the directory or the archive");
        to.fd = (int32_t)out;
        sha256_init(&to.hash);
        w.sink = unit_tar_write;
        w.to = &to;
        if (tar_write_one(&w, (int32_t)dirfd, argv[3], argv[4]) != 0) {
            put("failed: ");
            put(w.failed_at);
            put(": ");
            put(w.failure ? w.failure : "(no reason given)");
            put("\n");
            return 1;
        }
        put("entries ");
        put_int64((int64_t)w.entries);
        return 0;
    }
    if (argc >= 4 && streq(argv[1], "untar-copy")) {
        static tar_reader r;
        static struct unit_tar_source source;
        r.into = TAR_INTO_COPY;
        for (int i = 4; i < argc; i++) {
            if (streq(argv[i], "nosetid"))
                r.no_setid = true;
            else if (streq(argv[i], "owner") && i + 2 < argc && parse_u32_text(argv[i + 1], &r.owner_uid) &&
                     parse_u32_text(argv[i + 2], &r.owner_gid)) {
                r.owner_given = true;
                i += 2;
            } else
                die("usage: unit untar-copy <archive> <dir> [nosetid] [owner <uid> <gid>]");
        }
        lc_sysret in = lc_kernel_open_file(argv[2], O_RDONLY, 0);
        lc_sysret dirfd = lc_kernel_open_file(argv[3], O_RDONLY | O_DIRECTORY, 0);
        if (in < 0 || dirfd < 0)
            die("unit: cannot open the archive or the directory");
        source.fd = (int32_t)in;
        r.source = unit_tar_read;
        r.from = &source;
        r.source_fd = (int32_t)in;
        if (tar_read_tree(&r, (int32_t)dirfd) != 0) {
            put("failed: ");
            put(r.failed_at);
            put(": ");
            put(r.failure ? r.failure : "(no reason given)");
            put("\n");
            return 1;
        }
        put("entries ");
        put_int64((int64_t)r.entries);
        put("devices ");
        put_int64((int64_t)r.devices);
        return 0;
    }
    if (argc >= 4 && argc <= 8 && streq(argv[1], "untar")) {
        static tar_reader r;
        static struct unit_tar_source plain;
        struct unit_tar_source *source = unit_source ? unit_source : &plain;
        bool usage = argc == 6;
        if (argc >= 5) {
            if (streq(argv[4], "upper"))
                r.into = TAR_INTO_UPPER;
            else if (streq(argv[4], "upper-user"))
                r.into = TAR_INTO_UPPER_USERXATTR;
            else if (!streq(argv[4], "tree"))
                usage = true;
        }
        if (argc >= 7 && (!parse_u32_text(argv[5], &r.uid_start) || !parse_u32_text(argv[6], &r.gid_start)))
            usage = true;
        if (argc == 8 && (!parse_u32_text(argv[7], &source->piece) || !source->piece))
            usage = true;
        if (usage)
            die("usage: unit untar <archive> <dir> [tree|upper|upper-user [<uid_start> <gid_start> [<piece>]]]");
        lc_sysret in = lc_kernel_open_file(argv[2], O_RDONLY, 0);
        if (in < 0)
            die2("unit: cannot read ", argv[2]);
        lc_sysret dirfd = lc_kernel_open_file(argv[3], O_RDONLY | O_DIRECTORY, 0);
        if (dirfd < 0)
            die2("unit: cannot open the directory ", argv[3]);
        source->fd = (int32_t)in;
        r.source = unit_tar_read;
        r.from = source;
        r.source_fd = (int32_t)in;
        if (tar_read_tree(&r, (int32_t)dirfd) != 0) {
            put("failed: ");
            put(r.failed_at);
            put(": ");
            put(r.failure ? r.failure : "(no reason given)");
            put("\n");
            return 1;
        }
        char hex[SHA256_HEX + 1];
        sha256_hex(r.digest, hex);
        put("entries ");
        put_int64((int64_t)r.entries);
        put("devices ");
        put_int64((int64_t)r.devices);
        put("attributes-left ");
        put_int64((int64_t)r.attributes_left);
        put("bytes ");
        put_int64((int64_t)r.bytes);
        put_line("sha256 ", hex);
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "json-read")) {
        json_value root = unit_json_root(argv[2]);
        put("ok\n");
        for (int i = 3; i < argc; i++) {
            json_value v;
            int there = json_at(root, argv[i], &v);
            if (there == 1)
                unit_json_put(v);
            else
                put(there == 0 ? "none\n" : "other case\n");
        }
        return 0;
    }
    if (argc == 5 && streq(argv[1], "json-text")) {
        json_value root = unit_json_root(argv[2]), v;
        int size = number_arg(argv[4]);
        if (size < 0 || size > (int)sizeof(unit_json_string))
            die("unit: json-text takes 0 to 65536 bytes");
        if (json_at(root, argv[3], &v) != 1) {
            put("none\n");
            return 0;
        }
        /* a byte after what it may write into, which has to stay */
        if (size < (int)sizeof(unit_json_string))
            unit_json_string[size] = '#';
        int64_t len = json_text(v, unit_json_string, (size_t)size);
        if (size < (int)sizeof(unit_json_string) && unit_json_string[size] != '#')
            die("unit: json_text wrote past its size");
        if (len < 0) {
            if (size > 0 && unit_json_string[0] != '\0')
                die("unit: json_text left a text it refused");
            put("none\n");
            return 0;
        }
        char digits[16];
        fmt_int(digits, (int)len);
        put(digits);
        put(" ");
        put_line("", unit_json_string);
        return 0;
    }
    if (argc == 5 && streq(argv[1], "json-is")) {
        json_value root = unit_json_root(argv[2]), v;
        if (json_at(root, argv[3], &v) != 1) {
            put("none\n");
            return 0;
        }
        put(json_text_is(v, argv[4]) ? "same\n" : "other\n");
        return 0;
    }
    if (argc == 5 && streq(argv[1], "image-base")) {
        static image img;
        image_unpacked unpacked = { 0 };
        char id[BASE_ID_TEXT];
        bool took = false;
        cfg_global_init();
        str_copy_or_die(cfg_global.lightbox_dir, argv[2], sizeof(cfg_global.lightbox_dir), "lightbox_dir");
        image_open(argv[3], &img);
        if (image_base(&img, number_arg(argv[4]), id, &took, &unpacked) != 0)
            return 1;
        put_line(took ? "took " : "found ", id);
        put("entries ");
        put_int64((int64_t)unpacked.entries);
        put("devices ");
        put_int64((int64_t)unpacked.devices);
        return 0;
    }
    if (argc == 6 && streq(argv[1], "overlay-options")) {
        static char options[4 * MAX_PATH];
        cfg_global_init();
        str_copy_or_die(cfg_global.lightbox_dir, argv[2], sizeof(cfg_global.lightbox_dir), "lightbox_dir");
        if (!overlay_options(options, sizeof(options), argv[3], argv[4], argv[5])) {
            put("refused\n");
            return 1;
        }
        put_line(options, "");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "gpu")) {
        static device_spec found[MAX_DEVICES];
        int n = gpu_devices(argv[2], found, MAX_DEVICES);
        if (n < 0) {
            put("more than " STRINGIFY(MAX_DEVICES) "\n");
            return 1;
        }
        for (int i = 0; i < n; i++) {
            put(found[i].host);
            put_line(" -> ", found[i].path);
        }
        return 0;
    }
    if (argc == 3 && streq(argv[1], "nvidia")) {
        static nvidia_files nv;
        int rc = nvidia_libraries(argv[2], &nv);
        if (rc == 0) {
            put("none\n");
            return 0;
        }
        put_line("version ", nv.version);
        if (rc < 0) {
            put_line("missing ", nv.missing);
            return 1;
        }
        for (int i = 0; i < nv.nfiles; i++) {
            put("file ");
            put(nv.files[i].host);
            put(" ");
            put(nv.files[i].name);
            put(nv.files[i].bin ? " bin\n" : "\n");
        }
        for (int i = 0; i < nv.nlinks; i++) {
            put("link ");
            put(nv.links[i].name);
            put_line(" ", nv.links[i].target);
        }
        return 0;
    }
    if (argc == 3 && streq(argv[1], "musl")) {
        put(root_has_musl(argv[2]) ? "musl\n" : "not musl\n");
        return 0;
    }
    if (argc >= 3 && streq(argv[1], "gidmap")) {
        uint32_t start, groups[MAX_DEVICES + 4];
        size_t n = 0;
        if (!parse_u32_text(argv[2], &start))
            return 2;
        for (int i = 3; i < argc && n < sizeof(groups) / sizeof(groups[0]); i++)
            if (!parse_u32_text(argv[i], &groups[n++]))
                return 2;
        static char text[USERNS_MAP_TEXT_MAX + 64];
        if (!userns_gid_map_text(text, sizeof(text), start, groups, n)) {
            put("refused\n");
            return 1;
        }
        put(text);
        return 0;
    }
    if (argc == 3 && streq(argv[1], "devgroups")) {
        static char text[4096];
        if (read_file(argv[2], text, sizeof(text)) < 0)
            return 2;
        uint32_t inside[MAX_DEVICES];
        int n = gid_map_device_groups(text, inside, MAX_DEVICES);
        for (int i = 0; i < n; i++) {
            char digits[11];
            format_u32(digits, inside[i]);
            put_line(digits, "");
        }
        return 0;
    }
    if (argc == 4 && streq(argv[1], "cgroup2-root")) {
        /* the store's lock in a directory of the case's, and cgroup_root */
        if (!str_copy(cfg_global.container_dir, argv[2], sizeof(cfg_global.container_dir)) ||
            !str_copy(cfg_global.cgroup_root, argv[3], sizeof(cfg_global.cgroup_root)))
            return 2;
        ensure_cgroup2_for_start();
        put("cgroup2\n");
        return 0;
    }
    if (argc == 5 && streq(argv[1], "firewall-kernel")) {
        static char missing[512], links[256];
        cfg_global.ip_masq = streq(argv[4], "true");
        int rc = iptables_kernel_missing(argv[2], argv[3], missing, sizeof(missing), links, sizeof(links));
        if (rc < 0)
            put("not known\n");
        else if (rc == 0)
            put_line("missing: ", missing);
        else
            put("all there\n");
        if (links[0])
            put_line("links: ", links);
        return rc < 0 ? 2 : rc == 0 ? 1 : 0;
    }
    if (argc == 3 && streq(argv[1], "overlay-whole")) {
        static char found[MAX_PATH];
        int whole = overlay_upper_whole(argv[2], found, sizeof(found));
        if (whole < 0) {
            put("cannot read\n");
            return 2;
        }
        if (whole == 0) {
            put_line("not whole: ", found);
            return 1;
        }
        put("whole\n");
        return 0;
    }
    if (argc == 3 && streq(argv[1], "sha256-name")) {
        put(sha256_hex_ok(argv[2]) ? "ok\n" : "refused\n");
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
