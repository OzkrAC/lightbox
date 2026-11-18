#include "lightbox.h"

/*
 * Base snapshots: what lightbox keeps of a base root filesystem, as Docker
 * keeps its images, so that a container is an overlay of a snapshot and not
 * a copy of the base, and so that changing or removing the base afterwards
 * changes no container.
 *
 *   <lightbox_dir>/bases/<id>/rootfs   the copy, the overlay's lower layer
 *                             source   the base it was taken of, a line
 *                             taken    when: seconds and nanoseconds since 1970
 *
 * A snapshot is made in .<id>.new and renamed into place when it is whole,
 * so one that a killed command left is never taken for one. The id is 12
 * hex digits of a hash of the source and the time.
 */

bool base_id_ok(const char *id) {
    size_t len = lc_string_length(id);
    if (len != BASE_ID_LEN)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

void bases_dir_path(char out[MAX_PATH]) {
    path_join_or_die(out, MAX_PATH, cfg_global.lightbox_dir, "bases");
}

/* <bases>/<id>, or a file in it */
static bool base_file_path(char out[MAX_PATH], const char *id, const char *file) {
    char dir[MAX_PATH], base[MAX_PATH];
    bases_dir_path(dir);
    if (!path_join(base, sizeof(base), dir, id))
        return false;
    return file ? path_join(out, MAX_PATH, base, file) : str_copy(out, base, MAX_PATH);
}

bool base_rootfs_path(char out[MAX_PATH], const char *id) {
    return base_id_ok(id) && base_file_path(out, id, "rootfs");
}

/* what a snapshot says of itself: its source, and when it was taken */
static bool base_read(const char *id, char source[MAX_PATH], int64_t *seconds, int64_t *nanos) {
    char path[MAX_PATH], text[64];
    if (!base_file_path(path, id, "source") || read_file(path, source, MAX_PATH) <= 0)
        return false;
    size_t len = lc_string_length(source);
    if (len && source[len - 1] == '\n')
        source[len - 1] = '\0';
    *seconds = *nanos = 0;
    if (!base_file_path(path, id, "taken") || read_file(path, text, sizeof(text)) <= 0)
        return true;
    int64_t *field = seconds;
    for (const char *p = text; *p; p++) {
        if (*p >= '0' && *p <= '9')
            *field = *field * 10 + (*p - '0');
        else if (*p == ' ' && field == seconds)
            field = nanos;
        else
            break;
    }
    return true;
}

static uint64_t fnv1a64(const char *text, uint64_t hash) {
    for (; *text; text++) {
        hash ^= (uint8_t)*text;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

int base_take(const char *source, char id[BASE_ID_TEXT]) {
    lc_timespec now = { 0, 0 };
    lc_kernel_get_clock(LC_CLOCK_REALTIME, &now);
    /* "<seconds> <nanoseconds>\n", by hand: fmt_int is for an int */
    char taken[48];
    bool cut = false;
    size_t pos = 0;
    {
        char rev[24];
        int n = 0;
        int64_t v = now.seconds;
        do { rev[n++] = (char)('0' + v % 10); v /= 10; } while (v > 0 && n < 23);
        while (n) taken[pos++] = rev[--n];
        taken[pos++] = ' ';
        v = now.nanoseconds;
        n = 0;
        do { rev[n++] = (char)('0' + v % 10); v /= 10; } while (v > 0 && n < 23);
        while (n) taken[pos++] = rev[--n];
        taken[pos++] = '\n';
        taken[pos] = '\0';
    }
    uint64_t hash = fnv1a64(taken, fnv1a64(source, 0xcbf29ce484222325ULL));
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < BASE_ID_LEN; i++)
        id[i] = hex[(hash >> (60 - 4 * i)) & 0xf];
    id[BASE_ID_LEN] = '\0';

    char dir[MAX_PATH], fresh[MAX_PATH], name[BASE_ID_TEXT + 8], path[MAX_PATH], line[MAX_PATH + 2];
    bases_dir_path(dir);
    (void)lc_kernel_mkdirat(AT_FDCWD, dir, MODE_PRIVATE_DIR);   /* it may be there */
    str_append(name, str_append(name, str_append(name, 0, ".", sizeof(name), &cut), id, sizeof(name), &cut),
               ".new", sizeof(name), &cut);
    if (cut || !path_join(fresh, sizeof(fresh), dir, name)) {
        print_str(STDERR, "Error: the path of a base snapshot is too long\n");
        return -1;
    }
    if (path_exists(fresh))
        require_rm_rf(fresh);
    if (lc_kernel_mkdirat(AT_FDCWD, fresh, MODE_PRIVATE_DIR) < 0) {
        print_str(STDERR, "Error: cannot make a base snapshot in ");
        print_str(STDERR, dir);
        lc_print_char(STDERR, '\n');
        return -1;
    }
    str_append(line, str_append(line, 0, source, sizeof(line), &cut), "\n", sizeof(line), &cut);
    if (cut || !path_join(path, sizeof(path), fresh, "source") || write_file_volatile(path, line) != 0 ||
        !path_join(path, sizeof(path), fresh, "taken") || write_file_volatile(path, taken) != 0) {
        print_str(STDERR, "Error: cannot record the base snapshot\n");
        require_rm_rf(fresh);
        return -1;
    }

    /* what is in the base ("<base>/."), not the path: given a link to the
     * base, the snapshot would be that link. A reflink where the filesystem
     * has them, and a copy of every byte where it has not. */
    char contents[MAX_PATH + 4], rootfs[MAX_PATH];
    if (!path_join(contents, sizeof(contents), source, ".") || !path_join(rootfs, sizeof(rootfs), fresh, "rootfs")) {
        print_str(STDERR, "Error: the path of a base snapshot is too long\n");
        require_rm_rf(fresh);
        return -1;
    }
    print_str(STDOUT, "Taking a snapshot of the base ");
    print_str(STDOUT, source);
    print_str(STDOUT, "...\n");
    const char *reflink[] = { "cp", "-a", "--reflink=auto", contents, rootfs, NULL };
    if (run_cmd_quiet(tool_path_cp(), reflink) != 0) {
        if (path_exists(rootfs))
            require_rm_rf(rootfs);
        const char *plain[] = { "cp", "-a", contents, rootfs, NULL };
        if (run_cmd(tool_path_cp(), plain) != 0) {
            print_str(STDERR, "Error: cannot copy the base into its snapshot\n");
            require_rm_rf(fresh);
            return -1;
        }
    }
    char final[MAX_PATH];
    if (!path_join(final, sizeof(final), dir, id) || lb_sys_renameat(AT_FDCWD, fresh, AT_FDCWD, final) < 0) {
        print_str(STDERR, "Error: cannot put the base snapshot in place\n");
        require_rm_rf(fresh);
        return -1;
    }
    return 0;
}

int list_bases(char ids[][NAME_MAX_LEN + 1], int max) {
    char dir[MAX_PATH];
    bases_dir_path(dir);
    return list_entries(dir, base_id_ok, ids, max, NULL);
}

int base_snapshot_for(const char *source, char id[BASE_ID_TEXT], bool *took) {
    static char ids[MAX_LISTED][NAME_MAX_LEN + 1];
    int count = list_bases(ids, MAX_LISTED);
    int64_t best_s = -1, best_n = -1;
    *took = false;
    id[0] = '\0';
    for (int i = 0; i < count; i++) {
        char from[MAX_PATH];
        int64_t s, n;
        if (!base_read(ids[i], from, &s, &n) || !streq(from, source))
            continue;
        if (s > best_s || (s == best_s && n > best_n)) {
            best_s = s;
            best_n = n;
            lc_bytes_copy(id, ids[i], BASE_ID_TEXT);
        }
    }
    if (id[0])
        return 0;
    *took = true;
    return base_take(source, id);
}

/*
 * The options of an overlay of a snapshot, or false where a path has a
 * character that the options cannot carry: a comma or a colon separates
 * them, and a backslash escapes.
 */
bool overlay_options(char *out, size_t max, const char *id, const char *upper, const char *work) {
    char lower[MAX_PATH];
    if (!base_rootfs_path(lower, id))
        return false;
    const char *paths[] = { lower, upper, work };
    for (size_t i = 0; i < 3; i++) {
        for (const char *p = paths[i]; *p; p++)
            if (*p == ',' || *p == ':' || *p == '\\')
                return false;
    }
    bool cut = false;
    size_t pos = str_append(out, 0, "lowerdir=", max, &cut);
    pos = str_append(out, pos, lower, max, &cut);
    pos = str_append(out, pos, ",upperdir=", max, &cut);
    pos = str_append(out, pos, upper, max, &cut);
    pos = str_append(out, pos, ",workdir=", max, &cut);
    str_append(out, pos, work, max, &cut);
    return !cut;
}

/* ─── lightbox base ls | rm | add ──────────────────────────────────────── */

/* The containers on a snapshot, as their configurations say, with ", "
 * between them: how many. */
static int base_users(const char *id, char *out, size_t max) {
    static char names[MAX_LISTED][NAME_MAX_LEN + 1];
    int count = list_containers(names, MAX_LISTED, NULL);
    int users = 0;
    size_t pos = 0;
    bool cut = false;
    out[0] = '\0';
    for (int i = 0; i < count; i++) {
        static container_config config;
        if (container_config_load(names[i], &config) != NULL || !streq(config.base, id))
            continue;
        pos = str_append(out, pos, users++ ? ", " : "", max, &cut);
        pos = str_append(out, pos, names[i], max, &cut);
    }
    return users;
}

/* seconds since 1970 as UTC: "2026-11-17 14:10:03" */
static void format_utc(char out[20], int64_t seconds) {
    int64_t days = seconds / 86400, rest = seconds % 86400;
    /* days to a civil date, after Howard Hinnant's days_from_civil inverted */
    int64_t z = days + 719468, era = z / 146097, doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400, doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153, d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    int64_t parts[6] = { y, m, d, rest / 3600, rest % 3600 / 60, rest % 60 };
    static const char sep[] = "-- ::";
    size_t pos = 0;
    for (int i = 0; i < 6; i++) {
        int64_t v = parts[i];
        int width = i == 0 ? 4 : 2;
        for (int k = width - 1; k >= 0; k--) {
            out[pos + (size_t)k] = (char)('0' + v % 10);
            v /= 10;
        }
        pos += (size_t)width;
        if (i < 5)
            out[pos++] = sep[i];
    }
    out[pos] = '\0';
}

static void base_ls(void) {
    static char ids[MAX_LISTED][NAME_MAX_LEN + 1];
    int count = list_bases(ids, MAX_LISTED);
    print_str(STDOUT, "ID            TAKEN (UTC)          SOURCE  CONTAINERS\n");
    for (int i = 0; i < count; i++) {
        char source[MAX_PATH], when[20], users[1024];
        int64_t s, n;
        if (!base_read(ids[i], source, &s, &n))
            continue;
        format_utc(when, s);
        int used = base_users(ids[i], users, sizeof(users));
        print_str(STDOUT, ids[i]);
        print_str(STDOUT, "  ");
        print_str(STDOUT, when);
        print_str(STDOUT, "  ");
        print_str(STDOUT, source);
        print_str(STDOUT, "  ");
        print_str(STDOUT, used ? users : "-");
        lc_print_char(STDOUT, '\n');
    }
}

void cmd_base(int argc, char **argv) {
    if (argc < 1)
        die("Usage: lightbox base ls | base rm <id>... | base add <dir>");
    if (streq(argv[0], "ls")) {
        if (argc > 1)
            die2(argv[1][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[1]);
        base_ls();
        return;
    }
    if (streq(argv[0], "add")) {
        if (argc != 2)
            die(argc < 2 ? "Usage: lightbox base add <dir>" : "Error: base add takes one directory");
        const char *source = argv[1];
        if (!path_is_directory(source))
            die2("Error: base rootfs is not a directory: ", source);
        if (dir_is_empty(source) != 0)
            die2("Error: base rootfs is empty or cannot be read: ", source);
        require_tool("cp", tool_path_cp());
        (void)store_lock();
        char id[BASE_ID_TEXT];
        if (base_take(source, id) != 0)
            lc_kernel_exit(1);
        print_str(STDOUT, "Base ");
        print_str(STDOUT, id);
        print_str(STDOUT, " taken of ");
        print_str(STDOUT, source);
        print_str(STDOUT, "; new containers of it use this one\n");
        return;
    }
    if (streq(argv[0], "rm")) {
        if (argc < 2)
            die("Usage: lightbox base rm <id>...");
        for (int i = 1; i < argc; i++)
            if (!base_id_ok(argv[i]))
                die2("Error: not the id of a base snapshot: ", argv[i]);
        require_tool("rm", tool_path_rm());
        (void)store_lock();
        int failed = 0;
        for (int i = 1; i < argc; i++) {
            char path[MAX_PATH], users[1024];
            if (!base_file_path(path, argv[i], NULL) || !path_is_directory(path)) {
                print_str(STDERR, "Error: there is no base snapshot ");
                print_str(STDERR, argv[i]);
                lc_print_char(STDERR, '\n');
                failed++;
                continue;
            }
            if (base_users(argv[i], users, sizeof(users)) > 0) {
                print_str(STDERR, "Error: base ");
                print_str(STDERR, argv[i]);
                print_str(STDERR, " is used by: ");
                print_str(STDERR, users);
                lc_print_char(STDERR, '\n');
                failed++;
                continue;
            }
            require_rm_rf(path);
            print_str(STDOUT, "Base ");
            print_str(STDOUT, argv[i]);
            print_str(STDOUT, " removed\n");
        }
        if (failed)
            lc_kernel_exit(1);
        return;
    }
    die2("Error: unknown base command: ", argv[0]);
}
