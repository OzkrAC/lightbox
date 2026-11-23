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
 *                             layer    what it is as a layer of an image, once an
 *                                      export wrote it: its digest and its size
 *                             image    the layers of an image it was unpacked
 *                                      from, a line each, where import made it
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

int base_begin(const char *source, char id[BASE_ID_TEXT], char fresh[MAX_PATH]) {
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

    char dir[MAX_PATH], name[BASE_ID_TEXT + 8], path[MAX_PATH], line[MAX_PATH + 2];
    bases_dir_path(dir);
    (void)lc_kernel_mkdirat(AT_FDCWD, dir, MODE_PRIVATE_DIR);   /* it may be there */
    str_append(name, str_append(name, str_append(name, 0, ".", sizeof(name), &cut), id, sizeof(name), &cut),
               ".new", sizeof(name), &cut);
    if (cut || !path_join(fresh, MAX_PATH, dir, name)) {
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
    return 0;
}

int base_commit(const char *id, const char *fresh) {
    char dir[MAX_PATH], final[MAX_PATH];
    bases_dir_path(dir);
    if (!path_join(final, sizeof(final), dir, id) || lb_sys_renameat(AT_FDCWD, fresh, AT_FDCWD, final) < 0) {
        print_str(STDERR, "Error: cannot put the base snapshot in place\n");
        require_rm_rf(fresh);
        return -1;
    }
    return 0;
}

int base_take(const char *source, char id[BASE_ID_TEXT]) {
    char fresh[MAX_PATH];
    if (base_begin(source, id, fresh) != 0)
        return -1;

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
    return base_commit(id, fresh);
}

void base_discard(const char *id) {
    char path[MAX_PATH];
    if (base_id_ok(id) && base_file_path(path, id, NULL) && path_exists(path))
        require_rm_rf(path);
}

int list_bases(char ids[][NAME_MAX_LEN + 1], int max) {
    char dir[MAX_PATH];
    bases_dir_path(dir);
    return list_entries(dir, base_id_ok, ids, max, NULL);
}

/*
 * <bases>/<id>/layer: "sha256:<digest> <size>" and a newline, what the
 * snapshot is as a layer of an image. A snapshot does not change, so that
 * what an export found once holds: an import knows by it a base that is here
 * already.
 */
#define LAYER_RECORD_PREFIX "sha256:"

bool base_layer_read(const char *id, char digest[SHA256_HEX + 1], uint64_t *size) {
    char path[MAX_PATH], text[sizeof(LAYER_RECORD_PREFIX) + SHA256_HEX + 24];
    size_t prefix = sizeof(LAYER_RECORD_PREFIX) - 1;
    digest[0] = '\0';
    *size = 0;
    if (!base_id_ok(id) || !base_file_path(path, id, "layer") || read_file(path, text, sizeof(text)) <= 0)
        return false;
    size_t len = lc_string_length(text);
    if (len && text[len - 1] == '\n')
        text[--len] = '\0';
    if (len < prefix + SHA256_HEX + 2 || lc_bytes_compare(text, LAYER_RECORD_PREFIX, prefix) != 0 ||
        text[prefix + SHA256_HEX] != ' ')
        return false;
    text[prefix + SHA256_HEX] = '\0';
    int64_t bytes;
    if (!sha256_hex_ok(text + prefix) || !parse_number(text + prefix + SHA256_HEX + 1, 0, INT64_MAX, &bytes))
        return false;
    lc_bytes_copy(digest, text + prefix, SHA256_HEX + 1);
    *size = (uint64_t)bytes;
    return true;
}

int base_layer_keep(const char *id, const char *digest, uint64_t size) {
    char path[MAX_PATH], text[sizeof(LAYER_RECORD_PREFIX) + SHA256_HEX + 24], digits[24];
    int at = (int)sizeof(digits);
    digits[--at] = '\0';
    do { digits[--at] = (char)('0' + size % 10); size /= 10; } while (size);
    bool cut = false;
    size_t pos = str_append(text, 0, LAYER_RECORD_PREFIX, sizeof(text), &cut);
    pos = str_append(text, pos, digest, sizeof(text), &cut);
    pos = str_append(text, pos, " ", sizeof(text), &cut);
    pos = str_append(text, pos, digits + at, sizeof(text), &cut);
    str_append(text, pos, "\n", sizeof(text), &cut);
    if (cut || !sha256_hex_ok(digest) || !base_id_ok(id) || !base_file_path(path, id, "layer"))
        return -1;
    return write_file_atomic(path, text, MODE_PRIVATE_FILE);
}

/*
 * <bases>/<id>/image: the layers an import unpacked the snapshot from, each
 * as "sha256:<digest>" on a line, the digest of the layer as it is unpacked.
 * A later import of an image with the same layers under its own finds the
 * snapshot by it, and takes no second one.
 */
int base_image_keep(const char *fresh, const char *layers) {
    char path[MAX_PATH];
    return path_join(path, sizeof(path), fresh, "image") ? write_file_volatile(path, layers) : -1;
}

static bool base_image_read(const char *id, char layers[BASE_IMAGE_TEXT_MAX]) {
    char path[MAX_PATH];
    layers[0] = '\0';
    if (!base_file_path(path, id, "image"))
        return false;
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY | O_NOFOLLOW, 0);
    if (fd < 0)
        return false;
    lc_sysret n = lc_kernel_read_all((int32_t)fd, layers, BASE_IMAGE_TEXT_MAX);
    lc_kernel_close_file((int32_t)fd);
    if (n <= 0 || n >= BASE_IMAGE_TEXT_MAX)
        return false;
    layers[n] = '\0';
    return true;
}

bool base_of_layers(const char *layers, char id[BASE_ID_TEXT]) {
    static char ids[MAX_LISTED][NAME_MAX_LEN + 1];
    static char kept[BASE_IMAGE_TEXT_MAX];
    int count = list_bases(ids, MAX_LISTED);
    /* one layer: a snapshot that an export here wrote as that very layer is it too */
    size_t prefix = sizeof(LAYER_RECORD_PREFIX) - 1, len = lc_string_length(layers);
    bool one = len == prefix + SHA256_HEX + 1 && layers[len - 1] == '\n';
    id[0] = '\0';
    for (int i = 0; i < count && !id[0]; i++) {
        char digest[SHA256_HEX + 1], rootfs[MAX_PATH];
        uint64_t size;
        bool is = base_image_read(ids[i], kept) && streq(kept, layers);
        if (!is && one && base_layer_read(ids[i], digest, &size))
            is = lc_bytes_compare(digest, layers + prefix, SHA256_HEX) == 0;
        if (is && base_rootfs_path(rootfs, ids[i]) && path_is_directory(rootfs))
            lc_bytes_copy(id, ids[i], BASE_ID_TEXT);
    }
    return id[0] != '\0';
}

int base_snapshot_for(const char *source, char id[BASE_ID_TEXT], bool *took) {
    static char ids[MAX_LISTED][NAME_MAX_LEN + 1];
    int count = list_bases(ids, MAX_LISTED);
    int64_t best_s = -1, best_n = -1;
    *took = false;
    id[0] = '\0';
    for (int i = 0; i < count; i++) {
        char from[MAX_PATH], record[MAX_PATH];
        int64_t s, n;
        if (!base_read(ids[i], from, &s, &n) || !streq(from, source))
            continue;
        /* what import unpacked is of an image, whatever its source line reads as */
        if (base_file_path(record, ids[i], "image") && path_exists(record))
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
    pos = str_append(out, pos, work, max, &cut);
    str_append(out, pos, "," OVERLAY_WHOLE_OPTIONS, max, &cut);
    return !cut;
}

/* ─── An upper directory that is all of a container's own files (ROADMAP I.14) */

/* A name an overlay keeps of an entry in its upper directory that says the
 * entry is not all there: the directory or the file is in the snapshot. */
static bool overlay_left(int32_t fd, const char *const names[], size_t count) {
    static const char *const prefixes[] = { "trusted.overlay.", "user.overlay." };
    for (size_t p = 0; p < 2; p++)
        for (size_t i = 0; i < count; i++) {
            char name[48];
            bool cut = false;
            str_append(name, str_append(name, 0, prefixes[p], sizeof(name), &cut), names[i], sizeof(name), &cut);
            if (!cut && lb_sys_fgetxattr(fd, name, NULL, 0) >= 0)
                return true;
        }
    return false;
}

/* Below a directory that is open: 1 whole; 0 with the first entry that is
 * not, its path from the top in found; -1 for one that cannot be read. */
static int upper_walk(int32_t dirfd, char *found, size_t max, size_t at, int depth) {
    static const char *const of_dirs[] = { "redirect" }, *const of_files[] = { "metacopy" };
    if (depth > 4096)
        return -1;
    if (overlay_left(dirfd, of_dirs, 1))
        return 0;
    char buf[4096];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory(dirfd, buf, sizeof(buf));
        if (n < 0)
            return -1;
        if (n == 0)
            return 1;
        for (lc_sysret pos = 0; pos < n; ) {
            /* struct linux_dirent64: d_reclen at offset 16, d_type at 18, d_name at 19 */
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + 16, sizeof(reclen));
            if (reclen == 0)
                return -1;
            const char *entry = buf + pos + 19;
            pos += reclen;
            if (entry[0] == '.' && (entry[1] == '\0' || (entry[1] == '.' && entry[2] == '\0')))
                continue;
            struct lb_statx st;
            if (lb_sys_statx(dirfd, entry, AT_SYMLINK_NOFOLLOW, LB_STATX_TYPE, &st) < 0)
                return -1;
            uint32_t kind = st.stx_mode & LB_S_IFMT;
            if (kind != LB_S_IFDIR && kind != LB_S_IFREG)
                continue;
            bool cut = false;
            size_t here = str_append(found, str_append(found, at, at ? "/" : "", max, &cut), entry, max, &cut);
            if (cut)
                return -1;
            lc_sysret fd = lc_kernel_open_file_at(dirfd, entry, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC |
                                                  (kind == LB_S_IFDIR ? O_DIRECTORY : 0), 0);
            if (fd < 0)
                return -1;
            int rc = kind == LB_S_IFDIR ? upper_walk((int32_t)fd, found, max, here, depth + 1)
                                        : overlay_left((int32_t)fd, of_files, 1) ? 0 : 1;
            lc_kernel_close_file((int32_t)fd);
            if (rc != 1)
                return rc;
            found[at] = '\0';
        }
    }
}

int overlay_upper_whole(const char *upper, char *found, size_t max) {
    found[0] = '\0';
    lc_sysret fd = lc_kernel_open_file(upper, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int rc = upper_walk((int32_t)fd, found, max, 0, 0);
    lc_kernel_close_file((int32_t)fd);
    if (rc == 0 && !found[0] && max > 1) {
        found[0] = '.';
        found[1] = '\0';
    }
    return rc;
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

static void base_ls(void) {
    static char ids[MAX_LISTED][NAME_MAX_LEN + 1];
    int count = list_bases(ids, MAX_LISTED);
    print_str(STDOUT, "ID            TAKEN (UTC)          SOURCE  CONTAINERS\n");
    for (int i = 0; i < count; i++) {
        char source[MAX_PATH], when[UTC_TEXT_LEN + 1] = { 0 }, users[1024];
        int64_t s, n;
        if (!base_read(ids[i], source, &s, &n))
            continue;
        /* "2026-11-17 14:10:03": the time as RFC 3339 has it, to the second */
        format_utc(when, s, 0);
        when[10] = ' ';
        when[19] = '\0';
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
        die("Usage: lightbox base ls | base rm <id>... | base add <dir> | base import <dir>");
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
        if (image_layout_at(source))
            die2("Error: this is an image and no root filesystem, and base import <dir> makes a base of one: ", source);
        require_tool("cp", tool_path_cp());
        (void)store_lock();
        char id[BASE_ID_TEXT];
        if (base_take(source, id) != 0)
            lc_kernel_exit(failure_status);
        print_str(STDOUT, "Base ");
        print_str(STDOUT, id);
        print_str(STDOUT, " taken of ");
        print_str(STDOUT, source);
        print_str(STDOUT, "; new containers of it use this one\n");
        return;
    }
    if (streq(argv[0], "import")) {
        /*
         * base import <dir> (ROADMAP I.9): an image that somebody else
         * built, as a tool copied it from a registry into a directory, made
         * a base: all of its layers, one unpacked over the other, are a
         * snapshot, which create --base makes containers of. The image is
         * read as import reads one, whole and held to its digests before
         * root is asked for and before anything is made, and is unpacked as
         * import unpacks one. A snapshot that is those layers already is it.
         */
        if (argc != 2)
            die(argc < 2 ? "Usage: lightbox base import <dir>" : "Error: base import takes one directory, with an image in it");
        static image img;
        image_open(argv[1], &img);
        require_root("base import");
        for (int i = 0; i < img.nlayers; i++)
            if (img.layers[i].gzip) {
                require_tool("gzip", tool_path_gzip());
                break;
            }
        (void)store_lock();
        char id[BASE_ID_TEXT], layers[24];
        bool took = false;
        image_unpacked unpacked = { 0 };
        if (image_base(&img, img.nlayers, id, &took, &unpacked) != 0)
            die("Error: the image was not unpacked, and no snapshot of it is kept");
        int n = img.nlayers, at = (int)sizeof(layers);
        layers[--at] = '\0';
        do { layers[--at] = (char)('0' + n % 10); n /= 10; } while (n);
        print_str(STDOUT, "Base ");
        print_str(STDOUT, id);
        print_str(STDOUT, took ? " unpacked from the image sha256:" : " is the image sha256:");
        print_str(STDOUT, img.manifest);
        print_str(STDOUT, took ? ", " : " already, ");
        print_str(STDOUT, layers + at);
        print_str(STDOUT, img.nlayers == 1 ? " layer" : " layers");
        print_str(STDOUT, took ? "\n" : ": nothing was unpacked\n");
        image_notes(&img, &unpacked);
        print_str(STDOUT, "A container of it: lightbox create <name> --base ");
        print_str(STDOUT, id);
        lc_print_char(STDOUT, '\n');
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
            lc_kernel_exit(failure_status);
        return;
    }
    die2("Error: unknown base command: ", argv[0]);
}
