#include "lightbox.h"

/*
 * Images (ROADMAP Track I): a container as an OCI image layout, the directory
 * that every registry's tools read and write, so that skopeo or oras carries
 * it to a registry and back.
 *
 *   <dir>/oci-layout               that it is one, and of which version
 *         index.json               names the manifest
 *         blobs/sha256/<digest>    the manifest, the configuration and the
 *                                  layers, each named by its own SHA-256
 *
 * A container is in it the way lightbox keeps it. One that overlays a
 * snapshot is two layers, the snapshot and then its own files, rootfs/, with
 * what the overlay marks as taken out written as an image marks it; one that
 * is a copy of its base is one layer. A layer is a tar archive that is not
 * compressed, and the same tree gives the same archive, so that a snapshot
 * has one digest wherever and whenever it is written: a registry that has it
 * is sent the container's own files alone.
 *
 * The manifest carries what a container is limited to as annotations, under
 * ac.ozkr.lightbox.: memory, swap, processes, CPUs and the lifetime. Nothing
 * that says what a container may do on a host is written: that is said by
 * the machine that imports it. No time and no host's name is written either,
 * so that one container gives one image, byte for byte.
 */

#define OCI_LAYOUT_FILE     "oci-layout"
#define OCI_LAYOUT_TEXT     "{\"imageLayoutVersion\":\"1.0.0\"}"
#define OCI_INDEX_FILE      "index.json"
#define MEDIA_INDEX         "application/vnd.oci.image.index.v1+json"
#define MEDIA_MANIFEST      "application/vnd.oci.image.manifest.v1+json"
#define MEDIA_CONFIG        "application/vnd.oci.image.config.v1+json"
#define MEDIA_LAYER         "application/vnd.oci.image.layer.v1.tar"
#define ANNOTATION          "ac.ozkr.lightbox."
/* What the annotations say, and how: a later lightbox that says more, or
 * says it another way, writes another number. */
#define ANNOTATIONS_VERSION "1"

/* The architecture as an image names it, which is as Go does */
#if defined(__x86_64__)
#define OCI_ARCHITECTURE "amd64"
#elif defined(__aarch64__)
#define OCI_ARCHITECTURE "arm64"
#else
#error "lightbox_image.c: no name of an image's for this architecture"
#endif

#define LAYERS_MAX      2
#define IMAGE_TEXT_MAX  4096    /* a manifest, a configuration or an index that export writes */

struct blob {
    char     digest[SHA256_HEX + 1];
    uint64_t size;
};

/* ─── What an export made, to take away when it fails ───────────────────── */

/*
 * The directory an image is written into is new, or was empty: what is in
 * it is this export's, each file by its name. A failure takes those away
 * again, and the directories with them, so that what is left is no half of
 * an image. index.json is written last: a directory without it is none.
 */
#define MADE_MAX 8
static struct {
    char dir[MAX_PATH], blobs[MAX_PATH], sha256[MAX_PATH];
    bool made_dir, made_blobs, made_sha256;
    char files[MADE_MAX][MAX_PATH];
    int  nfiles;
} made;

static void made_file(const char *path) {
    if (made.nfiles >= MADE_MAX)
        die("Error: an export writes no more files than it can take away again");
    str_copy_or_die(made.files[made.nfiles++], path, MAX_PATH, "a file of the image");
}

static void export_undo(void) {
    for (int i = 0; i < made.nfiles; i++)
        (void)lc_kernel_unlinkat(AT_FDCWD, made.files[i], 0);
    if (made.made_sha256)
        (void)lc_kernel_unlinkat(AT_FDCWD, made.sha256, AT_REMOVEDIR);
    if (made.made_blobs)
        (void)lc_kernel_unlinkat(AT_FDCWD, made.blobs, AT_REMOVEDIR);
    if (made.made_dir)
        (void)lc_kernel_unlinkat(AT_FDCWD, made.dir, AT_REMOVEDIR);
}

/* ─── Text ──────────────────────────────────────────────────────────────── */

struct text {
    char   bytes[IMAGE_TEXT_MAX];
    size_t len;
    bool   cut;
};

static void add(struct text *t, const char *s) {
    t->len = str_append(t->bytes, t->len, s, sizeof(t->bytes), &t->cut);
}

/* a JSON string, in ASCII */
static void add_string(struct text *t, const char *s) {
    size_t len = lc_string_length(s);
    if (t->cut || JSON_QUOTED_MAX(len) >= sizeof(t->bytes) - t->len) {
        t->cut = true;
        return;
    }
    t->len += json_quote(t->bytes + t->len, s, len);
    t->bytes[t->len] = '\0';
}

static void u64_text(char out[24], uint64_t number) {
    char digits[24];
    int at = (int)sizeof(digits);
    digits[--at] = '\0';
    do { digits[--at] = (char)('0' + number % 10); number /= 10; } while (number);
    lc_bytes_copy(out, digits + at, sizeof(digits) - (size_t)at);
}

static void add_digest(struct text *t, const struct blob *blob) {
    add(t, "\"sha256:");
    add(t, blob->digest);
    add(t, "\"");
}

/* "mediaType":…,"digest":…,"size":…, what names a blob, without its braces */
static void add_descriptor(struct text *t, const char *media, const struct blob *blob) {
    char size[24];
    u64_text(size, blob->size);
    add(t, "\"mediaType\":\"");
    add(t, media);
    add(t, "\",\"digest\":");
    add_digest(t, blob);
    add(t, ",\"size\":");
    add(t, size);
}

static void add_annotation(struct text *t, const char *key, const char *value) {
    add(t, ",\"" ANNOTATION);
    add(t, key);
    add(t, "\":");
    add_string(t, value);
}

/* What export wrote is read by the reader an import reads it with, before it
 * is kept: a text that one refuses is not written. */
static void text_whole(const struct text *t, const char *what) {
    json_value root;
    json_refusal why;
    if (t->cut)
        die2("Error: export has no room for what it writes as ", what);
    if (json_check(t->bytes, t->len, &root, &why) != 0) {
        print_str(STDERR, "Error: export wrote what is no JSON as ");
        print_str(STDERR, what);
        print_str(STDERR, ": ");
        print_str(STDERR, why.why ? why.why : "it is refused");
        lc_print_char(STDERR, '\n');
        fail_now();
    }
}

/* ─── Blobs ─────────────────────────────────────────────────────────────── */

static void sync_dir_or_die(const char *path) {
    lc_sysret fd = lc_kernel_open_file(path, O_RDONLY | O_DIRECTORY, 0);
    lc_sysret rc = fd < 0 ? fd : lb_sys_fsync((int32_t)fd);
    if (fd >= 0)
        lc_kernel_close_file((int32_t)fd);
    if (rc < 0)
        die2("Error: the image is not known to be on the disk: cannot sync ", path);
}

static void blob_path(char out[MAX_PATH], const char *name) {
    if (!path_join(out, MAX_PATH, made.sha256, name))
        die2("Error: the path of the image's directory is too long: ", made.dir);
}

/* A text as a blob: its digest and its size, and the file of that name */
static void blob_of_text(const struct text *t, struct blob *blob) {
    sha256_ctx hash;
    uint8_t digest[SHA256_BYTES];
    char path[MAX_PATH];
    sha256_init(&hash);
    sha256_update(&hash, t->bytes, t->len);
    sha256_final(&hash, digest);
    sha256_hex(digest, blob->digest);
    blob->size = t->len;
    blob_path(path, blob->digest);
    made_file(path);
    if (write_file_atomic(path, t->bytes, MODE_PRIVATE_FILE) != 0)
        die2("Error: cannot write ", path);
}

struct layer_sink {
    int32_t    fd;
    sha256_ctx hash;
    uint64_t   bytes;
};

static int layer_write(void *to, const void *data, size_t len) {
    struct layer_sink *sink = to;
    sha256_update(&sink->hash, data, len);
    sink->bytes += len;
    return lc_kernel_write_all(sink->fd, data, len) < 0 ? -1 : 0;
}

/* What the writing of the layers left out, for the command to say */
static struct {
    uint64_t entries, sockets, attributes_left;
} written;

/*
 * A tree as a layer: written to a file of a name of its own, which is given
 * its digest's when it is whole and on the disk. upper: the tree is an
 * overlay's upper directory, whose marks are written as an image's.
 */
static void blob_of_tree(const char *tree, bool upper, uint32_t uid_start, uint32_t gid_start, struct blob *blob) {
    static tar_writer w;
    struct layer_sink sink = { 0 };
    char fresh[MAX_PATH], path[MAX_PATH];
    uint8_t digest[SHA256_BYTES];

    lc_sysret dirfd = lc_kernel_open_file(tree, O_RDONLY | O_DIRECTORY, 0);
    if (dirfd < 0)
        die2("Error: cannot read the container's files in ", tree);
    blob_path(fresh, ".layer.new");
    lc_sysret fd = lc_kernel_open_file(fresh, O_WRONLY | O_CREAT | LB_O_EXCL, MODE_PRIVATE_FILE);
    if (fd < 0)
        die2("Error: cannot write ", fresh);
    made_file(fresh);

    sink.fd = (int32_t)fd;
    sha256_init(&sink.hash);
    w = (tar_writer){ .sink = layer_write, .to = &sink, .uid_start = uid_start, .gid_start = gid_start,
                      .overlay = upper };
    if (tar_write_tree(&w, (int32_t)dirfd) != 0) {
        print_str(STDERR, "Error: cannot write ");
        print_str(STDERR, tree);
        print_str(STDERR, " as a layer");
        if (w.failed_at[0]) {
            print_str(STDERR, ": ");
            print_str(STDERR, w.failed_at);
        }
        print_str(STDERR, ": ");
        print_str(STDERR, w.failure ? w.failure : "it could not be written");
        lc_print_char(STDERR, '\n');
        fail_now();
    }
    lc_kernel_close_file((int32_t)dirfd);
    lc_sysret rc = lb_sys_fsync((int32_t)fd);
    lc_kernel_close_file((int32_t)fd);
    if (rc < 0)
        die2("Error: the layer is not known to be on the disk: ", fresh);

    sha256_final(&sink.hash, digest);
    sha256_hex(digest, blob->digest);
    blob->size = sink.bytes;
    blob_path(path, blob->digest);
    /* the name it is given is the one that is taken away from here on */
    str_copy_or_die(made.files[made.nfiles - 1], path, MAX_PATH, "a layer of the image");
    if (lb_sys_renameat(AT_FDCWD, fresh, AT_FDCWD, path) < 0) {
        (void)lc_kernel_unlinkat(AT_FDCWD, fresh, 0);
        die2("Error: cannot give the layer its name: ", path);
    }
    written.entries += w.entries;
    written.sockets += w.sockets;
    written.attributes_left += w.attributes_left;
}

/* ─── export ────────────────────────────────────────────────────────────── */

/* Whether a directory is another one or is under it, by what the two are
 * and not by how their paths are written. */
static bool dir_is_under(const char *dir, const char *above) {
    struct lb_statx top, at, before = { 0 };
    if (lb_sys_statx(AT_FDCWD, above, 0, LB_STATX_INO, &top) < 0)
        return false;
    lc_sysret fd = lc_kernel_open_file(dir, LB_O_PATH | O_DIRECTORY, 0);
    bool under = false;
    for (int up = 0; fd >= 0 && up < TAR_PATH_MAX; up++) {
        if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_INO, &at) < 0)
            break;
        under = at.stx_ino == top.stx_ino && at.stx_dev_major == top.stx_dev_major &&
                at.stx_dev_minor == top.stx_dev_minor;
        /* the root is the one directory that is its own parent */
        if (under || (up && at.stx_ino == before.stx_ino && at.stx_dev_major == before.stx_dev_major &&
                      at.stx_dev_minor == before.stx_dev_minor))
            break;
        before = at;
        lc_sysret parent = lc_kernel_open_file_at((int32_t)fd, "..", LB_O_PATH | O_DIRECTORY, 0);
        lc_kernel_close_file((int32_t)fd);
        fd = parent;
    }
    if (fd >= 0)
        lc_kernel_close_file((int32_t)fd);
    return under;
}

/*
 * A directory that is there already is taken when it is the caller's own
 * and has nothing in it, and is from then on its owner's alone, as one that
 * export makes is. A link to a directory is not followed, and another
 * user's is not written into: whoever a directory belongs to can put
 * something else in the place of what is written there, and then it is no
 * longer this command that says what the image is.
 */
static void image_dir_take(const char *dir) {
    struct lb_statx st;
    lc_sysret fd = lc_kernel_open_file(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
    if (fd < 0 && lb_sys_statx(AT_FDCWD, dir, AT_SYMLINK_NOFOLLOW, LB_STATX_TYPE, &st) == 0 &&
        (st.stx_mode & LB_S_IFMT) == LB_S_IFLNK)
        die2("Error: export writes an image into a directory, and this is a link: ", dir);
    if (fd < 0)
        die2("Error: export writes an image into a directory, and this is none: ", dir);
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_UID, &st) < 0 || st.stx_uid != (uint32_t)lb_sys_geteuid())
        die2("Error: export writes an image into a directory of its caller's own, and this is another user's: ", dir);
    /* empty before its mode is touched, and empty still once nobody else can write in it */
    if (dir_is_empty(dir) != 1)
        die2("Error: export writes an image into a directory of its own, and this one is not empty: ", dir);
    if (lb_sys_fchmod((int32_t)fd, MODE_PRIVATE_DIR) < 0)
        die2("Error: cannot make the image's directory its owner's alone: ", dir);
    lc_kernel_close_file((int32_t)fd);
    if (dir_is_empty(dir) != 1)
        die2("Error: export writes an image into a directory of its own, and this one is not empty: ", dir);
}

/* The image's directory, made, or found with nothing in it, and the two
 * inside it that hold the blobs. */
static void image_dir_make(const char *dir) {
    str_copy_or_die(made.dir, dir, MAX_PATH, "the image's directory");
    if (!path_join(made.blobs, MAX_PATH, dir, "blobs") || !path_join(made.sha256, MAX_PATH, made.blobs, "sha256"))
        die2("Error: the path of the image's directory is too long: ", dir);
    on_failure(export_undo);

    lc_sysret rc = lc_kernel_mkdirat(AT_FDCWD, dir, MODE_PRIVATE_DIR);
    if (rc == 0) {
        made.made_dir = true;
    } else if (rc != -LB_EEXIST) {
        die2("Error: cannot make the image's directory, which has to be in one that is there: ", dir);
    } else {
        image_dir_take(dir);
    }

    /* an image inside what it is an image of would be read while it is written */
    char bases[MAX_PATH];
    bases_dir_path(bases);
    if (dir_is_under(dir, cfg_global.container_dir) || dir_is_under(dir, bases))
        die2("Error: export does not write an image among lightbox's own files: ", dir);

    if (lc_kernel_mkdirat(AT_FDCWD, made.blobs, MODE_PRIVATE_DIR) < 0)
        die2("Error: cannot make ", made.blobs);
    made.made_blobs = true;
    if (lc_kernel_mkdirat(AT_FDCWD, made.sha256, MODE_PRIVATE_DIR) < 0)
        die2("Error: cannot make ", made.sha256);
    made.made_sha256 = true;
}

static void image_file(const char *name, const char *content) {
    char path[MAX_PATH];
    if (!path_join(path, sizeof(path), made.dir, name))
        die2("Error: the path of the image's directory is too long: ", made.dir);
    made_file(path);
    if (write_file_atomic(path, content, MODE_PRIVATE_FILE) != 0)
        die2("Error: cannot write ", path);
}

static void say_count(const char *before, uint64_t count, const char *after) {
    char digits[24];
    u64_text(digits, count);
    print_str(STDOUT, before);
    print_str(STDOUT, digits);
    print_str(STDOUT, after);
}

void cmd_export(int argc, char **argv) {
    static const char usage[] = "Usage: lightbox export <name> <dir>";
    for (int i = 0; i < argc && i < 2; i++)
        if (argv[i][0] == '-')
            die2("Error: unknown option: ", argv[i]);
    if (argc < 2)
        die(usage);
    if (argc > 2)
        die2(argv[2][0] == '-' ? "Error: unknown option: " : "Error: unexpected argument: ", argv[2]);
    const char *name = argv[0], *dir = argv[1];
    validate_name(name);
    if (!dir[0])
        die(usage);

    /* Held to the end of this process: no start, and no other command that
     * changes the container, comes between its files and their image. */
    container_lock(name);
    char creating[MAX_PATH];
    container_creating_path(creating, name);
    if (path_exists(creating))
        die2("Error: the container was not created completely, and is not exported; remove it with rm: ", name);
    if (is_running(name))
        die2("Error: container is running (stop it first): ", name);

    static container_config cfg;
    container_config_load_or_die(name, &cfg);
    char root[MAX_PATH], lower[MAX_PATH] = "";
    container_root(root, name);
    if (!path_is_directory(root))
        die2("Error: the container has no root filesystem to export: ", name);
    if (cfg.base[0] && (!base_rootfs_path(lower, cfg.base) || !path_is_directory(lower)))
        die2("Error: the base snapshot that the container overlays is not there: ", cfg.base);

    image_dir_make(dir);
    print_str(STDOUT, "Exporting container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "' to ");
    print_str(STDOUT, dir);
    print_str(STDOUT, "...\n");

    /* The layers. The files of a container with --userns that overlays a
     * snapshot are its root's on this host, uid_start and above; an image
     * has them from 0, as the snapshot and a copy have them on the disk. */
    struct blob layers[LAYERS_MAX];
    int nlayers = 0;
    if (cfg.base[0]) {
        struct blob *base = &layers[nlayers++];
        blob_of_tree(lower, false, 0, 0, base);
        char kept[SHA256_HEX + 1];
        uint64_t kept_size;
        if (base_layer_read(cfg.base, kept, &kept_size) && (!streq(kept, base->digest) || kept_size != base->size)) {
            print_str(STDERR, "Warning: the base snapshot ");
            print_str(STDERR, cfg.base);
            print_str(STDERR, " is another layer than it was when it was last written: its files were\n"
                              "changed after it was taken, under every container that overlays it\n");
        }
        if (base_layer_keep(cfg.base, base->digest, base->size) != 0) {
            print_str(STDERR, "Warning: the digest of the base snapshot ");
            print_str(STDERR, cfg.base);
            print_str(STDERR, " could not be kept beside it\n");
        }
        blob_of_tree(root, true, cfg.userns ? cfg.uid_start : 0, cfg.userns ? cfg.gid_start : 0, &layers[nlayers++]);
    } else {
        blob_of_tree(root, false, 0, 0, &layers[nlayers++]);
    }
    uint64_t bytes = 0;
    for (int i = 0; i < nlayers; i++)
        bytes += layers[i].size;

    /* The configuration: what the image is for, and its layers as they are
     * before any compression, which here is as they are. */
    static struct text t;
    struct blob config, manifest;
    t = (struct text){ 0 };
    add(&t, "{\"architecture\":\"" OCI_ARCHITECTURE "\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[");
    for (int i = 0; i < nlayers; i++) {
        add(&t, i ? "," : "");
        add_digest(&t, &layers[i]);
    }
    add(&t, "]}}");
    text_whole(&t, "the image's configuration");
    blob_of_text(&t, &config);

    /* The manifest: the configuration, the layers, and the container's limits */
    t = (struct text){ 0 };
    add(&t, "{\"schemaVersion\":2,\"mediaType\":\"" MEDIA_MANIFEST "\",\"config\":{");
    add_descriptor(&t, MEDIA_CONFIG, &config);
    add(&t, "},\"layers\":[");
    for (int i = 0; i < nlayers; i++) {
        add(&t, i ? ",{" : "{");
        add_descriptor(&t, MEDIA_LAYER, &layers[i]);
        add(&t, "}");
    }
    add(&t, "],\"annotations\":{\"" ANNOTATION "version\":\"" ANNOTATIONS_VERSION "\"");
    add_annotation(&t, "name", name);
    add_annotation(&t, "mem", cfg.mem);
    if (cfg.swap[0])
        add_annotation(&t, "swap", cfg.swap);
    add_annotation(&t, "pids", cfg.pids);
    add_annotation(&t, "cpu", cfg.cpu);
    if (cfg.ttl[0])
        add_annotation(&t, "ttl", cfg.ttl);
    add(&t, "}}");
    text_whole(&t, "the image's manifest");
    blob_of_text(&t, &manifest);
    sync_dir_or_die(made.sha256);
    sync_dir_or_die(made.blobs);

    /* and last what makes the directory an image */
    image_file(OCI_LAYOUT_FILE, OCI_LAYOUT_TEXT);
    t = (struct text){ 0 };
    add(&t, "{\"schemaVersion\":2,\"mediaType\":\"" MEDIA_INDEX "\",\"manifests\":[{");
    add_descriptor(&t, MEDIA_MANIFEST, &manifest);
    add(&t, ",\"platform\":{\"architecture\":\"" OCI_ARCHITECTURE "\",\"os\":\"linux\"}}]}");
    text_whole(&t, "the image's index");
    image_file(OCI_INDEX_FILE, t.bytes);
    char parent[MAX_PATH];
    if (made.made_dir && parent_dir(parent, sizeof(parent), dir))
        sync_dir_or_die(parent);
    on_failure(NULL);

    print_str(STDOUT, "Container '");
    print_str(STDOUT, name);
    print_str(STDOUT, "' exported: ");
    say_count("", (uint64_t)nlayers, nlayers == 1 ? " layer, " : " layers, ");
    say_count("", written.entries, " entries, ");
    say_count("", bytes, " bytes\n");
    print_str(STDOUT, "Image sha256:");
    print_str(STDOUT, manifest.digest);
    lc_print_char(STDOUT, '\n');
    if (written.sockets)
        say_count("Note: ", written.sockets, written.sockets == 1 ? " socket was left out: it is of a process that is gone\n"
                                                                 : " sockets were left out: they are of processes that are gone\n");
    if (written.attributes_left)
        say_count("Note: ", written.attributes_left,
                  written.attributes_left == 1
                      ? " extended attribute was left out: an image has security.capability and user.* alone\n"
                      : " extended attributes were left out: an image has security.capability and user.* alone\n");
}

/* ─── Reading an image (ROADMAP I.6) ────────────────────────────────────── */

/*
 * An image is read before anything is made of it, and all of it: the index,
 * the manifest it names, the configuration and every layer, each blob held
 * to the size and the SHA-256 its descriptor names it by. What is wrong ends
 * the command with the directory and the blob named, and nothing was made.
 *
 * A layer's blob stays open from there, so that what is unpacked later is
 * the file that was looked at; and what is unpacked is held once more, to
 * the digest the configuration names for the layer as it is unpacked, which
 * is the one check that holds for a layer that was compressed and for a file
 * that was changed in between (image_unpack).
 */

#define MEDIA_LAYER_GZIP MEDIA_LAYER "+gzip"
#define MEDIA_TEXT_MAX   128
#define DIGEST_PREFIX    "sha256:"

static char image_text[JSON_TEXT_MAX + 1];      /* the index, then the manifest, then the configuration */

/* A text of an image's as it is said to whoever runs the command: not one
 * with control characters in it, which a terminal would obey. */
static const char *shown(const char *text) {
    return has_control_chars(text) ? "(a text with control characters)" : text;
}

[[noreturn]] static void image_refused(const char *dir, const char *what, const char *detail) {
    print_str(STDERR, "Error: ");
    print_str(STDERR, dir);
    print_str(STDERR, " is no image that import takes: ");
    print_str(STDERR, what);
    if (detail)
        print_str(STDERR, detail);
    lc_print_char(STDERR, '\n');
    fail_now();
}

/* A text of the image's as JSON, with the file or the blob it is and where
 * in it named when it is none. */
static json_value image_json(const char *dir, const char *what, size_t len) {
    json_value root;
    json_refusal why;
    if (json_check(image_text, len, &root, &why) != 0) {
        char line[24], column[24];
        u64_text(line, why.line);
        u64_text(column, why.column);
        print_str(STDERR, "Error: ");
        print_str(STDERR, dir);
        print_str(STDERR, " is no image that import takes: ");
        print_str(STDERR, what);
        print_str(STDERR, " is no JSON, at ");
        print_str(STDERR, line);
        print_str(STDERR, ":");
        print_str(STDERR, column);
        print_str(STDERR, ": ");
        print_str(STDERR, why.why ? why.why : "it is refused");
        lc_print_char(STDERR, '\n');
        fail_now();
    }
    return root;
}

/* The value at a path, or one of no length where there is none. A name
 * there in letters of another case is two things to two readers. */
static json_value image_at(const char *dir, json_value v, const char *path, const char *what) {
    json_value found;
    int there = json_at(v, path, &found);
    if (there < 0) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, dir);
        print_str(STDERR, " is no image that import takes: ");
        print_str(STDERR, what);
        print_str(STDERR, " has a name on the way to ");
        print_str(STDERR, path);
        print_str(STDERR, " in letters of another case, which readers of JSON take two ways\n");
        fail_now();
    }
    return there == 1 ? found : (json_value){ 0 };
}

static bool text_at(const char *dir, json_value v, const char *path, const char *what, char *out, size_t size) {
    json_value found = image_at(dir, v, path, what);
    return found.len != 0 && json_text(found, out, size) >= 0;
}

static bool whole_at(const char *dir, json_value v, const char *path, const char *what, uint64_t *number) {
    json_value found = image_at(dir, v, path, what);
    return found.len != 0 && json_kind_of(found) == JSON_NUMBER && json_whole(found, number);
}

/* "sha256:<64 hex digits>": the digits, or false */
static bool digest_of(const char *text, char digest[SHA256_HEX + 1]) {
    size_t prefix = sizeof(DIGEST_PREFIX) - 1;
    if (lc_string_length(text) != prefix + SHA256_HEX || lc_bytes_compare(text, DIGEST_PREFIX, prefix) != 0 ||
        !sha256_hex_ok(text + prefix))
        return false;
    lc_bytes_copy(digest, text + prefix, SHA256_HEX + 1);
    return true;
}

struct descriptor {
    char     media[MEDIA_TEXT_MAX];
    char     digest[SHA256_HEX + 1];
    uint64_t size;
};

/* What names a blob: its media type, its digest and its size */
static void descriptor_at(const char *dir, json_value v, const char *what, struct descriptor *d) {
    char digest[sizeof(DIGEST_PREFIX) + SHA256_HEX + 1];
    if (json_kind_of(v) != JSON_OBJECT || !text_at(dir, v, "/mediaType", what, d->media, sizeof(d->media)))
        image_refused(dir, what, " is named without a media type");
    if (!text_at(dir, v, "/digest", what, digest, sizeof(digest)) || !digest_of(digest, d->digest))
        image_refused(dir, what, " is named by what is no SHA-256");
    if (!whole_at(dir, v, "/size", what, &d->size) || d->size > (uint64_t)INT64_MAX)
        image_refused(dir, what, " is named without a size");
}

/* A file of the image's own directory, which is no blob: its text, and its length */
static size_t image_file_read(const char *dir, int32_t dirfd, const char *name) {
    struct lb_statx st;
    lc_sysret fd = lc_kernel_open_file_at(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0)
        image_refused(dir, "it has no ", name);
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE, &st) < 0 || (st.stx_mode & LB_S_IFMT) != LB_S_IFREG)
        image_refused(dir, "it has no file ", name);
    lc_sysret n = lc_kernel_read_all((int32_t)fd, image_text, sizeof(image_text));
    lc_kernel_close_file((int32_t)fd);
    if (n < 0 || (size_t)n > JSON_TEXT_MAX)
        image_refused(dir, name, " cannot be read, or is longer than is read");
    return (size_t)n;
}

/*
 * The blob a descriptor names, held to it: a regular file in blobs/sha256,
 * of that size, whose bytes have that SHA-256. With text, a blob that is
 * JSON, its bytes are in image_text and the descriptor is closed again; a
 * layer's stays open, and is given back.
 */
static int32_t blob_held(const char *dir, int32_t blobs, const char *what, const struct descriptor *d, bool text) {
    static uint8_t piece[65536];
    struct lb_statx st;
    sha256_ctx hash;
    uint8_t digest[SHA256_BYTES];
    char hex[SHA256_HEX + 1];

    lc_sysret fd = lc_kernel_open_file_at(blobs, d->digest, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0)
        image_refused(dir, what, " is not among its blobs");
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE | LB_STATX_SIZE, &st) < 0 ||
        (st.stx_mode & LB_S_IFMT) != LB_S_IFREG)
        image_refused(dir, what, " is no regular file");
    if (st.stx_size != d->size)
        image_refused(dir, what, " has another size than it is named with");
    if (text && d->size > JSON_TEXT_MAX)
        image_refused(dir, what, " is longer than is read");

    sha256_init(&hash);
    uint64_t left = d->size;
    while (left) {
        size_t want = left < sizeof(piece) ? (size_t)left : sizeof(piece);
        lc_sysret n = lc_kernel_read_retry((int32_t)fd, text ? (void *)(image_text + (d->size - left)) : (void *)piece, want);
        if (n <= 0)
            image_refused(dir, what, " cannot be read to its end");
        sha256_update(&hash, text ? (const void *)(image_text + (d->size - left)) : (const void *)piece, (size_t)n);
        left -= (uint64_t)n;
    }
    sha256_final(&hash, digest);
    sha256_hex(digest, hex);
    if (!streq(hex, d->digest))
        image_refused(dir, what, " is not what it is named by: its bytes have another SHA-256");
    if (text) {
        lc_kernel_close_file((int32_t)fd);
        return -1;
    }
    return (int32_t)fd;
}

static void note(const char *before, const char *subject, const char *after) {
    print_str(STDOUT, "Note: ");
    print_str(STDOUT, before);
    print_str(STDOUT, subject);
    print_str(STDOUT, after);
    lc_print_char(STDOUT, '\n');
}

/*
 * What the manifest says of the container, under ac.ozkr.lightbox.: the five
 * limits are taken, each when it is one as an option would give it; the
 * name is kept, to be said. Anything else under that name, whatever it asks
 * for, is said and not taken, and so is all of it when its version is not
 * the one this lightbox writes.
 */
static void annotations_read(const char *dir, json_value manifest, image *img) {
    json_value all = image_at(dir, manifest, "/annotations", "the manifest");
    if (all.len == 0)
        return;
    if (json_kind_of(all) != JSON_OBJECT)
        image_refused(dir, "the manifest", " has annotations that are no object");

    char version[16] = "";
    bool said_version = false;
    size_t prefix = sizeof(ANNOTATION) - 1;
    json_item item;
    for (bool more = json_first(all, &item); more; more = json_next(&item)) {
        char name[sizeof(ANNOTATION) + 64], value[128];
        if (json_text(item.name, name, sizeof(name)) < 0) {
            /* too long to be one of lightbox's, unless it begins as one */
            if (item.name.len > prefix + 1 && lc_bytes_compare(item.name.text + 1, ANNOTATION, prefix) == 0)
                note("the image has an annotation under " ANNOTATION, " with a name longer than any import knows", ", which is not taken");
            continue;
        }
        if (lc_string_length(name) <= prefix || lc_bytes_compare(name, ANNOTATION, prefix) != 0)
            continue;
        const char *key = name + prefix;
        bool is_text = json_kind_of(item.value) == JSON_STRING && json_text(item.value, value, sizeof(value)) >= 0 &&
                       !has_control_chars(value);
        int64_t ms;
        int quota;
        char *into = NULL;
        size_t size = 0;
        bool ok = false;
        if (streq(key, "version")) {
            into = version, size = sizeof(version), ok = is_text;
            said_version = true;
        } else if (streq(key, "name")) {
            into = img->name, size = sizeof(img->name), ok = is_text && name_is_valid(value);
        } else if (streq(key, "mem")) {
            into = img->mem, size = sizeof(img->mem), ok = is_text && mem_limit_ok(value);
        } else if (streq(key, "swap")) {
            into = img->swap, size = sizeof(img->swap), ok = is_text && swap_limit_ok(value);
        } else if (streq(key, "pids")) {
            into = img->pids, size = sizeof(img->pids), ok = is_text && pids_limit_ok(value);
        } else if (streq(key, "cpu")) {
            into = img->cpu, size = sizeof(img->cpu), ok = is_text && parse_cpu_limit(value, &quota);
        } else if (streq(key, "ttl")) {
            into = img->ttl, size = sizeof(img->ttl), ok = is_text && parse_duration_ms(value, &ms);
        }
        if (!into)
            note("the image says ", shown(name), ", which import does not take: what a container may do is said here");
        else if (!ok || !str_copy(into, value, size))
            note("the image says ", shown(name), " with what is no such value, which is not taken");
    }
    if (said_version && !streq(version, ANNOTATIONS_VERSION)) {
        note("the image's annotations are of the version ", version[0] ? shown(version) : "(none that is read)",
             ", and this lightbox reads " ANNOTATIONS_VERSION ": none of them is taken");
        img->name[0] = img->mem[0] = img->swap[0] = img->pids[0] = img->cpu[0] = img->ttl[0] = '\0';
    }
    /* a container that export wrote says so, and no other image is taken for one */
    img->lightbox = said_version && streq(version, ANNOTATIONS_VERSION);
}

bool image_layout_at(const char *dir) {
    static const char *const parts[] = { OCI_LAYOUT_FILE, OCI_INDEX_FILE, "blobs" };
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        char path[MAX_PATH];
        if (!path_join(path, sizeof(path), dir, parts[i]) || !path_exists(path))
            return false;
    }
    return true;
}

void image_open(const char *dir, image *img) {
    struct descriptor named, config;
    char text[MEDIA_TEXT_MAX];
    uint64_t number;

    *img = (image){ 0 };
    str_copy_or_die(img->dir, dir, sizeof(img->dir), "the image's directory");
    lc_sysret dirfd = lc_kernel_open_file(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dirfd < 0)
        die2("Error: there is no directory with an image at ", dir);
    lc_sysret between = lc_kernel_open_file_at((int32_t)dirfd, "blobs", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    lc_sysret blobs = between < 0 ? between
        : lc_kernel_open_file_at((int32_t)between, "sha256", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (between >= 0)
        lc_kernel_close_file((int32_t)between);

    /* that it is an image layout, and of the one version there is */
    json_value v = image_json(dir, OCI_LAYOUT_FILE, image_file_read(dir, (int32_t)dirfd, OCI_LAYOUT_FILE));
    if (!text_at(dir, v, "/imageLayoutVersion", OCI_LAYOUT_FILE, text, sizeof(text)) || !streq(text, "1.0.0"))
        image_refused(dir, OCI_LAYOUT_FILE, " does not say that it is an image layout of version 1.0.0");
    if (blobs < 0)
        image_refused(dir, "it has no directory blobs/sha256", NULL);

    /* the index: one manifest */
    v = image_json(dir, OCI_INDEX_FILE, image_file_read(dir, (int32_t)dirfd, OCI_INDEX_FILE));
    lc_kernel_close_file((int32_t)dirfd);
    json_value manifests = image_at(dir, v, "/manifests", OCI_INDEX_FILE);
    if (!whole_at(dir, v, "/schemaVersion", OCI_INDEX_FILE, &number) || number != 2 || json_kind_of(manifests) != JSON_ARRAY)
        image_refused(dir, OCI_INDEX_FILE, " is no image index of schema 2");
    if (json_count(manifests) != 1)
        image_refused(dir, OCI_INDEX_FILE, json_count(manifests) ? " names more than one image, and import takes a directory with one"
                                                                 : " names no image");
    json_item only;
    if (!json_first(manifests, &only))
        image_refused(dir, OCI_INDEX_FILE, " names no image");
    descriptor_at(dir, only.value, "the manifest", &named);
    if (streq(named.media, MEDIA_INDEX))
        image_refused(dir, OCI_INDEX_FILE, " names an index of images and no image, which is not read");
    if (!streq(named.media, MEDIA_MANIFEST))
        image_refused(dir, "the manifest is of a type that is not read: ", shown(named.media));
    lc_bytes_copy(img->manifest, named.digest, sizeof(img->manifest));

    /* the manifest: the configuration, the layers and the annotations */
    (void)blob_held(dir, (int32_t)blobs, "the manifest", &named, true);
    v = image_json(dir, "the manifest", (size_t)named.size);
    if (!whole_at(dir, v, "/schemaVersion", "the manifest", &number) || number != 2)
        image_refused(dir, "the manifest", " is no image manifest of schema 2");
    if (image_at(dir, v, "/mediaType", "the manifest").len != 0 &&
        (!text_at(dir, v, "/mediaType", "the manifest", text, sizeof(text)) || !streq(text, MEDIA_MANIFEST)))
        image_refused(dir, "the manifest", " says it is of another type than the index names it with");
    descriptor_at(dir, image_at(dir, v, "/config", "the manifest"), "the configuration", &config);
    if (!streq(config.media, MEDIA_CONFIG))
        image_refused(dir, "the configuration is of a type that is not read: ", shown(config.media));
    json_value layers = image_at(dir, v, "/layers", "the manifest");
    size_t count = json_kind_of(layers) == JSON_ARRAY ? json_count(layers) : 0;
    if (count == 0 || count > IMAGE_LAYERS_MAX)
        image_refused(dir, "the manifest", count ? " names more layers than are read, which is " STRINGIFY(IMAGE_LAYERS_MAX)
                                                 : " names no layers");
    static struct descriptor of_layer[IMAGE_LAYERS_MAX];
    json_item item;
    for (bool more = json_first(layers, &item); more; more = json_next(&item)) {
        struct descriptor *d = &of_layer[img->nlayers];
        image_layer *layer = &img->layers[img->nlayers++];
        descriptor_at(dir, item.value, "a layer", d);
        layer->gzip = streq(d->media, MEDIA_LAYER_GZIP);
        if (!layer->gzip && !streq(d->media, MEDIA_LAYER))
            image_refused(dir, "it has a layer of a type that is not read: ", shown(d->media));
        lc_bytes_copy(layer->digest, d->digest, sizeof(layer->digest));
        layer->size = d->size;
        layer->fd = -1;
    }
    annotations_read(dir, v, img);

    /* the configuration: what the image is for, and each layer as it is unpacked */
    (void)blob_held(dir, (int32_t)blobs, "the configuration", &config, true);
    v = image_json(dir, "the configuration", (size_t)config.size);
    char os[32], arch[32];
    if (!text_at(dir, v, "/os", "the configuration", os, sizeof(os)) ||
        !text_at(dir, v, "/architecture", "the configuration", arch, sizeof(arch)))
        image_refused(dir, "the configuration", " does not say what the image is for");
    if (!streq(os, "linux") || !streq(arch, OCI_ARCHITECTURE)) {
        print_str(STDERR, "Error: ");
        print_str(STDERR, dir);
        print_str(STDERR, " is an image for ");
        print_str(STDERR, shown(os));
        print_str(STDERR, " on ");
        print_str(STDERR, shown(arch));
        print_str(STDERR, ", and this lightbox runs linux on " OCI_ARCHITECTURE ": nothing in it would run\n");
        fail_now();
    }
    /* A command to start is the image's word for what a container of
     * lightbox's has /init.sh for: it is not read, and that it is there is
     * said. A name in letters of another case is nothing to refuse here. */
    static const char *const commands[] = { "/config/Entrypoint", "/config/Cmd" };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        json_value found;
        if (json_at(v, commands[i], &found) == 1 && json_kind_of(found) == JSON_ARRAY && json_count(found) > 0)
            img->command = true;
    }
    json_value ids = image_at(dir, v, "/rootfs/diff_ids", "the configuration");
    if (!text_at(dir, v, "/rootfs/type", "the configuration", text, sizeof(text)) || !streq(text, "layers") ||
        json_kind_of(ids) != JSON_ARRAY || json_count(ids) != (size_t)img->nlayers)
        image_refused(dir, "the configuration", " does not name the manifest's layers as they are unpacked");
    int n = 0;
    for (bool more = json_first(ids, &item); more; more = json_next(&item), n++) {
        char digest[sizeof(DIGEST_PREFIX) + SHA256_HEX + 1];
        image_layer *layer = &img->layers[n];
        if (json_text(item.value, digest, sizeof(digest)) < 0 || !digest_of(digest, layer->diff_id))
            image_refused(dir, "the configuration", " names a layer by what is no SHA-256");
        /* one that is not compressed is unpacked as it is */
        if (!layer->gzip && !streq(layer->diff_id, layer->digest))
            image_refused(dir, "the configuration", " names another layer than the manifest, for one that is not compressed");
    }

    /* and every layer, which stays open */
    for (int i = 0; i < img->nlayers; i++)
        img->layers[i].fd = blob_held(dir, (int32_t)blobs, "a layer", &of_layer[i], false);
    lc_kernel_close_file((int32_t)blobs);
}

void image_layers_text(const image *img, int count, char out[BASE_IMAGE_TEXT_MAX]) {
    bool cut = false;
    size_t pos = 0;
    out[0] = '\0';
    for (int i = 0; i < count && i < img->nlayers; i++) {
        pos = str_append(out, pos, DIGEST_PREFIX, BASE_IMAGE_TEXT_MAX, &cut);
        pos = str_append(out, pos, img->layers[i].diff_id, BASE_IMAGE_TEXT_MAX, &cut);
        pos = str_append(out, pos, "\n", BASE_IMAGE_TEXT_MAX, &cut);
    }
    if (cut)
        die("Error: an image's layers do not fit in the record of a snapshot");
}

/* ─── Unpacking ─────────────────────────────────────────────────────────── */

static int64_t layer_read(void *from, void *data, size_t len) {
    return lc_kernel_read_retry(*(const int32_t *)from, data, len);
}

/*
 * The host's gzip, given a layer's blob to read and a pipe to write what it
 * unpacks into: its process, or less than 0. It has those two and the
 * command's standard error, and runs as sandbox_host_tool leaves it, as it
 * reads what somebody else wrote. *out is the pipe's other end.
 */
static lc_sysret gzip_start(int32_t blob, int32_t *out) {
    static const char *const argv[] = { "gzip", "-dc", NULL };
    int32_t pipe[2];
    if (lc_kernel_create_pipe(pipe, O_CLOEXEC) < 0)
        return -1;
    lc_sysret pid = lc_kernel_fork();
    if (pid < 0) {
        lc_kernel_close_file(pipe[0]);
        lc_kernel_close_file(pipe[1]);
        return pid;
    }
    if (pid == 0) {
        uint64_t no_signals = 0;
        lc_kernel_set_signal_mask(LC_SIG_SETMASK, &no_signals, NULL);
        on_failure(NULL);
        if (lc_kernel_duplicate_fd(blob, STDIN, 0) < 0 || lc_kernel_duplicate_fd(pipe[1], STDOUT, 0) < 0 ||
            lb_sys_close_range(STDERR + 1, ~0u, 0) < 0)
            die("Error: cannot give gzip the layer and a pipe, and nothing else");
        sandbox_host_tool();
        lc_sysret failed = exec_program(tool_path_gzip(), argv, TOOL_ENV);
        (void)failed;
        print_str(STDERR, "Error: cannot run gzip to unpack a layer that is compressed\n");
        lc_kernel_exit(127);
    }
    lc_kernel_close_file(pipe[1]);
    *out = pipe[0];
    return pid;
}

int image_unpack(const image *img, int first, int count, const char *dir, tar_into into, uint32_t uid_start,
                 uint32_t gid_start, image_unpacked *total) {
    static tar_reader r;
    lc_sysret dirfd = lc_kernel_open_file(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (dirfd < 0) {
        print_str(STDERR, "Error: cannot open the directory an image is unpacked into\n");
        return -1;
    }
    int rc = 0;
    for (int i = first; rc == 0 && i < first + count && i < img->nlayers; i++) {
        const image_layer *layer = &img->layers[i];
        char number[24], hex[SHA256_HEX + 1];
        int32_t source = layer->fd, status = 0;
        lc_sysret gzip = 0;
        u64_text(number, (uint64_t)i + 1);
        if (lc_kernel_seek_position(layer->fd, 0, 0) != 0) {
            print_str(STDERR, "Error: cannot read layer ");
            print_str(STDERR, number);
            print_str(STDERR, " from its beginning\n");
            rc = -1;
            break;
        }
        if (layer->gzip && (gzip = gzip_start(layer->fd, &source)) < 0) {
            print_str(STDERR, "Error: cannot start gzip to unpack layer ");
            print_str(STDERR, number);
            lc_print_char(STDERR, '\n');
            rc = -1;
            break;
        }

        r = (tar_reader){ .source = layer_read, .from = &source, .uid_start = uid_start, .gid_start = gid_start,
                          .into = into };
        int unpacked = tar_read_tree(&r, (int32_t)dirfd);
        bool gzip_failed = false;
        if (layer->gzip) {
            /* closed first: a gzip that still writes then ends, and does not wait for a reader */
            lc_kernel_close_file(source);
            gzip_failed = wait_child((int32_t)gzip, &status) < 0 || exit_code_from_status(status) != 0;
        }
        sha256_hex(r.digest, hex);
        if (unpacked != 0) {
            print_str(STDERR, "Error: layer ");
            print_str(STDERR, number);
            print_str(STDERR, " of the image cannot be unpacked");
            if (r.failed_at[0]) {
                print_str(STDERR, ": ");
                print_str(STDERR, r.failed_at);
            }
            print_str(STDERR, ": ");
            print_str(STDERR, r.failure ? r.failure : "it could not be read");
            lc_print_char(STDERR, '\n');
            rc = -1;
        } else if (gzip_failed) {
            print_str(STDERR, "Error: gzip did not unpack layer ");
            print_str(STDERR, number);
            print_str(STDERR, " of the image to its end\n");
            rc = -1;
        } else if (!streq(hex, layer->diff_id)) {
            print_str(STDERR, "Error: layer ");
            print_str(STDERR, number);
            print_str(STDERR, " of the image is, as it was unpacked, not the layer its configuration names\n");
            rc = -1;
        } else if (total) {
            total->entries += r.entries;
            total->devices += r.devices;
            total->attributes_left += r.attributes_left;
            total->bytes += r.bytes;
        }
    }
    lc_kernel_close_file((int32_t)dirfd);
    return rc;
}

void image_notes(const image *img, const image_unpacked *unpacked) {
    char count[24];
    if (unpacked->devices) {
        u64_text(count, unpacked->devices);
        note(count, unpacked->devices == 1 ? " device of the image's was not made" : " devices of the image's were not made",
             ": a container's devices are lightbox's to give");
    }
    if (unpacked->attributes_left) {
        u64_text(count, unpacked->attributes_left);
        note(count, unpacked->attributes_left == 1 ? " extended attribute of the image's was not set"
                                                   : " extended attributes of the image's were not set", "");
    }
    if (img->command)
        note("the image names a command to start, which lightbox does not read", "",
             ": a container starts its /init.sh, where it has one");
}

int image_base(const image *img, int count, char id[BASE_ID_TEXT], bool *took, image_unpacked *total) {
    static char layers[BASE_IMAGE_TEXT_MAX];
    *took = false;
    image_layers_text(img, count, layers);
    if (base_of_layers(layers, id))
        return 0;

    /* its source line is no path: what it was unpacked from */
    char source[sizeof(DIGEST_PREFIX) + SHA256_HEX + 32], fresh[MAX_PATH], rootfs[MAX_PATH];
    bool cut = false;
    size_t pos = str_append(source, 0, DIGEST_PREFIX, sizeof(source), &cut);
    pos = str_append(source, pos, img->layers[0].diff_id, sizeof(source), &cut);
    if (count > 1)
        (void)str_append(source, pos, " and the layers over it", sizeof(source), &cut);
    if (cut || base_begin(source, id, fresh) != 0)
        return -1;
    if (!path_join(rootfs, sizeof(rootfs), fresh, "rootfs") || lc_kernel_mkdirat(AT_FDCWD, rootfs, 0755) < 0 ||
        image_unpack(img, 0, count, rootfs, TAR_INTO_TREE, 0, 0, total) != 0 || base_image_keep(fresh, layers) != 0) {
        require_rm_rf(fresh);
        return -1;
    }
    if (base_commit(id, fresh) != 0)
        return -1;
    *took = true;
    return 0;
}
