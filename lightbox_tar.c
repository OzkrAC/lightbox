#include "lightbox.h"

#include <lightc/memory.h>

/*
 * tar, as the layers of an image have it (ROADMAP I.2): the writer.
 *
 * One tree gives one archive, byte for byte, whenever and wherever it is
 * written, so that a layer has one digest: a registry then sees that it has
 * the layer already, and an archive written after an import can be compared
 * with the one that was imported. What makes it so:
 *
 *   - a directory's entries are written in the order of their names' bytes,
 *     each directory's own before the next name beside it;
 *   - a header has the ids as numbers and no names of users or groups, times
 *     in whole seconds, and nothing of when or by whom the archive was made;
 *   - what a ustar header cannot hold goes before it as pax records, always
 *     in one order: the attributes by name, then path, linkpath, size, uid
 *     and gid.
 *
 * The tree is walked by descriptors: every name is looked up in the
 * directory it was read from, and never through a path put together here.
 *
 * An overlay's upper directory is written the way an image has it: what the
 * overlay marks as taken out of its base, a character device 0:0, becomes an
 * empty file .wh.<name>, and a directory that hides its base's, with the
 * attribute overlay.opaque, gets a file .wh..wh..opq in it.
 */

#define TAR_BLOCK        512
#define USTAR_NAME_MAX   100                /* a name or a link in a header */
#define USTAR_ID_MAX     2097151ull         /* 7 octal digits */
#define USTAR_SIZE_MAX   8589934591ull      /* 11 octal digits */
#define XATTR_LIST_MAX   65536              /* the kernel's limits (linux/limits.h) */
#define XATTR_VALUE_MAX  65536
#define COPY_PAGES       16
#define COPY_BUFFER      (COPY_PAGES * LC_PAGE_SIZE)
#define WHITEOUT_PREFIX  ".wh."
#define OPAQUE_MARK      ".wh..wh..opq"
#define PAX_HEADER_NAME  "././@PaxHeader"

/* struct linux_dirent64, as getdents64 fills a buffer with it: d_ino and
 * d_off, 8 bytes each, then these. */
#define TAR_DIRENT_RECLEN 16    /* uint16_t */
#define TAR_DIRENT_NAME   19    /* NUL-terminated */

/* Memory that grows, in pages from the kernel: lightbox has no heap. */
struct mem {
    void  *data;
    size_t used;
    size_t pages;
};

static bool mem_room(struct mem *m, size_t more) {
    size_t need = m->used + more;
    if (need < m->used)
        return false;
    if (need <= m->pages * LC_PAGE_SIZE)
        return true;
    size_t pages = m->pages ? m->pages : 4;
    while (pages * LC_PAGE_SIZE < need) {
        if (pages > ((size_t)1 << 40))
            return false;
        pages *= 2;
    }
    lc_result_ptr got = lc_allocate_pages(pages);
    if (lc_ptr_is_err(got))
        return false;
    if (m->data) {
        lc_bytes_copy(got.value, m->data, m->used);
        lc_free_pages(m->data, m->pages);
    }
    m->data = got.value;
    m->pages = pages;
    return true;
}

static void mem_free(struct mem *m) {
    if (m->data)
        lc_free_pages(m->data, m->pages);
    m->data = NULL;
    m->used = m->pages = 0;
}

/* A file that has several names: where the first of them was written. */
struct link {
    uint64_t ino;
    uint32_t dev_major, dev_minor;
    uint32_t name;          /* in link_names */
    uint32_t next;          /* 1 + the index of the next in its bucket, or 0 */
};
#define LINK_BUCKETS 1024

struct out {
    tar_writer *w;
    size_t      len;                    /* of path */
    char        path[TAR_PATH_MAX];     /* the name of the entry in hand, from the tree's root */
    char        target[TAR_PATH_MAX];   /* what a symbolic link names */
    struct mem  pax;                    /* the records of the entry in hand */
    struct mem  links, link_names;
    uint32_t    link_heads[LINK_BUCKETS];
    uint8_t    *buffer;                 /* COPY_BUFFER bytes: a directory's entries, a file's content */
    char       *xattr_names;            /* XATTR_LIST_MAX bytes */
    char       *xattr_value;            /* XATTR_VALUE_MAX bytes */
};

/* what a header says of an entry */
struct entry {
    char        type;           /* a ustar typeflag */
    uint32_t    mode;           /* the permission bits */
    uint64_t    uid, gid;
    uint64_t    size;           /* of what follows the header */
    int64_t     mtime;
    const char *link;           /* what a link names, or NULL */
    uint32_t    dev_major, dev_minor;
};

/* The first failure is the one that is said: what, and at which entry. */
static int fail(struct out *o, const char *why) {
    tar_writer *w = o->w;
    if (!w->failure) {
        w->failure = why;
        lc_bytes_copy(w->failed_at, o->path, o->len);
        w->failed_at[o->len] = '\0';
    }
    return -1;
}

static int emit(struct out *o, const void *data, size_t len) {
    if (o->w->sink(o->w->to, data, len) != 0)
        return fail(o, "the archive could not be written");
    return 0;
}

/* zeros up to the end of the block that size bytes end in */
static int emit_padding(struct out *o, uint64_t size) {
    static const uint8_t zeros[TAR_BLOCK];
    size_t over = (size_t)(size % TAR_BLOCK);
    return over ? emit(o, zeros, TAR_BLOCK - over) : 0;
}

static int text_compare(const char *a, const char *b) {
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    while (*x && *x == *y) {
        x++;
        y++;
    }
    return (int)*x - (int)*y;
}

static bool starts_with(const char *text, const char *prefix) {
    while (*prefix)
        if (*text++ != *prefix++)
            return false;
    return true;
}

/* ─── Headers ───────────────────────────────────────────────────────────── */

/* A number in a header's field: octal digits, zeros before them, and a NUL. */
static void put_octal(uint8_t *field, size_t width, uint64_t value) {
    field[width - 1] = '\0';
    for (size_t i = width - 1; i-- > 0; value >>= 3)
        field[i] = (uint8_t)('0' + (value & 7));
}

static size_t decimal_digits(uint64_t n) {
    size_t digits = 1;
    for (; n >= 10; n /= 10)
        digits++;
    return digits;
}

static size_t put_decimal(char *out, uint64_t value) {
    size_t digits = decimal_digits(value);
    for (size_t i = digits; i-- > 0; value /= 10)
        out[i] = (char)('0' + value % 10);
    return digits;
}

/* A pax record, "<length> <key><key_rest>=<value>\n", in which the length
 * counts all of it, itself too. */
static bool pax_add(struct out *o, const char *key, const char *key_rest, const void *value, size_t value_len) {
    size_t key_len = lc_string_length(key), rest_len = lc_string_length(key_rest);
    size_t after = 1 + key_len + rest_len + 1 + value_len + 1;
    size_t len = after + decimal_digits(after);
    while (after + decimal_digits(len) != len)
        len = after + decimal_digits(len);
    if (!mem_room(&o->pax, len))
        return false;
    char *at = (char *)o->pax.data + o->pax.used;
    at += put_decimal(at, len);
    *at++ = ' ';
    lc_bytes_copy(at, key, key_len);
    at += key_len;
    lc_bytes_copy(at, key_rest, rest_len);
    at += rest_len;
    *at++ = '=';
    lc_bytes_copy(at, value, value_len);
    at[value_len] = '\n';
    o->pax.used += len;
    return true;
}

/* A header block, with its checksum: the sum of its bytes, taken with the
 * checksum's own field as spaces. */
static void fill_block(uint8_t block[TAR_BLOCK], const char *name, size_t name_len, const struct entry *e) {
    size_t link_len = e->link ? lc_string_length(e->link) : 0;
    lc_bytes_fill(block, 0, TAR_BLOCK);
    lc_bytes_copy(block, name, name_len < USTAR_NAME_MAX ? name_len : USTAR_NAME_MAX);
    put_octal(block + 100, 8, e->mode);
    put_octal(block + 108, 8, e->uid > USTAR_ID_MAX ? 0 : e->uid);
    put_octal(block + 116, 8, e->gid > USTAR_ID_MAX ? 0 : e->gid);
    put_octal(block + 124, 12, e->size > USTAR_SIZE_MAX ? 0 : e->size);
    put_octal(block + 136, 12, e->mtime > 0 ? (uint64_t)e->mtime : 0);
    block[156] = (uint8_t)e->type;
    if (link_len)
        lc_bytes_copy(block + 157, e->link, link_len < USTAR_NAME_MAX ? link_len : USTAR_NAME_MAX);
    lc_bytes_copy(block + 257, "ustar\0" "00", 8);
    if (e->type == '3' || e->type == '4') {
        put_octal(block + 329, 8, e->dev_major);
        put_octal(block + 337, 8, e->dev_minor);
    }
    lc_bytes_fill(block + 148, ' ', 8);
    uint32_t sum = 0;
    for (size_t i = 0; i < TAR_BLOCK; i++)
        sum += block[i];
    put_octal(block + 148, 7, sum);
}

/* The header of the entry whose name is in path, after the pax records it
 * needs: those in hand, which are its attributes, and one for each field of
 * its own that does not fit. */
static int put_header(struct out *o, const struct entry *e) {
    size_t link_len = e->link ? lc_string_length(e->link) : 0;
    char number[24];
    bool whole = true;
    if (o->len > USTAR_NAME_MAX)
        whole = whole && pax_add(o, "path", "", o->path, o->len);
    if (link_len > USTAR_NAME_MAX)
        whole = whole && pax_add(o, "linkpath", "", e->link, link_len);
    if (e->size > USTAR_SIZE_MAX)
        whole = whole && pax_add(o, "size", "", number, put_decimal(number, e->size));
    if (e->uid > USTAR_ID_MAX)
        whole = whole && pax_add(o, "uid", "", number, put_decimal(number, e->uid));
    if (e->gid > USTAR_ID_MAX)
        whole = whole && pax_add(o, "gid", "", number, put_decimal(number, e->gid));
    if (!whole)
        return fail(o, "there is no memory for its header");

    uint8_t block[TAR_BLOCK];
    if (o->pax.used) {
        struct entry records = { .type = 'x', .mode = 0644, .size = o->pax.used };
        fill_block(block, PAX_HEADER_NAME, sizeof(PAX_HEADER_NAME) - 1, &records);
        size_t used = o->pax.used;
        o->pax.used = 0;
        if (emit(o, block, TAR_BLOCK) != 0 || emit(o, o->pax.data, used) != 0 || emit_padding(o, used) != 0)
            return -1;
    }
    fill_block(block, o->path, o->len, e);
    o->w->entries++;
    return emit(o, block, TAR_BLOCK);
}

/* ─── Attributes ────────────────────────────────────────────────────────── */

/* overlayfs's own, as root's mounts have them and as one mounted with
 * userxattr has them */
static bool attribute_is_overlays(const char *name) {
    return starts_with(name, "trusted.overlay.") || starts_with(name, "user.overlay.");
}

static bool attribute_is_carried(const char *name) {
    return streq(name, "security.capability") || (starts_with(name, "user.") && !attribute_is_overlays(name));
}

/* The value of an attribute into xattr_value: its length, -1 for one that
 * is gone again, or -2 once a failure is said. */
static int64_t attribute_value(struct out *o, int32_t fd, const char *name) {
    lc_sysret n = lb_sys_fgetxattr(fd, name, o->xattr_value, XATTR_VALUE_MAX);
    if (n == -LB_ENODATA)
        return -1;
    if (n < 0) {
        (void)fail(o, "has an attribute that cannot be read");
        return -2;
    }
    return n;
}

/*
 * The attributes of an open file or directory: those an archive carries
 * become pax records, in the order of their names; an overlay's own say
 * whether a directory is opaque; the others are counted and left.
 */
static int take_attributes(struct out *o, int32_t fd, bool *opaque) {
    *opaque = false;
    lc_sysret listed = lb_sys_flistxattr(fd, o->xattr_names, XATTR_LIST_MAX);
    if (listed == 0 || listed == -LB_EOPNOTSUPP)
        return 0;
    if (listed < 0)
        return fail(o, "has attributes that cannot be listed");
    const char *end = o->xattr_names + listed;
    if (end[-1] != '\0')
        return fail(o, "has attributes that cannot be listed");

    for (const char *name = o->xattr_names; name < end; name += lc_string_length(name) + 1) {
        if (attribute_is_carried(name))
            continue;
        if (!attribute_is_overlays(name)) {
            o->w->attributes_left++;
            continue;
        }
        if (streq(name, "trusted.overlay.opaque") || streq(name, "user.overlay.opaque")) {
            int64_t n = attribute_value(o, fd, name);
            if (n == -2)
                return -1;
            if (n == 1 && o->xattr_value[0] == 'y')
                *opaque = true;
        }
    }

    /* the carried ones, each time the first by name after the one before */
    const char *last = NULL;
    for (;;) {
        const char *next = NULL;
        for (const char *name = o->xattr_names; name < end; name += lc_string_length(name) + 1) {
            if (!attribute_is_carried(name) || (last && text_compare(name, last) <= 0))
                continue;
            if (!next || text_compare(name, next) < 0)
                next = name;
        }
        if (!next)
            return 0;
        last = next;
        int64_t n = attribute_value(o, fd, next);
        if (n == -2)
            return -1;
        if (n >= 0 && !pax_add(o, "SCHILY.xattr.", next, o->xattr_value, (size_t)n))
            return fail(o, "there is no memory for its attributes");
    }
}

/* ─── Entries ───────────────────────────────────────────────────────────── */

static int write_dir(struct out *o, int32_t dirfd);

/* The first name a file with several names was written under, or NULL for
 * one that is seen now, whose name in path is then kept as that. */
static const char *first_name(struct out *o, const struct lb_statx *st, bool *failed) {
    uint32_t *head = &o->link_heads[st->stx_ino % LINK_BUCKETS];
    for (uint32_t at = *head; at; ) {
        const struct link *l = (const struct link *)o->links.data + (at - 1);
        if (l->ino == st->stx_ino && l->dev_major == st->stx_dev_major && l->dev_minor == st->stx_dev_minor)
            return (const char *)o->link_names.data + l->name;
        at = l->next;
    }
    size_t count = o->links.used / sizeof(struct link);
    if (count >= UINT32_MAX - 1 || o->link_names.used > UINT32_MAX - TAR_PATH_MAX ||
        !mem_room(&o->links, sizeof(struct link)) || !mem_room(&o->link_names, o->len + 1)) {
        *failed = true;
        return NULL;
    }
    struct link *l = (struct link *)o->links.data + count;
    l->ino = st->stx_ino;
    l->dev_major = st->stx_dev_major;
    l->dev_minor = st->stx_dev_minor;
    l->name = (uint32_t)o->link_names.used;
    l->next = *head;
    *head = (uint32_t)count + 1;
    lc_bytes_copy((char *)o->link_names.data + o->link_names.used, o->path, o->len + 1);
    o->links.used += sizeof(struct link);
    o->link_names.used += o->len + 1;
    return NULL;
}

/* A regular file: its header, with its attributes before it, and its bytes. */
static int write_regular(struct out *o, int32_t dirfd, const char *name, const struct lb_statx *seen, struct entry *e) {
    lc_sysret fd = lc_kernel_open_file_at(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0);
    if (fd < 0)
        return fail(o, "cannot be opened");
    struct lb_statx st;
    bool opaque;
    int rc = -1;
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE | LB_STATX_INO | LB_STATX_SIZE, &st) < 0 ||
        (st.stx_mode & LB_S_IFMT) != LB_S_IFREG || st.stx_ino != seen->stx_ino) {
        rc = fail(o, "changed while it was read");
    } else if (take_attributes(o, (int32_t)fd, &opaque) == 0) {
        e->size = st.stx_size;
        rc = put_header(o, e);
        for (uint64_t left = e->size; rc == 0 && left; ) {
            size_t want = left < COPY_BUFFER ? (size_t)left : COPY_BUFFER;
            lc_sysret n = lc_kernel_read_retry((int32_t)fd, o->buffer, want);
            if (n < 0)
                rc = fail(o, "cannot be read");
            else if (n == 0)
                rc = fail(o, "became shorter while it was read");
            else if ((rc = emit(o, o->buffer, (size_t)n)) == 0)
                left -= (uint64_t)n;
        }
        if (rc == 0)
            rc = emit_padding(o, e->size);
    }
    lc_kernel_close_file((int32_t)fd);
    return rc;
}

/* A directory: its header, the mark of an overlay's opaque one, and what is
 * in it. */
static int write_subdir(struct out *o, int32_t dirfd, const char *name, const struct lb_statx *seen, struct entry *e) {
    lc_sysret fd = lc_kernel_open_file_at(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0)
        return fail(o, "cannot be opened");
    struct lb_statx st;
    bool opaque;
    int rc = -1;
    if (lb_sys_statx((int32_t)fd, "", LB_AT_EMPTY_PATH, LB_STATX_TYPE | LB_STATX_INO, &st) < 0 ||
        (st.stx_mode & LB_S_IFMT) != LB_S_IFDIR || st.stx_ino != seen->stx_ino) {
        rc = fail(o, "changed while it was read");
    } else if (o->len + sizeof(OPAQUE_MARK) + 1 > TAR_PATH_MAX) {
        rc = fail(o, "has a name too long for an archive");
    } else if (take_attributes(o, (int32_t)fd, &opaque) == 0) {
        o->path[o->len++] = '/';
        o->path[o->len] = '\0';
        rc = put_header(o, e);
        if (rc == 0 && opaque && o->w->overlay) {
            size_t dir_len = o->len;
            struct entry mark = { .type = '0', .mode = 0600, .uid = e->uid, .gid = e->gid, .mtime = e->mtime };
            lc_bytes_copy(o->path + o->len, OPAQUE_MARK, sizeof(OPAQUE_MARK));
            o->len += sizeof(OPAQUE_MARK) - 1;
            rc = put_header(o, &mark);
            o->len = dir_len;
            o->path[dir_len] = '\0';
        }
        if (rc == 0)
            rc = write_dir(o, (int32_t)fd);
    }
    lc_kernel_close_file((int32_t)fd);
    return rc;
}

/* An id as an image has it: less the first of the container's range. */
static bool shifted_id(uint32_t id, uint32_t start, uint64_t *out) {
    if (id < start || (start && id - start >= USERNS_SIZE))
        return false;
    *out = id - start;
    return true;
}

/* The entry of that name in a directory, whose own name, with its slash, is
 * in path. */
static int write_entry(struct out *o, int32_t dirfd, const char *name) {
    size_t name_len = lc_string_length(name);
    if (o->len + sizeof(WHITEOUT_PREFIX) + name_len + 1 > TAR_PATH_MAX)
        return fail(o, "has an entry whose name is too long for an archive");
    lc_bytes_copy(o->path + o->len, name, name_len + 1);
    o->len += name_len;

    struct lb_statx st;
    if (lb_sys_statx(dirfd, name, AT_SYMLINK_NOFOLLOW,
                     LB_STATX_TYPE | LB_STATX_MODE | LB_STATX_NLINK | LB_STATX_UID | LB_STATX_GID |
                     LB_STATX_MTIME | LB_STATX_INO | LB_STATX_SIZE, &st) < 0)
        return fail(o, "cannot be looked at");
    if (starts_with(name, WHITEOUT_PREFIX))
        return fail(o, "has a name that begins with .wh., which in an image marks what a layer removes");

    struct entry e = { .mode = st.stx_mode & 07777u, .mtime = st.stx_mtime_sec };
    if (!shifted_id(st.stx_uid, o->w->uid_start, &e.uid) || !shifted_id(st.stx_gid, o->w->gid_start, &e.gid))
        return fail(o, "belongs to an id outside the container's range");

    switch (st.stx_mode & LB_S_IFMT) {
    case LB_S_IFREG: {
        bool failed = false;
        e.type = '0';
        if (st.stx_nlink > 1 && (e.link = first_name(o, &st, &failed)) != NULL)
            e.type = '1';
        if (failed)
            return fail(o, "there is no memory for the files with several names");
        return e.type == '1' ? put_header(o, &e) : write_regular(o, dirfd, name, &st, &e);
    }
    case LB_S_IFDIR:
        e.type = '5';
        return write_subdir(o, dirfd, name, &st, &e);
    case LB_S_IFLNK: {
        lc_sysret n = lc_kernel_readlinkat(dirfd, name, o->target, TAR_PATH_MAX);
        if (n <= 0)
            return fail(o, "is a link that cannot be read");
        if (n >= TAR_PATH_MAX)
            return fail(o, "is a link to a name too long for an archive");
        o->target[n] = '\0';
        e.type = '2';
        e.mode = 0777;
        e.link = o->target;
        return put_header(o, &e);
    }
    case LB_S_IFCHR:
        if (o->w->overlay && st.stx_rdev_major == 0 && st.stx_rdev_minor == 0) {
            /* taken out of the base: .wh.<name>, in the place of the name */
            size_t dir_len = o->len - name_len;
            lc_bytes_copy(o->path + dir_len, WHITEOUT_PREFIX, sizeof(WHITEOUT_PREFIX) - 1);
            lc_bytes_copy(o->path + dir_len + sizeof(WHITEOUT_PREFIX) - 1, name, name_len + 1);
            o->len += sizeof(WHITEOUT_PREFIX) - 1;
            e.type = '0';
            return put_header(o, &e);
        }
        [[fallthrough]];
    case LB_S_IFBLK:
        e.type = (st.stx_mode & LB_S_IFMT) == LB_S_IFCHR ? '3' : '4';
        e.dev_major = st.stx_rdev_major;
        e.dev_minor = st.stx_rdev_minor;
        return put_header(o, &e);
    case LB_S_IFIFO:
        e.type = '6';
        return put_header(o, &e);
    case LB_S_IFSOCK:
        /* of a process that is gone with the container's last stop */
        o->w->sockets++;
        return 0;
    default:
        return fail(o, "is of a kind that an archive has no entry for");
    }
}

/* the heap of a heapsort: names by their bytes */
static void sift(uint32_t *order, size_t root, size_t end, const char *names) {
    for (;;) {
        size_t child = 2 * root + 1;
        if (child >= end)
            return;
        if (child + 1 < end && text_compare(names + order[child], names + order[child + 1]) < 0)
            child++;
        if (text_compare(names + order[root], names + order[child]) >= 0)
            return;
        uint32_t held = order[root];
        order[root] = order[child];
        order[child] = held;
        root = child;
    }
}

/* What is in a directory, whose name, with its slash, is in path: its
 * entries in the order of their names' bytes. */
static int write_dir(struct out *o, int32_t dirfd) {
    struct mem names = { 0 }, order = { 0 };
    size_t dir_len = o->len;
    int rc = 0;
    for (;;) {
        lc_sysret n = lc_kernel_read_directory(dirfd, o->buffer, COPY_BUFFER);
        if (n < 0)
            rc = fail(o, "is a directory that cannot be read");
        if (n <= 0)
            break;
        for (lc_sysret pos = 0; pos < n && rc == 0; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, o->buffer + pos + TAR_DIRENT_RECLEN, sizeof(reclen));
            if (reclen == 0)
                break;
            const char *name = (const char *)o->buffer + pos + TAR_DIRENT_NAME;
            pos += reclen;
            if (streq(name, ".") || streq(name, ".."))
                continue;
            size_t len = lc_string_length(name) + 1;
            if (names.used > UINT32_MAX - len || !mem_room(&names, len) || !mem_room(&order, sizeof(uint32_t))) {
                rc = fail(o, "is a directory with more entries than there is memory for");
                break;
            }
            lc_bytes_copy((char *)names.data + names.used, name, len);
            ((uint32_t *)order.data)[order.used / sizeof(uint32_t)] = (uint32_t)names.used;
            names.used += len;
            order.used += sizeof(uint32_t);
        }
        if (rc != 0)
            break;
    }

    if (rc == 0 && order.used) {
        uint32_t *sorted = order.data;
        const char *text = names.data;
        size_t count = order.used / sizeof(uint32_t);
        for (size_t i = count / 2; i-- > 0; )
            sift(sorted, i, count, text);
        for (size_t end = count; end-- > 1; ) {
            uint32_t held = sorted[0];
            sorted[0] = sorted[end];
            sorted[end] = held;
            sift(sorted, 0, end, text);
        }
        for (size_t i = 0; i < count && rc == 0; i++) {
            rc = write_entry(o, dirfd, text + sorted[i]);
            /* the directory's own name again, for the next entry or a failure's */
            if (rc == 0) {
                o->len = dir_len;
                o->path[dir_len] = '\0';
            }
        }
    }
    mem_free(&names);
    mem_free(&order);
    return rc;
}

int tar_write_tree(tar_writer *w, int32_t dirfd) {
    static const uint8_t end[2 * TAR_BLOCK];
    struct out o;
    lc_bytes_fill(&o, 0, sizeof(o));
    o.w = w;
    w->entries = w->sockets = w->attributes_left = 0;
    w->failure = NULL;
    w->failed_at[0] = '\0';

    lc_result_ptr buffer = lc_allocate_pages(COPY_PAGES);
    lc_result_ptr names = lc_allocate_pages(XATTR_LIST_MAX / LC_PAGE_SIZE);
    lc_result_ptr value = lc_allocate_pages(XATTR_VALUE_MAX / LC_PAGE_SIZE);
    int rc;
    if (lc_ptr_is_err(buffer) || lc_ptr_is_err(names) || lc_ptr_is_err(value)) {
        rc = fail(&o, "there is no memory to write an archive with");
    } else {
        o.buffer = buffer.value;
        o.xattr_names = names.value;
        o.xattr_value = value.value;
        rc = write_dir(&o, dirfd);
        if (rc == 0)
            rc = emit(&o, end, sizeof(end));
    }

    if (lc_ptr_is_ok(buffer))
        lc_free_pages(buffer.value, COPY_PAGES);
    if (lc_ptr_is_ok(names))
        lc_free_pages(names.value, XATTR_LIST_MAX / LC_PAGE_SIZE);
    if (lc_ptr_is_ok(value))
        lc_free_pages(value.value, XATTR_VALUE_MAX / LC_PAGE_SIZE);
    mem_free(&o.pax);
    mem_free(&o.links);
    mem_free(&o.link_names);
    return rc;
}
