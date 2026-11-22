#include "lightbox.h"

#include <lightc/memory.h>

/*
 * tar, as the layers of an image have it: a writer (ROADMAP I.2) and, after
 * it in this file, a reader (I.3).
 *
 * The writer. One tree gives one archive, byte for byte, whenever and wherever it is
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

/* The names in a directory but "." and "..", each with its NUL and one after
 * another, read through a buffer of that size: 0, -1 for a directory that
 * cannot be read, or -2 without the memory for them. */
static int list_names(int32_t dirfd, uint8_t *buffer, size_t size, struct mem *names, size_t *count) {
    *count = 0;
    for (;;) {
        lc_sysret n = lc_kernel_read_directory(dirfd, buffer, size);
        if (n < 0)
            return -1;
        if (n == 0)
            return 0;
        for (lc_sysret pos = 0; pos < n; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, buffer + pos + TAR_DIRENT_RECLEN, sizeof(reclen));
            if (reclen == 0)
                break;
            const char *name = (const char *)buffer + pos + TAR_DIRENT_NAME;
            pos += reclen;
            if (streq(name, ".") || streq(name, ".."))
                continue;
            size_t len = lc_string_length(name) + 1;
            if (names->used > UINT32_MAX - len || !mem_room(names, len))
                return -2;
            lc_bytes_copy((char *)names->data + names->used, name, len);
            names->used += len;
            (*count)++;
        }
    }
}

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
    size_t dir_len = o->len, count = 0;
    int rc = 0;
    switch (list_names(dirfd, o->buffer, COPY_BUFFER, &names, &count)) {
    case 0:
        break;
    case -1:
        rc = fail(o, "is a directory that cannot be read");
        break;
    default:
        rc = fail(o, "is a directory with more entries than there is memory for");
        break;
    }
    if (rc == 0 && count && !mem_room(&order, count * sizeof(uint32_t)))
        rc = fail(o, "is a directory with more entries than there is memory for");

    if (rc == 0 && count) {
        uint32_t *sorted = order.data;
        const char *text = names.data;
        size_t at = 0;
        for (size_t i = 0; i < count; i++) {
            sorted[i] = (uint32_t)at;
            at += lc_string_length(text + at) + 1;
        }
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

/* ─── The reader (ROADMAP I.3) ──────────────────────────────────────────── */

/*
 * An archive from elsewhere, unpacked into a directory.
 *
 * It is unpacked by a process of its own, which makes the directory its root
 * before it reads the first byte. Every name is then looked up by the kernel
 * under that root: a link to /etc leads to the tree's own etc, ".." at the
 * top leads nowhere, and a second name of a file is a name in the tree. On
 * top of that the reader refuses what a layer has no use for, a name from
 * the root or one with ".." in it, and it follows no link at the end of a
 * name: what is there is replaced, never written through.
 *
 * It reads what tar programs write: ustar with its prefix, the pax records
 * path, linkpath, size, uid, gid, mtime and SCHILY.xattr., GNU's long name
 * and long link and its numbers in base 256. A device is counted and not
 * made. Anything it does not know ends the unpacking, with the entry named:
 * a wrong tree is worse than none.
 *
 * A name that begins with .wh. is a mark of a layer. In an overlay's upper
 * directory it becomes what the overlay has for it: a character device 0:0
 * for .wh.<name>, the attribute overlay.opaque for .wh..wh..opq. In one tree
 * it takes out what it names, or all that is in its directory, but for what
 * this same archive made: a mark is about the layers under its own, wherever
 * in the archive it comes.
 *
 * What the process says back is read as a stranger's: the number of a
 * failure, which is looked up here, and a name, which is made printable.
 */

#define USTAR_PREFIX_MAX 155
#define PAX_RECORDS_MAX  ((uint64_t)4 << 20)    /* of one entry: its attributes are among them */
#define XATTR_NAME_MAX   255                    /* the kernel's limit (linux/limits.h) */
#define LIST_PAGES       4
#define LIST_BUFFER      (LIST_PAGES * LC_PAGE_SIZE)
#define FNV_START        0xcbf29ce484222325ull
#define FNV_PRIME        0x100000001b3ull

enum read_failure {
    READ_OK,
    READ_PROCESS,
    READ_NO_ROOT,
    READ_NO_MEMORY,
    READ_SOURCE,
    READ_CUT,
    READ_HEADER,
    READ_AFTER_END,
    READ_RECORDS_SIZE,
    READ_LONG_AHEAD,
    READ_NUMBER,
    READ_RECORDS,
    READ_SPARSE,
    READ_KIND,
    READ_NO_NAME,
    READ_LONG_NAME,
    READ_ABSOLUTE,
    READ_DOTDOT,
    READ_MARK,
    READ_ID,
    READ_MAKE,
    READ_REPLACE,
    READ_WRITE,
    READ_OWNER,
    READ_MODE,
    READ_TIME,
    READ_ATTRIBUTE,
    READ_LINK,
    READ_LINK_ABSOLUTE,
    READ_LINK_DOTDOT,
    READ_TAKE_OUT,
    READ_OPAQUE,
    READ_FAILURES
};

/* Each is said after the entry the unpacking was at, which is the last one
 * read where the text speaks of what follows or of the archive. */
static const char *const read_failures[READ_FAILURES] = {
    [READ_PROCESS]       = "the process that unpacks ended without a result",
    [READ_NO_ROOT]       = "the directory could not be made the root of the process that unpacks",
    [READ_NO_MEMORY]     = "there is no memory to unpack it with",
    [READ_SOURCE]        = "the archive could not be read",
    [READ_CUT]           = "the archive ends before it says so",
    [READ_HEADER]        = "what follows is no header of an archive",
    [READ_AFTER_END]     = "the archive has more after its end",
    [READ_RECORDS_SIZE]  = "what follows has more pax records than are read for one entry",
    [READ_LONG_AHEAD]    = "what follows has a name too long for a path",
    [READ_NUMBER]        = "has a number that is no number",
    [READ_RECORDS]       = "has pax records that cannot be read",
    [READ_SPARSE]        = "is a file with holes written GNU's way, which is not read",
    [READ_KIND]          = "is of a kind this reader does not know",
    [READ_NO_NAME]       = "has no name",
    [READ_LONG_NAME]     = "has a name too long for a path",
    [READ_ABSOLUTE]      = "has a name that begins at the root",
    [READ_DOTDOT]        = "has .. in its name",
    [READ_MARK]          = "has a name with .wh. in it that is no mark of a layer",
    [READ_ID]            = "belongs to an id that does not fit the container's range",
    [READ_MAKE]          = "could not be made",
    [READ_REPLACE]       = "could not take the place of what was there",
    [READ_WRITE]         = "could not be written",
    [READ_OWNER]         = "could not be given its owner",
    [READ_MODE]          = "could not be given its mode",
    [READ_TIME]          = "could not be given its time",
    [READ_ATTRIBUTE]     = "could not be given an attribute",
    [READ_LINK]          = "is a second name of a file that is not in the tree",
    [READ_LINK_ABSOLUTE] = "is a second name of a file named from the root",
    [READ_LINK_DOTDOT]   = "is a second name of a file named with ..",
    [READ_TAKE_OUT]      = "could not take out what it names",
    [READ_OPAQUE]        = "could not mark its directory as one that hides its base's",
};

/* What the process that unpacks says to the one that started it. */
struct outcome {
    uint32_t failure;                   /* a read_failure */
    uint32_t at_len;
    uint64_t entries, devices, attributes_left, bytes;
    uint8_t  digest[SHA256_BYTES];
    char     at[TAR_PATH_MAX];
};

/* The names an archive made, each as a number made of it: 64 bits of FNV-1a,
 * which two names share so seldom that it is not looked into. */
struct set {
    uint64_t *slots;                    /* 0 for one that is free */
    size_t    pages;
    size_t    count;
};

/* what a header says of an entry, and what was said before it in its place */
struct head {
    char     type;
    uint32_t mode;
    uint64_t uid, gid, size;
    int64_t  mtime;
    uint32_t mtime_nsec;
};

/* What comes before an entry's header and is about it: pax records, GNU's
 * long name and long link. */
struct ahead {
    bool     long_name, long_link;      /* GNU's, in ahead_name and ahead_link */
    bool     path, linkpath, size, uid, gid, mtime, sparse;     /* among the records */
    uint32_t attributes;                /* how many the records have that are carried */
    uint64_t size_is, uid_is, gid_is;
    int64_t  mtime_sec;
    uint32_t mtime_nsec;
};

struct in {
    tar_reader  *r;
    int32_t      root;                  /* the directory that is filled: this process's root, and where it stands */
    uint32_t     failure;               /* the first, which is the one that is said */
    uint8_t     *buffer;                /* COPY_BUFFER bytes of the archive */
    size_t       have, at;              /* how many are in it, and how many of those are taken */
    bool         ended;
    sha256_ctx   hash;
    uint64_t     bytes, entries, devices, attributes_left;
    uint8_t     *listing;               /* LIST_BUFFER bytes: the entries of a directory */

    size_t       name_len;
    char         name[TAR_PATH_MAX];    /* the entry in hand, from the root */
    char         link[TAR_PATH_MAX];    /* what it is a link to */
    struct ahead ahead;
    char         ahead_name[TAR_PATH_MAX];
    char         ahead_link[TAR_PATH_MAX];
    struct mem   pax;                   /* the records of the entry in hand */

    struct mem   dirs;                  /* the directories made: their times are set last */
    struct set   made;                  /* into one tree: the names this archive made */
    size_t       walk_len;
    char         walk[TAR_PATH_MAX];    /* a name of the tree, while what is in it is looked through */
};

/* a directory whose time is still to be set: its name follows, with its NUL */
struct dir_time {
    int64_t  sec;
    uint32_t nsec;
    uint32_t len;
};

static int lose(struct in *in, uint32_t failure) {
    if (!in->failure)
        in->failure = failure;
    return -1;
}

static bool same_bytes(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

static size_t copy_text(char *to, const char *from) {
    size_t len = lc_string_length(from);
    lc_bytes_copy(to, from, len + 1);
    return len;
}

/* ─── The set of names ──────────────────────────────────────────────────── */

static uint64_t name_hash(const char *text, size_t len) {
    uint64_t hash = FNV_START;
    for (size_t i = 0; i < len; i++)
        hash = (hash ^ (uint8_t)text[i]) * FNV_PRIME;
    return hash ? hash : 1;
}

static size_t set_slots(const struct set *s) {
    return s->pages * LC_PAGE_SIZE / sizeof(uint64_t);
}

static bool set_has(const struct set *s, uint64_t hash) {
    if (!s->slots)
        return false;
    size_t mask = set_slots(s) - 1;
    for (size_t i = (size_t)hash & mask; s->slots[i]; i = (i + 1) & mask)
        if (s->slots[i] == hash)
            return true;
    return false;
}

/* into a set that has room */
static void set_put(struct set *s, uint64_t hash) {
    size_t mask = set_slots(s) - 1;
    size_t i = (size_t)hash & mask;
    while (s->slots[i] && s->slots[i] != hash)
        i = (i + 1) & mask;
    if (!s->slots[i]) {
        s->slots[i] = hash;
        s->count++;
    }
}

/* Half of the slots stay free: the number of pages is a power of two, and
 * so is the number of slots. */
static bool set_add(struct set *s, uint64_t hash) {
    if (!s->slots || (s->count + 1) * 2 > set_slots(s)) {
        struct set bigger = { .pages = s->pages ? s->pages * 2 : 16 };
        lc_result_ptr got = lc_allocate_pages(bigger.pages);
        if (lc_ptr_is_err(got))
            return false;
        bigger.slots = got.value;
        lc_bytes_fill(bigger.slots, 0, bigger.pages * LC_PAGE_SIZE);
        if (s->slots) {
            for (size_t i = 0; i < set_slots(s); i++)
                if (s->slots[i])
                    set_put(&bigger, s->slots[i]);
            lc_free_pages(s->slots, s->pages);
        }
        *s = bigger;
    }
    set_put(s, hash);
    return true;
}

/* The name in hand and every directory it is in are this archive's: an
 * archive need not have an entry for each directory it goes through. */
static int remember(struct in *in) {
    if (in->r->into != TAR_INTO_TREE)
        return 0;
    uint64_t hash = FNV_START;
    for (size_t i = 0; ; i++) {
        if (in->name[i] == '/' || in->name[i] == '\0') {
            if (!set_add(&in->made, hash ? hash : 1))
                return lose(in, READ_NO_MEMORY);
            if (in->name[i] == '\0')
                return 0;
        }
        hash = (hash ^ (uint8_t)in->name[i]) * FNV_PRIME;
    }
}

/* ─── The archive's bytes ───────────────────────────────────────────────── */

/* More of the archive into the buffer: 1, 0 at its end, -1 once said. */
static int more(struct in *in) {
    if (in->ended)
        return 0;
    int64_t n = in->r->source(in->r->from, in->buffer, COPY_BUFFER);
    if (n < 0 || n > (int64_t)COPY_BUFFER)
        return lose(in, READ_SOURCE);
    in->at = 0;
    in->have = (size_t)n;
    if (n == 0) {
        in->ended = true;
        return 0;
    }
    sha256_update(&in->hash, in->buffer, (size_t)n);
    in->bytes += (uint64_t)n;
    return 1;
}

/* The next bytes of the archive: to a place, into a file, or with neither
 * passed over. */
static int take(struct in *in, void *to, int32_t fd, uint64_t len) {
    uint8_t *out = to;
    while (len) {
        if (in->at == in->have) {
            int got = more(in);
            if (got < 0)
                return -1;
            if (got == 0)
                return lose(in, READ_CUT);
        }
        size_t n = in->have - in->at;
        if (n > len)
            n = (size_t)len;
        if (out) {
            lc_bytes_copy(out, in->buffer + in->at, n);
            out += n;
        } else if (fd >= 0 && lc_kernel_write_all(fd, in->buffer + in->at, n) != (lc_sysret)n) {
            return lose(in, READ_WRITE);
        }
        in->at += n;
        len -= n;
    }
    return 0;
}

/* what fills the last block of that many bytes */
static uint64_t padding(uint64_t size) {
    return (TAR_BLOCK - size % TAR_BLOCK) % TAR_BLOCK;
}

static bool all_zeros(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (bytes[i])
            return false;
    return true;
}

/* After the two blocks of zeros that end an archive there is nothing, or
 * zeros that fill a tape's record: all of it is read, for the digest. */
static int take_end(struct in *in) {
    for (;;) {
        if (!all_zeros(in->buffer + in->at, in->have - in->at))
            return lose(in, READ_AFTER_END);
        in->at = in->have;
        int got = more(in);
        if (got <= 0)
            return got;
    }
}

/* ─── What a header says ────────────────────────────────────────────────── */

/* A number in a header's field: octal digits with spaces before them and
 * spaces or NULs after, or, as GNU tar writes one that is too large or less
 * than 0, a first byte of 0x80 or 0xff and the number in the bytes after it. */
static bool field_number(const uint8_t *field, size_t width, int64_t *out) {
    if (field[0] == 0x80 || field[0] == 0xff) {
        uint8_t sign = field[0] == 0xff ? 0xff : 0;
        uint64_t value = sign ? ~(uint64_t)0 : 0;
        for (size_t i = 1; i < width; i++) {
            if ((uint8_t)(value >> 56) != sign)
                return false;
            value = value << 8 | field[i];
        }
        if ((value >> 63) != (sign ? 1u : 0u))
            return false;
        *out = (int64_t)value;
        return true;
    }
    size_t i = 0, digits = 0;
    uint64_t value = 0;
    while (i < width && field[i] == ' ')
        i++;
    for (; i < width && field[i] >= '0' && field[i] <= '7'; i++, digits++) {
        if (value >> 60)
            return false;
        value = value << 3 | (uint64_t)(field[i] - '0');
    }
    for (; i < width; i++)
        if (field[i] != ' ' && field[i] != '\0')
            return false;
    if (!digits)
        return false;
    *out = (int64_t)value;
    return true;
}

/* A header's checksum is the sum of its bytes, taken with the checksum's
 * own field as spaces; some old programs summed the bytes as signed ones. */
static bool header_sums(const uint8_t block[TAR_BLOCK]) {
    int64_t said;
    if (!field_number(block + 148, 8, &said))
        return false;
    int64_t sum = 0, sum_signed = 0;
    for (size_t i = 0; i < TAR_BLOCK; i++) {
        uint8_t byte = i >= 148 && i < 156 ? ' ' : block[i];
        sum += byte;
        sum_signed += (int8_t)byte;
    }
    return said == sum || said == sum_signed;
}

/* the text in a field, which ends at a NUL or with the field: its length */
static size_t field_text(char *to, const uint8_t *field, size_t width) {
    size_t len = 0;
    while (len < width && field[len])
        len++;
    lc_bytes_copy(to, field, len);
    to[len] = '\0';
    return len;
}

/* A whole number in decimal, and nothing else. */
static bool decimal_text(const char *text, size_t len, uint64_t *out) {
    uint64_t value = 0;
    if (!len)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (text[i] < '0' || text[i] > '9' || value > (UINT64_MAX - 9) / 10)
            return false;
        value = value * 10 + (uint64_t)(text[i] - '0');
    }
    *out = value;
    return true;
}

/* A time as a pax record has it: seconds, which may be less than 0, and
 * after a point what part of a second more. */
static bool time_text(const char *text, size_t len, int64_t *sec, uint32_t *nsec) {
    bool negative = len && text[0] == '-';
    size_t whole = negative ? 1 : 0, point = whole;
    while (point < len && text[point] != '.')
        point++;
    uint64_t seconds, part = 0;
    if (!decimal_text(text + whole, point - whole, &seconds) || seconds > (uint64_t)INT64_MAX - 1)
        return false;
    if (point < len) {
        uint64_t scale = 100000000;
        if (point + 1 == len)
            return false;
        for (size_t i = point + 1; i < len; i++, scale /= 10) {
            if (text[i] < '0' || text[i] > '9')
                return false;
            part += (uint64_t)(text[i] - '0') * scale;
        }
    }
    if (negative && part) {
        *sec = -(int64_t)seconds - 1;
        *nsec = (uint32_t)(1000000000 - part);
    } else {
        *sec = negative ? -(int64_t)seconds : (int64_t)seconds;
        *nsec = (uint32_t)part;
    }
    return true;
}

/* ─── pax records ───────────────────────────────────────────────────────── */

struct record {
    const char *key, *value;
    size_t      key_len, value_len;
};

/* The record at a place among the records, "<length> <key>=<value>\n" with
 * a length that counts all of it, and the place of the one after it: false
 * for what is no record. */
static bool next_record(const struct mem *pax, size_t *at, struct record *rec) {
    const char *data = pax->data;
    size_t start = *at, i = start, len = 0;
    while (i < pax->used && data[i] >= '0' && data[i] <= '9') {
        len = len * 10 + (size_t)(data[i] - '0');
        if (len > PAX_RECORDS_MAX)
            return false;
        i++;
    }
    if (i == start || i == pax->used || data[i] != ' ' || len > pax->used - start || len < i - start + 3)
        return false;
    const char *end = data + start + len - 1;       /* its newline */
    const char *key = data + i + 1, *equals = key;
    if (*end != '\n')
        return false;
    while (equals < end && *equals != '=')
        equals++;
    if (equals == end)
        return false;
    rec->key = key;
    rec->key_len = (size_t)(equals - key);
    rec->value = equals + 1;
    rec->value_len = (size_t)(end - equals - 1);
    *at = start + len;
    return true;
}

static bool key_is(const struct record *rec, const char *key) {
    size_t len = lc_string_length(key);
    return rec->key_len == len && same_bytes(rec->key, key, len);
}

static bool key_starts(const struct record *rec, const char *prefix) {
    size_t len = lc_string_length(prefix);
    return rec->key_len >= len && same_bytes(rec->key, prefix, len);
}

/* An attribute among the records: 0 for a record that is none, 1 with the
 * name of one that is carried and can be set, 2 for one that is left. */
static int record_attribute(const struct record *rec, char name[XATTR_NAME_MAX + 1]) {
    static const char prefix[] = "SCHILY.xattr.";
    size_t skip = sizeof(prefix) - 1;
    if (!key_starts(rec, prefix))
        return 0;
    size_t len = rec->key_len - skip;
    if (!len || len > XATTR_NAME_MAX || rec->value_len > XATTR_VALUE_MAX)
        return 2;
    for (size_t i = 0; i < len; i++)
        if (rec->key[skip + i] == '\0')
            return 2;
    lc_bytes_copy(name, rec->key + skip, len);
    name[len] = '\0';
    return attribute_is_carried(name) ? 1 : 2;
}

/* a name among the records, into its place: one with a NUL in it is none */
static int record_name(struct in *in, const struct record *rec, char *to, bool *given) {
    if (rec->value_len >= TAR_PATH_MAX)
        return lose(in, READ_LONG_NAME);
    for (size_t i = 0; i < rec->value_len; i++)
        if (rec->value[i] == '\0')
            return lose(in, READ_RECORDS);
    if (rec->value_len) {
        lc_bytes_copy(to, rec->value, rec->value_len);
        to[rec->value_len] = '\0';
        *given = true;
    }
    return 0;
}

/* What the records in hand say of the entry whose header came after them. */
static int read_records(struct in *in) {
    struct ahead *a = &in->ahead;
    struct record rec;
    char name[XATTR_NAME_MAX + 1];
    for (size_t at = 0; at < in->pax.used; ) {
        if (!next_record(&in->pax, &at, &rec))
            return lose(in, READ_RECORDS);
        if (key_is(&rec, "path")) {
            if (record_name(in, &rec, in->ahead_name, &a->path) != 0)
                return -1;
        } else if (key_is(&rec, "linkpath")) {
            if (record_name(in, &rec, in->ahead_link, &a->linkpath) != 0)
                return -1;
        } else if (key_is(&rec, "size")) {
            a->size = true;
            if (!decimal_text(rec.value, rec.value_len, &a->size_is))
                return lose(in, READ_NUMBER);
        } else if (key_is(&rec, "uid")) {
            a->uid = true;
            if (!decimal_text(rec.value, rec.value_len, &a->uid_is))
                return lose(in, READ_NUMBER);
        } else if (key_is(&rec, "gid")) {
            a->gid = true;
            if (!decimal_text(rec.value, rec.value_len, &a->gid_is))
                return lose(in, READ_NUMBER);
        } else if (key_is(&rec, "mtime")) {
            a->mtime = true;
            if (!time_text(rec.value, rec.value_len, &a->mtime_sec, &a->mtime_nsec))
                return lose(in, READ_NUMBER);
        } else if (key_starts(&rec, "GNU.sparse.")) {
            a->sparse = true;
        } else {
            switch (record_attribute(&rec, name)) {
            case 1:
                a->attributes++;
                break;
            case 2:
                in->attributes_left++;
                break;
            default:
                break;
            }
        }
    }
    return 0;
}

/* The attributes among the records, set on an open file or directory. One
 * that the filesystem has no place for is counted as left. */
static int give_attributes(struct in *in, int32_t fd) {
    struct record rec;
    char name[XATTR_NAME_MAX + 1];
    for (size_t at = 0; at < in->pax.used; ) {
        if (!next_record(&in->pax, &at, &rec))
            return lose(in, READ_RECORDS);
        if (record_attribute(&rec, name) != 1)
            continue;
        lc_sysret rc = lb_sys_fsetxattr(fd, name, rec.value, rec.value_len);
        if (rc == -LB_EOPNOTSUPP)
            in->attributes_left++;
        else if (rc < 0)
            return lose(in, READ_ATTRIBUTE);
    }
    return 0;
}

/* ─── Names ─────────────────────────────────────────────────────────────── */

/*
 * A name as an archive has it, made the name of a place under the root:
 * without "." in it, without a slash twice or at its end. One that begins
 * at the root or has ".." in it is refused before a byte of it is changed,
 * so that it is said as the archive has it. The root's own name is empty.
 */
static int clean_name(struct in *in, char *name, size_t *len, bool *slash,
                      uint32_t when_absolute, uint32_t when_dotdot) {
    if (name[0] == '/')
        return lose(in, when_absolute);
    size_t end = 0;
    for (size_t i = 0; name[i]; i = end) {
        for (end = i; name[end] && name[end] != '/'; end++)
            ;
        if (end - i == 2 && name[i] == '.' && name[i + 1] == '.')
            return lose(in, when_dotdot);
        if (name[end])
            end++;
    }
    *slash = end && name[end - 1] == '/';

    size_t to = 0;
    for (size_t i = 0; name[i]; ) {
        size_t part = i;
        while (name[i] && name[i] != '/')
            i++;
        size_t part_len = i - part;
        while (name[i] == '/')
            i++;
        if (!part_len || (part_len == 1 && name[part] == '.'))
            continue;
        if (to)
            name[to++] = '/';
        lc_bytes_move(name + to, name + part, part_len);
        to += part_len;
    }
    name[to] = '\0';
    *len = to;
    return 0;
}

enum mark { MARK_NONE, MARK_WHITEOUT, MARK_OPAQUE, MARK_BAD };

/*
 * What a cleaned name says as a mark of a layer. For .wh.<name> the name is
 * made that of what is taken out, and for .wh..wh..opq that of the directory
 * it is in. Nothing else may begin with .wh.: not a directory on the way,
 * not the marks AUFS kept beside these, not a mark for "." or "..", and
 * not an entry that is no file. A name that is refused is left as it is.
 */
static enum mark mark_of(char *name, size_t *len, bool is_file) {
    size_t last = 0;
    for (size_t i = 0; name[i]; i++) {
        if (name[i] != '/')
            continue;
        if (starts_with(name + last, WHITEOUT_PREFIX))
            return MARK_BAD;
        last = i + 1;
    }
    char *base = name + last;
    if (!starts_with(base, WHITEOUT_PREFIX))
        return MARK_NONE;
    if (!is_file)
        return MARK_BAD;
    if (streq(base, OPAQUE_MARK)) {
        *len = last ? last - 1 : 0;
        name[*len] = '\0';
        return MARK_OPAQUE;
    }
    const char *rest = base + sizeof(WHITEOUT_PREFIX) - 1;
    if (!*rest || starts_with(rest, WHITEOUT_PREFIX) || streq(rest, ".") || streq(rest, ".."))
        return MARK_BAD;
    size_t rest_len = lc_string_length(rest);
    lc_bytes_move(base, rest, rest_len + 1);
    *len = last + rest_len;
    return MARK_WHITEOUT;
}

/* ─── Taking out ────────────────────────────────────────────────────────── */

/* Stands in a directory named from where the process stands, with
 * O_NOFOLLOW only if the name's end is no link: 0, 1 where there is no such
 * directory, -1 for another failure. */
static int enter(const char *name, int32_t flags) {
    lc_sysret fd = lc_kernel_open_file_at(AT_FDCWD, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | flags, 0);
    if (fd < 0)
        return fd == -LB_ENOENT || fd == -LB_ENOTDIR || fd == -LB_ELOOP ? 1 : -1;
    lc_sysret rc = lb_sys_fchdir((int32_t)fd);
    lc_kernel_close_file((int32_t)fd);
    return rc < 0 ? -1 : 0;
}

static bool is_directory(const char *name) {
    struct lb_statx st;
    return lb_sys_statx(AT_FDCWD, name, AT_SYMLINK_NOFOLLOW, LB_STATX_TYPE, &st) == 0 &&
           (st.stx_mode & LB_S_IFMT) == LB_S_IFDIR;
}

/* an empty directory or anything that is none, in the directory the process
 * stands in: 0 when it is gone, 1 for a directory that has something in it */
static int remove_one(const char *name) {
    lc_sysret rc = lc_kernel_unlinkat(AT_FDCWD, name, 0);
    if (rc == -LB_EISDIR)
        rc = lc_kernel_unlinkat(AT_FDCWD, name, AT_REMOVEDIR);
    if (rc == 0 || rc == -LB_ENOENT)
        return 0;
    return rc == -LB_ENOTEMPTY || rc == -LB_EEXIST ? 1 : -1;
}

/*
 * Takes out what a name in the directory the process stands in is, with all
 * that is in it. The process goes down into a directory that is not empty
 * and comes up again when it is, and keeps neither a descriptor nor a name
 * for the way: a tree may be deeper than a path is long.
 */
static int remove_here(struct in *in, const char *name) {
    int rc = remove_one(name);
    if (rc <= 0)
        return rc;
    if (enter(name, O_NOFOLLOW) != 0)
        return -1;
    for (size_t depth = 1; depth; ) {
        lc_sysret fd = lc_kernel_open_file_at(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if (fd < 0)
            return -1;
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, in->listing, LIST_BUFFER);
        lc_kernel_close_file((int32_t)fd);
        if (n < 0)
            return -1;
        bool empty = true, down = false;
        for (lc_sysret pos = 0; pos < n && !down; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, in->listing + pos + TAR_DIRENT_RECLEN, sizeof(reclen));
            if (reclen == 0)
                break;
            const char *entry = (const char *)in->listing + pos + TAR_DIRENT_NAME;
            pos += reclen;
            if (streq(entry, ".") || streq(entry, ".."))
                continue;
            empty = false;
            rc = remove_one(entry);
            if (rc < 0)
                return -1;
            if (rc == 1) {
                if (enter(entry, O_NOFOLLOW) != 0)
                    return -1;
                depth++;
                down = true;
            }
        }
        if (empty) {
            if (lc_kernel_chdir("..") < 0)
                return -1;
            depth--;
        }
    }
    return remove_one(name) == 0 ? 0 : -1;
}

/*
 * In the directory the process stands in, whose name is in walk: takes out
 * all that this archive did not make, and looks into the directories it did
 * make for more. A directory named through a link and by its own name in
 * one archive is two names here, and what was made under the other is not
 * known under this one.
 */
static int clear_lower(struct in *in) {
    struct mem names = { 0 };
    size_t count = 0, dir_len = in->walk_len;
    lc_sysret fd = lc_kernel_open_file_at(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int rc = list_names((int32_t)fd, in->listing, LIST_BUFFER, &names, &count) == 0 ? 0 : -1;
    lc_kernel_close_file((int32_t)fd);

    const char *name = names.data;
    for (size_t i = 0; i < count && rc == 0; i++) {
        size_t len = lc_string_length(name);
        size_t whole = dir_len + (dir_len ? 1 : 0) + len;
        bool made = false;
        if (whole < TAR_PATH_MAX) {
            if (dir_len)
                in->walk[dir_len] = '/';
            lc_bytes_copy(in->walk + whole - len, name, len + 1);
            made = set_has(&in->made, name_hash(in->walk, whole));
        }
        if (!made) {
            rc = remove_here(in, name);
        } else if (is_directory(name)) {
            in->walk_len = whole;
            if (enter(name, O_NOFOLLOW) != 0 || clear_lower(in) != 0 || lc_kernel_chdir("..") < 0)
                rc = -1;
        }
        in->walk_len = dir_len;
        in->walk[dir_len] = '\0';
        name += len + 1;
    }
    mem_free(&names);
    return rc;
}

/* Stands in the directory a name from the root is in, and gives the name's
 * last part: 0, 1 where there is no such directory, -1 for another failure.
 * The process has to be put back at the root after it. */
static int enter_parent(char *path, const char **base) {
    char *slash = NULL;
    for (char *at = path; *at; at++)
        if (*at == '/')
            slash = at;
    *base = slash ? slash + 1 : path;
    if (!slash)
        return 0;
    *slash = '\0';
    int rc = enter(path, 0);
    *slash = '/';
    return rc;
}

/* Takes away what is at a name from the root, whatever it is. */
static int take_away(struct in *in, char *path) {
    lc_sysret rc = lc_kernel_unlinkat(AT_FDCWD, path, 0);
    if (rc == -LB_EISDIR)
        rc = lc_kernel_unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
    if (rc == 0 || rc == -LB_ENOENT)
        return 0;
    if (rc != -LB_ENOTEMPTY && rc != -LB_EEXIST)
        return -1;
    const char *base;
    int result = enter_parent(path, &base) == 0 ? remove_here(in, base) : -1;
    if (lb_sys_fchdir(in->root) < 0)
        result = -1;
    return result;
}

/* Into one tree, .wh.<name>: the name in hand is taken out, but for what
 * this archive made there. */
static int whiteout_in_tree(struct in *in) {
    const char *base;
    int rc = enter_parent(in->name, &base);
    if (rc == 0) {
        if (!set_has(&in->made, name_hash(in->name, in->name_len))) {
            rc = remove_here(in, base);
        } else if (is_directory(base)) {
            in->walk_len = copy_text(in->walk, in->name);
            rc = enter(base, O_NOFOLLOW) == 0 ? clear_lower(in) : -1;
        }
    }
    if (lb_sys_fchdir(in->root) < 0)
        rc = -1;
    /* with no directory for the name to be in, there is nothing to take out */
    return rc < 0 ? lose(in, READ_TAKE_OUT) : 0;
}

/* Into one tree, .wh..wh..opq: all that is in the directory in hand and is
 * not this archive's is taken out. */
static int opaque_in_tree(struct in *in) {
    int rc = in->name_len ? enter(in->name, O_NOFOLLOW) : 0;
    if (rc == 0) {
        in->walk_len = copy_text(in->walk, in->name);
        rc = clear_lower(in);
    }
    if (lb_sys_fchdir(in->root) < 0)
        rc = -1;
    return rc < 0 ? lose(in, READ_TAKE_OUT) : 0;
}

/* ─── Making ────────────────────────────────────────────────────────────── */

/* The ids an entry is given: the header's and the start of the range. */
static int entry_ids(struct in *in, const struct head *h, uint32_t *uid, uint32_t *gid) {
    const tar_reader *r = in->r;
    if ((r->uid_start && h->uid >= USERNS_SIZE) || (r->gid_start && h->gid >= USERNS_SIZE) ||
        h->uid >= UINT32_MAX - (uint64_t)r->uid_start || h->gid >= UINT32_MAX - (uint64_t)r->gid_start)
        return lose(in, READ_ID);
    *uid = (uint32_t)h->uid + r->uid_start;
    *gid = (uint32_t)h->gid + r->gid_start;
    return 0;
}

/* The time of its last change, by a name without following a link or, with
 * no name, of what a descriptor is open on. The time of its last reading is
 * left as it is. */
static lc_sysret set_time(int32_t dirfd, const char *name, int64_t sec, uint32_t nsec) {
    const lc_timespec times[2] = { { 0, LB_UTIME_OMIT }, { sec, nsec } };
    return lb_sys_utimensat(dirfd, name, times, name ? AT_SYMLINK_NOFOLLOW : 0);
}

/* The directories a name goes through, made where they are missing, as the
 * root of the range's: an archive need not have an entry for each. */
static void make_parents(const struct in *in, char *path) {
    for (char *at = path; *at; at++) {
        if (*at != '/')
            continue;
        *at = '\0';
        if (lc_kernel_mkdirat(AT_FDCWD, path, 0755) == 0)
            (void)lc_kernel_fchownat(AT_FDCWD, path, in->r->uid_start, in->r->gid_start, AT_SYMLINK_NOFOLLOW);
        *at = '/';
    }
}

/* one try at the entry in hand; 'w' is what an overlay has for a name that
 * is taken out */
static lc_sysret make_once(const struct in *in, char kind, uint32_t mode) {
    switch (kind) {
    case '0':
        return lc_kernel_open_file_at(AT_FDCWD, in->name,
                                      O_WRONLY | O_CREAT | LB_O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    case '1':
        return lb_sys_linkat(AT_FDCWD, in->link, AT_FDCWD, in->name, 0);
    case '2':
        return lc_kernel_symlinkat(in->link, AT_FDCWD, in->name);
    case '5':
        return lc_kernel_mkdirat(AT_FDCWD, in->name, 0700);
    case '6':
        return lc_kernel_mknodat(AT_FDCWD, in->name, (int32_t)(LB_S_IFIFO | mode), 0);
    default:
        return lc_kernel_mknodat(AT_FDCWD, in->name, (int32_t)(LB_S_IFCHR | mode), 0);
    }
}

/*
 * The entry in hand, made: what its call gives, which for a file is its
 * descriptor, or -1 once said. Directories that are missing on the way are
 * made. What is at the name already is taken away first, whatever it is,
 * except that a directory stays for a directory: a layer adds to the
 * directories of the ones under it.
 */
static lc_sysret make(struct in *in, char kind, uint32_t mode) {
    lc_sysret rc = make_once(in, kind, mode);
    if (rc == -LB_ENOENT) {
        make_parents(in, in->name);
        rc = make_once(in, kind, mode);
    }
    if (rc == -LB_EEXIST) {
        if (kind == '5' && is_directory(in->name))
            return 0;
        if (take_away(in, in->name) != 0)
            return lose(in, READ_REPLACE);
        rc = make_once(in, kind, mode);
    }
    return rc < 0 ? lose(in, READ_MAKE) : rc;
}

/* The owner, the attributes and the mode of what a descriptor is open on,
 * in the one order in which none undoes another: a new owner takes a file's
 * capabilities and its set-id bits away. */
static int finish(struct in *in, int32_t fd, const struct head *h, uint32_t uid, uint32_t gid) {
    if (lc_kernel_fchownat(fd, "", uid, gid, LB_AT_EMPTY_PATH) < 0)
        return lose(in, READ_OWNER);
    if (in->ahead.attributes && give_attributes(in, fd) != 0)
        return -1;
    if (lb_sys_fchmod(fd, h->mode) < 0)
        return lose(in, READ_MODE);
    return 0;
}

static int make_file(struct in *in, const struct head *h, uint32_t uid, uint32_t gid) {
    lc_sysret fd = make(in, '0', 0);
    if (fd < 0)
        return -1;
    int rc = take(in, NULL, (int32_t)fd, h->size);
    if (rc == 0)
        rc = take(in, NULL, -1, padding(h->size));
    if (rc == 0)
        rc = finish(in, (int32_t)fd, h, uid, gid);
    if (rc == 0 && set_time((int32_t)fd, NULL, h->mtime, h->mtime_nsec) < 0)
        rc = lose(in, READ_TIME);
    lc_kernel_close_file((int32_t)fd);
    return rc;
}

/* A directory's time is set when all is unpacked: every entry made in it
 * until then changes it. */
static int make_directory(struct in *in, const struct head *h, uint32_t uid, uint32_t gid) {
    if (make(in, '5', 0) < 0)
        return -1;
    lc_sysret fd = lc_kernel_open_file_at(AT_FDCWD, in->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0)
        return lose(in, READ_MAKE);
    int rc = finish(in, (int32_t)fd, h, uid, gid);
    lc_kernel_close_file((int32_t)fd);
    if (rc != 0)
        return rc;

    struct dir_time later = { .sec = h->mtime, .nsec = h->mtime_nsec, .len = (uint32_t)in->name_len };
    if (!mem_room(&in->dirs, sizeof(later) + in->name_len + 1))
        return lose(in, READ_NO_MEMORY);
    char *to = (char *)in->dirs.data + in->dirs.used;
    lc_bytes_copy(to, &later, sizeof(later));
    lc_bytes_copy(to + sizeof(later), in->name, in->name_len + 1);
    in->dirs.used += sizeof(later) + in->name_len + 1;
    return 0;
}

/* a link, a pipe, or an overlay's mark for a name: its owner and its time,
 * by its name and of itself */
static int make_other(struct in *in, char kind, const struct head *h, uint32_t uid, uint32_t gid) {
    if (make(in, kind, h->mode) < 0)
        return -1;
    if (lc_kernel_fchownat(AT_FDCWD, in->name, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
        return lose(in, READ_OWNER);
    if (set_time(AT_FDCWD, in->name, h->mtime, h->mtime_nsec) < 0)
        return lose(in, READ_TIME);
    return 0;
}

/* A second name of a file that is in the tree: of the file itself, where
 * the first name is a link's. */
static int make_second_name(struct in *in) {
    size_t len;
    bool slash;
    struct lb_statx st;
    if (clean_name(in, in->link, &len, &slash, READ_LINK_ABSOLUTE, READ_LINK_DOTDOT) != 0)
        return -1;
    if (!len || lb_sys_statx(AT_FDCWD, in->link, AT_SYMLINK_NOFOLLOW, LB_STATX_TYPE, &st) < 0 ||
        (st.stx_mode & LB_S_IFMT) == LB_S_IFDIR)
        return lose(in, READ_LINK);
    return make(in, '1', 0) < 0 ? -1 : 0;
}

/* Into an overlay's upper directory, .wh..wh..opq: the directory in hand
 * hides what its base has under its name. The upper directory itself hides
 * nothing: an overlay always has its base under it, so that a mark at the
 * top, which would take all of the base away, cannot be kept. */
static int opaque_in_upper(struct in *in) {
    int32_t flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    if (!in->name_len)
        return lose(in, READ_OPAQUE);
    lc_sysret fd = lc_kernel_open_file_at(AT_FDCWD, in->name, flags, 0);
    if (fd == -LB_ENOENT) {
        /* the mark came before its directory, or the archive has none for it */
        make_parents(in, in->name);
        if (lc_kernel_mkdirat(AT_FDCWD, in->name, 0755) == 0)
            (void)lc_kernel_fchownat(AT_FDCWD, in->name, in->r->uid_start, in->r->gid_start,
                                     AT_SYMLINK_NOFOLLOW);
        fd = lc_kernel_open_file_at(AT_FDCWD, in->name, flags, 0);
    }
    if (fd < 0)
        return lose(in, READ_OPAQUE);
    const char *attribute = in->r->into == TAR_INTO_UPPER ? "trusted.overlay.opaque" : "user.overlay.opaque";
    lc_sysret rc = lb_sys_fsetxattr((int32_t)fd, attribute, "y", 1);
    lc_kernel_close_file((int32_t)fd);
    return rc < 0 ? lose(in, READ_OPAQUE) : 0;
}

/* ─── Entries ───────────────────────────────────────────────────────────── */

/* The entry a header block begins, which is no record and no long name. */
static int entry(struct in *in, const uint8_t block[TAR_BLOCK]) {
    struct ahead *a = &in->ahead;
    struct head h = { .type = (char)block[156] };

    /* its name as the header has it, for what is said of it from here on */
    if (a->long_name) {
        copy_text(in->name, in->ahead_name);
    } else {
        size_t len = 0;
        if (same_bytes((const char *)block + 257, "ustar", 6) && block[345])
            len = field_text(in->name, block + 345, USTAR_PREFIX_MAX);
        if (len)
            in->name[len++] = '/';
        field_text(in->name + len, block, USTAR_NAME_MAX);
    }
    if (a->long_link)
        copy_text(in->link, in->ahead_link);
    else
        field_text(in->link, block + 157, USTAR_NAME_MAX);

    int64_t mode, uid, gid, size;
    if (!field_number(block + 100, 8, &mode) || !field_number(block + 108, 8, &uid) ||
        !field_number(block + 116, 8, &gid) || !field_number(block + 124, 12, &size) ||
        !field_number(block + 136, 12, &h.mtime) || mode < 0 || uid < 0 || gid < 0 || size < 0)
        return lose(in, READ_NUMBER);
    h.mode = (uint32_t)mode & 07777u;
    h.uid = (uint64_t)uid;
    h.gid = (uint64_t)gid;
    h.size = (uint64_t)size;

    if (in->pax.used && read_records(in) != 0)
        return -1;
    if (a->path)
        copy_text(in->name, in->ahead_name);
    if (a->linkpath)
        copy_text(in->link, in->ahead_link);
    if (a->size)
        h.size = a->size_is;
    if (a->uid)
        h.uid = a->uid_is;
    if (a->gid)
        h.gid = a->gid_is;
    if (a->mtime) {
        h.mtime = a->mtime_sec;
        h.mtime_nsec = a->mtime_nsec;
    }
    if (a->sparse)
        return lose(in, READ_SPARSE);

    /* the kinds before ustar had its own, and the one for a file that is
     * kept in one piece */
    if (h.type == '\0' || h.type == '7')
        h.type = '0';
    if (h.type < '0' || h.type > '6')
        return lose(in, READ_KIND);

    bool slash;
    if (in->name[0] == '\0')
        return lose(in, READ_NO_NAME);
    if (clean_name(in, in->name, &in->name_len, &slash, READ_ABSOLUTE, READ_DOTDOT) != 0)
        return -1;
    if (h.type == '0' && slash)
        h.type = '5';       /* how a directory was said before it had a kind */
    uint64_t content = h.type == '0' ? h.size : 0;

    if (in->name_len == 0) {
        /* the root itself, which is the caller's and stays as it is */
        return h.type == '5' ? 0 : lose(in, READ_NO_NAME);
    }
    if (h.type == '3' || h.type == '4') {
        in->devices++;
        return 0;
    }
    uint32_t to_uid, to_gid;
    if (entry_ids(in, &h, &to_uid, &to_gid) != 0)
        return -1;

    enum mark mark = mark_of(in->name, &in->name_len, h.type == '0');
    if (mark == MARK_BAD)
        return lose(in, READ_MARK);
    if (mark != MARK_NONE) {
        if (take(in, NULL, -1, content) != 0 || take(in, NULL, -1, padding(content)) != 0)
            return -1;
        int rc;
        if (in->r->into == TAR_INTO_TREE)
            rc = mark == MARK_OPAQUE ? opaque_in_tree(in) : whiteout_in_tree(in);
        else
            rc = mark == MARK_OPAQUE ? opaque_in_upper(in) : make_other(in, 'w', &h, to_uid, to_gid);
        if (rc == 0)
            in->entries++;
        return rc;
    }

    int rc;
    switch (h.type) {
    case '0':
        rc = make_file(in, &h, to_uid, to_gid);
        break;
    case '1':
        rc = make_second_name(in);
        break;
    case '5':
        rc = make_directory(in, &h, to_uid, to_gid);
        break;
    default:
        /* the attributes Linux gives neither a link nor a pipe a place for */
        in->attributes_left += a->attributes;
        rc = make_other(in, h.type, &h, to_uid, to_gid);
        break;
    }
    if (rc == 0) {
        in->entries++;
        rc = remember(in);
    }
    return rc;
}

/* What comes before an entry and is about it, kept for its header: pax
 * records, or GNU's long name or long link. */
static int keep_ahead(struct in *in, char type, uint64_t size) {
    if (type == 'x') {
        if (size > PAX_RECORDS_MAX)
            return lose(in, READ_RECORDS_SIZE);
        in->pax.used = 0;
        if (!mem_room(&in->pax, (size_t)size + 1))
            return lose(in, READ_NO_MEMORY);
        if (take(in, in->pax.data, -1, size) != 0)
            return -1;
        in->pax.used = (size_t)size;
    } else {
        char *to = type == 'L' ? in->ahead_name : in->ahead_link;
        if (size > TAR_PATH_MAX)
            return lose(in, READ_LONG_AHEAD);
        if (take(in, to, -1, size) != 0)
            return -1;
        size_t len = 0;
        while (len < size && to[len])
            len++;
        if (len == TAR_PATH_MAX)
            return lose(in, READ_LONG_AHEAD);
        to[len] = '\0';
        if (type == 'L')
            in->ahead.long_name = true;
        else
            in->ahead.long_link = true;
    }
    return take(in, NULL, -1, padding(size));
}

/* The times of the directories that were made, now that nothing more is
 * made in them. One that is no directory any more was replaced since. */
static int set_directory_times(struct in *in) {
    for (size_t at = 0; at < in->dirs.used; ) {
        struct dir_time later;
        const char *from = (const char *)in->dirs.data + at;
        lc_bytes_copy(&later, from, sizeof(later));
        const char *name = from + sizeof(later);
        at += sizeof(later) + later.len + 1;
        if (is_directory(name) && set_time(AT_FDCWD, name, later.sec, later.nsec) < 0) {
            in->name_len = copy_text(in->name, name);
            return lose(in, READ_TIME);
        }
    }
    return 0;
}

/* The whole archive, from its first header to the source's end. */
static int unpack(struct in *in) {
    uint8_t block[TAR_BLOCK];
    for (;;) {
        if (take(in, block, -1, TAR_BLOCK) != 0)
            return -1;
        if (all_zeros(block, TAR_BLOCK)) {
            /* its end is two such blocks */
            if (take(in, block, -1, TAR_BLOCK) != 0)
                return -1;
            if (!all_zeros(block, TAR_BLOCK))
                return lose(in, READ_HEADER);
            if (take_end(in) != 0)
                return -1;
            return set_directory_times(in);
        }
        if (!header_sums(block))
            return lose(in, READ_HEADER);

        char type = (char)block[156];
        if (type == 'x' || type == 'g' || type == 'L' || type == 'K') {
            int64_t size;
            if (!field_number(block + 124, 12, &size) || size < 0)
                return lose(in, READ_HEADER);
            /* records for all entries from here on say nothing a layer needs */
            int rc = type == 'g' ? take(in, NULL, -1, (uint64_t)size + padding((uint64_t)size))
                                 : keep_ahead(in, type, (uint64_t)size);
            if (rc != 0)
                return -1;
            continue;
        }
        if (entry(in, block) != 0)
            return -1;
        in->pax.used = 0;
        lc_bytes_fill(&in->ahead, 0, sizeof(in->ahead));
    }
}

/* The process that unpacks: it says how it went, and ends. */
static _Noreturn void unpack_and_end(tar_reader *r, int32_t dirfd, int32_t say) {
    /* this process's own: the one that started it never writes to them */
    static struct in in;
    static struct outcome out;
    in.r = r;
    sha256_init(&in.hash);

    lc_result_ptr buffer = lc_allocate_pages(COPY_PAGES);
    lc_result_ptr listing = lc_allocate_pages(LIST_PAGES);
    lc_sysret root = -1;
    if (lb_sys_fchdir(dirfd) < 0 || lb_sys_chroot(".") < 0 ||
        (root = lc_kernel_open_file_at(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)) < 0) {
        (void)lose(&in, READ_NO_ROOT);
    } else if (lc_ptr_is_err(buffer) || lc_ptr_is_err(listing)) {
        (void)lose(&in, READ_NO_MEMORY);
    } else {
        in.root = (int32_t)root;
        in.buffer = buffer.value;
        in.listing = listing.value;
        /* a mode is the archive's, with nothing taken from it */
        (void)lb_sys_umask(0);
        (void)unpack(&in);
    }

    out.failure = in.failure;
    out.entries = in.entries;
    out.devices = in.devices;
    out.attributes_left = in.attributes_left;
    out.bytes = in.bytes;
    sha256_final(&in.hash, out.digest);
    out.at_len = (uint32_t)lc_string_length(in.name);
    lc_bytes_copy(out.at, in.name, out.at_len);
    lc_kernel_exit(lc_kernel_write_all(say, &out, sizeof(out)) == (lc_sysret)sizeof(out) ? 0 : 1);
}

int tar_read_tree(tar_reader *r, int32_t dirfd) {
    static struct outcome out;
    int32_t pipe[2], status = 0;
    r->entries = r->devices = r->attributes_left = r->bytes = 0;
    r->failure = NULL;
    r->failed_at[0] = '\0';
    lc_bytes_fill(r->digest, 0, sizeof(r->digest));
    lc_bytes_fill(&out, 0, sizeof(out));

    if (lc_kernel_create_pipe(pipe, O_CLOEXEC) < 0) {
        r->failure = read_failures[READ_PROCESS];
        return -1;
    }
    lc_sysret pid = lc_kernel_fork();
    if (pid == 0) {
        lc_kernel_close_file(pipe[0]);
        unpack_and_end(r, dirfd, pipe[1]);
    }
    lc_kernel_close_file(pipe[1]);
    lc_sysret got = pid < 0 ? -1 : lc_kernel_read_all(pipe[0], &out, sizeof(out));
    lc_kernel_close_file(pipe[0]);
    while (pid > 0) {
        lc_sysret waited = lc_kernel_wait_for_child((int32_t)pid, &status, 0);
        if (waited == pid)
            break;
        if (waited != -LB_EINTR) {
            status = -1;
            break;
        }
    }

    /* what came back is not taken on trust */
    if (got != (lc_sysret)sizeof(out) || status != 0 || out.failure >= READ_FAILURES ||
        out.at_len >= TAR_PATH_MAX) {
        r->failure = read_failures[READ_PROCESS];
        return -1;
    }
    for (uint32_t i = 0; i < out.at_len; i++) {
        uint8_t byte = (uint8_t)out.at[i];
        r->failed_at[i] = byte < 0x20 || byte == 0x7f ? '?' : (char)byte;
    }
    r->failed_at[out.at_len] = '\0';
    r->entries = out.entries;
    r->devices = out.devices;
    r->attributes_left = out.attributes_left;
    r->bytes = out.bytes;
    if (out.failure != READ_OK) {
        r->failure = read_failures[out.failure];
        return -1;
    }
    lc_bytes_copy(r->digest, out.digest, sizeof(r->digest));
    return 0;
}
