#include "lightbox.h"

/*
 * --gpu (ROADMAP G.3): the host's GPUs, for compute, found at each start, as
 * the devices of create --device are given (ROADMAP G.1): the render nodes
 * of /dev/dri, Intel's, AMD's and any other driver's of DRM; NVIDIA's GPUs,
 * its control node and nvidia-uvm; and AMD's kfd, which ROCm opens beside a
 * render node. Not a card node, nor nvidia-modeset: what they give is a
 * display's, and no compute needs it. The kernel may number them otherwise
 * after a boot, and a driver may come or go, so they are looked for at each
 * start and never kept in .conf.
 */

/* "renderD" and digits */
static bool render_node_name(const char *name) {
    if (!lc_string_starts_with(name, lc_string_length(name), "renderD", 7) || !name[7])
        return false;
    for (const char *p = name + 7; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

/* "nvidia" and digits, nvidiactl, nvidia-uvm and nvidia-uvm-tools; and kfd */
static bool compute_node_name(const char *name) {
    if (streq(name, "nvidiactl") || streq(name, "nvidia-uvm") || streq(name, "nvidia-uvm-tools") || streq(name, "kfd"))
        return true;
    if (!lc_string_starts_with(name, lc_string_length(name), "nvidia", 6) || !name[6])
        return false;
    for (const char *p = name + 6; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

#define GPU_NAME_MAX 32

/* The names in dir that valid takes, of what is no directory, in the order
 * of their bytes: how many, at most max. */
static int names_in(const char *dir, bool (*valid)(const char *), char names[][GPU_NAME_MAX], int max) {
    lc_sysret fd = lc_kernel_open_file(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    int count = 0;
    char buf[4096];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        for (lc_sysret pos = 0; pos < n; ) {
            /* struct linux_dirent64: d_reclen at offset 16, d_type at 18, d_name at 19 */
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + 16, sizeof(reclen));
            if (reclen == 0)
                break;
            uint8_t type = (uint8_t)buf[pos + 18];
            const char *entry = buf + pos + 19;
            pos += reclen;
            size_t len = lc_string_length(entry);
            if (type == 4 || len >= GPU_NAME_MAX || !valid(entry) || count == max)     /* 4: DT_DIR */
                continue;
            int at = count++;
            while (at > 0 && lc_bytes_compare(entry, names[at - 1], len + 1) < 0) {
                lc_bytes_copy(names[at], names[at - 1], GPU_NAME_MAX);
                at--;
            }
            lc_bytes_copy(names[at], entry, len + 1);
        }
    }
    lc_kernel_close_file((int32_t)fd);
    return count;
}

int gpu_devices(const char *root, device_spec *out, int max) {
    static const struct { const char *dir; bool (*valid)(const char *); } places[] = {
        { "/dev/dri", render_node_name },
        { "/dev", compute_node_name },
    };
    int count = 0;
    for (size_t p = 0; p < sizeof(places) / sizeof(places[0]); p++) {
        char dir[MAX_PATH];
        bool cut = false;
        str_append(dir, str_append(dir, 0, root, sizeof(dir), &cut), places[p].dir, sizeof(dir), &cut);
        if (cut)
            return -1;
        static char names[MAX_DEVICES + 1][GPU_NAME_MAX];
        int n = names_in(dir, places[p].valid, names, MAX_DEVICES + 1);
        for (int i = 0; i < n; i++) {
            if (count == max)
                return -1;
            device_spec *dev = &out[count++];
            *dev = (device_spec){ 0 };
            str_append(dev->path, str_append(dev->path, str_append(dev->path, 0, places[p].dir, sizeof(dev->path), &cut),
                                             "/", sizeof(dev->path), &cut), names[i], sizeof(dev->path), &cut);
            str_append(dev->host, str_append(dev->host, 0, root, sizeof(dev->host), &cut), dev->path,
                       sizeof(dev->host), &cut);
            if (cut)
                return -1;
        }
    }
    return count;
}

/* ─── NVIDIA's libraries (ROADMAP G.3) ─────────────────────────────────── */

/*
 * NVIDIA's user-space driver is of the very version of its kernel module, and
 * no image can carry it for every host: a box of --gpu on a host with the
 * module loaded is given the host's own, read-only, at /run/lightbox/gpu, and
 * no program of the image's or of NVIDIA's container toolkit runs to set
 * that up. The libraries are those a CUDA program and nvidia-smi load, each
 * by the name of that version, from the first of the host's directories of
 * libraries that has it, with the host's own links to it, libcuda.so.1 and
 * the like; not those of OpenGL or Vulkan, which are a display's. They are
 * built for glibc, and a box of musl cannot load them.
 */

static const char *const NVIDIA_LIBRARIES[] = {
    "libcuda", "libnvidia-ml", "libnvidia-ptxjitcompiler", "libnvidia-nvvm", "libnvidia-gpucomp", "libcudadebugger",
};
static_assert(sizeof(NVIDIA_LIBRARIES) / sizeof(NVIDIA_LIBRARIES[0]) + 1 <= NVIDIA_FILES_MAX,
              "NVIDIA_FILES_MAX holds the libraries and nvidia-smi");

static const char *const LIBRARY_DIRS[] = {
#if defined(__x86_64__)
    "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu",
#elif defined(__aarch64__)
    "/usr/lib/aarch64-linux-gnu", "/lib/aarch64-linux-gnu",
#endif
    "/usr/lib64", "/lib64", "/usr/lib",
};

/* The version of the module, "550.54.14", from the first line of
 * /proc/driver/nvidia/version: its first word of digits and dots with a dot. */
static bool nvidia_version(const char *root, char version[NVIDIA_VERSION_MAX]) {
    char path[MAX_PATH], text[512];
    bool cut = false;
    str_append(path, str_append(path, 0, root, sizeof(path), &cut), "/proc/driver/nvidia/version", sizeof(path), &cut);
    if (cut || read_file(path, text, sizeof(text)) <= 0)
        return false;
    for (const char *p = text; *p && *p != '\n'; ) {
        while (*p == ' ' || *p == '\t')
            p++;
        const char *w = p;
        bool dot = false, digits = true;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            dot = dot || *p == '.';
            digits = digits && ((*p >= '0' && *p <= '9') || *p == '.');
            p++;
        }
        size_t len = (size_t)(p - w);
        if (len && dot && digits && w[0] != '.' && len < NVIDIA_VERSION_MAX) {
            lc_bytes_copy(version, w, len);
            version[len] = '\0';
            return true;
        }
    }
    return false;
}

/* Whether path is a regular file, once its links are followed. */
static bool regular_file(const char *path) {
    struct lb_statx stx;
    return lb_sys_statx(AT_FDCWD, path, 0, LB_STATX_TYPE, &stx) == 0 && (stx.stx_mode & LB_S_IFMT) == LB_S_IFREG;
}

/* The host's links in dir to the file of name, by names of base: a link that
 * leads there in at most three steps, each a name in the same directory. */
static void library_links(const char *dir, const char *base, const char *name, nvidia_files *out) {
    lc_sysret fd = lc_kernel_open_file(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return;
    size_t blen = lc_string_length(base);
    char buf[4096];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, buf, sizeof(buf));
        if (n <= 0)
            break;
        for (lc_sysret pos = 0; pos < n; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + 16, sizeof(reclen));
            if (reclen == 0)
                break;
            const char *entry = buf + pos + 19;
            pos += reclen;
            size_t len = lc_string_length(entry);
            if (len >= NVIDIA_NAME_MAX || !lc_string_starts_with(entry, len, base, blen) ||
                !lc_string_starts_with(entry + blen, len - blen, ".so", 3) || streq(entry, name) ||
                out->nlinks == NVIDIA_LINKS_MAX)
                continue;
            char target[NVIDIA_NAME_MAX], step[NVIDIA_NAME_MAX];
            lc_sysret t = lc_kernel_readlinkat((int32_t)fd, entry, target, sizeof(target) - 1);
            if (t <= 0)
                continue;
            target[t] = '\0';
            /* where it leads: names of this directory alone */
            bool reaches = false;
            lc_bytes_copy(step, target, (size_t)t + 1);
            for (int hop = 0; hop < 3 && !reaches; hop++) {
                if (lc_string_find_byte(step, lc_string_length(step), '/') >= 0)
                    break;
                reaches = streq(step, name);
                if (reaches)
                    break;
                char next[NVIDIA_NAME_MAX];
                lc_sysret m = lc_kernel_readlinkat((int32_t)fd, step, next, sizeof(next) - 1);
                if (m <= 0)
                    break;
                next[m] = '\0';
                lc_bytes_copy(step, next, (size_t)m + 1);
            }
            if (!reaches || lc_string_find_byte(target, (size_t)t, '/') >= 0)
                continue;
            lc_bytes_copy(out->links[out->nlinks].name, entry, len + 1);
            lc_bytes_copy(out->links[out->nlinks].target, target, (size_t)t + 1);
            out->nlinks++;
        }
    }
    lc_kernel_close_file((int32_t)fd);
}

int nvidia_libraries(const char *root, nvidia_files *out) {
    *out = (nvidia_files){ 0 };
    if (!nvidia_version(root, out->version))
        return 0;
    bool cut = false;
    for (size_t l = 0; l < sizeof(NVIDIA_LIBRARIES) / sizeof(NVIDIA_LIBRARIES[0]); l++) {
        char name[NVIDIA_NAME_MAX];
        str_append(name, str_append(name, str_append(name, 0, NVIDIA_LIBRARIES[l], sizeof(name), &cut), ".so.",
                                    sizeof(name), &cut), out->version, sizeof(name), &cut);
        for (size_t d = 0; d < sizeof(LIBRARY_DIRS) / sizeof(LIBRARY_DIRS[0]) && !cut; d++) {
            char dir[MAX_PATH], path[MAX_PATH];
            str_append(dir, str_append(dir, 0, root, sizeof(dir), &cut), LIBRARY_DIRS[d], sizeof(dir), &cut);
            str_append(path, str_append(path, str_append(path, 0, dir, sizeof(path), &cut), "/", sizeof(path), &cut),
                       name, sizeof(path), &cut);
            if (cut || !regular_file(path))
                continue;
            lc_bytes_copy(out->files[out->nfiles].host, path, lc_string_length(path) + 1);
            lc_bytes_copy(out->files[out->nfiles].name, name, lc_string_length(name) + 1);
            out->files[out->nfiles++].bin = false;
            library_links(dir, NVIDIA_LIBRARIES[l], name, out);
            break;
        }
        if (l == 0 && out->nfiles == 0) {
            /* without libcuda there is no CUDA to give */
            lc_bytes_copy(out->missing, name, lc_string_length(name) + 1);
            return -1;
        }
    }
    static const char *const smi[] = { "/usr/bin/nvidia-smi", "/bin/nvidia-smi" };
    for (size_t i = 0; i < sizeof(smi) / sizeof(smi[0]); i++) {
        char path[MAX_PATH];
        str_append(path, str_append(path, 0, root, sizeof(path), &cut), smi[i], sizeof(path), &cut);
        if (!cut && regular_file(path)) {
            lc_bytes_copy(out->files[out->nfiles].host, path, lc_string_length(path) + 1);
            lc_bytes_copy(out->files[out->nfiles].name, "nvidia-smi", sizeof("nvidia-smi"));
            out->files[out->nfiles++].bin = true;
            break;
        }
    }
    return cut ? -1 : 1;
}

bool root_has_musl(const char *rootfs) {
    char lib[MAX_PATH];
    bool cut = false;
    str_append(lib, str_append(lib, 0, rootfs, sizeof(lib), &cut), "/lib", sizeof(lib), &cut);
    lc_sysret fd = cut ? -1 : lc_kernel_open_file(lib, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0)
        return false;
    bool musl = false;
    char buf[4096];
    for (;;) {
        lc_sysret n = lc_kernel_read_directory((int32_t)fd, buf, sizeof(buf));
        if (n <= 0 || musl)
            break;
        for (lc_sysret pos = 0; pos < n && !musl; ) {
            uint16_t reclen;
            lc_bytes_copy(&reclen, buf + pos + 16, sizeof(reclen));
            if (reclen == 0)
                break;
            const char *entry = buf + pos + 19;
            pos += reclen;
            musl = lc_string_starts_with(entry, lc_string_length(entry), "ld-musl-", 8);
        }
    }
    lc_kernel_close_file((int32_t)fd);
    return musl;
}
