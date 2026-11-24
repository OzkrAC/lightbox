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
