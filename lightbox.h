#ifndef LIGHTBOX_H
#define LIGHTBOX_H

#include <lightc/syscall.h>
#include <lightc/types.h>
#include <lightc/string.h>
#include <lightc/print.h>
#include <lightc/format.h>
#include <lightc/io.h>

#include "lightbox_sys.h"

#define MAX_PATH         512
#define NAME_MAX_LEN     12
#define MAX_VOLS         16
#define MAX_LINKS        8

/* The largest legal container .conf: MAX_VOLS volumes of two MAX_PATH paths,
 * MAX_LINKS links and the scalar keys. Every reader and writer of a .conf uses
 * a buffer of exactly this size, so a config is never cut on the way in or
 * out; one that does not fit is an error. */
#define CONF_MAX         20480
_Static_assert(CONF_MAX > MAX_VOLS * (2 * MAX_PATH + 8) + MAX_LINKS * (NAME_MAX_LEN + 8) + 512,
               "CONF_MAX is too small for the largest legal container config");

typedef struct {
    char lightbox_dir[MAX_PATH];
    char rootfs[MAX_PATH];
    char container_dir[MAX_PATH];
    char run_dir[MAX_PATH];
    char cgroup_root[MAX_PATH];
    char cgroup_base[MAX_PATH];
    char bridge[32];
    char subnet[20];
    char gw[16];
    char default_mem[16];
    char default_pids[8];
    char default_cpu[4];
    int  default_oom;
} global_config;

extern global_config cfg_global;

void print_str(int32_t fd, const char *s);
[[noreturn]] void die(const char *msg);
[[noreturn]] void die2(const char *prefix, const char *detail);
bool streq(const char *a, const char *b);
size_t str_copy(char *dst, const char *src, size_t max);
size_t str_append(char *dst, size_t pos, const char *src, size_t max);
size_t str_append_whole(char *dst, size_t pos, const char *src, size_t max, bool *overflow);
void path_join(char *buf, size_t bufsz, const char *a, const char *b);
int parse_int(const char *s);
int fmt_int(char *buf, int val);
int write_file(const char *path, const char *data);
void require_write_file(const char *path, const char *data);

/* Modes for what lightbox creates. Container storage is for root alone: root
 * filesystems hold setuid binaries and secrets other local users must not
 * reach, and the records beside them say what each container may do. */
#define MODE_PRIVATE_DIR   0700
#define MODE_PRIVATE_FILE  0600
#define MODE_PUBLIC_FILE   0644

int write_file_atomic(const char *path, const char *data, int32_t mode);
/* For lightbox's own records: always MODE_PRIVATE_FILE. */
void require_write_file_atomic(const char *path, const char *data);
void cfg_global_init(void);
void cfg_global_load(char **envp);

int read_file(const char *path, char *buf, size_t bufsz);
bool path_exists(const char *path);
int dir_is_empty(const char *path);
void require_rm_rf(const char *path);

/* Running a program and waiting for it. The result is its exit status, 0 to
 * 255, or one of these when there is none; each of them has been reported on
 * stderr by the time the call returns. */
#define RUN_FORK_FAILED  256   /* no child process could be made */
#define RUN_EXEC_FAILED  257   /* the program could not be executed */
#define RUN_SIGNALED     258   /* a signal ended the program */
#define RUN_WAIT_FAILED  259   /* the program could not be waited for */

extern const char *const TOOL_ENV[];   /* what tools run with: a fixed PATH */

[[nodiscard]] int run_cmd(const char *prog, const char *const argv[]);
/* the same with the program's stdout and stderr sent to /dev/null */
[[nodiscard]] int run_cmd_quiet(const char *prog, const char *const argv[]);
/* the same with another environment than TOOL_ENV */
[[nodiscard]] int run_cmd_env(const char *prog, const char *const argv[], const char *const envp[]);
/* the same with the program's stdout collected in out as a string, cut to fit */
[[nodiscard]] int run_cmd_capture(const char *prog, const char *const argv[], char *out, size_t outsz);

lc_sysret exec_program(const char *prog, const char *const argv[], const char *const envp[]);
[[nodiscard]] int wait_child(int32_t pid, int32_t *status);
int exit_code_from_status(int32_t status);
int do_mount(const char *source, const char *target,
             const char *fstype, uint64_t flags, const char *data);
void require_mount(const char *source, const char *target,
                   const char *fstype, uint64_t flags, const char *data);
const char *tool_path_ip(void);
const char *tool_path_iptables(void);
const char *tool_path_mount(void);
const char *tool_path_umount(void);
const char *tool_path_mkdir(void);
const char *tool_path_cp(void);
const char *tool_path_chown(void);
const char *tool_path_rm(void);
const char *tool_path_nsenter(void);
bool tool_available(const char *path);
void require_tool(const char *label, const char *path);
/* a macro's value as a string literal */
#define STRINGIFY_(x) #x
#define STRINGIFY(x)  STRINGIFY_(x)

void validate_name(const char *name);
/* [a-zA-Z0-9_-], 1 to NAME_MAX_LEN characters: what validate_name accepts */
bool name_is_valid(const char *name);

/* The most containers one listing holds. */
#define MAX_LISTED 1024
/* The containers under container_dir, sorted by name: every directory whose
 * name is a valid container name. Anything else there is not lightbox's and is
 * left out. Stores at most max names and returns how many; *more, if given,
 * says whether some did not fit. */
int list_containers(char names[][NAME_MAX_LEN + 1], int max, bool *more);

void container_dir_path(char *buf, const char *name);
void container_root(char *buf, const char *name);
void container_pid_path(char *buf, const char *name);
void container_pid_start_path(char *buf, const char *name);
void container_ip_path(char *buf, const char *name);
void container_conf_path(char *buf, const char *name);
void container_state_path(char *buf, const char *name);

void set_container_state(const char *name, const char *state);
void get_container_state(const char *name, char *buf, size_t bufsz);
int container_conf_read(const char *name, char *buf);
int conf_get(const char *name, const char *key, char *val, size_t valsz, const char *def);
int conf_get_int(const char *name, const char *key, int def);
int get_container_pid(const char *name);
int get_container_pid_starttime(const char *name, char *buf, size_t bufsz);

/* What the runtime files say about a container's init process. */
typedef enum {
    CONTAINER_NO_RECORD,   /* no PID is recorded */
    CONTAINER_RUNNING,     /* the recorded process is there */
    CONTAINER_DEAD,        /* a PID is recorded and that process is gone */
} container_liveness;

container_liveness container_probe(const char *name);
bool is_running(const char *name);
void container_reap_if_dead(const char *name);
void container_shown_state(const char *name, container_liveness live, char *buf, size_t bufsz);
int read_container_ip(const char *name, char *ip, size_t ipsz);
int update_link_rules(const char *name, const char *ip, bool add_rules);

void cmd_setup(void);
void cmd_doctor(void);
void cmd_ls(int argc, char **argv);
void cmd_inspect(int argc, char **argv);

#endif
