#ifndef LIGHTBOX_H
#define LIGHTBOX_H

#include <lightc/syscall.h>
#include <lightc/types.h>
#include <lightc/string.h>
#include <lightc/print.h>
#include <lightc/format.h>
#include <lightc/io.h>

#include "lightbox_sys.h"

/* mount(2) goes through lightc's wrapper. On x86_64 that wrapper has the
 * right syscall number from lightc 0.1.1 on; before, it called sendfile. */
#if LC_VERSION_MAJOR == 0 && (LC_VERSION_MINOR < 1 || (LC_VERSION_MINOR == 1 && LC_VERSION_PATCH < 1))
#error "lightbox needs lightc 0.1.1 or later"
#endif

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
    int  start_timeout;     /* seconds start waits for the init hook; 0: not at all */
    int  stop_timeout;      /* seconds a container gets to end when it is asked to */
    char dns[64];           /* name servers for new containers, as written; empty: the host's */
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

/* A time limit in whole seconds, as an option or a setting gives it: digits
 * only, 0 to SECONDS_MAX. */
#define SECONDS_MAX            86400
#define START_TIMEOUT_DEFAULT  30
#define STOP_TIMEOUT_DEFAULT   10
bool parse_seconds(const char *s, int *out);
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

/* Files in a root filesystem that is not this process's root: <root>/<dir>/<name>,
 * with every link on the way followed as that root's own processes would
 * follow it, so that nothing is read or written outside the root. dir is one
 * directory name, and is made if it is missing.
 *
 * Writing is atomic, and replaces a link of that name with the file. 0 or -1.
 * Reading gives the text and its length, 0 for a file that is not there, and
 * -1 for one that cannot be read, is not a regular file or does not fit. */
[[nodiscard]] int write_file_in_root(const char *root, const char *dir, const char *name,
                                     const char *data, int32_t mode);
[[nodiscard]] int read_file_in_root(const char *root, const char *dir, const char *name,
                                    char *buf, size_t bufsz);
/* For lightbox's own records: always MODE_PRIVATE_FILE. */
void require_write_file_atomic(const char *path, const char *data);
void cfg_global_init(void);
/* the value of a variable in an environment, or NULL */
const char *env_get(char **envp, const char *name);
void cfg_global_load(char **envp);

int read_file(const char *path, char *buf, size_t bufsz);
bool path_exists(const char *path);
bool path_is_directory(const char *path);
/* mkdir -p, in this process: 0, or -1 with the failure reported */
[[nodiscard]] int make_dirs(const char *path);
/* ip link set lo up, in this process: 0, or -1 with the failure reported */
[[nodiscard]] int loopback_up(void);
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
/* mount(2): 0, or -1 with the failure reported. A change of a mount's flags
 * (MS_REMOUNT | MS_BIND) keeps the restrictions the mount already has. */
[[nodiscard]] int do_mount(const char *source, const char *target,
                           const char *fstype, uint64_t flags, const char *data);
/* the same, ending the process on failure */
void require_mount(const char *source, const char *target,
                   const char *fstype, uint64_t flags, const char *data);
const char *tool_path_ip(void);
const char *tool_path_iptables(void);
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
/* what the container's init, its hook and its services write to stdout and stderr */
void container_log_path(char *buf, const char *name);

/* 0, or -1 when the state could not be written */
[[nodiscard]] int record_container_state(const char *name, const char *state);
/* the same, ending the process on failure */
void set_container_state(const char *name, const char *state);
void get_container_state(const char *name, char *buf, size_t bufsz);
int container_conf_read(const char *name, char *buf);
int conf_get(const char *name, const char *key, char *val, size_t valsz, const char *def);
int conf_get_int(const char *name, const char *key, int def);
int get_container_pid(const char *name);
int get_container_pid_starttime(const char *name, char *buf, size_t bufsz);
/* write .pid_start and .pid for a running init: 0, or -1 */
[[nodiscard]] int container_record_pid(const char *name, int pid);
/* remove both */
void container_forget_pid(const char *name);

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

/*
 * Locks. Each is held from the call to the end of the process, and by
 * nothing the process starts.
 *
 * A command that changes a container takes that container's lock, so that
 * two of them do their work one after the other and each sees what the other
 * left. It waits for the lock, and says so when it has to. create and setup
 * take the lock of the whole store. A query takes a container's lock shared,
 * and only if it is free: a query never waits.
 */
void container_lock(const char *name);          /* ends the process when there is no such container */
void container_lock_if_free(const char *name);
void store_lock(void);

/* Ends the process, saying which command it was, unless it runs as root. */
void require_root(const char *command);
int read_container_ip(const char *name, char *ip, size_t ipsz);
int update_link_rules(const char *name, const char *ip, bool add_rules);
/* does iptables see what the bridge switches between containers? */
bool bridge_traffic_is_filtered(void);

/* How exec can run from a copy of this binary that cannot be written to. */
typedef enum {
    SEAL_NONE,          /* not at all: exec refuses to run */
    SEAL_MEMFD,         /* a sealed copy in memory */
    SEAL_READONLY,      /* the binary itself, on a read-only mount of its own */
} seal_method;

/* which of them works here, found by doing all of it but the execution */
seal_method exec_seal_method(void);

void cmd_setup(void);
void cmd_doctor(void);
void cmd_ls(int argc, char **argv);
void cmd_inspect(int argc, char **argv);
void cmd_logs(int argc, char **argv);

#endif
