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
 * MAX_LINKS links and the scalar keys. The reader and the writer of a .conf
 * use a buffer of exactly this size, so a config is never cut on the way in
 * or out; one that does not fit is an error. */
#define CONF_MAX         20480
_Static_assert(CONF_MAX > MAX_VOLS * (2 * MAX_PATH + 8) + MAX_LINKS * (NAME_MAX_LEN + 8) + 512,
               "CONF_MAX is too small for the largest legal container config");

/* The limits as text, the way they are given and the way the file has them. */
#define MEM_TEXT_MAX    24      /* "<number>[K|M|G|T]" or "max" */
#define PIDS_TEXT_MAX   12      /* a count or "max" */
#define CPU_TEXT_MAX    12      /* CPUs, "2" or "0.5" */
#define IO_TEXT_MAX     128     /* a line for io.max */

#define PIDS_LIMIT_MAX  4194304         /* the most processes Linux numbers */
#define CPU_LIMIT_MAX   512             /* CPUs */
#define CPU_PERIOD_US   100000          /* cpu.max: the period a quota is of */
#define OOM_SCORE_MIN   (-1000)
#define OOM_SCORE_MAX   1000

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
    /* A default_* setting that cannot be used is an empty string here, and
     * default_oom_ok is false: said once when the settings are read, and
     * refused by the command that would have needed it. */
    char default_mem[MEM_TEXT_MAX];
    char default_pids[PIDS_TEXT_MAX];
    char default_cpu[CPU_TEXT_MAX];
    int  default_oom;
    bool default_oom_ok;
    int  start_timeout;     /* seconds start waits for the init hook; 0: not at all */
    int  stop_timeout;      /* seconds a container gets to end when it is asked to */
    char dns[64];           /* name servers for new containers, as written; empty: the host's */
} global_config;

extern global_config cfg_global;

/*
 * What a container is configured with: the content of its .conf.
 *
 * lightbox_container.c holds the one reader and the one writer of that
 * file. Everything else works on this structure and never on the file's
 * text, so there is one place that decides what a value may be.
 */

typedef struct {
    char src[MAX_PATH];
    char dst[MAX_PATH];
    bool ro;
} volume_spec;

typedef struct {
    int  version;               /* 0: a file from before it had the line */
    char mem[MEM_TEXT_MAX];
    char swap[MEM_TEXT_MAX];    /* empty: not given, which is none */
    char pids[PIDS_TEXT_MAX];
    char cpu[CPU_TEXT_MAX];
    char io[IO_TEXT_MAX];       /* empty: no limit */
    int  oom_score;
    bool privileged;
    bool read_only;
    bool userns;
    int  uid_start;
    int  nvols;
    volume_spec vols[MAX_VOLS];
    int  nlinks;
    char links[MAX_LINKS][NAME_MAX_LEN + 1];
} container_config;

#define CONTAINER_CONFIG_VERSION 1

/* Is this a limit as an option, a setting and the file may give it? */
[[nodiscard]] bool mem_limit_ok(const char *text);      /* <number>[K|M|G|T] or max */
[[nodiscard]] bool swap_limit_ok(const char *text);     /* the same, or 0 */
/* A line for io.max: <major>:<minor> and one or more of rbps, wbps, riops and
 * wiops, each =<number> or =max, with a space before each */
[[nodiscard]] bool io_limit_ok(const char *text);
[[nodiscard]] bool pids_limit_ok(const char *text);     /* 1 to PIDS_LIMIT_MAX, or max */
/* 0.01 to CPU_LIMIT_MAX CPUs with at most two decimals: the quota, in
 * microseconds of each CPU_PERIOD_US */
[[nodiscard]] bool parse_cpu_limit(const char *text, int *quota_us);
[[nodiscard]] bool parse_oom_score(const char *text, int *out);

/*
 * A volume as it is written: src:dst[:ro]. NULL when it is one, with both
 * paths normalised in vol; otherwise what is wrong with it. An option and
 * the file are both read through this, so they agree on what a volume is.
 */
[[nodiscard]] const char *parse_volume_spec(const char *spec, volume_spec *vol);
/* The destination alone, in the one spelling it is stored in. */
[[nodiscard]] const char *parse_volume_destination(const char *text, char dst[MAX_PATH]);

/* A configuration with nothing in it and no limit given yet. */
void container_config_init(container_config *config);
/* Give every limit that has not been given the default of lightbox.conf.
 * NULL, or the name of a default_* setting that was needed and cannot be
 * used. */
[[nodiscard]] const char *container_config_fill_defaults(container_config *config);

/*
 * Read a container's .conf. NULL, or what is wrong, with the file and the
 * line named; the text is good until the next call. A key the file does not
 * have keeps its default. A file with a version line is lightbox's own
 * writing and is read strictly: an unknown key, a second value for a key and
 * a line that is not key=value are all errors. One without the line is from
 * before, and those are passed over as they were then.
 */
[[nodiscard]] const char *container_config_load(const char *name, container_config *config);
/* the same for text in hand, which it cuts into lines; path is for the message */
[[nodiscard]] const char *container_config_parse(char *text, const char *path, container_config *config);
void container_config_load_or_die(const char *name, container_config *config);

/* Write it, replacing the file in one step. NULL, or what went wrong. */
[[nodiscard]] const char *container_config_save(const char *name, const container_config *config);

/* The volume at a destination: its index, or -1. */
int config_volume_at(const container_config *config, const char *dst);
/* NULL, or why the volume cannot be added: no room, or the destination is taken. */
[[nodiscard]] const char *config_add_volume(container_config *config, const volume_spec *vol);
/* Take out every volume at a destination: how many there were. */
int config_remove_volumes_at(container_config *config, const char *dst);

void print_str(int32_t fd, const char *s);
[[noreturn]] void die(const char *msg);
[[noreturn]] void die2(const char *prefix, const char *detail);
bool streq(const char *a, const char *b);

/*
 * Text that has to arrive whole. None of these cut: a source that does not
 * fit is not copied in part, and the caller is told and has to say what
 * happens then.
 *
 * str_copy and path_join leave an empty string and return false. str_append
 * appends nothing and sets *overflow, which stays set, so a text can be put
 * together from many pieces and asked once whether it is whole. The _or_die
 * forms end the process with the text named; they are for a command's own
 * arguments and settings, where too long is the user's to correct.
 */
[[nodiscard]] bool str_copy(char *dst, const char *src, size_t max);
size_t str_append(char *dst, size_t pos, const char *src, size_t max, bool *overflow);
[[nodiscard]] bool path_join(char *buf, size_t bufsz, const char *a, const char *b);
void str_copy_or_die(char *dst, const char *src, size_t max, const char *what);
void path_join_or_die(char *buf, size_t bufsz, const char *a, const char *b);
/* "/proc/<pid><suffix>" */
[[nodiscard]] bool proc_pid_path(char *buf, size_t bufsz, int pid, const char *suffix);
/* the directory a path's last component is in */
[[nodiscard]] bool parent_dir(char *buf, size_t bufsz, const char *path);
/* a byte below 0x20, or 0x7f: a newline among them */
bool has_control_chars(const char *s);

/*
 * A whole number in decimal from min to max: an optional minus sign and
 * digits, nothing else. Empty text, anything after the digits and a value
 * out of range are refused, and nothing wraps around.
 */
[[nodiscard]] bool parse_number(const char *s, int64_t min, int64_t max, int64_t *out);
[[nodiscard]] bool parse_int_in(const char *s, int min, int max, int *out);

/* A time limit in whole seconds, as an option or a setting gives it: digits
 * only, 0 to SECONDS_MAX. */
#define SECONDS_MAX            86400
#define START_TIMEOUT_DEFAULT  30
#define STOP_TIMEOUT_DEFAULT   10
[[nodiscard]] bool parse_seconds(const char *s, int *out);
int fmt_int(char *buf, int val);
int write_file(const char *path, const char *data);
void require_write_file(const char *path, const char *data);

/* Modes for what lightbox creates. Container storage is for root alone: root
 * filesystems hold setuid binaries and secrets other local users must not
 * reach, and the records beside them say what each container may do. */
#define MODE_PRIVATE_DIR   0700
#define MODE_PRIVATE_FILE  0600
#define MODE_PUBLIC_FILE   0644

/* A file given its content in one step, by a rename: a reader finds the old
 * content or the new. write_file_atomic is for what has to outlast a power
 * cut, and is on the disk when it returns. write_file_volatile is for the
 * records of what is running, which no reboot outlives anyway: the same
 * step without the wait for the disk, always MODE_PRIVATE_FILE. */
[[nodiscard]] int write_file_atomic(const char *path, const char *data, int32_t mode);
[[nodiscard]] int write_file_volatile(const char *path, const char *data);
/* Remove a file, and have it stay removed after a power cut. One that is
 * not there is removed. 0, or -1. */
[[nodiscard]] int remove_file_durably(const char *path);

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

/*
 * What a container is made of is in <container_dir>/<name>/ and is written
 * to stay: its root filesystem, its configuration, its address, its log,
 * and a mark while create has not finished with it.
 */
void container_dir_path(char *buf, const char *name);
void container_root(char *buf, const char *name);
void container_ip_path(char *buf, const char *name);
void container_conf_path(char *buf, const char *name);
void container_creating_path(char *buf, const char *name);
/* what the container's init, its hook and its services write to stdout and stderr */
void container_log_path(char *buf, const char *name);

/*
 * What is known about a container that is running, or was, is in
 * <run_dir>/<name>/: the PID of its init and that process's start time, the
 * state, and what init said when it ended. A reboot ends every container
 * and, with run_dir where it belongs, takes these along; a container
 * without them is stopped.
 */
void container_run_path(char *buf, const char *name);
void container_pid_path(char *buf, const char *name);
void container_pid_start_path(char *buf, const char *name);
void container_state_path(char *buf, const char *name);
void container_exit_path(char *buf, const char *name);
/* run_dir and the container's directory in it, for root alone: 0, or -1 with
 * the failure reported */
[[nodiscard]] int container_run_dir_make(const char *name);
/* every runtime record of the container, and their directory */
void container_forget_run(const char *name);

/* 0, or -1 when the state could not be written */
[[nodiscard]] int record_container_state(const char *name, const char *state);
/* the same, ending the process on failure */
void set_container_state(const char *name, const char *state);
/* what is on record; "stopped" when nothing is, or "creating" for a
 * container that create did not finish */
void get_container_state(const char *name, char *buf, size_t bufsz);
int get_container_pid(const char *name);
int get_container_pid_starttime(const char *name, char *buf, size_t bufsz);
/* record a running init, its start time before its PID: 0, or -1 */
[[nodiscard]] int container_record_pid(const char *name, int pid);
/* forget which process init was and what it said when it ended */
void container_forget_pid(const char *name);
/* the exit status init reported; false when it reported none */
[[nodiscard]] bool container_exit_report(const char *name, int *status);

/* What the runtime files say about a container's init process. */
typedef enum {
    CONTAINER_NO_RECORD,   /* no PID is recorded */
    CONTAINER_RUNNING,     /* the recorded process is there */
    CONTAINER_DEAD,        /* a PID is recorded and that process is gone */
} container_liveness;

container_liveness container_probe(const char *name);
bool is_running(const char *name);
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

/* ─── Addresses ─────────────────────────────────────────────────────────── */

#define IPV4_TEXT_MAX      16       /* "255.255.255.255" and its end */
#define CIDR_TEXT_MAX      19       /* with "/32" */
#define SUBNET_PREFIX_MIN  8        /* the widest subnet containers can be on */
#define SUBNET_PREFIX_MAX  30       /* the narrowest: the bridge and one container */

/* The network containers are on, as the settings subnet and gw give it. */
typedef struct {
    uint32_t network;       /* the first address of the subnet, which is nobody's */
    uint32_t broadcast;     /* the last, which is everybody's */
    uint32_t gateway;       /* the bridge's */
    int      prefix;        /* how many bits of an address name the subnet */
} container_network;

/* Four numbers of 0 to 255 with dots between them and nothing else. A number
 * with a zero in front of it is refused. */
[[nodiscard]] bool parse_ipv4(const char *text, uint32_t *addr);
void format_ipv4(char out[IPV4_TEXT_MAX], uint32_t addr);
/* NULL, or what is wrong with the setting that *setting then names. */
const char *container_network_parse(const char *subnet, const char *gw, container_network *net,
                                    const char **setting);
/* From lightbox.conf; ends the process when the two settings are no network. */
void container_network_load_or_die(container_network *net);
/* NULL, or why no container can have this address on that network. */
const char *address_unusable(const container_network *net, uint32_t addr);
/* "<address>/<bits>": an address as an interface of that network is given it */
void address_with_prefix(char out[CIDR_TEXT_MAX], uint32_t addr, const container_network *net);
/* "<network>/<bits>": the subnet, however the setting spelled it */
void subnet_text(char out[CIDR_TEXT_MAX], const container_network *net);
/* The address a container was created with, as text that parse_ipv4 takes;
 * -1 when it has none on record, and ip is left as it was. */
int read_container_ip(const char *name, char *ip, size_t ipsz);
int update_link_rules(const container_config *config, const char *ip, bool add_rules);
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
