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

/* What --version says: the release, set when it is tagged, and "-dev" after
 * it on the way to the next one. */
#define LIGHTBOX_VERSION "0.10.0"

#define MAX_PATH         512
#define NAME_MAX_LEN     30
#define MAX_VOLS         16
#define MAX_LINKS        8
#define MAX_DNS          3       /* as many as a resolver reads from resolv.conf */

/* What a container may reach (ROADMAP 8.5, 8.6): today's network, the
 * internet and its name servers only, nothing at all, or one port of the
 * gateway, where a proxy listens. A .conf without the line is of a container
 * made before 0.8, which has today's. */
enum { NET_NAT = 0, NET_OUTSIDE = 1, NET_NONE = 2, NET_PROXY = 3 };
#define NET_MODE_TEXT_MAX 12    /* "proxy:65535" and its NUL */

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
/* --ttl as it is kept: a duration as parse_duration_ms takes it */
#define DURATION_TEXT_MAX 24
#define IO_TEXT_MAX     128     /* a line for io.max */

#define PIDS_LIMIT_MAX  4194304         /* the most processes Linux numbers */
#define CPU_LIMIT_MAX   512             /* CPUs */
#define CPU_PERIOD_US   100000          /* cpu.max: the period a quota is of */
#define OOM_SCORE_MIN   (-1000)
#define OOM_SCORE_MAX   1000

/* Which firewall lightbox puts its rules in, as Docker's firewall-backend. */
typedef enum { FIREWALL_IPTABLES, FIREWALL_NFTABLES } firewall_backend_kind;

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
    /* What --profile agent gives a box that no option gives a limit or a
     * lifetime (ROADMAP 8.10), empty when it cannot be used, as above.
     * agent_ttl is "none" for no lifetime, and agent_ttl_ok false when it
     * cannot be used. */
    char agent_mem[MEM_TEXT_MAX];
    char agent_pids[PIDS_TEXT_MAX];
    char agent_cpu[CPU_TEXT_MAX];
    char agent_ttl[DURATION_TEXT_MAX];
    bool agent_ttl_ok;
    int  start_timeout;     /* seconds start waits for the init hook; 0: not at all */
    int  stop_timeout;      /* seconds a container gets to end when it is asked to */
    char dns[64];           /* name servers for new containers, as written; empty: the host's */
    /* The firewall, as Docker's daemon.json has these: */
    bool firewall;              /* lightbox makes its rules (Docker: "iptables") */
    bool ip_forward;            /* setup turns IPv4 forwarding on, where firewall has it make the rules ("ip-forward") */
    bool ip_forward_no_drop;    /* and then leaves the FORWARD policy as it is ("ip-forward-no-drop") */
    bool ip_masq;               /* what leaves by anything but the bridge is masqueraded ("ip-masq") */
    firewall_backend_kind firewall_backend;     /* "firewall-backend" */
    /* With nftables, what lightbox's rules accept before they drop anything:
     * packets whose mark, under the mask, is this ("bridge-accept-fwmark"). */
    bool     accept_fwmark_set;
    uint32_t accept_fwmark;
    uint32_t accept_fwmask;
} global_config;

extern global_config cfg_global;

/* Where the settings come from: --config, then $LIGHTBOX_CONFIG, then
 * /etc/lightbox/lightbox.conf; or the built-in values. Where lightbox looked
 * before 0.6, $HOME/.config/lightbox/lightbox.conf, is not read: CONFIG_HOME
 * is a file there with nothing named and none in /etc, which ends the
 * command. */
#define CONFIG_ETC_FILE  "/etc/lightbox/lightbox.conf"
#define CONFIG_HOME_FILE ".config/lightbox/lightbox.conf"
typedef enum { CONFIG_GIVEN, CONFIG_ENV, CONFIG_ETC, CONFIG_HOME, CONFIG_NONE } config_source;
config_source config_source_of(const char *given, const char *from_env, bool etc_there, bool home_there);

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

/* A box's id (ROADMAP 8.9): 16 lowercase hex digits that create draws and
 * .conf keeps, which the audit log tells a box from a later one of its name
 * by. A box made before boxes had one has none. */
#define BOX_ID_LEN 16

/* --profile (ROADMAP 8.10): what a box was made with, kept in .conf as
 * profile=agent. Each setting the profile gave is kept under its own key
 * beside it, so that what the profile means later does not change a box
 * that is there. --workspace binds its directory here, and makes it where
 * every exec runs. */
#define PROFILE_NONE  0
#define PROFILE_AGENT 1
#define WORKSPACE_DIR "/workspace"

/* What init reports when --ttl ended the container, besides 0 for a stop and
 * 1 for a failure (ROADMAP 8.8): its state is then "expired". */
#define INIT_EXPIRED 2

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
    bool seccomp_allow;         /* the allow-list profile; false: the deny-list */
    int  net;                   /* NET_NAT, NET_OUTSIDE, NET_NONE or NET_PROXY */
    int  proxy_port;            /* NET_PROXY: the port of the gateway its proxy listens on */
    int  ndns;                  /* the name servers create gave it, which outside lets it ask */
    char dns[MAX_DNS][16];
    char base[13];              /* the snapshot it overlays; empty: a copy of its base */
    char ttl[DURATION_TEXT_MAX];    /* --ttl as given; empty: none */
    char id[BOX_ID_LEN + 1];    /* empty: made before boxes had one */
    int  profile;               /* PROFILE_NONE, or PROFILE_AGENT: made with --profile agent */
    char workdir[MAX_PATH];     /* where exec runs a command without --workdir; empty: / */
    int64_t ttl_ms;             /* its lifetime from each start, or 0 */
    bool userns;                /* uid and gid 0 are uid_start and gid_start on the host */
    uint32_t uid_start;
    uint32_t gid_start;
    int  nvols;
    volume_spec vols[MAX_VOLS];
    int  nlinks;
    char links[MAX_LINKS][NAME_MAX_LEN + 1];
} container_config;

#define CONTAINER_CONFIG_VERSION 1

/* Is this a limit as an option, a setting and the file may give it? */
[[nodiscard]] bool mem_limit_ok(const char *text);      /* <number>[K|M|G|T] or max */
[[nodiscard]] bool swap_limit_ok(const char *text);     /* the same, or 0 */
/* The bytes such a limit is: all there are for max, none for a swap of 0 */
[[nodiscard]] bool limit_bytes(const char *text, uint64_t *bytes);
/* A line for io.max: <major>:<minor> and one or more of rbps, wbps, riops and
 * wiops, each =<number> or =max, with a space before each */
[[nodiscard]] bool io_limit_ok(const char *text);
[[nodiscard]] bool pids_limit_ok(const char *text);     /* 1 to PIDS_LIMIT_MAX, or max */
/* 0.01 to CPU_LIMIT_MAX CPUs with at most two decimals: the quota, in
 * microseconds of each CPU_PERIOD_US */
[[nodiscard]] bool parse_cpu_limit(const char *text, int *quota_us);
[[nodiscard]] bool parse_oom_score(const char *text, int *out);
/* "allow" or "deny", the seccomp profile, as an option and the file give it */
[[nodiscard]] bool parse_seccomp_profile(const char *text, bool *allow);
/* "nat", "outside", "none" or "proxy:<port>", as --net and the file give it,
 * and the text of one */
[[nodiscard]] bool parse_net_mode(const char *text, int *mode, int *proxy_port);
void net_mode_text(char out[NET_MODE_TEXT_MAX], int mode, int proxy_port);

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

/*
 * The status lightbox ends with when it fails: 1, but for exec, whose status
 * is its command's (ROADMAP 8.7). There a failure of lightbox's is
 * EXEC_FAILED, as env and timeout have it, so that a driver can tell it from
 * what the command did: 126 is a command that could not be executed, 127 one
 * that is not there, and EXEC_TIMED_OUT one that --timeout ended. Every exit
 * that is a failure of lightbox's uses failure_status, die and die2 among them.
 */
#define EXEC_TIMED_OUT 124
#define EXEC_FAILED    125
extern int failure_status;
/* fn is run before a failure ends this process, die's or fail_now's; NULL: nothing */
void on_failure(void (*fn)(void));
[[noreturn]] void fail_now(void);
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

/*
 * A duration in milliseconds, above 0 and at most DURATION_MAX_MS: digits,
 * up to three more after a point, and a unit, s, m, h or d, or none for
 * seconds. "2s", "1.5m" and "90" are durations; "0", ".5", "1.", "1.2345s",
 * "-1", "+1", "1 s", "1ms" and "2x" are not.
 */
#define DURATION_MAX_MS ((int64_t)365 * 86400 * 1000)
[[nodiscard]] bool parse_duration_ms(const char *text, int64_t *ms);
int fmt_int(char *buf, int val);
[[nodiscard]] bool random_hex(char *out, size_t bytes);
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
/* The cgroup device program of lightbox_devices.h, loaded (ROADMAP 8.4): its
 * descriptor, or -errno. A program the kernel refuses is loaded once more
 * for the verifier to say why, into log, which is empty otherwise. */
lc_sysret device_program_load(char *log, uint32_t log_size);

[[nodiscard]] int write_file_in_root(const char *root, const char *dir, const char *name,
                                     const char *data, int32_t mode);
[[nodiscard]] int read_file_in_root(const char *root, const char *dir, const char *name,
                                    char *buf, size_t bufsz);
void cfg_global_init(void);
/* the value of a variable in an environment, or NULL */
const char *env_get(char **envp, const char *name);
/* given: the path --config names, or NULL */
void cfg_global_load(char **envp, const char *given);

int read_file(const char *path, char *buf, size_t bufsz);
bool path_exists(const char *path);
bool path_is_directory(const char *path);
bool path_executable(const char *path);
/* A release as uname gives it, "6.12.117-x": at least want_major.want_minor?
 * What it reads goes in major and minor, -1 each when it reads nothing. */
bool kernel_release_at_least(const char *release, int want_major, int want_minor, int *major, int *minor);
/* The kernel lightc and lightbox need. */
#define KERNEL_FLOOR_MAJOR 5
#define KERNEL_FLOOR_MINOR 10
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
/* the same, with what it says on stderr thrown away */
[[nodiscard]] int run_cmd_capture_quiet(const char *prog, const char *const argv[], char *out, size_t outsz);
/* the same with input as the program's standard input, at most RUN_INPUT_MAX bytes of it */
#define RUN_INPUT_MAX 32768
[[nodiscard]] int run_cmd_input(const char *prog, const char *const argv[], const char *input, bool quiet);

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
const char *tool_path_iptables(void);
const char *tool_path_iptables_restore(void);
const char *tool_path_nft(void);
const char *tool_path_cp(void);
const char *tool_path_rm(void);
const char *tool_path_gzip(void);
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
/* The entries of a directory that valid takes, directories only, sorted. */
int list_entries(const char *dir, bool (*valid)(const char *), char names[][NAME_MAX_LEN + 1], int max, bool *more);

/* ─── User namespaces (lightbox_userns.c) ───────────────────────────────── */

/* A container's own ids: USERNS_SIZE uids and gids from the ranges that
 * /etc/subuid and /etc/subgid give USERNS_OWNER, as Podman's --userns=auto
 * takes those of "containers". Its uid 0 is uid_start on the host. */
#define USERNS_SIZE      65536u
#define USERNS_OWNER     "lightbox"
#define SUBUID_FILE      "/etc/subuid"
#define SUBGID_FILE      "/etc/subgid"
#define SUBID_RANGES_MAX 256
typedef struct {
    uint32_t start;
    uint32_t count;
} subid_range;
/* A decimal number of at most 4294967295, without a zero in front. */
[[nodiscard]] bool parse_u32_text(const char *text, uint32_t *out);
/* A first id of a range: a number, not 0, whose range ends before 4294967295. */
[[nodiscard]] bool userns_start_ok(const char *text, uint32_t *start);
void format_u32(char out[11], uint32_t value);
/* The ranges that a subid file's text gives owner: how many, or -1 for a
 * line of owner's that is no usable range, whose number *line then has. */
int subid_ranges(const char *text, const char *owner, subid_range *out, int max, int *line);
/* The first range of USERNS_SIZE uids that overlaps none of the ntaken
 * taken[i][0], and the first of gids that overlaps none of taken[i][1].
 * NULL, or why there is none. */
const char *userns_choose(const subid_range *uids, int nu, const subid_range *gids, int ng,
                          const uint32_t taken[][2], int ntaken, uint32_t *uid_start, uint32_t *gid_start);
/* How many ranges of USERNS_SIZE uids and gids the two files give lightbox,
 * taken or not; -1 when one of them has a line that is no range. */
int userns_range_count(void);
/* The same from /etc/subuid, /etc/subgid and every container's .conf, under
 * the store's lock. NULL, or why there is none. */
const char *userns_allocate(uint32_t *uid_start, uint32_t *gid_start);
/* One line of a uid_map or gid_map: count ids from inside, in the
 * namespace, are the ids from outside in the one it was made in. To an
 * idmapped mount, inside is the id a file has on its filesystem and outside
 * the one it shows. */
typedef struct {
    uint32_t inside;
    uint32_t outside;
    uint32_t count;
} id_map;
#define ID_MAP_LINE_MAX 36
/* "<inside> <outside> <count>\n" */
void id_map_line(char out[ID_MAP_LINE_MAX], const id_map *map);
/* The maps of a volume of a container with --userns whose source is owned
 * by owner_uid and owner_gid on the host: they are its root, uid_start and
 * gid_start, and no other id is mapped. False for a source of host root's,
 * uid 0 or gid 0, which no container may stand for. */
[[nodiscard]] bool volume_maps(uint32_t owner_uid, uint32_t owner_gid, uint32_t uid_start, uint32_t gid_start,
                               id_map *uids, id_map *gids);
/* uid_map and gid_map of a process in a new user namespace: 0, or minus an errno */
[[nodiscard]] int userns_write_maps(int pid, uint32_t uid_start, uint32_t gid_start);
/* A user namespace with a container's maps, for idmapped mounts: a
 * descriptor, or minus an errno */
[[nodiscard]] int userns_fd_with(uint32_t uid_start, uint32_t gid_start);
/* The same with the maps given, a line each */
[[nodiscard]] int userns_fd_mapped(const id_map *uids, const id_map *gids);
/* An idmapped, nodev copy of the mount at path, attached nowhere; nosuid
 * unless privileged. Its descriptor, or minus an errno and *step the call. */
[[nodiscard]] int idmapped_tree(const char *path, int userns_fd, bool privileged, const char **step);
[[nodiscard]] int attach_tree(int tree, const char *target);

/* ─── SHA-256 (lightbox_sha256.c, ROADMAP I.1) ──────────────────────────── */

/*
 * What a blob of an image is named by. The input is taken in pieces of any
 * length, so that a layer is hashed while it is written or read:
 *
 *   sha256_init, sha256_update for each piece, sha256_final
 */
#define SHA256_BYTES 32
#define SHA256_HEX   64         /* a digest's digits, without their NUL */
#define SHA256_BLOCK 64         /* the bytes the hash takes at a time */
typedef struct {
    uint32_t state[8];
    uint64_t length;                /* the bytes taken so far */
    uint8_t  block[SHA256_BLOCK];   /* those of them that do not fill a block yet */
} sha256_ctx;
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
/* The digest of all that was taken. The context is spent and wiped: it takes
 * a sha256_init before it is used again. */
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_BYTES]);
/* A digest as 64 lowercase hex digits and their NUL, and whether a text is
 * one: the way a blob's name and a descriptor have it. */
void sha256_hex(const uint8_t digest[SHA256_BYTES], char out[SHA256_HEX + 1]);
[[nodiscard]] bool sha256_hex_ok(const char *text);

/* ─── tar (lightbox_tar.c, ROADMAP I.2 and I.3) ─────────────────────────── */

/* The longest name an archive's entry may have from its root, a link's
 * target too, with the NUL: the kernel's own limit for a path. */
#define TAR_PATH_MAX 4096

/* Where an archive's bytes go, all of them and in order: 0, or anything else
 * to end the writing. */
typedef int (*tar_sink)(void *to, const void *data, size_t len);

/*
 * A tree written as a tar archive, the way a layer of an image is one. The
 * same tree gives the same bytes every time. The caller sets the first five
 * members; the others say afterwards what was written and what was not.
 */
typedef struct {
    tar_sink    sink;
    void       *to;
    /* Ids are written less these, and one that is not in the 65536 from a
     * start that is not 0 ends the writing: a container's with --userns has
     * its files under its own range, and an image has them from 0. */
    uint32_t    uid_start;
    uint32_t    gid_start;
    /* The tree is an overlay's upper directory: what it marks as taken out
     * of its base is written as an image marks it. */
    bool        overlay;

    uint64_t    entries;            /* written */
    uint64_t    sockets;            /* left out: a socket is of a process that is gone */
    uint64_t    attributes_left;    /* extended attributes an archive does not carry */
    const char *failure;            /* NULL, or what ended the writing */
    char        failed_at[TAR_PATH_MAX];    /* and the entry it was at, from the tree's root */
} tar_writer;

/* The tree under a directory, which is not an entry itself, and the
 * archive's end: 0, or -1 with failure and failed_at set. */
[[nodiscard]] int tar_write_tree(tar_writer *w, int32_t dirfd);

/* Where an archive's bytes come from, in order: how many were put at data,
 * at most len, 0 at the archive's end, or less than 0 to end the reading.
 * It is called in the process that unpacks, not in the caller's. */
typedef int64_t (*tar_source)(void *from, void *data, size_t len);

/* What the directory an archive is unpacked into is. An image marks what a
 * layer takes out of the ones under it with names that begin with .wh. */
typedef enum {
    TAR_INTO_TREE,              /* one tree for all layers: a mark takes out what it names */
    TAR_INTO_UPPER,             /* an overlay's upper directory: a mark becomes the overlay's own */
    TAR_INTO_UPPER_USERXATTR,   /* the same, for an overlay mounted with userxattr */
} tar_into;

/*
 * An archive unpacked into a directory, by a process of its own whose root is
 * that directory: no name and no link of the archive leads out of it. The
 * caller, which has to be root there, sets the first five members; the others
 * say afterwards what was made and what was not.
 */
typedef struct {
    tar_source  source;
    void       *from;
    /* The one descriptor the source reads: the process that unpacks keeps
     * it, the root's and the pipe it answers on, and closes every other one
     * before it reads a byte (ROADMAP I.12). */
    int32_t     source_fd;
    /* Ids are made these more, and with a start that is not 0 one that is
     * not in the 65536 from it ends the unpacking. */
    uint32_t    uid_start;
    uint32_t    gid_start;
    tar_into    into;

    uint64_t    entries;            /* made, or taken out by a mark */
    uint64_t    devices;            /* not made: a container's devices are lightbox's to give */
    uint64_t    attributes_left;    /* extended attributes that were not set */
    uint64_t    bytes;              /* read from the source, to its end */
    uint8_t     digest[SHA256_BYTES];   /* and their SHA-256, when the unpacking did not fail */
    const char *failure;            /* NULL, or what ended the unpacking */
    /* and the entry it was at, as the archive names it, with a ? for each
     * byte that is not printable: empty before the first */
    char        failed_at[TAR_PATH_MAX];
} tar_reader;

/* The archive's entries under a directory, to the source's end: 0, or -1
 * with failure and failed_at set. What was made before a failure stays. */
[[nodiscard]] int tar_read_tree(tar_reader *r, int32_t dirfd);

/* ─── JSON, read (lightbox_json.c, ROADMAP I.4) ─────────────────────────── */

/*
 * What an image's index, manifest and configuration are written in. A text
 * is checked whole and strictly, json_check, and then its values are looked
 * up in it; nothing is built from it, and a value is its bytes in the text,
 * which has to stay where it is for as long as one is used.
 */
#define JSON_TEXT_MAX  ((size_t)1 << 20)    /* the longest text that is read */
#define JSON_DEPTH_MAX 32                   /* arrays and objects inside one another */

typedef enum { JSON_NULL, JSON_FALSE, JSON_TRUE, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT } json_kind;

typedef struct {
    const char *text;
    size_t      len;
} json_value;

/* Why a text is not read, and where: the bytes before the place, its line
 * from 1, and its column in the line, in bytes and from 1. */
typedef struct {
    const char *why;
    size_t      offset;
    size_t      line;
    size_t      column;
} json_refusal;

/* A text as RFC 8259 has one, and nothing that readers take differently: a
 * name twice in one object, bytes that are no UTF-8, half a surrogate pair,
 * \u0000, anything but blanks around the value. 0 and the value the text is,
 * or -1 and why not. */
[[nodiscard]] int json_check(const char *text, size_t len, json_value *root, json_refusal *why);

json_kind json_kind_of(json_value v);

/* An array's elements or an object's members, in the order they are written:
 *   for (bool more = json_first(v, &item); more; more = json_next(&item)) */
typedef struct {
    json_value name;    /* of a member, a string; of an element, nothing */
    json_value value;
    json_value rest;    /* what follows it in its array or object */
    bool       named;
} json_item;
[[nodiscard]] bool json_first(json_value in, json_item *item);
[[nodiscard]] bool json_next(json_item *item);
size_t json_count(json_value v);

/*
 * The value at a path from v, written as RFC 6901 has a path: "" is v,
 * "/layers/0/digest" the member digest of the first element of the member
 * layers; in a name, ~1 stands for / and ~0 for ~. 1 with the value, 0 when
 * nothing is there, and -1 when an object on the way has a member whose name
 * is the path's but for the case of its letters: Go's reader of JSON takes
 * that member for the field, so that the text says two things.
 */
[[nodiscard]] int json_at(json_value v, const char *path, json_value *out);

/* What a string says, its escapes resolved, with a NUL: its length, or -1
 * and an empty text for what is no string or does not fit. */
[[nodiscard]] int64_t json_text(json_value v, char *out, size_t size);
[[nodiscard]] bool json_text_is(json_value v, const char *text);
/* A number written with digits alone, 0 to 2^64 - 1: no sign, no fraction
 * and no exponent, which is how a size and a version are written. */
[[nodiscard]] bool json_whole(json_value v, uint64_t *number);

/* ─── Base snapshots (lightbox_base.c) ──────────────────────────────────── */

#define BASE_ID_LEN  12
#define BASE_ID_TEXT (BASE_ID_LEN + 1)
bool base_id_ok(const char *id);
void bases_dir_path(char out[MAX_PATH]);
/* <bases>/<id>/rootfs: false for an id that is not one */
bool base_rootfs_path(char out[MAX_PATH], const char *id);
/* A snapshot of a base directory taken now: 0, or -1 once said. */
int base_take(const char *source, char id[BASE_ID_TEXT]);
/* The two halves of that, for a snapshot that is filled another way: its id
 * drawn and <bases>/.<id>.new made, with its source line and its time on
 * record and nothing else in it; and that directory put in place under the
 * id. Each 0, or -1 once said, with the directory taken away. */
int base_begin(const char *source, char id[BASE_ID_TEXT], char fresh[MAX_PATH]);
int base_commit(const char *id, const char *fresh);
/* A snapshot that was put in place and that nothing came to use, taken away */
void base_discard(const char *id);
/* The newest snapshot of a base directory, or one taken now, which took
 * says: 0, or -1 once said. */
int base_snapshot_for(const char *source, char id[BASE_ID_TEXT], bool *took);
int list_bases(char ids[][NAME_MAX_LEN + 1], int max);
/* <bases>/<id>/layer: the digest and the size of the snapshot written as a
 * layer of an image, which an export keeps (ROADMAP I.5). False when none
 * is kept, or what is there is no such record. */
[[nodiscard]] bool base_layer_read(const char *id, char digest[SHA256_HEX + 1], uint64_t *size);
[[nodiscard]] int base_layer_keep(const char *id, const char *digest, uint64_t size);
/* The layers of an image that a snapshot was unpacked from, one over the
 * other: "sha256:<digest>" and a newline for each, the digest of the layer
 * as it is unpacked. Kept in a snapshot that is being made, in the directory
 * base_begin gave; and the snapshot that is those layers, if there is one. */
#define IMAGE_LAYERS_MAX    128
#define BASE_IMAGE_TEXT_MAX (IMAGE_LAYERS_MAX * (SHA256_HEX + 8) + 1)
[[nodiscard]] int base_image_keep(const char *fresh, const char *layers);
[[nodiscard]] bool base_of_layers(const char *layers, char id[BASE_ID_TEXT]);
/* The mount options of an overlay of a snapshot with this upper and work
 * directory, or false where a path cannot go into them. */
bool overlay_options(char *out, size_t max, const char *id, const char *upper, const char *work);
/* What every overlay of a container is mounted with beside its directories
 * (ROADMAP I.14): no directory stands for one of the snapshot, and no file
 * keeps its bytes there, so that a container's files are all in its rootfs/
 * on every host, whatever the host's own settings for overlays are. */
#define OVERLAY_WHOLE_OPTIONS "redirect_dir=off,metacopy=off"
/* Whether an upper directory is all of what it stands for: 1 yes; 0 no, with
 * the path of the first entry that is not, a directory moved from the
 * snapshot or a file whose bytes are there, as an overlay mounted without
 * those options leaves them; -1 when it cannot be read through. */
int overlay_upper_whole(const char *upper, char *found, size_t max);
void cmd_base(int argc, char **argv);

/* ─── Images (lightbox_image.c, ROADMAP Track I) ────────────────────────── */

/* export <name> <dir>: a container that is not running as an OCI image
 * layout in a directory of its own */
void cmd_export(int argc, char **argv);

/*
 * Generations (ROADMAP I.10). A container that is exported is of a line,
 * which the first export names with 16 hex digits drawn then, and at a
 * generation of it: the first export is 1, and each export of a container
 * that was started since the one before is one more. A generation has a
 * token of its own, 8 hex digits drawn when it is made, and a container and
 * an image keep those of the generations they come from, the newest last:
 * by them one is known to continue the other, or not to.
 *
 *   <container>/.generation   "<line> <number> <token>,<token>,...\n"
 *   <container>/.changed      there when the container was started, or
 *                             reset, since its generation was written
 */
#define LINEAGE_HEX            16
#define GENERATION_HEX         8
#define GENERATIONS_KEPT       32
#define GENERATION_HISTORY_MAX (GENERATIONS_KEPT * (GENERATION_HEX + 1) + 1)

typedef struct {
    char     lineage[LINEAGE_HEX + 1];      /* empty: of no line */
    uint32_t number;                        /* of the newest generation: 1 and up */
    int      count;                         /* how many tokens are kept: at least 1 */
    char     tokens[GENERATIONS_KEPT][GENERATION_HEX + 1];
} generation;

/* what one generation is to another of its line, or that it is of none */
typedef enum {
    GENERATION_OF_ANOTHER_LINE,
    GENERATION_THE_SAME,
    GENERATION_CONTINUED,                   /* the second continues the first */
    GENERATION_CONTINUES,                   /* the first continues the second */
    GENERATION_APART,                       /* of one line, and neither continues the other */
} generation_relation;

/* A container's generation on record: false where it has none, or what is
 * there is none. */
[[nodiscard]] bool generation_read(const char *name, generation *g);
[[nodiscard]] int generation_keep(const char *name, const generation *g);
/* Of no line any more: what is on record is taken away */
void generation_forget(const char *name);
/* Whether the container was started, or reset, since its generation was written */
[[nodiscard]] bool generation_changed(const char *name);
/* On record that it was: 0, also for a container of no line, which keeps no
 * such record; -1 when it could not be written. And that record taken away. */
[[nodiscard]] int generation_started(const char *name);
void generation_unchanged(const char *name);
/* The tokens as an image carries them, "<token>,<token>,...", and taken from that */
void generation_history_text(const generation *g, char out[GENERATION_HISTORY_MAX]);
[[nodiscard]] bool generation_history_take(const char *text, generation *g);
generation_relation generation_compare(const generation *first, const generation *second);

/*
 * An image that import read (ROADMAP I.6): every blob of it was held to the
 * size and the SHA-256 it is named by, and its layers are open. The limits
 * are those its manifest carries, each empty where it carries none.
 */
typedef struct {
    char     digest[SHA256_HEX + 1];    /* of the blob */
    char     diff_id[SHA256_HEX + 1];   /* of the layer as it is unpacked, which the configuration names */
    uint64_t size;
    bool     gzip;                      /* the blob is the layer compressed */
    int32_t  fd;
} image_layer;

typedef struct {
    char        dir[MAX_PATH];
    char        manifest[SHA256_HEX + 1];
    int         nlayers;
    image_layer layers[IMAGE_LAYERS_MAX];
    char        name[NAME_MAX_LEN + 1];     /* what the container was called where it was exported */
    char        mem[MEM_TEXT_MAX];
    char        swap[MEM_TEXT_MAX];
    char        pids[PIDS_TEXT_MAX];
    char        cpu[CPU_TEXT_MAX];
    char        ttl[DURATION_TEXT_MAX];
    bool        lightbox;                   /* export wrote it: its annotations are lightbox's, of the version read here */
    generation  gen;                        /* the generation it is, of its container's line; of none where it names none */
    bool        command;                    /* its configuration names a command to start, which lightbox does not read */
} image;

/* The image in a directory, read and held to its digests. What is no image
 * that import takes ends the process, said; what an image says of its
 * container and import does not take is said too, as a note. */
void image_open(const char *dir, image *img);
/* The first count layers as base_image_keep and base_of_layers take them */
void image_layers_text(const image *img, int count, char out[BASE_IMAGE_TEXT_MAX]);

typedef struct {
    uint64_t entries, devices, attributes_left, bytes;
} image_unpacked;
/* count layers from the one at first, unpacked into a directory one over the
 * other, each held to the digest the configuration names for it as it is
 * unpacked; a compressed one through the host's gzip. 0, or -1 once said,
 * with what was unpacked until then left for the caller to take away. */
[[nodiscard]] int image_unpack(const image *img, int first, int count, const char *dir, tar_into into,
                               uint32_t uid_start, uint32_t gid_start, image_unpacked *total);

/*
 * The snapshot that is the first count layers of an image, one unpacked over
 * the other: one that is here already, by the record it keeps of the layers
 * it was unpacked from, or of the layer an export wrote it as; or one made
 * now, in a directory that is put in place when it is whole. 0, with its id
 * and whether it was made now; -1 once said, with nothing kept.
 */
[[nodiscard]] int image_base(const image *img, int count, char id[BASE_ID_TEXT], bool *took, image_unpacked *total);
/* What of an image was left out when it was unpacked, and what of it lightbox
 * does not read, each as a note on standard output */
void image_notes(const image *img, const image_unpacked *unpacked);
/* Whether a directory is laid out as an image, and so is no root filesystem:
 * what create and base add are told is a base, by mistake */
bool image_layout_at(const char *dir);

/* What the host's gzip runs under, which reads bytes somebody else wrote: no
 * network of the host's, nobody's ids, no capability, no new privilege, and
 * a filter of the calls gzip makes, with execve of program alone, at this
 * address, which is what the caller then runs (ROADMAP I.12). Ends the
 * process where it cannot. */
void sandbox_host_tool(const char *program);

/*
 * What a container is made of is in <container_dir>/<name>/ and is written
 * to stay: its root filesystem, its configuration, its address, its log,
 * and a mark while create has not finished with it.
 */
void container_dir_path(char *buf, const char *name);
void container_root(char *buf, const char *name);
void container_ip_path(char *buf, const char *name);
/* <run_dir>/<name>/firewall: there while the container may have link rules.
 * container_forget_run leaves it, and so its directory, in place. */
void container_firewall_path(char *buf, const char *name);
/* <run_dir>/<name>/egress: the same, for the rules of --net outside */
void container_egress_path(char *buf, const char *name);
void container_conf_path(char *buf, const char *name);
void container_creating_path(char *buf, const char *name);
/* .resolv: what create wrote in its resolv.conf, which reset writes again */
void container_resolv_path(char *buf, const char *name);
/* .runner: the run whose box it is */
void container_runner_path(char *buf, const char *name);
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
/* a process's start time, field 22 of /proc/<pid>/stat, as digits: 0, or -1 */
[[nodiscard]] int proc_starttime(int pid, char *buf, size_t bufsz);
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
/* The store's lock: the descriptor that holds it, to close when it may go,
 * or -1 when there is no store yet to lock. */
int32_t store_lock(void);
/* A container's lock if no command holds it, without waiting: the
 * descriptor that holds it, or -1. */
int32_t container_lock_try(const char *name);

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

/* ─── The firewall ──────────────────────────────────────────────────────── */

/*
 * lightbox's rules are in chains of its own, as Docker's are, so that they
 * come before a host firewall's and are taken out whole:
 *
 *   filter  FORWARD -> LIGHTBOX-USER       the host's own rules, which lightbox never changes
 *           FORWARD -> LIGHTBOX-FORWARD    what the bridge forwards
 *           LIGHTBOX-FORWARD -> LIGHTBOX-LINKS -> LB-<name>, one chain for each running
 *                                          container with links
 *   nat     POSTROUTING -> LIGHTBOX-POSTROUTING
 */
/*
 * What a container is called where its name does not fit: the end of its
 * interface on the host, vb-<12 hex digits>, and the chain of its links,
 * LB-<the same digits>. The digits are 48 bits of an FNV-1a hash of the
 * name, the same for a name every time. In the container the interface is
 * eth0.
 */
#define IFNAME_TEXT_MAX  16
#define CONTAINER_IFNAME "eth0"
void host_port_name(const char *name, char out[IFNAME_TEXT_MAX]);
void link_chain_name(const char *name, char out[IFNAME_TEXT_MAX]);
/* Whose an interface on the host is, by the alias lightbox gives what it
 * makes for a container: lightbox:<name>. One without it is not lightbox's.
 * PORT_UNKNOWN: the kernel could not be asked. */
typedef enum { PORT_ABSENT, PORT_OURS, PORT_FOREIGN, PORT_UNKNOWN } port_owner;
port_owner host_port_owner(const char *ifname, const char *name);
/* The same from the interface's alias, "" when it has none. */
port_owner port_owner_of_alias(const char *alias, const char *name);
/* Is this a chain a record of link rules may name: LB- and what an iptables
 * chain name may hold, within its 28 characters? */
bool link_chain_ok(const char *chain);
/* The interface removed when it is this container's: 0 when none of the
 * container's is there afterwards, 1 when one of that name that is not
 * lightbox's was left alone, -1 when it could not be removed. */
int remove_own_port(const char *ifname, const char *name);

/* ─── rtnetlink (lightbox_netlink.c) ─────────────────────────────────────── */

/*
 * The kernel's configuration of interfaces, addresses and routes, asked over
 * a netlink socket: what lightbox had ip and nsenter do until 0.7. Each call
 * is one request: 0, or what it asks for, or minus the errno the kernel
 * refused it with (-ENODEV for an interface that is not there).
 */
typedef struct {
    int32_t  fd;
    uint32_t seq;
} rtnl;
[[nodiscard]] int rtnl_open(rtnl *nl);
void rtnl_close(rtnl *nl);
/* The interface's index; with alias, its alias as well, "" when it has none. */
[[nodiscard]] int rtnl_link_get(rtnl *nl, const char *ifname, char *alias, size_t alias_max);
[[nodiscard]] int rtnl_link_name(rtnl *nl, int index, char out[IFNAME_TEXT_MAX]);
/* A veth pair, its peer made in the network namespace of process peer_pid. */
[[nodiscard]] int rtnl_veth_add(rtnl *nl, const char *ifname, const char *peer, int peer_pid);
[[nodiscard]] int rtnl_bridge_add(rtnl *nl, const char *ifname);
/* The alias, and then the bridge of that index as the interface's master. */
[[nodiscard]] int rtnl_link_attach(rtnl *nl, const char *ifname, const char *alias, int master);
/* A bridge's port that does not reach its other isolated ports. */
[[nodiscard]] int rtnl_port_isolate(rtnl *nl, const char *ifname);
[[nodiscard]] int rtnl_link_up(rtnl *nl, const char *ifname);
[[nodiscard]] int rtnl_link_delete(rtnl *nl, const char *ifname);
[[nodiscard]] int rtnl_addr_add(rtnl *nl, int index, uint32_t addr, int prefix);
[[nodiscard]] int rtnl_default_route_add(rtnl *nl, uint32_t gateway, int index);
/* The index of the interface of the main table's default route, 0 for none. */
[[nodiscard]] int rtnl_default_route_index(rtnl *nl);
/* Init, in the container's network namespace: eth0 up, with its address and
 * the default route through the gateway. 0, or -1 once it has said why not. */
[[nodiscard]] int container_interface_up(uint32_t addr, int prefix, uint32_t gateway);
#define FIREWALL_TEXT_MAX 4096
/* What iptables-restore is given: for a container's links, or for setup.
 * False when it does not fit. */
[[nodiscard]] bool firewall_links_text(const char *name, const container_config *config, char *out, size_t outsz);
[[nodiscard]] bool firewall_setup_text(const container_network *net, char *out, size_t outsz);
/* A container's link rules put in, with one process: 0, or -1 once said. */
int firewall_add_links(const char *name, const container_config *config);
/* What firewall_add_links put in, taken out: 0 when nothing of it is left. */
int firewall_remove_links(const char *name);
/* --net outside and --net proxy (ROADMAP 8.5, 8.6): what iptables-restore is
 * given for the container at ip, whose proxy is at gw, and under nftables
 * the record of its elements and the text that puts them in or takes them
 * out. False when it does not fit, or for another --net. */
[[nodiscard]] bool firewall_egress_text(const char *name, const char *ip, const char *gw,
                                        const container_config *config, char *out, size_t outsz);
[[nodiscard]] bool nft_egress_record(const char *name, const char *ip, const char *gw,
                                     const container_config *config, char *out, size_t outsz);
[[nodiscard]] bool nft_egress_text(const char *record, bool removal, char *out, size_t outsz);
/* Whether a --net has rules of its own: outside and proxy. */
bool net_has_rules(int mode);
/* The rules of --net outside or proxy for the container at ip put in: 0, or
 * -1 once said. Nothing for another --net. */
int firewall_add_egress(const char *name, const char *ip, const container_config *config);
/* What firewall_add_egress put in, taken out: 0 when nothing of it is left. */
int firewall_remove_egress(const char *name);
/* The texts of a container's links and of its --net outside as one, which
 * either may be empty: nft's in a row, iptables-restore's as one table with
 * every chain declared before any rule. False when it does not fit. */
[[nodiscard]] bool firewall_rules_text(bool nftables, const char *links, const char *egress, char *out, size_t outsz);
/* The links and the --net outside rules of a container, as a start puts them
 * in: with one process. 0, or -1 once said. */
int firewall_add_rules(const char *name, const char *ip, const container_config *config);
/* does iptables see what the bridge switches between containers? */
bool bridge_traffic_is_filtered(void);

/*
 * The host's side of lightbox's network, which lives in the kernel only and
 * is gone after a reboot: the bridge, the firewall rules and forwarding.
 * start makes it again when it is not all there, as setup makes it.
 */
void ensure_host_network(const char *starting);
/* What of it is not there, as "the bridge, the firewall rules", or NULL
 * when all of it is. The firewall is looked at only by root. */
const char *host_network_missing(void);
/* Forwarding is off, and with firewall = false lightbox leaves it so: it is
 * no part of lightbox's host network then, and containers reach this host
 * and nothing beyond it. */
bool host_forwarding_left_off(void);
/* setup --teardown, once no container runs: lightbox's firewall rules, in
 * either backend, the bridge, cgroup_base and the record of forwarding. */
void teardown_host(void);

/*
 * firewall_backend = nftables: two tables of lightbox's own, made whole by
 * setup and loaded as one transaction each time.
 *
 *   ip lightbox      forward       what comes back to the bridge, and nothing new
 *                    postrouting   masquerading of what leaves by anything but it
 *   bridge lightbox  forward       between two ports of the bridge, only what the
 *                    set links     pairs of ports in links allow
 *
 * The bridge-family chain sees what the bridge switches without br_netfilter.
 * A container's links are elements of links; its record in run_dir names
 * them, as "nftables" and a line for each link: its port and the other's.
 */
#define NFT_RECORD_HEAD "nftables\n"
/* A mark, or a mark and a mask, "0x10" or "16/0xf0": what a packet can carry. */
[[nodiscard]] bool parse_fwmark(const char *text, uint32_t *mark, uint32_t *mask);
/* "0x10/0xf0", or the mark alone when the mask is all of it. */
void fwmark_text(char out[24], uint32_t mark, uint32_t mask);
/* vb- and twelve lowercase hex digits: a name host_port_name gives. */
bool host_port_ok(const char *ifname);
[[nodiscard]] bool nft_setup_text(const container_network *net, char *out, size_t outsz);
/* The record of a container's links, from its configuration. */
[[nodiscard]] bool nft_links_record(const char *name, const container_config *config, char *out, size_t outsz);
/* What nft is given for a record: its elements added, and with removal taken
 * out again, so that what is gone already does not stop the rest. False when
 * the record is not one lightbox writes, or the text does not fit. */
[[nodiscard]] bool nft_links_text(const char *record, bool removal, char *out, size_t outsz);
/* From what "nft list chains" printed, which this cuts into lines where it
 * stands: the base chains on the forward hook, of any table but lightbox's,
 * whose policy is drop, as "<family> <table> <chain>" with ", " between. */
size_t forward_drop_chains(char *listing, char *out, size_t outsz);
/* The same for this host, iptables' FORWARD among them: an empty text when
 * nothing drops what lightbox's nftables rules accept. */
void forward_drops_on_host(char *out, size_t outsz);

/* How exec can run from a copy of this binary that cannot be written to. */
typedef enum {
    SEAL_NONE,          /* not at all: exec refuses to run */
    SEAL_MEMFD,         /* a sealed copy in memory */
    SEAL_READONLY,      /* the binary itself, on a read-only mount of its own */
} seal_method;

/* which of them works here, found by doing all of it but the execution */
seal_method exec_seal_method(void);

void cmd_setup(void);
/* setup's part of the network again, and the link rules of the containers
 * that run: what a firewall's reload took */
void cmd_reload(int argc, char **argv);
/* the link rules and the rules of --net outside of the containers that run
 * but except, put in again; how many could not be */
int put_back_running_links(const char *except);
void cmd_doctor(int argc, char **argv);
void cmd_ls(int argc, char **argv);
void cmd_inspect(int argc, char **argv);
void cmd_logs(int argc, char **argv);

/* ─── The audit log (lightbox_audit.c, ROADMAP 8.9) ─────────────────────── */

/* <lightbox_dir>/audit.log */
void audit_log_path(char *buf);

/* s[0..len) as a JSON string in ASCII; out NULL: counted only. At most
 * JSON_QUOTED_MAX(len) bytes, the number written. */
#define JSON_QUOTED_MAX(len) ((len) * 6 + 2)
size_t json_quote(char *out, const char *s, size_t len);

/* "YYYY-MM-DDTHH:MM:SS.mmmZ" */
#define UTC_TEXT_LEN 24
void format_utc(char out[UTC_TEXT_LEN + 1], int64_t seconds, int64_t nanoseconds);

/* What the line of an exec's start records: what was asked of the box */
struct audit_start {
    const char *box, *box_id;           /* box_id empty or NULL: a box made before boxes had one */
    const char *exec_id;                /* <pid>-<start time> of the exec, as its cgroup is named */
    const char *via;                    /* "exec" or "run" */
    int64_t     uid, loginuid;          /* loginuid -1: none */
    const char *user, *workdir, *timeout;   /* as given, or NULL */
    const char *const *env;             /* --env KEY=VALUE, of which the keys are recorded */
    int         nenv;
    const char *const *argv;            /* the command, NULL at its end */
};

/* and of its end */
struct audit_end {
    const char *box, *box_id, *exec_id;
    int         status;                 /* what exec exits with */
    int64_t     duration_ms;
    bool        timed_out;
};

/* The line, with its newline; out NULL: counted only. Its length. */
size_t audit_start_line(char *out, const struct audit_start *a, const char *time);
size_t audit_end_line(char *out, const struct audit_end *e, const char *time);
/* Append the line, stamped with the time now: 0 or a negative errno. */
[[nodiscard]] int audit_record_start(const struct audit_start *a);
[[nodiscard]] int audit_record_end(const struct audit_end *e);
int64_t audit_loginuid(void);

/* The lines of one box, from the log as it is read in pieces */
enum audit_line_state { AUDIT_LINE_START, AUDIT_LINE_KEPT, AUDIT_LINE_SKIPPED };
struct audit_filter {
    char   prefix[NAME_MAX_LEN + 16];   /* {"box":"<name>", */
    size_t len, matched;
    enum audit_line_state state;
};
void audit_filter_start(struct audit_filter *f, const char *box);
/* in[0..n) into out, which has room for n + sizeof(f->prefix): the length kept */
size_t audit_filter(struct audit_filter *f, const char *in, size_t n, char *out);

#endif
