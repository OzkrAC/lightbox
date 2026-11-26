/*
 * lightbox_seccomp.h: the seccomp profile, as one table and one BPF program.
 *
 * There are two profiles, a deny-list and an allow-list (ROADMAP 8.3). Each
 * row of the deny table names a syscall, gives its number on x86_64 and on
 * aarch64, and the errno a sandboxed caller gets. A second table names the
 * syscalls that set a file's mode, which are refused when the mode has the
 * setuid or setgid bit. Both keep socket and socketpair to the families a
 * container uses. The deny-list allows everything else. The allow-list has
 * the same rules, then the syscalls it allows, and answers every other one
 * with ENOSYS.
 * lb_seccomp_build() and lb_seccomp_build_allow() turn the rows for the
 * target architecture into the program lightbox installs.
 *
 * Two more are for what lightbox runs on bytes from elsewhere (ROADMAP
 * I.12): the process that unpacks an archive, which may make the calls of
 * LB_SECCOMP_UNPACK and nothing else, and the host's gzip that unpacks a
 * compressed layer, which may make those of LB_SECCOMP_GZIP and is answered
 * ENOSYS for any other. lb_seccomp_build_unpack() and lb_seccomp_build_gzip()
 * write them.
 *
 * Nothing here is taken on trust:
 *   tests/sys_check.c       compares every number and constant below with the
 *                           kernel's headers, for both architectures
 *   tests/seccomp_filter.c  interprets the program of each architecture and
 *                           checks its verdict for every syscall number
 *   tests/seccomp_profile.c installs each program and calls the syscalls
 *
 * This header needs no lightc and no C library, so the tests can include it.
 */

#ifndef LIGHTBOX_SECCOMP_H
#define LIGHTBOX_SECCOMP_H

#include <stddef.h>
#include <stdint.h>

/*
 * The architecture the program is built for: the one being compiled, unless a
 * test asks for another by defining LB_SECCOMP_TARGET_X86_64 or
 * LB_SECCOMP_TARGET_AARCH64 itself.
 */
#if !defined(LB_SECCOMP_TARGET_X86_64) && !defined(LB_SECCOMP_TARGET_AARCH64)
#  if defined(__x86_64__)
#    define LB_SECCOMP_TARGET_X86_64 1
#  elif defined(__aarch64__)
#    define LB_SECCOMP_TARGET_AARCH64 1
#  else
#    error "lightbox_seccomp.h has no syscall numbers for this architecture"
#  endif
#endif

/* Both targets are little-endian, which LB_SECCOMP_DATA_ARG0_LO relies on. */
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "the seccomp program reads the low word of a 64-bit argument");

/* ─── Kernel constants ──────────────────────────────────────────────────── */

#define LB_SECCOMP_MODE_FILTER       2

#define LB_SECCOMP_RET_KILL_PROCESS  0x80000000U
#define LB_SECCOMP_RET_ERRNO         0x00050000U
#define LB_SECCOMP_RET_ALLOW         0x7fff0000U

#define LB_AUDIT_ARCH_X86_64         0xc000003eU
#define LB_AUDIT_ARCH_AARCH64        0xc00000b7U

/* classic BPF: class | size or operation | source */
#define LB_BPF_LD_W_ABS              0x20   /* A = 32-bit word at offset k */
#define LB_BPF_JEQ_K                 0x15   /* A == k */
#define LB_BPF_JGE_K                 0x35   /* A >= k, unsigned */
#define LB_BPF_JSET_K                0x45   /* A & k */
#define LB_BPF_RET_K                 0x06   /* return k */

/* offsets in struct seccomp_data */
#define LB_SECCOMP_DATA_NR           0
#define LB_SECCOMP_DATA_ARCH         4
#define LB_SECCOMP_DATA_ARG0_LO      16     /* low 32 bits of args[0] */
#define LB_SECCOMP_DATA_ARG_LO(i)    (LB_SECCOMP_DATA_ARG0_LO + 8 * (i))

/* x86_64 only: x32 calls report AUDIT_ARCH_X86_64 and carry this bit. */
#define LB_X32_SYSCALL_BIT           0x40000000U

/* CLONE_NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID and NEWNET.
 * CLONE_NEWTIME is not a clone() flag: its bit belongs to the exit signal. */
#define LB_SECCOMP_CLONE_NS_FLAGS    0x7e020000U

/* S_ISUID | S_ISGID, in the mode of the calls of LB_SECCOMP_MODE */
#define LB_SECCOMP_SUID_SGID         06000U
/* O_CREAT | __O_TMPFILE, the same on both targets: an open with either sets
 * the mode of what it makes */
#define LB_SECCOMP_CREATE_FLAGS      (0100U | 020000000U)

#define LB_SECCOMP_NR_CLONE_X86_64   56
#define LB_SECCOMP_NR_CLONE_AARCH64  220

#define LB_SC_EPERM                  1
#define LB_SC_ENOTTY                 25
#define LB_SC_ENOSYS                 38

#define LB_SECCOMP_PROT_EXEC         4U
#define LB_SECCOMP_TCGETS            0x5401U
#define LB_SECCOMP_NR_MMAP_X86_64    9
#define LB_SECCOMP_NR_MMAP_AARCH64   222
#define LB_SECCOMP_NR_EXECVE_X86_64  59
#define LB_SECCOMP_NR_EXECVE_AARCH64 221
#define LB_SECCOMP_NR_IOCTL_X86_64   16
#define LB_SECCOMP_NR_IOCTL_AARCH64  29
#define LB_SC_EAFNOSUPPORT           97

#define LB_SECCOMP_NR_SOCKET_X86_64       41
#define LB_SECCOMP_NR_SOCKET_AARCH64      198
#define LB_SECCOMP_NR_SOCKETPAIR_X86_64   53
#define LB_SECCOMP_NR_SOCKETPAIR_AARCH64  199

/* AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK, the same on both targets */
#define LB_SECCOMP_AF_UNIX           1
#define LB_SECCOMP_AF_INET           2
#define LB_SECCOMP_AF_INET6          10
#define LB_SECCOMP_AF_NETLINK        16

struct lb_sock_filter {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct lb_sock_fprog {
    uint16_t               len;
    struct lb_sock_filter *filter;
};

/* ─── The table ─────────────────────────────────────────────────────────── */

/*
 * Docker's default deny list. Almost every row answers EPERM. clone3 answers
 * ENOSYS: its flags sit behind a pointer the filter cannot read, so it cannot
 * be allowed selectively, and ENOSYS is the one answer that makes a C library
 * fall back to clone. With EPERM, glibc 2.34 and later cannot create a thread.
 * openat2 answers ENOSYS for the same reason: the mode of what it makes is
 * behind a pointer, and a program that uses it falls back to openat, whose
 * mode the filter can read (see LB_SECCOMP_MODE).
 *
 * pidfd_getfd, process_madvise and set_mempolicy_home_node are refused as
 * Docker refuses them to a container without CAP_SYS_PTRACE or CAP_SYS_NICE,
 * which no container here has. The kernel asks pidfd_getfd only for the right
 * to trace the process whose descriptor it takes, and set_mempolicy_home_node
 * for nothing; ptrace and the other NUMA calls have rows of their own.
 *
 * Not in the table on purpose: mount and pivot_root, which container setup
 * uses before the capabilities that permit them are dropped.
 *
 *   X(name, number on x86_64, number on aarch64, errno)
 */
#define LB_SECCOMP_DENY(X) \
    X(acct,               163,   89, LB_SC_EPERM) \
    X(add_key,            248,  217, LB_SC_EPERM) \
    X(bpf,                321,  280, LB_SC_EPERM) \
    X(clock_adjtime,      305,  266, LB_SC_EPERM) \
    X(clock_settime,      227,  112, LB_SC_EPERM) \
    X(delete_module,      176,  106, LB_SC_EPERM) \
    X(finit_module,       313,  273, LB_SC_EPERM) \
    X(get_mempolicy,      239,  236, LB_SC_EPERM) \
    X(io_uring_setup,     425,  425, LB_SC_EPERM) \
    X(io_uring_enter,     426,  426, LB_SC_EPERM) \
    X(io_uring_register,  427,  427, LB_SC_EPERM) \
    X(init_module,        175,  105, LB_SC_EPERM) \
    X(kcmp,               312,  272, LB_SC_EPERM) \
    X(kexec_file_load,    320,  294, LB_SC_EPERM) \
    X(kexec_load,         246,  104, LB_SC_EPERM) \
    X(keyctl,             250,  219, LB_SC_EPERM) \
    X(lookup_dcookie,     212,   18, LB_SC_EPERM) \
    X(mbind,              237,  235, LB_SC_EPERM) \
    X(migrate_pages,      256,  238, LB_SC_EPERM) \
    X(move_mount,         429,  429, LB_SC_EPERM) \
    X(move_pages,         279,  239, LB_SC_EPERM) \
    X(name_to_handle_at,  303,  264, LB_SC_EPERM) \
    X(nfsservctl,         180,   42, LB_SC_EPERM) \
    X(open_by_handle_at,  304,  265, LB_SC_EPERM) \
    X(open_tree,          428,  428, LB_SC_EPERM) \
    X(perf_event_open,    298,  241, LB_SC_EPERM) \
    X(personality,        135,   92, LB_SC_EPERM) \
    X(pidfd_getfd,        438,  438, LB_SC_EPERM) \
    X(process_madvise,    440,  440, LB_SC_EPERM) \
    X(process_vm_readv,   310,  270, LB_SC_EPERM) \
    X(process_vm_writev,  311,  271, LB_SC_EPERM) \
    X(ptrace,             101,  117, LB_SC_EPERM) \
    X(quotactl,           179,   60, LB_SC_EPERM) \
    X(reboot,             169,  142, LB_SC_EPERM) \
    X(request_key,        249,  218, LB_SC_EPERM) \
    X(set_mempolicy,      238,  237, LB_SC_EPERM) \
    X(set_mempolicy_home_node, 450, 450, LB_SC_EPERM) \
    X(setns,              308,  268, LB_SC_EPERM) \
    X(settimeofday,       164,  170, LB_SC_EPERM) \
    X(swapon,             167,  224, LB_SC_EPERM) \
    X(swapoff,            168,  225, LB_SC_EPERM) \
    X(umount2,            166,   39, LB_SC_EPERM) \
    X(unshare,            272,   97, LB_SC_EPERM) \
    X(userfaultfd,        323,  282, LB_SC_EPERM) \
    X(clone3,             435,  435, LB_SC_ENOSYS) \
    X(openat2,            437,  437, LB_SC_ENOSYS) \
    X(mount_setattr,      442,  442, LB_SC_EPERM) \
    X(fsopen,             430,  430, LB_SC_EPERM) \
    X(fsconfig,           431,  431, LB_SC_EPERM) \
    X(fsmount,            432,  432, LB_SC_EPERM) \
    X(fspick,             433,  433, LB_SC_EPERM)

/*
 * Syscalls only x86_64 has. tests/sys_check.c fails the aarch64 build if the
 * kernel's aarch64 headers ever define one of them.
 *
 *   X(name, number on x86_64, errno)
 */
#define LB_SECCOMP_DENY_X86_64(X) \
    X(create_module,      174, LB_SC_EPERM) \
    X(get_kernel_syms,    177, LB_SC_EPERM) \
    X(ioperm,             173, LB_SC_EPERM) \
    X(iopl,               172, LB_SC_EPERM) \
    X(query_module,       178, LB_SC_EPERM) \
    X(_sysctl,            156, LB_SC_EPERM) \
    X(sysfs,              139, LB_SC_EPERM) \
    X(uselib,             134, LB_SC_EPERM) \
    X(ustat,              136, LB_SC_EPERM)

/*
 * The calls that set the mode of a file or directory, with the argument the
 * mode is in. One that would give it the setuid or the setgid bit is refused
 * with EPERM (ROADMAP 8.2): a file a container makes in a volume is on the
 * host too, with that bit and its owner there, as systemd's RestrictSUIDSGID=
 * refuses it a service. Inside the container the bits would mean nothing, as
 * its root is nosuid and no_new_privs is set. An open makes a file, and uses
 * its mode, only with O_CREAT or O_TMPFILE, which is in the flags argument;
 * without either it is allowed whatever the mode says. mkdir and mkdirat are
 * not here: the kernel drops both bits from their mode, and a directory gets
 * the setgid bit only from its parent. These calls are in no other row, so
 * the program allows the rest of them at once.
 *
 *   X(name, number on x86_64, number on aarch64, mode argument, flags argument or -1)
 */
#define LB_SECCOMP_MODE(X) \
    X(fchmod,             91,   52, 1, -1) \
    X(fchmodat,          268,   53, 2, -1) \
    X(fchmodat2,         452,  452, 2, -1) \
    X(mknodat,           259,   33, 2, -1) \
    X(openat,            257,   56, 3,  2)

/* The same calls that only x86_64 has:
 *   X(name, number on x86_64, mode argument, flags argument or -1) */
#define LB_SECCOMP_MODE_X86_64(X) \
    X(chmod,              90, 1, -1) \
    X(creat,              85, 1, -1) \
    X(mknod,             133, 1, -1) \
    X(open,                2, 2,  1)

/*
 * The allow-list: what agents and the Alpine and Debian images run, a shell,
 * git, Python, Node.js, a C compiler and a package manager, taken from
 * Docker's default profile. Docker's list without the rows of the two tables
 * above and without clone, which is filtered by its flags; with chroot, as a
 * container keeps CAP_SYS_CHROOT, and arch_prctl. Left out on purpose:
 * modify_ldt, which only 16-bit and 32-bit code needs; mount, pivot_root,
 * sethostname and the other calls that need a capability a container does not
 * have; and calls newer than Linux 6.8, the oldest headers this table is
 * checked with (mseal, uretprobe and the *xattrat calls). Each of them, and any
 * call a later kernel adds, answers ENOSYS, so that a program falls back as it
 * would on an older kernel (ROADMAP 2.3).
 *
 *   X(name, number on x86_64, number on aarch64)
 */
#define LB_SECCOMP_ALLOW(X) \
    X(accept,                   43,  202) \
    X(accept4,                 288,  242) \
    X(adjtimex,                159,  171) \
    X(bind,                     49,  200) \
    X(brk,                      12,  214) \
    X(cachestat,               451,  451) \
    X(capget,                  125,   90) \
    X(capset,                  126,   91) \
    X(chdir,                    80,   49) \
    X(chroot,                  161,   51) \
    X(clock_getres,            229,  114) \
    X(clock_gettime,           228,  113) \
    X(clock_nanosleep,         230,  115) \
    X(close,                     3,   57) \
    X(close_range,             436,  436) \
    X(connect,                  42,  203) \
    X(copy_file_range,         326,  285) \
    X(dup,                      32,   23) \
    X(dup3,                    292,   24) \
    X(epoll_create1,           291,   20) \
    X(epoll_ctl,               233,   21) \
    X(epoll_pwait,             281,   22) \
    X(epoll_pwait2,            441,  441) \
    X(eventfd2,                290,   19) \
    X(execve,                   59,  221) \
    X(execveat,                322,  281) \
    X(exit,                     60,   93) \
    X(exit_group,              231,   94) \
    X(faccessat,               269,   48) \
    X(faccessat2,              439,  439) \
    X(fadvise64,               221,  223) \
    X(fallocate,               285,   47) \
    X(fanotify_mark,           301,  263) \
    X(fchdir,                   81,   50) \
    X(fchown,                   93,   55) \
    X(fchownat,                260,   54) \
    X(fcntl,                    72,   25) \
    X(fdatasync,                75,   83) \
    X(fgetxattr,               193,   10) \
    X(flistxattr,              196,   13) \
    X(flock,                    73,   32) \
    X(fremovexattr,            199,   16) \
    X(fsetxattr,               190,    7) \
    X(fstat,                     5,   80) \
    X(fstatfs,                 138,   44) \
    X(fsync,                    74,   82) \
    X(ftruncate,                77,   46) \
    X(futex,                   202,   98) \
    X(futex_requeue,           456,  456) \
    X(futex_wait,              455,  455) \
    X(futex_waitv,             449,  449) \
    X(futex_wake,              454,  454) \
    X(get_robust_list,         274,  100) \
    X(getcpu,                  309,  168) \
    X(getcwd,                   79,   17) \
    X(getdents64,              217,   61) \
    X(getegid,                 108,  177) \
    X(geteuid,                 107,  175) \
    X(getgid,                  104,  176) \
    X(getgroups,               115,  158) \
    X(getitimer,                36,  102) \
    X(getpeername,              52,  205) \
    X(getpgid,                 121,  155) \
    X(getpid,                   39,  172) \
    X(getppid,                 110,  173) \
    X(getpriority,             140,  141) \
    X(getrandom,               318,  278) \
    X(getresgid,               120,  150) \
    X(getresuid,               118,  148) \
    X(getrlimit,                97,  163) \
    X(getrusage,                98,  165) \
    X(getsid,                  124,  156) \
    X(getsockname,              51,  204) \
    X(getsockopt,               55,  209) \
    X(gettid,                  186,  178) \
    X(gettimeofday,             96,  169) \
    X(getuid,                  102,  174) \
    X(getxattr,                191,    8) \
    X(inotify_add_watch,       254,   27) \
    X(inotify_init1,           294,   26) \
    X(inotify_rm_watch,        255,   28) \
    X(io_cancel,               210,    3) \
    X(io_destroy,              207,    1) \
    X(io_getevents,            208,    4) \
    X(io_pgetevents,           333,  292) \
    X(io_setup,                206,    0) \
    X(io_submit,               209,    2) \
    X(ioctl,                    16,   29) \
    X(ioprio_get,              252,   31) \
    X(ioprio_set,              251,   30) \
    X(kill,                     62,  129) \
    X(landlock_add_rule,       445,  445) \
    X(landlock_create_ruleset, 444,  444) \
    X(landlock_restrict_self,  446,  446) \
    X(lgetxattr,               192,    9) \
    X(linkat,                  265,   37) \
    X(listen,                   50,  201) \
    X(listmount,               458,  458) \
    X(listxattr,               194,   11) \
    X(llistxattr,              195,   12) \
    X(lremovexattr,            198,   15) \
    X(lseek,                     8,   62) \
    X(lsetxattr,               189,    6) \
    X(madvise,                  28,  233) \
    X(map_shadow_stack,        453,  453) \
    X(membarrier,              324,  283) \
    X(memfd_create,            319,  279) \
    X(memfd_secret,            447,  447) \
    X(mincore,                  27,  232) \
    X(mkdirat,                 258,   34) \
    X(mlock,                   149,  228) \
    X(mlock2,                  325,  284) \
    X(mlockall,                151,  230) \
    X(mmap,                      9,  222) \
    X(mprotect,                 10,  226) \
    X(mq_getsetattr,           245,  185) \
    X(mq_notify,               244,  184) \
    X(mq_open,                 240,  180) \
    X(mq_timedreceive,         243,  183) \
    X(mq_timedsend,            242,  182) \
    X(mq_unlink,               241,  181) \
    X(mremap,                   25,  216) \
    X(msgctl,                   71,  187) \
    X(msgget,                   68,  186) \
    X(msgrcv,                   70,  188) \
    X(msgsnd,                   69,  189) \
    X(msync,                    26,  227) \
    X(munlock,                 150,  229) \
    X(munlockall,              152,  231) \
    X(munmap,                   11,  215) \
    X(nanosleep,                35,  101) \
    X(newfstatat,              262,   79) \
    X(pidfd_open,              434,  434) \
    X(pidfd_send_signal,       424,  424) \
    X(pipe2,                   293,   59) \
    X(pkey_alloc,              330,  289) \
    X(pkey_free,               331,  290) \
    X(pkey_mprotect,           329,  288) \
    X(ppoll,                   271,   73) \
    X(prctl,                   157,  167) \
    X(pread64,                  17,   67) \
    X(preadv,                  295,   69) \
    X(preadv2,                 327,  286) \
    X(prlimit64,               302,  261) \
    X(process_mrelease,        448,  448) \
    X(pselect6,                270,   72) \
    X(pwrite64,                 18,   68) \
    X(pwritev,                 296,   70) \
    X(pwritev2,                328,  287) \
    X(read,                      0,   63) \
    X(readahead,               187,  213) \
    X(readlinkat,              267,   78) \
    X(readv,                    19,   65) \
    X(recvfrom,                 45,  207) \
    X(recvmmsg,                299,  243) \
    X(recvmsg,                  47,  212) \
    X(remap_file_pages,        216,  234) \
    X(removexattr,             197,   14) \
    X(renameat,                264,   38) \
    X(renameat2,               316,  276) \
    X(restart_syscall,         219,  128) \
    X(rseq,                    334,  293) \
    X(rt_sigaction,             13,  134) \
    X(rt_sigpending,           127,  136) \
    X(rt_sigprocmask,           14,  135) \
    X(rt_sigqueueinfo,         129,  138) \
    X(rt_sigreturn,             15,  139) \
    X(rt_sigsuspend,           130,  133) \
    X(rt_sigtimedwait,         128,  137) \
    X(rt_tgsigqueueinfo,       297,  240) \
    X(sched_get_priority_max,  146,  125) \
    X(sched_get_priority_min,  147,  126) \
    X(sched_getaffinity,       204,  123) \
    X(sched_getattr,           315,  275) \
    X(sched_getparam,          143,  121) \
    X(sched_getscheduler,      145,  120) \
    X(sched_rr_get_interval,   148,  127) \
    X(sched_setaffinity,       203,  122) \
    X(sched_setattr,           314,  274) \
    X(sched_setparam,          142,  118) \
    X(sched_setscheduler,      144,  119) \
    X(sched_yield,              24,  124) \
    X(seccomp,                 317,  277) \
    X(semctl,                   66,  191) \
    X(semget,                   64,  190) \
    X(semop,                    65,  193) \
    X(semtimedop,              220,  192) \
    X(sendfile,                 40,   71) \
    X(sendmmsg,                307,  269) \
    X(sendmsg,                  46,  211) \
    X(sendto,                   44,  206) \
    X(set_robust_list,         273,   99) \
    X(set_tid_address,         218,   96) \
    X(setfsgid,                123,  152) \
    X(setfsuid,                122,  151) \
    X(setgid,                  106,  144) \
    X(setgroups,               116,  159) \
    X(setitimer,                38,  103) \
    X(setpgid,                 109,  154) \
    X(setpriority,             141,  140) \
    X(setregid,                114,  143) \
    X(setresgid,               119,  149) \
    X(setresuid,               117,  147) \
    X(setreuid,                113,  145) \
    X(setrlimit,               160,  164) \
    X(setsid,                  112,  157) \
    X(setsockopt,               54,  208) \
    X(setuid,                  105,  146) \
    X(setxattr,                188,    5) \
    X(shmat,                    30,  196) \
    X(shmctl,                   31,  195) \
    X(shmdt,                    67,  197) \
    X(shmget,                   29,  194) \
    X(shutdown,                 48,  210) \
    X(sigaltstack,             131,  132) \
    X(signalfd4,               289,   74) \
    X(splice,                  275,   76) \
    X(statfs,                  137,   43) \
    X(statmount,               457,  457) \
    X(statx,                   332,  291) \
    X(symlinkat,               266,   36) \
    X(sync,                    162,   81) \
    X(sync_file_range,         277,   84) \
    X(syncfs,                  306,  267) \
    X(sysinfo,                  99,  179) \
    X(tee,                     276,   77) \
    X(tgkill,                  234,  131) \
    X(timer_create,            222,  107) \
    X(timer_delete,            226,  111) \
    X(timer_getoverrun,        225,  109) \
    X(timer_gettime,           224,  108) \
    X(timer_settime,           223,  110) \
    X(timerfd_create,          283,   85) \
    X(timerfd_gettime,         287,   87) \
    X(timerfd_settime,         286,   86) \
    X(times,                   100,  153) \
    X(tkill,                   200,  130) \
    X(truncate,                 76,   45) \
    X(umask,                    95,  166) \
    X(uname,                    63,  160) \
    X(unlinkat,                263,   35) \
    X(utimensat,               280,   88) \
    X(vmsplice,                278,   75) \
    X(wait4,                    61,  260) \
    X(waitid,                  247,   95) \
    X(write,                     1,   64) \
    X(writev,                   20,   66)

/* The calls of the allow-list that only x86_64 has, the old spellings of
 * calls aarch64 has with an "at" (open is a mode row):
 *   X(name, number on x86_64) */
#define LB_SECCOMP_ALLOW_X86_64(X) \
    X(access,                   21) \
    X(alarm,                    37) \
    X(arch_prctl,              158) \
    X(chown,                    92) \
    X(dup2,                     33) \
    X(epoll_create,            213) \
    X(epoll_wait,              232) \
    X(eventfd,                 284) \
    X(fork,                     57) \
    X(futimesat,               261) \
    X(get_thread_area,         211) \
    X(getdents,                 78) \
    X(getpgrp,                 111) \
    X(inotify_init,            253) \
    X(lchown,                   94) \
    X(link,                     86) \
    X(lstat,                     6) \
    X(mkdir,                    83) \
    X(pause,                    34) \
    X(pipe,                     22) \
    X(poll,                      7) \
    X(readlink,                 89) \
    X(rename,                   82) \
    X(rmdir,                    84) \
    X(select,                   23) \
    X(set_thread_area,         205) \
    X(signalfd,                282) \
    X(stat,                      4) \
    X(symlink,                  88) \
    X(time,                    201) \
    X(unlink,                   87) \
    X(utime,                   132) \
    X(utimes,                  235) \
    X(vfork,                    58)

/*
 * The process that unpacks an archive (ROADMAP I.12), once its root is the
 * directory it fills and it has closed every descriptor but the archive's,
 * the root's and the pipe it answers on: the calls the reader makes, read
 * from lightbox_tar.c and seen by tracing it over every archive of the unit
 * cases, and nothing else. A call that is not here ends the process, which
 * the command says as a failure of the unpacking. mmap, which a buffer that
 * grows takes its pages with, is allowed without PROT_EXEC, and mprotect not
 * at all, so that no page of it is ever code. No chroot, mount, execve,
 * ptrace, socket, kill or setuid is among them.
 *
 *   X(name, number on x86_64, number on aarch64)
 */
#define LB_SECCOMP_UNPACK(X) \
    X(chdir,                    80,   49) \
    X(close,                     3,   57) \
    X(exit,                     60,   93) \
    X(exit_group,              231,   94) \
    X(fchdir,                   81,   50) \
    X(fchmod,                   91,   52) \
    X(fchownat,                260,   54) \
    X(fsetxattr,               190,    7) \
    X(getdents64,              217,   61) \
    X(linkat,                  265,   37) \
    X(mkdirat,                 258,   34) \
    X(mknodat,                 259,   33) \
    X(munmap,                   11,  215) \
    X(openat,                  257,   56) \
    X(read,                      0,   63) \
    X(rt_sigreturn,             15,  139) \
    X(statx,                   332,  291) \
    X(symlinkat,               266,   36) \
    X(unlinkat,                263,   35) \
    X(utimensat,               280,   88) \
    X(write,                     1,   64)

/*
 * The relay of a box's published ports (ROADMAP N.1), once it holds the
 * host's sockets that listen, is in the box's network namespace, is nobody
 * with no capability, and has its buffers: it takes a connection, opens a
 * TCP socket to the box's port on the box's loopback, copies bytes both ways
 * and reads none of them, and makes no other call. socket is allowed of
 * AF_INET and of the one type the relay asks for alone; no open, mmap, kill,
 * setns or execve is among them. A call that is not here ends the relay.
 *
 *   X(name, number on x86_64, number on aarch64)
 */
#define LB_SECCOMP_RELAY(X) \
    X(accept4,                 288,  242) \
    X(close,                     3,   57) \
    X(connect,                  42,  203) \
    X(exit,                     60,   93) \
    X(exit_group,              231,   94) \
    X(getsockopt,               55,  209) \
    X(ppoll,                   271,   73) \
    X(read,                      0,   63) \
    X(rt_sigreturn,             15,  139) \
    X(shutdown,                 48,  210) \
    X(write,                     1,   64)

/* SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, the same on both targets: the
 * one type of socket the relay makes */
#define LB_SECCOMP_RELAY_SOCKET_TYPE (1U | 04000U | 02000000U)

/*
 * The host's gzip that unpacks a compressed layer (ROADMAP I.12), as nobody,
 * with no capability and a network of its own: what a program of a C
 * library's needs to start, to read its standard input and to write its
 * standard output, seen by tracing GNU gzip 1.14 with glibc, and a little
 * room for other libraries' ways. Every other call is answered ENOSYS, as a
 * kernel without it would. Beside these: execve only of the path lightbox
 * gave it, by the address of that path in lightbox's own memory, so that
 * once gzip runs no second program can be started; and ioctl only to ask
 * whether a descriptor is a terminal, which keeps the command's terminal,
 * its standard error, from being written into with TIOCSTI.
 *
 *   X(name, number on x86_64, number on aarch64)
 */
#define LB_SECCOMP_GZIP(X) \
    X(brk,                      12,  214) \
    X(clock_gettime,           228,  113) \
    X(close,                     3,   57) \
    X(exit,                     60,   93) \
    X(exit_group,              231,   94) \
    X(faccessat,               269,   48) \
    X(faccessat2,              439,  439) \
    X(fadvise64,               221,  223) \
    X(fcntl,                    72,   25) \
    X(fstat,                     5,   80) \
    X(futex,                   202,   98) \
    X(getegid,                 108,  177) \
    X(geteuid,                 107,  175) \
    X(getgid,                  104,  176) \
    X(getpid,                   39,  172) \
    X(getrandom,               318,  278) \
    X(gettid,                  186,  178) \
    X(getuid,                  102,  174) \
    X(lseek,                     8,   62) \
    X(madvise,                  28,  233) \
    X(mmap,                      9,  222) \
    X(mprotect,                 10,  226) \
    X(mremap,                   25,  216) \
    X(munmap,                   11,  215) \
    X(newfstatat,              262,   79) \
    X(openat,                  257,   56) \
    X(pread64,                  17,   67) \
    X(prlimit64,               302,  261) \
    X(read,                      0,   63) \
    X(readlinkat,              267,   78) \
    X(readv,                    19,   65) \
    X(rseq,                    334,  293) \
    X(rt_sigaction,             13,  134) \
    X(rt_sigprocmask,           14,  135) \
    X(rt_sigreturn,             15,  139) \
    X(set_robust_list,         273,   99) \
    X(set_tid_address,         218,   96) \
    X(sigaltstack,             131,  132) \
    X(statx,                   332,  291) \
    X(uname,                    63,  160) \
    X(write,                     1,   64) \
    X(writev,                   20,   66)

/* and those of x86_64 alone:  X(name, number on x86_64) */
#define LB_SECCOMP_GZIP_X86_64(X) \
    X(access,                   21) \
    X(arch_prctl,              158) \
    X(lstat,                     6) \
    X(open,                      2) \
    X(readlink,                 89) \
    X(stat,                      4)

/*
 * In both profiles, socket and socketpair are allowed for the families agents
 * use, and answer any other with EAFNOSUPPORT, as a kernel without that family
 * would. AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK, which C libraries use to
 * learn a host's addresses, and for socketpair AF_UNIX. Out are, among others,
 * AF_PACKET and AF_XDP, which need CAP_NET_RAW; AF_VSOCK, which no network
 * namespace confines; AF_ALG and the families of old and rare protocols, much
 * of the kernel that a container needs none of.
 */
#define LB_SECCOMP_SOCKET_FAMILIES(X) \
    X(LB_SECCOMP_AF_UNIX) X(LB_SECCOMP_AF_INET) X(LB_SECCOMP_AF_INET6) X(LB_SECCOMP_AF_NETLINK)
#define LB_SECCOMP_SOCKETPAIR_FAMILIES(X) \
    X(LB_SECCOMP_AF_UNIX)

/* ─── The rows and the program for the target ───────────────────────────── */

struct lb_seccomp_deny {
    uint32_t nr;
    uint16_t err;   /* the errno the caller sees */
};

struct lb_seccomp_mode {
    uint32_t nr;
    uint8_t  mode_arg;
    int8_t   flags_arg;     /* -1: the call always sets the mode */
};

/* the instructions of a row of LB_SECCOMP_MODE: five, and two for its flags */
#define LB_SC_MODE_INSNS(flags) (5 + ((flags) >= 0 ? 2 : 0))

#if defined(LB_SECCOMP_TARGET_X86_64)
#  define LB_SECCOMP_AUDIT_ARCH   LB_AUDIT_ARCH_X86_64
#  define LB_SECCOMP_NR_MMAP      LB_SECCOMP_NR_MMAP_X86_64
#  define LB_SECCOMP_NR_EXECVE    LB_SECCOMP_NR_EXECVE_X86_64
#  define LB_SECCOMP_NR_IOCTL     LB_SECCOMP_NR_IOCTL_X86_64
#  define LB_SECCOMP_NR_CLONE     LB_SECCOMP_NR_CLONE_X86_64
#  define LB_SECCOMP_NR_SOCKET    LB_SECCOMP_NR_SOCKET_X86_64
#  define LB_SECCOMP_NR_SOCKETPAIR LB_SECCOMP_NR_SOCKETPAIR_X86_64
#  define LB_SECCOMP_PROG_HEAD    6
#  define LB_SC_ROW(name, x86_64, aarch64, err)  { x86_64, err },
#  define LB_SC_ROW_X86_64(name, nr, err)        { nr, err },
#  define LB_SC_MODE_ROW(name, x86_64, aarch64, mode, flags)  { x86_64, mode, flags },
#  define LB_SC_MODE_ROW_X86_64(name, nr, mode, flags)        { nr, mode, flags },
#  define LB_SC_MODE_LEN(name, x86_64, aarch64, mode, flags)  + LB_SC_MODE_INSNS(flags)
#  define LB_SC_MODE_LEN_X86_64(name, nr, mode, flags)        + LB_SC_MODE_INSNS(flags)
#  define LB_SC_ALLOW_ROW(name, x86_64, aarch64)              x86_64,
#  define LB_SC_ALLOW_ROW_X86_64(name, nr)                    nr,
#else
#  define LB_SECCOMP_AUDIT_ARCH   LB_AUDIT_ARCH_AARCH64
#  define LB_SECCOMP_NR_MMAP      LB_SECCOMP_NR_MMAP_AARCH64
#  define LB_SECCOMP_NR_EXECVE    LB_SECCOMP_NR_EXECVE_AARCH64
#  define LB_SECCOMP_NR_IOCTL     LB_SECCOMP_NR_IOCTL_AARCH64
#  define LB_SECCOMP_NR_CLONE     LB_SECCOMP_NR_CLONE_AARCH64
#  define LB_SECCOMP_NR_SOCKET    LB_SECCOMP_NR_SOCKET_AARCH64
#  define LB_SECCOMP_NR_SOCKETPAIR LB_SECCOMP_NR_SOCKETPAIR_AARCH64
#  define LB_SECCOMP_PROG_HEAD    4
#  define LB_SC_ROW(name, x86_64, aarch64, err)  { aarch64, err },
#  define LB_SC_ROW_X86_64(name, nr, err)
#  define LB_SC_MODE_ROW(name, x86_64, aarch64, mode, flags)  { aarch64, mode, flags },
#  define LB_SC_MODE_ROW_X86_64(name, nr, mode, flags)
#  define LB_SC_MODE_LEN(name, x86_64, aarch64, mode, flags)  + LB_SC_MODE_INSNS(flags)
#  define LB_SC_MODE_LEN_X86_64(name, nr, mode, flags)
#  define LB_SC_ALLOW_ROW(name, x86_64, aarch64)              aarch64,
#  define LB_SC_ALLOW_ROW_X86_64(name, nr)
#endif

static const struct lb_seccomp_deny LB_SECCOMP_TABLE[] = {
    LB_SECCOMP_DENY(LB_SC_ROW)
    LB_SECCOMP_DENY_X86_64(LB_SC_ROW_X86_64)
};

static const struct lb_seccomp_mode LB_SECCOMP_MODE_TABLE[] = {
    LB_SECCOMP_MODE(LB_SC_MODE_ROW)
    LB_SECCOMP_MODE_X86_64(LB_SC_MODE_ROW_X86_64)
};

#define LB_SECCOMP_MODE_PROG_LEN (0 LB_SECCOMP_MODE(LB_SC_MODE_LEN) LB_SECCOMP_MODE_X86_64(LB_SC_MODE_LEN_X86_64))

static const uint32_t LB_SECCOMP_ALLOW_TABLE[] = {
    LB_SECCOMP_ALLOW(LB_SC_ALLOW_ROW)
    LB_SECCOMP_ALLOW_X86_64(LB_SC_ALLOW_ROW_X86_64)
};

static const uint32_t LB_SECCOMP_UNPACK_TABLE[] = {
    LB_SECCOMP_UNPACK(LB_SC_ALLOW_ROW)
};

static const uint32_t LB_SECCOMP_RELAY_TABLE[] = {
    LB_SECCOMP_RELAY(LB_SC_ALLOW_ROW)
};

static const uint32_t LB_SECCOMP_GZIP_TABLE[] = {
    LB_SECCOMP_GZIP(LB_SC_ALLOW_ROW)
    LB_SECCOMP_GZIP_X86_64(LB_SC_ALLOW_ROW_X86_64)
};

#define LB_SC_FAMILY(af) af,
static const uint32_t LB_SECCOMP_SOCKET_FAMILY_TABLE[] = { LB_SECCOMP_SOCKET_FAMILIES(LB_SC_FAMILY) };
static const uint32_t LB_SECCOMP_SOCKETPAIR_FAMILY_TABLE[] = { LB_SECCOMP_SOCKETPAIR_FAMILIES(LB_SC_FAMILY) };
#undef LB_SC_FAMILY

#undef LB_SC_ROW
#undef LB_SC_ROW_X86_64
#undef LB_SC_MODE_ROW
#undef LB_SC_MODE_ROW_X86_64
#undef LB_SC_ALLOW_ROW
#undef LB_SC_ALLOW_ROW_X86_64

#define LB_SECCOMP_TABLE_LEN (sizeof(LB_SECCOMP_TABLE) / sizeof(LB_SECCOMP_TABLE[0]))
#define LB_SECCOMP_MODE_TABLE_LEN (sizeof(LB_SECCOMP_MODE_TABLE) / sizeof(LB_SECCOMP_MODE_TABLE[0]))
#define LB_SECCOMP_ALLOW_TABLE_LEN (sizeof(LB_SECCOMP_ALLOW_TABLE) / sizeof(LB_SECCOMP_ALLOW_TABLE[0]))
#define LB_SECCOMP_UNPACK_TABLE_LEN (sizeof(LB_SECCOMP_UNPACK_TABLE) / sizeof(LB_SECCOMP_UNPACK_TABLE[0]))
#define LB_SECCOMP_RELAY_TABLE_LEN (sizeof(LB_SECCOMP_RELAY_TABLE) / sizeof(LB_SECCOMP_RELAY_TABLE[0]))
#define LB_SECCOMP_GZIP_TABLE_LEN (sizeof(LB_SECCOMP_GZIP_TABLE) / sizeof(LB_SECCOMP_GZIP_TABLE[0]))
#define LB_SECCOMP_SOCKET_FAMILY_LEN \
    (sizeof(LB_SECCOMP_SOCKET_FAMILY_TABLE) / sizeof(LB_SECCOMP_SOCKET_FAMILY_TABLE[0]))
#define LB_SECCOMP_SOCKETPAIR_FAMILY_LEN \
    (sizeof(LB_SECCOMP_SOCKETPAIR_FAMILY_TABLE) / sizeof(LB_SECCOMP_SOCKETPAIR_FAMILY_TABLE[0]))

/* four and one per family for socket and for socketpair, in both */
#define LB_SECCOMP_SOCKET_PROG_LEN \
    (4 + LB_SECCOMP_SOCKET_FAMILY_LEN + 4 + LB_SECCOMP_SOCKETPAIR_FAMILY_LEN)

/* Instructions in the deny-list: the head, two per row, those of the mode
 * rows and of socket and socketpair, four for clone and the final allow.
 * lb_seccomp_build() writes exactly this many. */
#define LB_SECCOMP_PROG_LEN \
    (LB_SECCOMP_PROG_HEAD + 2 * LB_SECCOMP_TABLE_LEN + LB_SECCOMP_MODE_PROG_LEN + LB_SECCOMP_SOCKET_PROG_LEN + 5)

/* In the allow-list: the same, but five for clone, then two per call it
 * allows and the final ENOSYS. lb_seccomp_build_allow() writes exactly this
 * many. */
#define LB_SECCOMP_ALLOW_PROG_LEN \
    (LB_SECCOMP_PROG_HEAD + 2 * LB_SECCOMP_TABLE_LEN + LB_SECCOMP_MODE_PROG_LEN + LB_SECCOMP_SOCKET_PROG_LEN + 5 + \
     2 * LB_SECCOMP_ALLOW_TABLE_LEN + 1)

/* room for either */
#define LB_SECCOMP_PROG_MAX \
    (LB_SECCOMP_ALLOW_PROG_LEN > LB_SECCOMP_PROG_LEN ? LB_SECCOMP_ALLOW_PROG_LEN : LB_SECCOMP_PROG_LEN)

/* The one of the process that unpacks: the head, two per call, five for mmap
 * and the final kill. That of gzip: the head, two per call, seven for execve,
 * five for ioctl and the final ENOSYS. */
#define LB_SECCOMP_UNPACK_PROG_LEN (LB_SECCOMP_PROG_HEAD + 2 * LB_SECCOMP_UNPACK_TABLE_LEN + 5 + 1)
/* That of the relay: the head, two per call, six for socket and the final kill. */
#define LB_SECCOMP_RELAY_PROG_LEN (LB_SECCOMP_PROG_HEAD + 2 * LB_SECCOMP_RELAY_TABLE_LEN + 6 + 1)
#define LB_SECCOMP_GZIP_PROG_LEN   (LB_SECCOMP_PROG_HEAD + 2 * LB_SECCOMP_GZIP_TABLE_LEN + 7 + 5 + 1)

_Static_assert(LB_SECCOMP_PROG_LEN <= 4096, "the kernel accepts at most 4096 BPF instructions");
_Static_assert(LB_SECCOMP_ALLOW_PROG_LEN <= 4096, "the kernel accepts at most 4096 BPF instructions");

/*
 * Write a program into prog, the allow-list if allow and the deny-list if
 * not, and return how many instructions were written. No jump is longer than
 * a socket's families and three, so the tables can grow without any offset
 * overflowing its 8 bits.
 */
static inline size_t lb_seccomp_program(struct lb_sock_filter *prog, int allow) {
    size_t n = 0;

#define LB_STMT(op, value) \
    prog[n++] = (struct lb_sock_filter){ (op), 0, 0, (value) }
#define LB_JUMP(op, value, if_true, if_false) \
    prog[n++] = (struct lb_sock_filter){ (op), (if_true), (if_false), (value) }

    /* A syscall made through another ABI of this machine (i386 on x86_64,
     * AArch32 on aarch64) has other numbers: kill the process. */
    LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARCH);
    LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_AUDIT_ARCH, 1, 0);
    LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_KILL_PROCESS);

    LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_NR);

#if defined(LB_SECCOMP_TARGET_X86_64)
    /* x32 calls pass the architecture check with bit 30 set in the number,
     * so no row below would match them: refuse the whole range. */
    LB_JUMP(LB_BPF_JGE_K, LB_X32_SYSCALL_BIT, 0, 1);
    LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM);
#endif

    for (size_t i = 0; i < LB_SECCOMP_TABLE_LEN; i++) {
        LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_TABLE[i].nr, 0, 1);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SECCOMP_TABLE[i].err);
    }

    /* The calls that set a mode: refused with the setuid or setgid bit in
     * it, and allowed at once without, as they are in no other row. Until a
     * row matches, A still holds the number. */
    for (size_t i = 0; i < LB_SECCOMP_MODE_TABLE_LEN; i++) {
        const struct lb_seccomp_mode *row = &LB_SECCOMP_MODE_TABLE[i];
        int flags = row->flags_arg >= 0;
        LB_JUMP(LB_BPF_JEQ_K, row->nr, 0, flags ? 6 : 4);
        if (flags) {
            /* neither O_CREAT nor O_TMPFILE: no mode is used */
            LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARG_LO((uint32_t)row->flags_arg));
            LB_JUMP(LB_BPF_JSET_K, LB_SECCOMP_CREATE_FLAGS, 0, 3);
        }
        LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARG_LO((uint32_t)row->mode_arg));
        LB_JUMP(LB_BPF_JSET_K, LB_SECCOMP_SUID_SGID, 0, 1);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ALLOW);
    }

    /* socket and socketpair: one of their families, which is the first
     * argument, or EAFNOSUPPORT */
    static const struct { uint32_t nr; const uint32_t *af; size_t naf; } sockets[] = {
        { LB_SECCOMP_NR_SOCKET, LB_SECCOMP_SOCKET_FAMILY_TABLE, LB_SECCOMP_SOCKET_FAMILY_LEN },
        { LB_SECCOMP_NR_SOCKETPAIR, LB_SECCOMP_SOCKETPAIR_FAMILY_TABLE, LB_SECCOMP_SOCKETPAIR_FAMILY_LEN },
    };
    for (size_t s = 0; s < 2; s++) {
        uint8_t naf = (uint8_t)sockets[s].naf;
        LB_JUMP(LB_BPF_JEQ_K, sockets[s].nr, 0, (uint8_t)(naf + 3));
        LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARG0_LO);
        for (uint8_t f = 0; f < naf; f++)
            LB_JUMP(LB_BPF_JEQ_K, sockets[s].af[f], (uint8_t)(naf - f), 0);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EAFNOSUPPORT);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ALLOW);
    }

    if (!allow) {
        /* clone may create processes and threads but not namespaces, which
         * is what denying unshare, setns and clone3 above is for. Its flags
         * are the first argument on both targets. */
        LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_NR_CLONE, 0, 3);
        LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARG0_LO);
        LB_JUMP(LB_BPF_JSET_K, LB_SECCOMP_CLONE_NS_FLAGS, 0, 1);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM);

        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ALLOW);
    } else {
        /* clone, as in the deny-list, and allowed at once without a
         * namespace flag */
        LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_NR_CLONE, 0, 4);
        LB_STMT(LB_BPF_LD_W_ABS, LB_SECCOMP_DATA_ARG0_LO);
        LB_JUMP(LB_BPF_JSET_K, LB_SECCOMP_CLONE_NS_FLAGS, 0, 1);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM);
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ALLOW);

        /* what it allows, and ENOSYS for everything else */
        for (size_t i = 0; i < LB_SECCOMP_ALLOW_TABLE_LEN; i++) {
            LB_JUMP(LB_BPF_JEQ_K, LB_SECCOMP_ALLOW_TABLE[i], 0, 1);
            LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ALLOW);
        }
        LB_STMT(LB_BPF_RET_K, LB_SECCOMP_RET_ERRNO | LB_SC_ENOSYS);
    }

#undef LB_STMT
#undef LB_JUMP

    return n;
}

/* The deny-list into prog, which holds LB_SECCOMP_PROG_LEN instructions. */
static inline size_t lb_seccomp_build(struct lb_sock_filter *prog) {
    return lb_seccomp_program(prog, 0);
}

/* The allow-list into prog, which holds LB_SECCOMP_ALLOW_PROG_LEN instructions. */
static inline size_t lb_seccomp_build_allow(struct lb_sock_filter *prog) {
    return lb_seccomp_program(prog, 1);
}

/*
 * The head both programs below begin with: a call of another ABI of this
 * machine, and on x86_64 an x32 call, ends the process; then the number is
 * in A.
 */
static inline size_t lb_seccomp_head(struct lb_sock_filter *prog) {
    size_t n = 0;
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARCH };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 1, 0, LB_SECCOMP_AUDIT_ARCH };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_KILL_PROCESS };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_NR };
#if defined(LB_SECCOMP_TARGET_X86_64)
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JGE_K, 0, 1, LB_X32_SYSCALL_BIT };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_KILL_PROCESS };
#endif
    return n;
}

/* The program of the process that unpacks, into prog, which holds
 * LB_SECCOMP_UNPACK_PROG_LEN instructions. */
static inline size_t lb_seccomp_build_unpack(struct lb_sock_filter *prog) {
    size_t n = lb_seccomp_head(prog);
    for (size_t i = 0; i < LB_SECCOMP_UNPACK_TABLE_LEN; i++) {
        prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 1, LB_SECCOMP_UNPACK_TABLE[i] };
        prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    }
    /* mmap of pages that are no code: its prot is the third argument */
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 4, LB_SECCOMP_NR_MMAP };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARG_LO(2) };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JSET_K, 0, 1, LB_SECCOMP_PROT_EXEC };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_KILL_PROCESS };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_KILL_PROCESS };
    return n;
}

/* The program of the relay of a box's ports, into prog, which holds
 * LB_SECCOMP_RELAY_PROG_LEN instructions. */
static inline size_t lb_seccomp_build_relay(struct lb_sock_filter *prog) {
    size_t n = lb_seccomp_head(prog);
    for (size_t i = 0; i < LB_SECCOMP_RELAY_TABLE_LEN; i++) {
        prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 1, LB_SECCOMP_RELAY_TABLE[i] };
        prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    }
    /* socket of AF_INET and of the relay's one type: its first two arguments */
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 5, LB_SECCOMP_NR_SOCKET };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARG_LO(0) };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 3, LB_SECCOMP_AF_INET };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARG_LO(1) };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 1, LB_SECCOMP_RELAY_SOCKET_TYPE };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_KILL_PROCESS };
    return n;
}

/* The program of the host's gzip, into prog, which holds
 * LB_SECCOMP_GZIP_PROG_LEN instructions: path is the address of the path
 * execve is to be given, which is the one execve it may make. */
static inline size_t lb_seccomp_build_gzip(struct lb_sock_filter *prog, uint64_t path) {
    size_t n = lb_seccomp_head(prog);
    for (size_t i = 0; i < LB_SECCOMP_GZIP_TABLE_LEN; i++) {
        prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 1, LB_SECCOMP_GZIP_TABLE[i] };
        prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    }
    /* execve of that path, both halves of its address, or EPERM */
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 6, LB_SECCOMP_NR_EXECVE };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARG_LO(0) };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 3, (uint32_t)path };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARG_LO(0) + 4 };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 1, (uint32_t)(path >> 32) };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ERRNO | LB_SC_EPERM };
    /* ioctl to ask whether it is a terminal, which its request says, or ENOTTY */
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 4, LB_SECCOMP_NR_IOCTL };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_LD_W_ABS, 0, 0, LB_SECCOMP_DATA_ARG_LO(1) };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_JEQ_K, 0, 1, LB_SECCOMP_TCGETS };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ALLOW };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ERRNO | LB_SC_ENOTTY };
    prog[n++] = (struct lb_sock_filter){ LB_BPF_RET_K, 0, 0, LB_SECCOMP_RET_ERRNO | LB_SC_ENOSYS };
    return n;
}

#endif /* LIGHTBOX_SECCOMP_H */
