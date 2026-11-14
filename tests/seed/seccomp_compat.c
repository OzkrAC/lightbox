/*
 * Compatibility harness: applies lightbox's own default seccomp profile
 * (the unmodified apply_seccomp() from lightbox.c) and then runs an ordinary
 * program, to see whether everyday software still works under it.
 */
#define main lightbox_main
#include "lightbox.c"
#undef main

int main(int argc, char **argv, char **envp) {
    if (argc < 2) die("usage: seccomp_compat <program> [args...]");
    if (lc_kernel_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die("Error: failed to enable no_new_privs");
    apply_seccomp();
    lc_kernel_execute(argv[1], argv + 1, envp);
    die2("Error: failed to exec: ", argv[1]);
    return 1;
}
