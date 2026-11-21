/* Part of the seccomp suite's workload (ROADMAP 8.3): compiled, linked and
 * run under the profile, the compiler's own processes and all. It starts a
 * thread, as a C library that tries clone3 first does. */
#include <pthread.h>
#include <stdio.h>

static void *give_back(void *arg) { return arg; }

int main(void) {
    pthread_t thread;
    void *back = NULL;
    if (pthread_create(&thread, NULL, give_back, (void *)42) != 0 || pthread_join(thread, &back) != 0 ||
        back != (void *)42)
        return 1;
    puts("compiled, linked and ran, with a thread");
    return 0;
}
