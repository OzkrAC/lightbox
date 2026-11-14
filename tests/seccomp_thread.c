/*
 * An ordinary hosted program that starts one thread. tests/seccomp_cases.sh
 * runs it under lightbox's seccomp profile: this is what a threaded service
 * does at start-up, through whatever the C library uses to create a thread.
 */

#include <pthread.h>
#include <stdio.h>
#include <string.h>

static void *body(void *arg) {
    *(int *)arg = 42;
    return NULL;
}

int main(void) {
    pthread_t thread;
    int value = 0;

    int err = pthread_create(&thread, NULL, body, &value);
    if (err != 0) {
        fprintf(stderr, "pthread_create: %s\n", strerror(err));
        return 1;
    }
    pthread_join(thread, NULL);
    if (value != 42)
        return 2;
    puts("thread ran");
    return 0;
}
