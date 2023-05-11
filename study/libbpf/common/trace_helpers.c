#include "trace_helpers.h"
#include <time.h>

unsigned long long get_ktime_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}