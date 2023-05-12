#include "helpers.h"
#include <stdio.h>
#include <time.h>

unsigned long long get_ktime_ns(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

bool find_ksym_by_name(const char* name) {

    FILE* fp = NULL;
    char  cmd[CMD_LEN];
    char  buf[SYM_LEN] = "\0";

    sprintf(cmd, "FIND_KSYM=`echo %s |awk -F'kprobe_' '{print $2}'`; cat /proc/kallsyms |grep -w $FIND_KSYM", name);

    fp = popen(cmd, "r");

    if (fp == NULL) {
        return false;
    }

    bool  has = false;
    char* f   = fgets(buf, SYM_LEN, fp);

    if (f != NULL) {
        has = true;
    }

    pclose(fp);

    return has;
}
