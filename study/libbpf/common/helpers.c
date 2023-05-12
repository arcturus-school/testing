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

static void print_stars(unsigned int val, unsigned int val_max, int width) {
    int  num_stars, num_spaces, i;
    bool need_plus;

    num_stars  = (val < val_max ? val : val_max) * width / val_max;
    num_spaces = width - num_stars;
    need_plus  = val > val_max;

    for (i = 0; i < num_stars; i++) {
        printf("*");
    }

    for (i = 0; i < num_spaces; i++) {
        printf(" ");
    }

    if (need_plus) printf("+");
}

// 输出直方图
void print_log2_hist(unsigned int* vals, int vals_size, const char* val_type) {
    int                stars_max = 40, idx_max = -1;
    unsigned int       val, val_max            = 0;
    unsigned long long low, high;
    int                stars, width, i;

    for (i = 0; i < vals_size; i++) {
        val = vals[i];

        if (val > 0) {
            idx_max = i;
        }

        if (val > val_max) {
            val_max = val;
        }
    }

    if (idx_max < 0) return;

    // 输出表格标题
    printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 11 : 15, "", idx_max <= 32 ? 13 : 29, val_type);

    if (idx_max <= 32) {
        stars = stars_max;
    } else {
        stars = stars_max / 2;
    }

    for (i = 0; i <= idx_max; i++) {
        low  = (1ULL << (i + 1)) >> 1;
        high = (1ULL << (i + 1)) - 1;

        if (low == high) {
            low -= 1;
        }

        val   = vals[i];
        width = idx_max <= 32 ? 10 : 20;

        printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
        print_stars(val, val_max, stars);
        printf("|\n");
    }
}