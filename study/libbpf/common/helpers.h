#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <stdbool.h>

#define NSEC_PER_SEC 1000000000ULL

#define CMD_LEN 4096

#define SYM_LEN 1024

unsigned long long get_ktime_ns(void);

bool find_ksym_by_name(const char*);

void print_log2_hist(unsigned int* vals, int vals_size, const char* val_type);

#endif