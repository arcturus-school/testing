#ifndef _BPF_H
#define _BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#define TASK_COMM_LEN 16

#define MAX_ENTRIES 10240

#define AF_INET 2   // IPv4
#define AF_INET6 10 // IPv6

#define RETRANSMIT 1
#define TLP 2

#define MAX_DISKS 255 // 最大磁盘数
#define MAX_SLOTS 27  // 桶数

// 主从设备号合并
#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

#endif