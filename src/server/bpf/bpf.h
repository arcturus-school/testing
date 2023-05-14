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

struct data_t {
    char comm[TASK_COMM_LEN]; // 进程名
    union {
        // 源地址
        u32 saddr_v4;
        u8  saddr_v6[16];
    };
    union {
        // 目的地址
        u32 daddr_v4;
        u8  daddr_v6[16];
    };
    int af;    // 协议族
    u32 pid;   // 进程 ID
    u8  sport; // 源端口
    u8  dport; // 目的端口
    u64 ts;    // 时间戳

    // tcpconnlat
    u64 delta; // 建连耗时

    // tcprtt
    u64 rtt; // TCP 往返时间

    // tcpretrans
    u64 state; // TCP 状态
    u64 type;  // 报文类型
};

struct flow_key_t {
    union {
        u32 saddr_v4;
        u8  saddr_v6[16];
    };
    union {
        u32 daddr_v4;
        u8  daddr_v6[16];
    };
    u8  lport;
    u8  dport;
    int af;
};

struct pid_key_t {
    char comm[TASK_COMM_LEN]; // 进程名
    u64  ts;                  // 时间戳
    u32  pid;                 // 进程 ID
};

#define MAX_DISKS 255 // 最大磁盘数
#define MAX_SLOTS 27  // 桶数

// 主从设备号合并
#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

struct disk_latency_key_t {
    u32 dev;
    u8  op;
    u64 latency;
};

int increment_map(void* map, void* key, u64 increment) {
    u64 zero = 0 /* 默认值 */, *count = bpf_map_lookup_elem(map, key);

    if (!count) {
        bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(map, key);

        if (!count) {
            return 0;
        }
    }

    __sync_fetch_and_add(count, increment);

    return *count;
}

#endif