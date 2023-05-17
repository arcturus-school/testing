#ifndef __BIOLATENCY_H
#define __BIOLATENCY_H

#define MAX_ENTRIES 10240 // 哈希表最大实体数
#define MAX_DISKS 255     // 最大磁盘数
#define MAX_SLOTS 27      // 桶数

// 主从设备号合并
#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

struct disk_latency_key_t {
    unsigned int       dev;
    unsigned char      op;
    unsigned long long slot;
};

#endif