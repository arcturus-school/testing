#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

extern int LINUX_KERNEL_VERSION __kconfig; // 内核版本

const volatile bool k_queued = false;      // 是否包含操作系统排队时间
const volatile bool k_ms     = false;      // 延迟单位是否是毫秒
const volatile u32  k_dev    = 0;          // 仅跟踪某个磁盘

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct request*);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_SLOTS + 1) * MAX_DISKS);
    __type(key, struct disk_latency_key_t);
    __type(value, u64);
} bio_latency SEC(".maps");

struct request_queue___x {
    struct gendisk* disk;
} __attribute__((preserve_access_index));

struct request___x {
    struct request_queue___x* q;
    struct gendisk*           rq_disk;
} __attribute__((preserve_access_index));

// 从请求上下文中获取指向设备的指针
static __always_inline struct gendisk* get_disk(void* request) {
    struct request___x* r = request;

    if (bpf_core_field_exists(r->rq_disk)) {
        return BPF_CORE_READ(r, rq_disk);
    }

    return BPF_CORE_READ(r, q, disk);
}

static int __always_inline trace_rq_start(struct request* rq, int issue) {
    if (issue && k_queued && BPF_CORE_READ(rq, q, elevator)) return 0;

    u64 ts = bpf_ktime_get_ns();

    // 磁盘过滤
    if (k_dev) {
        struct gendisk* disk = get_disk(rq);

        u32 dev = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;

        if (k_dev != dev) {
            return 0;
        }
    }

    // 保存请求开始时间
    bpf_map_update_elem(&start, &rq, &ts, 0);

    return 0;
}

// 根据内核版本处理块设备请求插入事件
static int handle_block_rq_insert(__u64* ctx) {
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        return trace_rq_start((void*)ctx[1], false);
    } else {
        return trace_rq_start((void*)ctx[0], false);
    }
}

static int handle_block_rq_issue(__u64* ctx) {
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 11, 0)) {
        return trace_rq_start((void*)ctx[1], true);
    } else {
        return trace_rq_start((void*)ctx[0], true);
    }
}

static int handle_block_rq_complete(struct request* rq, int error, unsigned int nr_bytes) {
    u64* tsp = bpf_map_lookup_elem(&start, &rq);

    if (!tsp) return 0;

    // 获取当前时间戳
    u64 ts = bpf_ktime_get_ns();

    struct disk_latency_key_t d_key = {};

    // 获取设备指针
    struct gendisk* disk = get_disk(rq);

    // 计算请求延迟
    s64 delta = (s64)(ts - *tsp);

    if (delta < 0) {
        bpf_map_delete_elem(&start, &rq);
        return 0;
    }

    if (k_ms) {
        delta /= 1000000U;
    }

    d_key.latency = delta;
    d_key.dev     = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;
    d_key.op      = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;

    increment_map(&bio_latency, &d_key, 1);

    bpf_map_delete_elem(&start, &rq);

    return 0;
}

SEC("raw_tp/block_rq_insert")
int BPF_PROG(block_rq_insert) {
    return handle_block_rq_insert(ctx);
}

SEC("raw_tp/block_rq_issue")
int BPF_PROG(block_rq_issue) {
    return handle_block_rq_issue(ctx);
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request* rq, int error, unsigned int nr_bytes) {
    return handle_block_rq_complete(rq, error, nr_bytes);
}