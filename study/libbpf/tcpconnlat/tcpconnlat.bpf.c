#include "tcpconnlat.h"
#include "../common/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 min_us = 0; // 最小耗时(微秒)
const volatile pid_t k_tgid = 0;

struct piddata {
    char comm[TASK_COMM_LEN]; // 进程/命令名
    u64  ts;                  // 时间戳
    u32  tgid;                // 进程 ID
};

// 用于存储开始时间, 键为 socket 指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock*);
    __type(value, struct piddata);
} start SEC(".maps");

// Perf 缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int trace_connect(struct sock* sk) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    // 过滤进程
    if (k_tgid && k_tgid != tgid) return 0;

    struct piddata piddata = {};

    bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));

    piddata.ts   = bpf_ktime_get_ns();
    piddata.tgid = tgid;

    bpf_map_update_elem(&start, &sk, &piddata, 0);

    return 0;
}

static int handle_tcp_rcv_state_process(void* ctx, struct sock* sk) {
    // TCP 的状态不为 SYN_SENT 时退出
    if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT) return 0;

    struct piddata* piddatap;
    struct data_t   event = {};
    s64             delta;
    u64             ts;

    piddatap = bpf_map_lookup_elem(&start, &sk);

    if (!piddatap) return 0;

    ts    = bpf_ktime_get_ns();
    delta = (s64)(ts - piddatap->ts);

    if (delta < 0) {
        bpf_map_delete_elem(&start, &sk);
        return 0;
    }

    event.delta = delta / 1000U;

    if (min_us && event.delta < min_us) {
        // 不符合最小耗时的不用记录
        bpf_map_delete_elem(&start, &sk);
        return 0;
    }

    memcpy(&event.comm, piddatap->comm, sizeof(event.comm));

    event.ts    = ts / 1000;
    event.tgid  = piddatap->tgid;
    event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event.af    = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (event.af == AF_INET) {
        event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&event.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&event.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    bpf_map_delete_elem(&start, &sk);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock* sk) {
    return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock* sk) {
    return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock* sk) {
    return handle_tcp_rcv_state_process(ctx, sk);
}

// TCP 连接销毁后从 start 中删除 sk
SEC("tracepoint/tcp/tcp_destroy_sock")
int tcp_destroy_sock(struct trace_event_raw_tcp_event_sk* ctx) {
    const struct sock* sk = ctx->skaddr;

    bpf_map_delete_elem(&start, &sk);

    return 0;
}
