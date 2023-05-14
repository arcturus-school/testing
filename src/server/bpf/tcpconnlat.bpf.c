#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile u64  k_min_t = 0; // 最小耗时(微秒)
const volatile bool k_ipv4  = false;
const volatile bool k_ipv6  = false;
const volatile u32  k_pid   = -1;
const volatile u16  k_sport = 0;
const volatile u16  k_dport = 0;
const volatile u32  k_saddr = 0;
const volatile u32  k_daddr = 0;

// 用于存储开始时间, 键为 socket 指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock*);
    __type(value, struct pid_key_t);
} start SEC(".maps");

// Perf 缓冲区
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int trace_connect(struct sock* sk) {
    // 进程过滤
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (k_pid != -1 && k_pid != pid) return 0;

    const struct inet_sock* inet = (struct inet_sock*)(sk);

    // 端口号过滤
    u16 sport = BPF_CORE_READ(inet, inet_sport);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if (k_sport && k_sport != sport) return 0;
    if (k_dport && k_dport != dport) return 0;

    int family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // 协议族过滤
    if (k_ipv4 && family != AF_INET) return 0;
    if (k_ipv6 && family != AF_INET6) return 0;

    // IP 地址过滤( 仅支持 IPv4 )
    if (family == AF_INET) {
        u32 saddr = BPF_CORE_READ(inet, inet_saddr);
        u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        if (k_saddr && k_saddr != saddr) return 0;
        if (k_daddr && k_daddr != daddr) return 0;
    }

    struct pid_key_t key = {};

    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    key.ts  = bpf_ktime_get_ns();
    key.pid = pid;

    bpf_map_update_elem(&start, &sk, &key, BPF_ANY);

    return 0;
}

static int handle_tcp_rcv_state_process(void* ctx, struct sock* sk) {
    if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT) return 0;

    struct pid_key_t* key;

    key = bpf_map_lookup_elem(&start, &sk);

    if (!key) return 0;

    struct data_t data = {};

    u64 ts    = bpf_ktime_get_ns();
    s64 delta = (s64)(ts - key->ts);

    if (delta < 0) {
        bpf_map_delete_elem(&start, &sk);
        return 0;
    }

    data.delta = delta / 1000U;

    if (k_min_t && data.delta < k_min_t) {
        // 不符合最小耗时的不用记录
        bpf_map_delete_elem(&start, &sk);
        return 0;
    }

    memcpy(&data.comm, key->comm, sizeof(data.comm));

    data.ts    = ts / 1000U;
    data.pid   = key->pid;
    data.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    data.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    data.af    = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (data.af == AF_INET) {
        data.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        data.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&data.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&data.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

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

SEC("tracepoint/tcp/tcp_destroy_sock")
int tcp_destroy_sock(struct trace_event_raw_tcp_event_sk* ctx) {
    const struct sock* sk = ctx->skaddr;

    bpf_map_delete_elem(&start, &sk);

    return 0;
}
