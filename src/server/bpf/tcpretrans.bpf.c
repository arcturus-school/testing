#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile bool k_count = false; // 统计重传次数
const volatile bool k_info  = false; // 统计重传信息
const volatile bool k_ipv4  = false;
const volatile bool k_ipv6  = false;
const volatile u32  k_pid   = -1;
const volatile u16  k_sport = 0;
const volatile u16  k_dport = 0;
const volatile u32  k_saddr = 0;
const volatile u32  k_daddr = 0;

// 记录每个 TCP 的重传次数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key_t);
    __type(value, u64);
} counts SEC(".maps");

// 缓冲区, 用于与用户态交换数据
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int trace_event(struct pt_regs* ctx, struct sock* sk, struct sk_buff* skb, int type) {
    // 进程号过滤
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (k_pid != -1 && pid != k_pid) return 0;

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

    if (k_count) {
        // 记录重传次数
        struct flow_key_t key = {};

        key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        key.af    = family;

        if (family == AF_INET) {
            key.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            key.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            BPF_CORE_READ_INTO(&key.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&key.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }

        increment_map(&counts, &key, 1);
    }

    if (k_info) {
        // 记录重传信息
        struct data_t data = {};

        data.ts    = bpf_ktime_get_ns() / 1000U;
        data.pid   = pid;
        data.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        data.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        data.af    = family;
        data.state = BPF_CORE_READ(sk, __sk_common.skc_state);
        data.type  = type;

        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        if (family == AF_INET) {
            data.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            data.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            BPF_CORE_READ_INTO(&data.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&data.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(trace_retransmit, struct sock* sk, struct sk_buff* skb) {
    return trace_event(ctx, sk, skb, RETRANSMIT);
}

SEC("kprobe/tcp_send_loss_probe")
int BPF_KPROBE(trace_tlp, struct sock* sk) {
    return trace_event(ctx, sk, NULL, TLP);
}
