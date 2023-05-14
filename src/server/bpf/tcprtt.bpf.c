#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile bool k_ms    = false;
const volatile bool k_ipv4  = false;
const volatile bool k_ipv6  = false;
const volatile u32  k_pid   = -1;
const volatile u16  k_sport = 0;
const volatile u16  k_dport = 0;
const volatile u32  k_saddr = 0;
const volatile u32  k_daddr = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int handle_tcp_rcv_established(void* ctx, struct sock* sk) {
    // 进程号过滤
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (k_pid != -1 && pid != k_pid) return 0;

    const struct inet_sock* inet = (struct inet_sock*)(sk);

    // 端口号过滤
    u16 sport = BPF_CORE_READ(inet, inet_sport);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if (k_sport && k_sport != sport) return 0;
    if (k_dport && k_dport != dport) return 0;

    // 协议族过滤
    int family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (k_ipv4 && family != AF_INET) return 0;
    if (k_ipv6 && family != AF_INET6) return 0;

    // IP 地址过滤( 仅支持 IPv4 )
    if (family == AF_INET) {
        u32 saddr = BPF_CORE_READ(inet, inet_saddr);
        u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        if (k_saddr && k_saddr != saddr) return 0;
        if (k_daddr && k_daddr != daddr) return 0;
    }

    struct data_t data = {};

    data.ts    = bpf_ktime_get_ns() / 1000U;
    data.dport = dport;
    data.sport = sport;
    data.pid   = pid;
    data.af    = family;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (family == AF_INET) {
        data.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        data.saddr_v4 = BPF_CORE_READ(inet, inet_saddr);
    } else {
        BPF_CORE_READ_INTO(&data.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&data.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    struct tcp_sock* ts = (struct tcp_sock*)(sk);

    u32 srtt = BPF_CORE_READ(ts, srtt_us) >> 3;

    if (k_ms) srtt /= 1000U;

    data.rtt = srtt;

    // 向用户态推送消息
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock* sk) {
    return handle_tcp_rcv_established(ctx, sk);
}
