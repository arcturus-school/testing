#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct data_tcp_retrans_counter_t {
    union {
        u32 saddr_v4;
        u8  saddr_v6[16];
    };
    union {
        u32 daddr_v4;
        u8  daddr_v6[16];
    };
    u8  sport;
    u8  dport;
    int af;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int trace_event(struct pt_regs* ctx, struct sock* sk, struct sk_buff* skb, int type) {
    const struct inet_sock* inet = (struct inet_sock*)(sk);

    int family = BPF_CORE_READ(sk, __sk_common.skc_family);

    struct data_tcp_retrans_counter_t key = {};

    key.sport = BPF_CORE_READ(inet, inet_sport);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.af    = family;

    if (family == AF_INET) {
        key.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        key.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&key.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&key.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));

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
