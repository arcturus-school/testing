#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

// 记录每个 TCP 的重传次数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct data_tcp_retrans_counter_t);
    __type(value, u64);
} counts SEC(".maps");

static int trace_event(struct pt_regs* ctx, struct sock* sk, struct sk_buff* skb, int type) {
    const struct inet_sock* inet = (struct inet_sock*)(sk);

    u16 sport = BPF_CORE_READ(inet, inet_sport);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    int family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // 记录重传次数
    struct data_tcp_retrans_counter_t key = {};

    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
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
