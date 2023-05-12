#include "tcpretrans.h"
#include "../common/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char LICENSE[] SEC("license") = "GPL";

const volatile bool count = 0; // 统计重传次数
const volatile bool ipv4  = 0; // 仅跟踪 IPv4
const volatile bool ipv6  = 0; // 仅跟踪 IPv6

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

// 数据自增, 增量为 increment
static int increment_map(void* map, void* key, u64 increment) {
    u64 zero = 0, *count = bpf_map_lookup_elem(map, key);

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

static int trace_event(struct pt_regs* ctx, struct sock* sk, struct sk_buff* skb, int type) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    int family = BPF_CORE_READ(sk, __sk_common.skc_family);

    // 协议族过滤
    if (ipv4 && family != AF_INET) return 0;

    if (ipv6 && family != AF_INET6) return 0;

    if (count) {
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
    } else {
        // 推送重传信息
        struct data_t event = {};

        event.ts    = bpf_ktime_get_ns() / 1000;
        event.tgid  = tgid;
        event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        event.af    = family;
        event.state = BPF_CORE_READ(sk, __sk_common.skc_state);
        event.type  = type;

        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        if (family == AF_INET) {
            event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else if (family == AF_INET6) {
            BPF_CORE_READ_INTO(&event.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            BPF_CORE_READ_INTO(&event.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
        }

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
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
