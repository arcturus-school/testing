#include "tcprtt.h"
#include "../../libbpf/common/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "GPL";

const volatile bool  ms      = false;
const volatile __u16 k_sport = 0;
const volatile __u16 k_dport = 0;
const volatile __u32 k_saddr = 0;
const volatile __u32 k_daddr = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static int handle_tcp_rcv_established(void* ctx, struct sock* sk) {
    const struct inet_sock* inet = (struct inet_sock*)(sk);

    u16 sport = BPF_CORE_READ(inet, inet_sport);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u32 saddr = BPF_CORE_READ(inet, inet_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    if (k_sport && k_sport != sport) return 0;
    if (k_dport && k_dport != dport) return 0;
    if (k_saddr && k_saddr != saddr) return 0;
    if (k_daddr && k_daddr != daddr) return 0;

    struct data_t data = {};

    data.daddr = daddr;
    data.dport = dport;
    data.sport = sport;
    data.saddr = saddr;
    data.ts    = bpf_ktime_get_ns();

    struct tcp_sock* ts = (struct tcp_sock*)(sk);

    u32 srtt = BPF_CORE_READ(ts, srtt_us) >> 3;

    if (ms) srtt /= 1000U;

    data.rtt = srtt;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock* sk) {
    return handle_tcp_rcv_established(ctx, sk);
}
