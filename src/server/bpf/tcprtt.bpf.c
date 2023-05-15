#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct data_tcp_rtt_t {
    u64 rtt; // TCP 往返时间
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} tcp_rtt_histogram SEC(".maps");

static int handle_tcp_rcv_established(void* ctx, struct sock* sk) {
    struct data_tcp_rtt_t data = {};

    struct tcp_sock* ts = (struct tcp_sock*)(sk);

    u32 srtt = BPF_CORE_READ(ts, srtt_us) >> 3;

    data.rtt = srtt / 1000U;

    // 向用户态推送消息
    bpf_perf_event_output(ctx, &tcp_rtt_histogram, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock* sk) {
    return handle_tcp_rcv_established(ctx, sk);
}
