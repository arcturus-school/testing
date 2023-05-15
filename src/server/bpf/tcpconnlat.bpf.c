#include "bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct data_tcp_connlat_t {
    u64 delta; // 建连耗时
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock*);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 记录开始时间
static int trace_connect(struct sock* sk) {
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&start, &sk, &ts, BPF_ANY);

    return 0;
}

static int handle_tcp_rcv_state_process(void* ctx, struct sock* sk) {
    if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT) return 0;

    u64* start = bpf_map_lookup_elem(&start, &sk);

    if (!start) return 0;

    struct data_tcp_connlat_t data = {};

    u64 ts    = bpf_ktime_get_ns();
    s64 delta = (s64)(ts - *start);

    if (delta < 0) {
        bpf_map_delete_elem(&start, &sk);
        return 0;
    }

    data.delta = delta / 1000U; // 微秒

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
