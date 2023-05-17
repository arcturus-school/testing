#ifndef __INTELLISENSE__

#include <net/inet_sock.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u64 ts;        // 当前时间戳
    u64 rtt_ns;    // 往返延迟
    u32 dest_ip;   // 目的地址
    u32 src_ip;    // 源地址
    u16 dest_port; // 目的端口
    u16 src_port;  // 源端口
};

BPF_HASH(start, struct sock*, struct data_t);

BPF_PERF_OUTPUT(events);

int trace_tcp_send(struct pt_regs* ctx, struct sock* sk) {
    if (sk == NULL) return 0;

    struct data_t data = {};

    data.ts        = bpf_ktime_get_ns();
    data.src_ip    = sk->__sk_common.skc_rcv_saddr;
    data.dest_ip   = sk->__sk_common.skc_daddr;
    data.src_port  = sk->__sk_common.skc_num;
    data.dest_port = sk->__sk_common.skc_dport;

    start.update(&sk, &data);

    return 0;
}

int trace_tcp_ack(struct pt_regs* ctx, struct sock* sk) {
    struct data_t* datap = start.lookup(&sk);

    if (datap == NULL) return 0;

    u64 rtt_ns    = bpf_ktime_get_ns() /* ack 的时间 */ - datap->ts;
    datap->rtt_ns = rtt_ns;

    events.perf_submit(ctx, datap, sizeof(struct data_t));

    start.delete(&sk);

    return 0;
}

#endif