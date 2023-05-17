"""
跟踪 TCP 数据包丢弃情况

sudo python ./tcpdrop.py

output:
    TIME     PID     IP SADDR:SPORT     > DADDR:DPORT          STATE     (FLAGS)
    15:58:35 0       4  110.242.68.3:80 > 172.18.246.19:60394  FIN_WAIT1 (PSH|ACK)
            b'tcp_drop+0x1'
            b'tcp_data_queue+0x1e8'
            b'tcp_rcv_state_process+0x30b'
            ....
"""

from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
from bcc import tcp

# arguments
examples = """
examples:
    ./tcpdrop      # 跟踪内核 TCP 数据包丢弃情况
    ./tcpdrop -4   # 仅跟踪 IPv4 协议族
    ./tcpdrop -6   # 仅跟踪 IPv6 协议族
"""

parser = argparse.ArgumentParser(
    description="跟踪内核 TCP 数据包丢弃情况",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 协议族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 协议族")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

debug = False

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_STACK_TRACE(stack_traces, 1024);

struct ipv4_data_t {
    u32 pid;      // 进程 ID
    u64 ip;       // 协议类型(4 or 6)
    u32 saddr;    // 源地址
    u32 daddr;    // 目的地址
    u16 sport;    // 源端口
    u16 dport;    // 目的端口
    u8 state;     // 连接状态
    u8 tcpflags;  // tcp 标志位
    u32 stack_id; // 栈 ID
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u8 state;
    u8 tcpflags;
    u32 stack_id;
};

BPF_PERF_OUTPUT(ipv6_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(skb->head + skb->network_header);
}

// from include/net/tcp.h:
#ifndef tcp_flag_byte
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#endif

static int __trace_tcp_drop(void *ctx, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL)
        return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 从数据包头和 sock 结构中获取详细信息
    u16 family = sk->__sk_common.skc_family;
    char state = sk->__sk_common.skc_state;
    u16 sport = 0, dport = 0;
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct iphdr *ip = skb_to_iphdr(skb);
    u8 tcpflags = ((u_int8_t *)tcp)[13];
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);

    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.ip = 4;
        data4.saddr = ip->saddr;
        data4.daddr = ip->daddr;
        data4.dport = dport;
        data4.sport = sport;
        data4.state = state;
        data4.tcpflags = tcpflags;
        data4.stack_id = stack_traces.get_stackid(ctx, 0);

        // 提交 IPv4 信息
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {};
        data6.pid = pid;
        data6.ip = 6;
        // 远程地址 skc_v6_daddr 是来源
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // 本地地址 skc_v6_rcv_saddr 是目的地
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        data6.dport = dport;
        data6.sport = sport;
        data6.state = state;
        data6.tcpflags = tcpflags;
        data6.stack_id = stack_traces.get_stackid(ctx, 0);
        
        // 提交 IPv6 数据
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
}

int trace_tcp_drop(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    return __trace_tcp_drop(ctx, sk, skb);
}
"""

bpf_kfree_skb_text = """
#include <linux/skbuff.h>

TRACEPOINT_PROBE(skb, kfree_skb) {
    struct sk_buff *skb = args->skbaddr;
    struct sock *sk = skb->sk;
    enum skb_drop_reason reason = args->reason;

    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        return __trace_tcp_drop(args, sk, skb);
    }

    return 0;
}
"""

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

if args.ipv4:
    prog = prog.replace("FILTER_FAMILY", "if (family != AF_INET) { return 0; }")
elif args.ipv6:
    prog = prog.replace("FILTER_FAMILY", "if (family != AF_INET6) { return 0; }")
else:
    prog = prog.replace("FILTER_FAMILY", "")


# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)

    print(
        "%-8s %-7d %-2d %-20s > %-20s %s (%s)"
        % (
            strftime("%H:%M:%S"),
            event.pid,
            event.ip,
            "%s:%d" % (inet_ntop(AF_INET, pack("I", event.saddr)), event.sport),
            "%s:%s" % (inet_ntop(AF_INET, pack("I", event.daddr)), event.dport),
            tcp.tcpstate[event.state],
            tcp.flags2str(event.tcpflags),
        )
    )

    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=True)
        print(f"\t{sym}")

    print()  # 换行


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    print(
        "%-8s %-7d %-2d %-20s > %-20s %s (%s)"
        % (
            strftime("%H:%M:%S"),
            event.pid,
            event.ip,
            "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.sport),
            "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
            tcp.tcpstate[event.state],
            tcp.flags2str(event.tcpflags),
        )
    )

    for addr in stack_traces.walk(event.stack_id):
        sym = b.ksym(addr, show_offset=True)
        print(f"\t{sym}")

    print()


if BPF.tracepoint_exists("skb", "kfree_skb"):
    if BPF.kernel_struct_has_field("trace_event_raw_kfree_skb", "reason") == 1:
        prog += bpf_kfree_skb_text

# initialize BPF
b = BPF(text=prog)

if b.get_kprobe_functions(b"tcp_drop"):
    b.attach_kprobe(event="tcp_drop", fn_name="trace_tcp_drop")
elif b.tracepoint_exists("skb", "kfree_skb"):
    print(
        "WARNING: tcp_drop() kernel function not found or traceable. "
        "Use tracpoint:skb:kfree_skb instead."
    )
else:
    print(
        "ERROR: tcp_drop() kernel function and tracpoint:skb:kfree_skb"
        " not found or traceable. "
        "The kernel might be too old or the the function has been inlined."
    )

    exit()

stack_traces = b.get_table("stack_traces")

# header
print(
    f"{'TIME':<8} {'PID':<7} IP {'SADDR:SPORT':<20} > {'DADDR:DPORT':<20} STATE (FLAGS)"
)

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
