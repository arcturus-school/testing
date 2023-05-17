"""
跟踪 TCP 重传的情况

sudo python ./tcpretrans.py
"""

from bcc import BPF
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep
import argparse

# arguments
examples = """
examples:
    ./tcpretrans    # 跟踪 TCP 重传
    ./tcpretrans -l # 包括 TLP 尝试
    ./tcpretrans -4 # 仅跟踪 IPv4 协议族
    ./tcpretrans -6 # 仅跟踪 IPv6 协议族
"""

parser = argparse.ArgumentParser(
    description="跟踪 TCP 重传",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-s", "--sequence", action="store_true", help="显示 TCP 序列号")
parser.add_argument("-l", "--lossprobe", action="store_true", help="包括尾部丢包探测尝试")
parser.add_argument("-c", "--count", action="store_true", help="统计每个流中发生的重传次数")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 协议族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 协议族")

parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

debug = False

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <bcc/proto.h>

#define RETRANSMIT  1
#define TLP         2

struct ipv4_data_t {
    u32 pid;    // 进程 ID
    u64 ip;     // IP 地址
    u32 seq;    // 序列号
    u32 saddr;  // 源 IP
    u32 daddr;  // 目的 IP
    u16 lport;  // 本地端口
    u16 dport;  // 远程端口
    u64 state;  // TCP 状态
    u64 type;   // 数据报类型
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u32 seq;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};

BPF_PERF_OUTPUT(ipv6_events);

// IPv4 地址族的键
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};

// 记录协议族中每个流的重传次数
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
};

BPF_HASH(ipv6_count, struct ipv6_flow_key_t);
"""

prog_kprobe = """
static int trace_event(struct pt_regs *ctx, struct sock *skp, struct sk_buff *skb, int type) {
    struct tcp_skb_cb *tcb;
    u32 seq;

    if (skp == NULL)
        return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 获取 TCP scoket 相关信息
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;

    seq = 0;
    
    // 提取 TCP 序列号
    if (skb) {
        tcb = ((struct tcp_skb_cb *)&((skb)->cb[0]));
        seq = tcb->seq;
    }

    // 协议族过滤
    FILTER_FAMILY

    if (family == AF_INET) {
        IPV4_INIT
        IPV4_CORE
    } else if (family == AF_INET6) {
        IPV6_INIT
        IPV6_CORE
    }

    return 0;
}
"""

prog_kprobe_retransmit = """
int trace_retransmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    trace_event(ctx, sk, skb, RETRANSMIT);
    return 0;
}
"""

prog_kprobe_tlp = """
int trace_tlp(struct pt_regs *ctx, struct sock *sk) {
    trace_event(ctx, sk, NULL, TLP);
    return 0;
}
"""

# 和 prog_kprobe 一样, kfuncs 写法
prog_tracepoint = """
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    struct tcp_skb_cb *tcb;
    u32 seq;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    const struct sock *skp = (const struct sock *)args->skaddr;
    const struct sk_buff *skb = (const struct sk_buff *)args->skbaddr;
    u16 lport = args->sport;
    u16 dport = args->dport;
    char state = skp->__sk_common.skc_state;
    u16 family = skp->__sk_common.skc_family;

    seq = 0;
    
    if (skb) {
        tcb = ((struct tcp_skb_cb *)&((skb)->cb[0]));
        seq = tcb->seq;
    }

    FILTER_FAMILY

    if (family == AF_INET) {
        IPV4_CODE
    } else if (family == AF_INET6) {
        IPV6_CODE
    }
    
    return 0;
}
"""

ipv4_init_count = """
        struct ipv4_flow_key_t flow_key = {};
        
        flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
        flow_key.daddr = skp->__sk_common.skc_daddr;
        flow_key.lport = lport;
        flow_key.dport = ntohs(dport);
"""

ipv4_init_trace = """
        // 记录 IPv4 信息到 data4 中
        struct ipv4_data_t data4 = {};
        
        data4.pid = pid;
        data4.ip = 4;
        data4.seq = seq;
        data4.type = type;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = ntohs(dport);
        data4.state = state;
"""

ipv6_init_count = """
        struct ipv6_flow_key_t flow_key = {};
        
        bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        flow_key.lport = lport;
        flow_key.dport = ntohs(dport);
"""

ipv6_init_trace = """
        // 记录 IPv6 信息到 data6 中
        struct ipv6_data_t data6 = {};
        
        data6.pid = pid;
        data6.ip = 6;
        data6.seq = seq;
        data6.type = type;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        data6.dport = ntohs(dport);
        data6.state = state;
"""

ipv4_init_tp_count = """
        struct ipv4_flow_key_t flow_key = {};
        
        __builtin_memcpy(&flow_key.saddr, args->saddr, sizeof(flow_key.saddr));
        __builtin_memcpy(&flow_key.daddr, args->daddr, sizeof(flow_key.daddr));
        flow_key.lport = lport;
        flow_key.dport = dport;
        
        ipv4_count.increment(flow_key);
"""

ipv4_init_tp_trace = """
        struct ipv4_data_t data4 = {};
        
        data4.pid = pid;
        data4.lport = lport;
        data4.dport = dport;
        data4.type = RETRANSMIT;
        data4.ip = 4;
        data4.seq = seq;
        data4.state = state;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        
        // 提交 IPv4 信息到缓冲区
        ipv4_events.perf_submit(args, &data4, sizeof(data4));
"""

ipv6_init_tp_count = """
        struct ipv6_flow_key_t flow_key = {};
        
        __builtin_memcpy(&flow_key.saddr, args->saddr_v6, sizeof(flow_key.saddr));
        __builtin_memcpy(&flow_key.daddr, args->daddr_v6, sizeof(flow_key.daddr));
        flow_key.lport = lport;
        flow_key.dport = dport;
        
        ipv6_count.increment(flow_key);
"""

ipv6_init_tp_trace = """
        struct ipv6_data_t data6 = {};
        
        data6.pid = pid;
        data6.lport = lport;
        data6.dport = dport;
        data6.type = RETRANSMIT;
        data6.ip = 6;
        data6.seq = seq;
        data6.state = state;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
"""

if BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
    if args.count:
        prog_tracepoint = prog_tracepoint.replace("IPV4_CODE", ipv4_init_tp_count)
        prog_tracepoint = prog_tracepoint.replace("IPV6_CODE", ipv6_init_tp_count)
    else:
        prog_tracepoint = prog_tracepoint.replace("IPV4_CODE", ipv4_init_tp_trace)
        prog_tracepoint = prog_tracepoint.replace("IPV6_CODE", ipv6_init_tp_trace)

    prog += prog_tracepoint

# 尾部丢包探测
if args.lossprobe or not BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
    prog += prog_kprobe

    if args.count:
        # 如果仅需要统计重传次数, 则不需要提交 IP 信息(及 trace)
        prog = prog.replace("IPV4_INIT", ipv4_init_count)
        prog = prog.replace("IPV6_INIT", ipv6_init_count)
        prog = prog.replace("IPV4_CORE", "ipv4_count.increment(flow_key);")
        prog = prog.replace("IPV6_CORE", "ipv6_count.increment(flow_key);")
    else:
        prog = prog.replace("IPV4_INIT", ipv4_init_trace)
        prog = prog.replace("IPV6_INIT", ipv6_init_trace)
        prog = prog.replace(
            "IPV4_CORE", "ipv4_events.perf_submit(ctx, &data4, sizeof(data4));"
        )
        prog = prog.replace(
            "IPV6_CORE", "ipv6_events.perf_submit(ctx, &data6, sizeof(data6));"
        )

    if args.lossprobe:
        prog += prog_kprobe_tlp

    if not BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
        prog += prog_kprobe_retransmit

# 协议族过滤
if args.ipv4:
    prog = prog.replace("FILTER_FAMILY", "if (family != AF_INET) { return 0; }")
elif args.ipv6:
    prog = prog.replace("FILTER_FAMILY", "if (family != AF_INET6) { return 0; }")
else:
    prog = prog.replace("FILTER_FAMILY", "")

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()


type = {}
type[1] = "R"
type[2] = "L"

# from include/net/tcp_states.h:
tcpstate = {}
tcpstate[1] = "ESTABLISHED"
tcpstate[2] = "SYN_SENT"
tcpstate[3] = "SYN_RECV"
tcpstate[4] = "FIN_WAIT1"
tcpstate[5] = "FIN_WAIT2"
tcpstate[6] = "TIME_WAIT"
tcpstate[7] = "CLOSE"
tcpstate[8] = "CLOSE_WAIT"
tcpstate[9] = "LAST_ACK"
tcpstate[10] = "LISTEN"
tcpstate[11] = "CLOSING"
tcpstate[12] = "NEW_SYN_RECV"


# process event
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)

    print(
        "%-8s %-7d %-2d %-20s %1s> %-20s"
        % (
            strftime("%H:%M:%S"),
            event.pid,
            event.ip,
            "%s:%d" % (inet_ntop(AF_INET, pack("I", event.saddr)), event.lport),
            type[event.type],
            "%s:%s" % (inet_ntop(AF_INET, pack("I", event.daddr)), event.dport),
        ),
        end="",
    )

    if args.sequence:
        print(f" {tcpstate[event.state]:<12} {event.seq}")
    else:
        print(f" {tcpstate[event.state]}")


def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)

    print(
        "%-8s %-7d %-2d %-20s %1s> %-20s"
        % (
            strftime("%H:%M:%S"),
            event.pid,
            event.ip,
            "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.lport),
            type[event.type],
            "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
        ),
        end="",
    )

    if args.sequence:
        print(" %-12s %s" % (tcpstate[event.state], event.seq))
    else:
        print(" %s" % (tcpstate[event.state]))


def depict_cnt(counts_tab, l3prot="ipv4"):
    for k, v in sorted(counts_tab.items(), key=lambda counts: counts[1].value):
        depict_key = ""
        ep_fmt = "[%s]#%d"

        if l3prot == "ipv4":
            depict_key = "%-20s <-> %-20s" % (
                ep_fmt % (inet_ntop(AF_INET, pack("I", k.saddr)), k.lport),
                ep_fmt % (inet_ntop(AF_INET, pack("I", k.daddr)), k.dport),
            )
        else:
            depict_key = "%-20s <-> %-20s" % (
                ep_fmt % (inet_ntop(AF_INET6, k.saddr), k.lport),
                ep_fmt % (inet_ntop(AF_INET6, k.daddr), k.dport),
            )

        print("%s %10d" % (depict_key, v.value))


# initialize BPF
b = BPF(text=prog)

if not BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
    b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")

if args.lossprobe:
    b.attach_kprobe(event="tcp_send_loss_probe", fn_name="trace_tlp")

print("Tracing retransmits ... Hit Ctrl-C to end")

if args.count:
    try:
        while True:
            sleep(99999999)
    except BaseException:
        pass

    print(f"\n{'LADDR:LPORT':<25} {'RADDR:RPORT':<25} {'RETRANSMITS':<10}")

    # 输出直方图
    depict_cnt(b.get_table("ipv4_count"))
    depict_cnt(b.get_table("ipv6_count"), l3prot="ipv6")
else:
    # 输出 IP 相关信息
    print(
        f"{'TIME':<8} {'PID':<7} {'IP':<2} {'LADDR:LPORT':<20} T {'RADDR:RPORT':<20}",
        end="",
    )

    if args.sequence:
        print(f" {'STATE':<12} {'SEQ':<10}")
    else:
        print(f" {'STATE':<4}")

    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
