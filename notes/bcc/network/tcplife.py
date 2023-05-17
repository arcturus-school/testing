"""
跟踪 TCP 生命周期

sudo python ./tcplife.py
"""

from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime

# arguments
examples = """examples:
    ./tcplife           # 跟踪所有 TCP 连接
    ./tcplife -T        # 包含时间列(HH:MM:SS)
    ./tcplife -w        # 更宽的列(适合 IPv6)
    ./tcplife -stT      # 输出 csv, 包括时间和时间戳
    ./tcplife -p 181    # 仅跟踪 PID 181
    ./tcplife -L 80     # 仅跟踪本地端口 80
    ./tcplife -L 80,81  # 仅跟踪本地端口 80 和 81
    ./tcplife -D 80     # 仅跟踪远程端口 80
    ./tcplife -4        # 仅跟踪 IPv4 协议族
    ./tcplife -6        # 仅跟踪 IPv6 协议族
"""

parser = argparse.ArgumentParser(
    description="跟踪 TCP 会话的生命周期",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-T", "--time", action="store_true", help="输出包含时间列(HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true", help="输出时间戳(秒)")
parser.add_argument("-w", "--wide", action="store_true", help="更宽的列(适合 IPv6)")
parser.add_argument("-s", "--csv", action="store_true", help="输出时值以逗号分割")
parser.add_argument("-p", "--pid", help="仅跟踪此 PID")
parser.add_argument("-L", "--localport", help="跟踪本地端口列表, 逗号分割")
parser.add_argument("-D", "--remoteport", help="跟踪的远程端口列表, 逗号分割")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

debug = True

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(birth, struct sock *, u64);

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u64 ports;
    u64 rx_b;                 // 接收的字节数
    u64 tx_b;                 // 确认的字节数
    u64 span_us;              // 数据包之间的间隔
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ports;
    u64 rx_b;
    u64 tx_b;
    u64 span_us;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv6_events);

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};

BPF_HASH(whoami, struct sock *, struct id_t);
"""

prog_kprobe = """
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u16 lport = sk->__sk_common.skc_num;
    
    // 过滤本地端口
    FILTER_LPORT

    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    
    // 过滤目的端口
    FILTER_DPORT

    // 在 TCP_FIN_WAIT1 之前记录开始时间
    if (state < TCP_FIN_WAIT1) {
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }

    // 在 TCP_SYN_SENT 和 TCP_LAST_ACK 时记录 PID 和 comm
    if (state == TCP_SYN_SENT || state == TCP_LAST_ACK) {
        FILTER_PID

        struct id_t me = {
            .pid = pid
        };

        bpf_get_current_comm(&me.task, sizeof(me.task));
        
        whoami.update(&sk, &me);
    }

    if (state != TCP_CLOSE)
        return 0;

    // 记录生命周期长度
    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);
    
    if (tsp == 0) {
        whoami.delete(&sk);
        return 0;
    }

    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    // 获取可能的缓存数据，并进行过滤
    struct id_t *mep;
    mep = whoami.lookup(&sk);
    
    if (mep != 0)
        pid = mep->pid;
    
    FILTER_PID

    // 获取吞吐量统计信息
    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    u16 family = sk->__sk_common.skc_family;

    // 过滤协议族
    FILTER_FAMILY

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};

        data4.span_us = delta_us;
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.pid = pid;
        data4.ports = dport + ((0ULL + lport) << 32);
        
        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read_kernel(&data4.task, sizeof(data4.task), (void *)mep->task);
        }
        
        // 提交 IPv4 信息
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        
        data6.span_us = delta_us;
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.ports = dport + ((0ULL + lport) << 32);
        data6.pid = pid;
        
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read_kernel(&data6.task, sizeof(data6.task), (void *)mep->task);
        }
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    if (mep != 0) {
        whoami.delete(&sk);
    }

    return 0;
}
"""

# 和 prog_kprobe 一样, kfuncs 写法
prog_tracepoint = """
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk = (struct sock *)args->skaddr;
    u16 lport = args->sport;

    FILTER_LPORT

    u16 dport = args->dport;
    FILTER_DPORT

    if (args->newstate < TCP_FIN_WAIT1) {
        u64 ts = bpf_ktime_get_ns();
        birth.update(&sk, &ts);
    }

    if (args->newstate == TCP_SYN_SENT || args->newstate == TCP_LAST_ACK) {
        FILTER_PID

        struct id_t me = {
            .pid = pid
        };

        bpf_get_current_comm(&me.task, sizeof(me.task));
        whoami.update(&sk, &me);
    }

    if (args->newstate != TCP_CLOSE)
        return 0;

    u64 *tsp, delta_us;
    tsp = birth.lookup(&sk);

    if (tsp == 0) {
        whoami.delete(&sk);
        return 0;
    }

    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    birth.delete(&sk);

    struct id_t *mep;
    mep = whoami.lookup(&sk);
    
    if (mep != 0) {
        pid = mep->pid;
    }

    FILTER_PID

    u16 family = args->family;
    
    FILTER_FAMILY

    u64 rx_b = 0, tx_b = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    rx_b = tp->bytes_received;
    tx_b = tp->bytes_acked;

    if (args->family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.span_us = delta_us;
        data4.rx_b = rx_b;
        data4.tx_b = tx_b;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));

        data4.ports = dport + ((0ULL + lport) << 32);
        data4.pid = pid;

        if (mep == 0) {
            bpf_get_current_comm(&data4.task, sizeof(data4.task));
        } else {
            bpf_probe_read_kernel(&data4.task, sizeof(data4.task), (void *)mep->task);
        }

        ipv4_events.perf_submit(args, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {};
        data6.span_us = delta_us;
        data6.rx_b = rx_b;
        data6.tx_b = tx_b;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        data6.ports = dport + ((0ULL + lport) << 32);
        data6.pid = pid;
        
        if (mep == 0) {
            bpf_get_current_comm(&data6.task, sizeof(data6.task));
        } else {
            bpf_probe_read_kernel(&data6.task, sizeof(data6.task), (void *)mep->task);
        }

        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    if (mep != 0) {
        whoami.delete(&sk);
    }

    return 0;
}
"""

if BPF.tracepoint_exists("sock", "inet_sock_set_state"):
    prog += prog_tracepoint
else:
    prog += prog_kprobe

# code substitutions
if args.pid:
    prog = prog.replace("FILTER_PID", f"if (pid != {args.pid}) {{ return 0; }}")
else:
    prog = prog.replace("FILTER_PID", "")

if args.remoteport:
    dports = [int(dport) for dport in args.remoteport.split(",")]
    dports_if = " && ".join([f"dport != {dport}" for dport in dports])
    prog = prog.replace(
        "FILTER_DPORT", f"if ({dports_if}) {{ birth.delete(&sk); return 0; }}"
    )
else:
    prog = prog.replace("FILTER_DPORT", "")

if args.localport:
    lports = [int(lport) for lport in args.localport.split(",")]
    lports_if = " && ".join(["lport != %d" % lport for lport in lports])
    prog = prog.replace(
        "FILTER_LPORT", f"if ({lports_if}) {{ birth.delete(&sk); return 0; }}"
    )
else:
    prog = prog.replace("FILTER_LPORT", "")

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

header_string = "%-5s %-10.10s %s%-15s %-5s %-15s %-5s %5s %5s %s"
format_string = "%-5d %-10.10s %s%-15s %-5d %-15s %-5d %5d %5d %.2f"

if args.wide:
    header_string = "%-5s %-16.16s %-2s %-26s %-5s %-26s %-5s %6s %6s %s"
    format_string = "%-5d %-16.16s %-2s %-26s %-5s %-26s %-5d %6d %6d %.2f"

if args.csv:
    header_string = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
    format_string = "%d,%s,%s,%s,%s,%s,%d,%d,%d,%.2f"


# process event
def print_ipv4_event(cpu, data, size):
    global start_ts

    event = b["ipv4_events"].event(data)

    if args.time:
        if args.csv:
            print(f"{strftime('%H:%M:%S')},", end="")
        else:
            print(f"{strftime('%H:%M:%S'):<8} ", end="")

    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us

        delta_s = (float(event.ts_us) - start_ts) / 1000000

        if args.csv:
            print(f"{delta_s:.6f},", end="")
        else:
            print(f"{delta_s:9.6f} ", end="")

    print(
        format_string
        % (
            event.pid,
            event.task.decode("utf-8", "replace"),
            "4" if args.wide or args.csv else "",
            inet_ntop(AF_INET, pack("I", event.saddr)),
            event.ports >> 32,
            inet_ntop(AF_INET, pack("I", event.daddr)),
            event.ports & 0xFFFFFFFF,
            event.tx_b / 1024,
            event.rx_b / 1024,
            float(event.span_us) / 1000,
        )
    )


def print_ipv6_event(cpu, data, size):
    global start_ts

    event = b["ipv6_events"].event(data)

    if args.time:
        if args.csv:
            print(f"{strftime('%H:%M:%S')},", end="")
        else:
            print(f"{strftime('%H:%M:%S'):<8} ", end="")

    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us

        delta_s = (float(event.ts_us) - start_ts) / 1000000

        if args.csv:
            print(f"{delta_s:.6f},", end="")
        else:
            print(f"{delta_s:9.6f} ", end="")

    print(
        format_string
        % (
            event.pid,
            event.task.decode("utf-8", "replace"),
            "6" if args.wide or args.csv else "",
            inet_ntop(AF_INET6, event.saddr),
            event.ports >> 32,
            inet_ntop(AF_INET6, event.daddr),
            event.ports & 0xFFFFFFFF,
            event.tx_b / 1024,
            event.rx_b / 1024,
            float(event.span_us) / 1000,
        )
    )


# initialize BPF
b = BPF(text=prog)

# header
if args.time:
    if args.csv:
        print(f"{'TIME(s)'},", end="")
    else:
        print(f"{'TIME(s)':<8},", end="")

if args.timestamp:
    if args.csv:
        print(f"{'TIME(s)'},", end="")
    else:
        print(f"{'TIME(s)':<9} ", end="")

print(
    header_string
    % (
        "PID",
        "COMM",
        "IP" if args.wide or args.csv else "",
        "LADDR",
        "LPORT",
        "RADDR",
        "RPORT",
        "TX_KB",
        "RX_KB",
        "MS",
    )
)

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event, page_cnt=64)
b["ipv6_events"].open_perf_buffer(print_ipv6_event, page_cnt=64)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
