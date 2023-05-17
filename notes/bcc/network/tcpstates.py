"""
跟踪 TCP 状态改变信息

sudo python ./tcpstates.py

output:
    SKADDR           C-PID C-COMM LADDR  LPORT RADDR RPORT OLDSTATE -> NEWSTATE    MS
    ffff888015a38000 153   init   ::1    0     ::1   8083  CLOSE    -> SYN_SENT    0.000
    ffff888015a38000 153   init   ::1    39596 ::1   8083  SYN_SENT -> ESTABLISHED 0.035
    ffff888015a38940 153   init   ::     8083  ::    0     LISTEN   -> SYN_RECV    0.000
    ffff888015a38940 153   init   ::1    8083  ::1   39596 SYN_RECV -> ESTABLISHED 0.005
"""

from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime, time
from os import getuid
import argparse

# arguments
examples = """examples:
    ./tcpstates           # 跟踪所有 TCP 状态改变
    ./tcpstates -t        # 包含时间戳
    ./tcpstates -T        # 包含时间(HH:MM:SS)
    ./tcpstates -w        # 更宽的列(适合 IPv6)
    ./tcpstates -stT      # 输出 cvs, 同时包含时间和时间戳
    ./tcpstates -Y        # 将事件记录到系统日志
    ./tcpstates -L 80     # 仅跟踪本地端口 80
    ./tcpstates -L 80,81  # 仅跟踪本地端口 80 和 81
    ./tcpstates -D 80     # 仅跟踪远程端口 80
    ./tcpstates -4        # 仅跟踪 IPv4 协议族
    ./tcpstates -6        # 仅跟踪 IPv6 协议族
"""
parser = argparse.ArgumentParser(
    description="跟踪 TCP 状态改变和持续时间",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-T", "--time", action="store_true", help="输出包含时间(HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true", help="输出包含时间戳(秒)")
parser.add_argument("-w", "--wide", action="store_true", help="输出更宽的列(适合 IPv6)")
parser.add_argument("-s", "--csv", action="store_true", help="输出值以逗号分割")
parser.add_argument("-L", "--localport", help="跟踪本地端口列表, 逗号分割")
parser.add_argument("-D", "--remoteport", help="跟踪远程端口列表, 逗号分割")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
parser.add_argument("-Y", "--journal", action="store_true", help="将会话状态更改记录到系统日志")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 协议族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 协议族")

args = parser.parse_args()

debug = False

# define BPF program
bpf_header = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(last, struct sock *, u64);

struct ipv4_data_t {
    u64 ts_us;
    u64 skaddr;   // 套接字地址
    u32 saddr;
    u32 daddr;
    u64 span_us;
    u32 pid;
    u32 ports;
    u32 oldstate; // 旧状态
    u32 newstate; // 新状态
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 skaddr;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 span_us;
    u32 pid;
    u32 ports;
    u32 oldstate;
    u32 newstate;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv6_events);
"""

prog_kprobe = """
// 套接字状态改变时触发
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u16 lport = sk->__sk_common.skc_num;
    
    FILTER_LPORT

    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    
    FILTER_DPORT

    // 计算上一个状态到当前状态的时间差
    u64 *tsp, delta_us;
    tsp = last.lookup(&sk);
    
    if (tsp == 0) {
        delta_us = 0;
    }
    else {
        delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    }

    u16 family = sk->__sk_common.skc_family;
    
    FILTER_FAMILY

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {
            .span_us = delta_us,
            .oldstate = sk->__sk_common.skc_state,
            .newstate = state
        };

        data4.skaddr = (u64)sk;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.ports = dport + ((0ULL + lport) << 16);
        data4.pid = pid;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {
            .span_us = delta_us,
            .oldstate = sk->__sk_common.skc_state,
            .newstate = state
        };

        data6.skaddr = (u64)sk;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.ports = dport + ((0ULL + lport) << 16);
        data6.pid = pid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));

        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    if (state == TCP_CLOSE) {
        last.delete(&sk);
    } else {
        u64 ts = bpf_ktime_get_ns();
        last.update(&sk, &ts);
    }

    return 0;

};
"""

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

    u64 *tsp, delta_us;
    tsp = last.lookup(&sk);
    if (tsp == 0) {
         delta_us = 0;
    }
    else {
        delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    }

    u16 family = args->family;
    
    FILTER_FAMILY

    if (args->family == AF_INET) {
        struct ipv4_data_t data4 = {
            .span_us = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate
        };

        data4.skaddr = (u64)args->skaddr;
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        data4.ports = dport + ((0ULL + lport) << 16);
        data4.pid = pid;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        
        // 提交 IPv4 信息
        ipv4_events.perf_submit(args, &data4, sizeof(data4));
    } else /* 6 */ {
        struct ipv6_data_t data6 = {
            .span_us = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate
        };

        data6.skaddr = (u64)args->skaddr;
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        data6.ports = dport + ((0ULL + lport) << 16);
        data6.pid = pid;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        
        // 提交 IPv6 信息
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    if (args->newstate == TCP_CLOSE) {
        last.delete(&sk);
    } else {
        u64 ts = bpf_ktime_get_ns();
        last.update(&sk, &ts);
    }

    return 0;
}
"""

prog = bpf_header

if BPF.tracepoint_exists("sock", "inet_sock_set_state"):
    prog += prog_tracepoint
else:
    prog += prog_kprobe

# code substitutions
if args.remoteport:
    dports = [int(dport) for dport in args.remoteport.split(",")]
    dports_if = " && ".join([f"dport != {dport}" for dport in dports])
    prog = prog.replace(
        "FILTER_DPORT", f"if ({dports_if}) {{ last.delete(&sk); return 0; }}"
    )
else:
    prog = prog.replace("FILTER_DPORT", "")

if args.localport:
    lports = [int(lport) for lport in args.localport.split(",")]
    lports_if = " && ".join([f"lport != {lport}" for lport in lports])
    prog = prog.replace(
        "FILTER_LPORT", "if (%s) { last.delete(&sk); return 0; }" % lports_if
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

header_string = "%-16s %-5s %-10.10s %s%-15s %-5s %-15s %-5s %-11s -> %-11s %s"
format_string = "%-16x %-5d %-10.10s %s%-15s %-5d %-15s %-5d %-11s -> %-11s %.3f"

if args.wide:
    header_string = "%-16s %-5s %-16.16s %-2s %-26s %-5s %-26s %-5s %-11s -> %-11s %s"
    format_string = "%-16x %-5d %-16.16s %-2s %-26s %-5s %-26s %-5d %-11s -> %-11s %.3f"

if args.csv:
    header_string = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
    format_string = "%x,%d,%s,%s,%s,%s,%s,%d,%s,%s,%.3f"

if args.journal:
    try:
        from systemd import journal
    except ImportError:
        print("ERROR: Journal logging requires the systemd.journal module")
        exit(1)


def tcpstate2str(state):
    # from include/net/tcp_states.h
    tcpstate = {
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",
        12: "NEW_SYN_RECV",
    }

    if state in tcpstate:
        return tcpstate[state]
    else:
        return str(state)


def journal_fields(event, addr_family):
    addr_pfx = "IPV4"

    if addr_family == AF_INET6:
        addr_pfx = "IPV6"

    fields = {
        "SYSLOG_IDENTIFIER": "tcpstates",
        "PRIORITY": 5,
        "_SOURCE_REALTIME_TIMESTAMP": time() * 1000000,
        "OBJECT_PID": str(event.pid),
        "OBJECT_COMM": event.task.decode("utf-8", "replace"),
        f"OBJECT_{addr_pfx}_SOURCE_ADDRESS": inet_ntop(
            addr_family, pack("I", event.saddr)
        ),
        "OBJECT_TCP_SOURCE_PORT": str(event.ports >> 16),
        f"OBJECT_{addr_pfx}_DESTINATION_ADDRESS": inet_ntop(
            addr_family, pack("I", event.daddr)
        ),
        "OBJECT_TCP_DESTINATION_PORT": str(event.ports & 0xFFFF),
        "OBJECT_TCP_OLD_STATE": tcpstate2str(event.oldstate),
        "OBJECT_TCP_NEW_STATE": tcpstate2str(event.newstate),
        "OBJECT_TCP_SPAN_TIME": str(event.span_us),
    }

    msg_format_string = (
        "%(OBJECT_COMM)s "
        + f"%(OBJECT_{addr_pfx}_SOURCE_ADDRESS)s"
        + "%(OBJECT_TCP_SOURCE_PORT)s → "
        + f"%(OBJECT_{addr_pfx}_DESTINATION_ADDRESS)s "
        + "%(OBJECT_TCP_DESTINATION_PORT)s "
        + "%(OBJECT_TCP_OLD_STATE)s → %(OBJECT_TCP_NEW_STATE)s"
    )

    fields["MESSAGE"] = msg_format_string % (fields)

    if getuid() == 0:
        del fields["OBJECT_COMM"]

    return fields


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
            print(f"{delta_s:<9.6f} ", end="")

    print(
        format_string
        % (
            event.skaddr,
            event.pid,
            event.task.decode("utf-8", "replace"),
            "4" if args.wide or args.csv else "",
            inet_ntop(AF_INET, pack("I", event.saddr)),
            event.ports >> 16,
            inet_ntop(AF_INET, pack("I", event.daddr)),
            event.ports & 0xFFFF,
            tcpstate2str(event.oldstate),
            tcpstate2str(event.newstate),
            float(event.span_us) / 1000,
        )
    )

    if args.journal:
        journal.send(**journal_fields(event, AF_INET))


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
            print(f"{delta_s:<9.6f} ", end="")

    print(
        format_string
        % (
            event.skaddr,
            event.pid,
            event.task.decode("utf-8", "replace"),
            "6" if args.wide or args.csv else "",
            inet_ntop(AF_INET6, event.saddr),
            event.ports >> 16,
            inet_ntop(AF_INET6, event.daddr),
            event.ports & 0xFFFF,
            tcpstate2str(event.oldstate),
            tcpstate2str(event.newstate),
            float(event.span_us) / 1000,
        )
    )

    if args.journal:
        journal.send(**journal_fields(event, AF_INET6))


# initialize BPF
b = BPF(text=prog)

# header
if args.time:
    if args.csv:
        print(f"{'TIME'},", end="")
    else:
        print(f"{'TIME':<8} ", end="")

if args.timestamp:
    if args.csv:
        print(f"{'TIME(s)'},", end="")
    else:
        print(f"{'TIME(s)':<9} ", end="")

print(
    header_string
    % (
        "SKADDR",
        "C-PID",
        "C-COMM",
        "IP" if args.wide or args.csv else "",
        "LADDR",
        "LPORT",
        "RADDR",
        "RPORT",
        "OLDSTATE",
        "NEWSTATE",
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
