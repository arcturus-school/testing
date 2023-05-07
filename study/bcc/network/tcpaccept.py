"""
跟踪 TCP 被动连接情况

sudo python ./tcpaccept.py -t

运行 nodejs 下的 index.js 后, 每当访问后端时就会建立 TCP 连接

output:
    TIME(s) PID   COMM  IP RADDR RPORT LADDR LPORT
    0.000   19297 node  6  ::1   39456 ::1   8083 
    0.001   19297 node  6  ::1   39470 ::1   8083
"""

from bcc.containers import filter_by_containers
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from bcc.utils import printb
from time import strftime
import argparse

# arguments
examples = """
examples:
    ./tcpaccept                      # 跟踪所有 tcp 被动连接
    ./tcpaccept -t                   # 包含时间戳
    ./tcpaccept -P 80,81             # 仅跟踪端口 80 和 81
    ./tcpaccept -p 181               # 仅跟踪 PID 为 181 的进程
    ./tcpaccept --cgroupmap mappath  # 仅跟踪此 BPF 映射中的 cgroup
    ./tcpaccept --mntnsmap mappath   # 仅跟踪此 BPF 映射中的挂载命名空间
    ./tcpaccept -4                   # 仅跟踪 IPv4
    ./tcpaccept -6                   # 仅跟踪 IPv6
"""

parser = argparse.ArgumentParser(
    description="跟踪服务器端接受 TCP 连接的情况",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-T", "--time", action="store_true", help="输出包括时间列(HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true", help="输出包括时间戳")
parser.add_argument("-p", "--pid", help="仅跟踪此 PID 进程")
parser.add_argument("-P", "--port", help="跟踪本地端口, 逗号分割")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6")
parser.add_argument("--cgroupmap", help="仅跟踪此 BPF 映射中的 cgroup")
parser.add_argument("--mntnsmap", help="仅跟踪此 BPF 映射中的挂载命名空间")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

debug = False

prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_data_t {
    u64 ts_us;                // 时间戳
    u32 pid;                  // 进程 ID
    u32 saddr;                // 源 IP
    u32 daddr;                // 目的 IP
    u64 ip;                   // 协议与头长度
    u16 lport;                // 本地端口
    u16 dport;                // 目的端口
    char task[TASK_COMM_LEN]; // 进程名称
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv6_events);
"""


prog_kprobe = """
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    if (container_should_be_filtered()) {
        return 0;
    }

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 是否需要仅关注某个 PID
    ##FILTER_PID##

    if (newsk == NULL)
        return 0;

    u16 protocol = 0;

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    // 计算 sk_protocol 和 sk_gso_max_segs 之间的距离以获取内核版本
    if (sk_lingertime_offset - gso_max_segs_offset == 2) {
        protocol = newsk->sk_protocol;
    }
    else if (sk_lingertime_offset - gso_max_segs_offset == 4) {
        // 内核 4.10+ 小端模式
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
    }
    else {
        // 内核 4.10- 小端模式
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
    }  
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        // 内核 4.10+ 大端模式
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
    }
    else {
        // 内核 4.10- 大端模式
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
    }
#else

# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    // 不是 TCP 套接字
    if (protocol != IPPROTO_TCP)
        return 0;


    u16 family = 0, lport = 0, dport;
    family = newsk->__sk_common.skc_family;
    lport = newsk->__sk_common.skc_num;
    dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);

    // 是否需要仅关注某个协议(IPv4 or IPv6)
    ##FILTER_FAMILY##

    // 是否需要仅关注某个端口
    ##FILTER_PORT##

    if (family == AF_INET) {
        // IPv4
        struct ipv4_data_t data4 = {
            .pid = pid, 
            .ip = 4
        };

        data4.ts_us = bpf_ktime_get_ns() / 1000; // 当前时间(ms)
        data4.saddr = newsk->__sk_common.skc_rcv_saddr;
        data4.daddr = newsk->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = dport;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        
        // 数据送入缓冲区
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        // IPv6
        struct ipv6_data_t data6 = {
            .pid = pid, 
            .ip = 6
        };

        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        data6.dport = dport;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        
        // 数据送入缓冲区
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
}
"""

prog += prog_kprobe

# code substitutions
if args.pid:
    prog = prog.replace("##FILTER_PID##", f"if (pid != {args.pid}) {{ return 0; }}")
else:
    prog = prog.replace("##FILTER_PID##", "")

if args.port:
    lports = [int(lport) for lport in args.port.split(",")]
    lports_if = " && ".join([f"lport != {lport}" for lport in lports])

    prog = prog.replace("##FILTER_PORT##", f"if ({lports_if}) {{ return 0; }}")
else:
    prog = prog.replace("##FILTER_PORT##", "")

if args.ipv4:
    prog = prog.replace("##FILTER_FAMILY##", "if (family != AF_INET) { return 0; }")
elif args.ipv6:
    prog = prog.replace("##FILTER_FAMILY##", "if (family != AF_INET6) { return 0; }")
else:
    prog = prog.replace("##FILTER_FAMILY##", "")

prog = filter_by_containers(args) + prog

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()


# process event
def print_ipv4_event(cpu, data, size):
    global start_ts

    event = b["ipv4_events"].event(data)

    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode("ascii"), nl="")

    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us

        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")

    printb(
        b"%-7d %-12.12s %-2d %-16s %-5d %-16s %-5d"
        % (
            event.pid,
            event.task,
            event.ip,
            inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
            event.dport,
            inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
            event.lport,
        )
    )


def print_ipv6_event(cpu, data, size):
    global start_ts

    event = b["ipv6_events"].event(data)

    if args.time:
        printb(b"%-9s" % strftime("%H:%M:%S").encode("ascii"), nl="")

    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us

        printb(b"%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), nl="")

    printb(
        b"%-7d %-12.12s %-2d %-16s %-5d %-16s %-5d"
        % (
            event.pid,
            event.task,
            event.ip,
            inet_ntop(AF_INET6, event.daddr).encode(),
            event.dport,
            inet_ntop(AF_INET6, event.saddr).encode(),
            event.lport,
        )
    )


# initialize BPF
b = BPF(text=prog)

# header
if args.time:
    print("%-9s" % ("TIME"), end="")

if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")

print(
    "%-7s %-12s %-2s %-16s %-5s %-16s %-5s"
    % ("PID", "COMM", "IP", "RADDR", "RPORT", "LADDR", "LPORT")
)

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)

while True:
    try:
        b.perf_buffer_poll()  # 从缓冲区读取数据
    except KeyboardInterrupt:
        exit()
