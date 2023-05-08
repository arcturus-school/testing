"""
跟踪 TCP 连接的吞吐量

sudo python ./tcptop.py

output:
    16:47:38 loadavg: 0.14 0.07 0.05 2/267 9824
    
    PID  COMM    LADDR            RADDR            RX_KB  TX_KB 
    205  b'node' 127.0.0.1:44497  127.0.0.1:57460    0      3
    248  b'node' 127.0.0.1:57460  127.0.0.1:44497    3      0
"""

from bcc import BPF
from bcc.containers import filter_by_containers
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict
import argparse


# arguments
def range_check(string):
    value = int(string)

    if value < 1:
        msg = f"value must be stricly positive, got {value}"
        raise argparse.ArgumentTypeError(msg)

    return value


examples = """
examples:
    ./tcptop           # 跟踪主机上的 TCP 发送/接收流量
    ./tcptop -C        # 不清除屏幕
    ./tcptop -p 181    # 仅跟踪 PID 为 181 的 TCP 连接
    ./tcptop --cgroupmap mappath  # 仅跟踪 BPF 映射中的 cgroups
    ./tcptop --mntnsmap mappath   # 仅跟踪 BPF 映射中的挂载命名空间
    ./tcptop -4        # 仅跟踪 IPv4 协议族
    ./tcptop -6        # 仅跟踪 IPv6 协议族
"""

parser = argparse.ArgumentParser(
    description="跟踪主机 TCP 发送/接收吞吐量",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-C", "--noclear", action="store_true", help="不清除屏幕")
parser.add_argument("-S", "--nosummary", action="store_true", help="跳过系统摘要行")
parser.add_argument("-p", "--pid", help="仅跟踪此 PID")
parser.add_argument(
    "interval", nargs="?", default=1, type=range_check, help="输出间隔, 默认 1s"
)
parser.add_argument("count", nargs="?", default=-1, type=range_check, help="输出次数")
parser.add_argument("--cgroupmap", help="仅跟踪 BPF 映射中的 cgroups")
parser.add_argument("--mntnsmap", help="仅跟踪 BPF 映射中的挂载命名空间")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 协议族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 协议族")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

debug = False

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 pid;                    // 进程 ID
    char name[TASK_COMM_LEN];   // 命令名
    u32 saddr;                  // 源地址
    u32 daddr;                  // 目的地址
    u16 lport;                  // 本地端口
    u16 dport;                  // 目的端口
};

// 记录发送字节大小
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);

// 记录接收字节大小
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);

struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 pid;
    char name[TASK_COMM_LEN];
    u16 lport;
    u16 dport;
    u64 __pad__;
};

BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);

// 记录 scoket 指针
BPF_HASH(sock_store, u32, struct sock *);

static int tcp_sendstat(int size) {
    if (container_should_be_filtered()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    FILTER_PID
    
    u32 tid = bpf_get_current_pid_tgid();
    struct sock **sockpp;
    sockpp = sock_store.lookup(&tid);
    
    if (sockpp == 0) {
        return 0;
    }

    struct sock *sk = *sockpp;
    u16 dport = 0, family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    
    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {
            .pid = pid
        };
        
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport), &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ipv4_key.dport = ntohs(dport);
        
        // 记录接收流量大小
        ipv4_send_bytes.increment(ipv4_key, size);
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {
            .pid = pid
        };
        
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.lport, sizeof(ipv6_key.lport), &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        ipv6_key.dport = ntohs(dport);
        
        ipv6_send_bytes.increment(ipv6_key, size);
    }

    sock_store.delete(&tid);

    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    int size = PT_REGS_RC(ctx);
    
    if (size > 0) {
        return tcp_sendstat(size);
    }
    else {
        return 0;
    }
}

int kretprobe__tcp_sendpage(struct pt_regs *ctx) {
    int size = PT_REGS_RC(ctx);
    
    if (size > 0) {
        return tcp_sendstat(size);
    }
    else {
        return 0;
    }
}

static int tcp_send_entry(struct sock *sk) {
    if (container_should_be_filtered()) {
        return 0;
    }
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    FILTER_PID
  
    u32 tid = bpf_get_current_pid_tgid();
    u16 family = sk->__sk_common.skc_family;
    
    FILTER_FAMILY
    
    sock_store.update(&tid, &sk);
    
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    return tcp_send_entry(sk);
}

int kprobe__tcp_sendpage(struct pt_regs *ctx, struct sock *sk, struct page *page, int offset, size_t size) {
    return tcp_send_entry(sk);
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (container_should_be_filtered()) {
        return 0;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    FILTER_PID

    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;

    if (copied <= 0) {
        return 0;
    }

    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {
            .pid = pid
        };
        
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        
        // 记录发送字节大小
        ipv4_recv_bytes.increment(ipv4_key, copied);
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {
            .pid = pid
        };

        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        
        ipv6_recv_bytes.increment(ipv6_key, copied);
    }

    return 0;
}
"""

# code substitutions
if args.pid:
    prog = prog.replace("FILTER_PID", f"if (pid != {args.pid}) {{ return 0; }}")
else:
    prog = prog.replace("FILTER_PID", "")

if args.ipv4:
    prog = prog.replace("FILTER_FAMILY", "if (family != AF_INET) { return 0; }")
elif args.ipv6:
    prog = prog.replace("FILTER_FAMILY", "if (family != AF_INET6) { return 0; }")
else:
    prog = prog.replace("FILTER_FAMILY", "")

prog = filter_by_containers(args) + prog

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

field_names = ["pid", "name", "laddr", "lport", "daddr", "dport"]
TCPSessionKey = namedtuple("TCPSession", field_names)


def get_ipv4_session_key(k):
    laddr = inet_ntop(AF_INET, pack("I", k.saddr))
    daddr = inet_ntop(AF_INET, pack("I", k.daddr))

    return TCPSessionKey(
        pid=k.pid,
        name=k.name,
        laddr=laddr,
        lport=k.lport,
        daddr=daddr,
        dport=k.dport,
    )


def get_ipv6_session_key(k):
    laddr = inet_ntop(AF_INET6, k.saddr)
    daddr = inet_ntop(AF_INET6, k.daddr)

    return TCPSessionKey(
        pid=k.pid,
        name=k.name,
        laddr=laddr,
        lport=k.lport,
        daddr=daddr,
        dport=k.dport,
    )


# initialize BPF
b = BPF(text=prog)

ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]
ipv6_send_bytes = b["ipv6_send_bytes"]
ipv6_recv_bytes = b["ipv6_recv_bytes"]

print(f"Tracing... Output every {args.interval} secs. Hit Ctrl-C to end")

# output
i = 0
exiting = False

while i != args.count and not exiting:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True

    # header
    if args.noclear:
        print()
    else:
        call("clear")

    if not args.nosummary:
        with open(loadavg) as stats:
            print(f"{strftime('%H:%M:%S'):<8} loadavg: {stats.read()}")

    ipv4_throughput = defaultdict(lambda: [0, 0])

    for k, v in ipv4_send_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value

    ipv4_send_bytes.clear()

    for k, v in ipv4_recv_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value

    ipv4_recv_bytes.clear()

    if ipv4_throughput:
        print(
            f"\n{'PID':<7} {'COMM':<12} {'LADDR':<21} {'RADDR':<21} {'RX_KB':<6} {'TX_KB':<6}"
        )

    items = sorted(ipv4_throughput.items(), key=lambda kv: sum(kv[1]), reverse=True)

    for k, (send_bytes, recv_bytes) in items:
        print(
            "%-7d %-12.12s %-21s %-21s %6d %6d"
            % (
                k.pid,
                k.name,
                f"{k.laddr}:{k.lport}",
                f"{k.daddr}:{k.dport}",
                int(recv_bytes / 1024),
                int(send_bytes / 1024),
            )
        )

    ipv6_throughput = defaultdict(lambda: [0, 0])

    for k, v in ipv6_send_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][0] = v.value

    ipv6_send_bytes.clear()

    for k, v in ipv6_recv_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][1] = v.value

    ipv6_recv_bytes.clear()

    if ipv6_throughput:
        print(
            f"\n{'PID':<7} {'COMM':<12} {'LADDR6':<32} {'RADDR6':<32} {'RX_KB':<6} {'TX_KB':<6}"
        )

    items = sorted(ipv6_throughput.items(), key=lambda kv: sum(kv[1]), reverse=True)
    for k, (send_bytes, recv_bytes) in items:
        print(
            "%-7d %-12.12s %-32s %-32s %6d %6d"
            % (
                k.pid,
                k.name,
                f"{k.laddr}:{k.lport}",
                f"{k.daddr}:{k.dport}",
                int(recv_bytes / 1024),
                int(send_bytes / 1024),
            )
        )

    i += 1
