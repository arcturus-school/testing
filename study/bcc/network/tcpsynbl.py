"""
以直方图的形式显示 SYN 队列(半连接队列)的大小

客户端发送 SYN 给服务端时, 服务端收到后 TCP 的状态变为半连接(SYN_RCVD)的
当三次握手结束后才变为全连接状态

sudo python ./tcpsynbl.py

output:
    Tracing SYN backlog size. Ctrl-C to end.
    ^C

    backlog_max = 511
        backlog  : count   distribution
        0 -> 1   : 2      |****************************************|
"""

import argparse
from bcc import BPF
from time import sleep

# load BPF program
prog = """
#include <net/sock.h>

typedef struct backlog_key {
    u32 backlog;
    u64 slot;
} backlog_key_t;

BPF_HISTOGRAM(dist, backlog_key_t);

int do_entry(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    backlog_key_t key = {};
    key.backlog = sk->sk_max_ack_backlog;
    key.slot = bpf_log2l(sk->sk_ack_backlog);
    
    // 记录 backlog
    dist.atomic_increment(key);

    return 0;
};
"""

examples = """examples:
    ./tcpsynbl     # 跟踪 syn backlog
    ./tcpsynbl -4  # 仅跟踪 IPv4 协议族
    ./tcpsynbl -6  # 仅跟踪 IPv6 协议族
"""

parser = argparse.ArgumentParser(
    description="Show TCP SYN backlog.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 协议族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 协议族")
args = parser.parse_args()

b = BPF(text=prog)

if args.ipv4:
    b.attach_kprobe(event="tcp_v4_syn_recv_sock", fn_name="do_entry")
elif args.ipv6:
    b.attach_kprobe(event="tcp_v6_syn_recv_sock", fn_name="do_entry")
else:
    b.attach_kprobe(event="tcp_v4_syn_recv_sock", fn_name="do_entry")
    b.attach_kprobe(event="tcp_v6_syn_recv_sock", fn_name="do_entry")

print("Tracing SYN backlog size. Ctrl-C to end.")

try:
    sleep(99999999)
except KeyboardInterrupt:
    print()

dist = b.get_table("dist")
dist.print_log2_hist("backlog", "backlog_max")
