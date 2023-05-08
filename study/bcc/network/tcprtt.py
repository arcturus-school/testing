"""
跟踪 TCP 往返时间
"""

from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, AF_INET
import socket, struct
import argparse
import ctypes

# arguments
examples = """
examples:
    ./tcprtt            # TCP RTT
    ./tcprtt -i 1 -d 10 # 1 秒汇总一次, 共 10 次
    ./tcprtt -m -T      # 毫秒级, 带时间戳
    ./tcprtt -p [port]  # 过滤本地端口
    ./tcprtt -P [port]  # 过滤远程端口
    ./tcprtt -a [IP]    # 过滤本地地址
    ./tcprtt -A [IP]    # 过滤远程地址
    ./tcprtt -b         # 按本地地址显示套接字直方图
    ./tcprtt -B         # 按远程地址显示套接字直方图
    ./tcprtt -D         # 显示 BPF 文本(用于调试)
    ./tcprtt -e         # 显示扩展汇总信息(平均值)
    ./tcprtt -4         # 仅跟踪 IPv4 协议族
    ./tcprtt -6         # 仅跟踪 IPv6 协议族
"""

parser = argparse.ArgumentParser(
    description="TCP RTT 直方图",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-i", "--interval", help="汇总时间间隔(秒)")
parser.add_argument("-d", "--duration", type=int, default=99999, help="跟踪持续时间(秒)")
parser.add_argument("-T", "--timestamp", action="store_true", help="输出包含时间戳")
parser.add_argument("-m", "--milliseconds", action="store_true", help="毫秒级直方图")
parser.add_argument("-p", "--lport", help="过滤本地端口")
parser.add_argument("-P", "--rport", help="过滤远程端口")
parser.add_argument("-a", "--laddr", help="过滤本地地址")
parser.add_argument("-A", "--raddr", help="过滤远程地址")
parser.add_argument("-b", "--byladdr", action="store_true", help="按本地地址显示套接字直方图")
parser.add_argument("-B", "--byraddr", action="store_true", help="按远程地址显示套接字直方图")
parser.add_argument("-e", "--extension", action="store_true", help="显示扩展汇总信息(平均值)")
parser.add_argument("-D", "--debug", action="store_true", help="启动前打印 BPF 程序(用于调试)")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 协议族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 协议族")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

if not args.interval:
    args.interval = args.duration

# define BPF program
prog = """
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif

#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

// 套接字信息
typedef struct sock_key {
    u64 addr;
    u64 slot;
} sock_key_t;

// 延迟
typedef struct sock_latenty {
    u64 latency;
    u64 count;
} sock_latency_t;

BPF_HISTOGRAM(hist_srtt, sock_key_t);
BPF_HASH(latency, u64, sock_latency_t);

int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct tcp_sock *ts = tcp_sk(sk);
    u32 srtt = ts->srtt_us >> 3;
    const struct inet_sock *inet = inet_sk(sk);

    u16 sport = 0;  // 本地端口
    u16 dport = 0;  // 远程端口
    u32 saddr = 0;  // 本地地址
    u32 daddr = 0;  // 远程地址
    u16 family = 0; // 协议

    sock_key_t key;

    // 平均延迟
    u64 addr = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

    // 是否过滤本地端口
    LPORTFILTER
    
    // 是否过滤远程端口
    RPORTFILTER
    
    // 是否过滤本地地址
    LADDRFILTER
    
    // 是否过滤远程地址
    RADDRFILTER
    
    // 是否过滤协议族
    FAMILYFILTER

    // 是否是毫秒单位
    FACTOR

    // 特定地址的直方图还是全部(0作为键)
    STORE_HIST

    key.slot = bpf_log2l(srtt);
    hist_srtt.atomic_increment(key);

    // 是否记录延迟
    STORE_LATENCY

    return 0;
}
"""

# 过滤本地端口
if args.lport:
    prog = prog.replace(
        "LPORTFILTER", f"if (ntohs(sport) != {int(args.lport)}) return 0;"
    )
else:
    prog = prog.replace("LPORTFILTER", "")

# 过滤远程端口
if args.rport:
    prog = prog.replace(
        "RPORTFILTER", f"if (ntohs(dport) != {int(args.rport)}) return 0;"
    )
else:
    prog = prog.replace("RPORTFILTER", "")

# 过滤本地地址
if args.laddr:
    # 将 IPv4 地址字符串转换为一个无符号整数
    prog = prog.replace(
        "LADDRFILTER",
        f"if (saddr != {struct.unpack('=I', socket.inet_aton(args.laddr))[0]}) return 0;",
    )
else:
    prog = prog.replace("LADDRFILTER", "")

# 过滤远程
if args.raddr:
    prog = prog.replace(
        "RADDRFILTER",
        f"if (daddr != {struct.unpack('=I', socket.inet_aton(args.raddr))[0]}) return 0;",
    )
else:
    prog = prog.replace("RADDRFILTER", "")

if args.ipv4:
    # 仅跟踪 IPv4
    prog = prog.replace("FAMILYFILTER", "if (family != AF_INET) { return 0; }")
elif args.ipv6:
    prog = prog.replace("FAMILYFILTER", "if (family != AF_INET6) { return 0; }")
else:
    prog = prog.replace("FAMILYFILTER", "")

# 纳秒或微妙[default]
if args.milliseconds:
    prog = prog.replace("FACTOR", "srtt /= 1000;")
    label = "msecs"
else:
    prog = prog.replace("FACTOR", "")
    label = "usecs"

print_header = "srtt"

# 显示本地地址/远程地址直方图
if args.byladdr:
    prog = prog.replace("STORE_HIST", "key.addr = addr = saddr;")
    print_header = "Local Address"
elif args.byraddr:
    prog = prog.replace("STORE_HIST", "key.addr = addr = daddr;")
    print_header = "Remote Addres"
else:
    prog = prog.replace("STORE_HIST", "key.addr = addr = 0;")
    print_header = "All Addresses"

ext = """
    sock_latency_t newlat = {0};
    sock_latency_t *lat;
    
    // 查找延迟
    lat = latency.lookup(&addr);
    
    if (!lat) {
        // 延迟数
        newlat.latency += srtt;
        // 样本数
        newlat.count += 1;
        latency.update(&addr, &newlat);
    } else {
        // 如果存在则更新
        lat->latency +=srtt;
        lat->count += 1;
    }
"""

if args.extension:
    prog = prog.replace("STORE_LATENCY", ext)
else:
    prog = prog.replace("STORE_LATENCY", "")

#
if args.debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")

print("Tracing TCP RTT... Hit Ctrl-C to end.")


def print_section(addr):
    addrstr = "*******"

    if addr:
        addrstr = inet_ntop(AF_INET, struct.pack("I", addr))

    avglat = ""

    if args.extension:
        lats = b.get_table("latency")
        lat = lats[ctypes.c_ulong(addr)]
        avglat = " [AVG %d]" % (lat.latency / lat.count)

    return addrstr + avglat


exiting = False if args.interval else True
dist = b.get_table("hist_srtt")
lathash = b.get_table("latency")

seconds = 0  # 程序执行时间

while True:
    try:
        sleep(int(args.interval))
        seconds = seconds + int(args.interval)
    except KeyboardInterrupt:
        exiting = True

    if args.timestamp:
        print(f"{strftime('%H:%M:%S'):<8}\n", end="")

    dist.print_log2_hist(
        label,
        section_header=print_header,
        section_print_fn=print_section,
    )

    dist.clear()
    lathash.clear()

    if exiting or seconds >= args.duration:
        exit()
