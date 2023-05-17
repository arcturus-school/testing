"""
跟踪发送至子网的 TCP 数据包大小

sudo python ./tcpsubnet.py

output:
    Tracing... Output every 1 secs. Hit Ctrl-C to end
    [05/08/23 17:31:21]
    127.0.0.1/32          97    
    [05/08/23 17:31:22]
    127.0.0.1/32          114   
    [05/08/23 17:31:23]
    127.0.0.1/32          137 
"""

from bcc import BPF
from datetime import datetime as dt
from time import sleep
import argparse
import json
import logging
import struct
import socket

# arguments
examples = """
examples:
    ./tcpsubnet               # 跟踪发送至默认子网的 TCP:
                              # 127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,
                              # 192.168.0.0/16,0.0.0.0/0
    ./tcpsubnet -f K          # 跟踪发送到默认子网的 TCP , 以 KBytes 为单位
    ./tcpsubnet 10.80.0.0/24  # 仅跟踪发送至 10.80.0.0/24 的 TCP 连接
    ./tcpsubnet -J            # 以 json 格式输出
"""

default_subnets = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,0.0.0.0/0"

parser = argparse.ArgumentParser(
    description="跟踪发送至子网的 TCP",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)


parser.add_argument("-v", "--verbose", action="store_true", help="输出调试语句")
parser.add_argument("-J", "--json", action="store_true", help="以 json 格式输出")
parser.add_argument("-i", "--interval", default=1, type=int, help="输出间隔, 默认 1 秒")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
parser.add_argument(
    "-f",
    "--format",
    default="B",
    help="[bkmBKM] 格式化: bits, Kbits, Mbits, bytes, KBytes, MBytes (default B)",
    choices=["b", "k", "m", "B", "K", "M"],
)
parser.add_argument(
    "subnets",
    help="子网, 逗号分割",
    type=str,
    nargs="?",
    default=default_subnets,
)

args = parser.parse_args()

level = logging.INFO

if args.verbose:
    level = logging.DEBUG

logging.basicConfig(level=level)

logging.debug("Starting with the following args:")
logging.debug(args)

# args checking
if int(args.interval) <= 0:
    logging.error("无效间隔, 间隔必须大于 0.")
    exit(1)
else:
    args.interval = int(args.interval)

# 格式化操作
formats = {
    "b": lambda x: (x * 8),
    "k": lambda x: ((x * 8) / 1024),
    "m": lambda x: ((x * 8) / pow(1024, 2)),
    "B": lambda x: x,
    "K": lambda x: x / 1024,
    "M": lambda x: x / pow(1024, 2),
}


formatFn = formats[args.format]

# define the BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct index_key_t {
  u32 index;
};

BPF_HASH(ipv4_send_bytes, struct index_key_t);

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        u32 dst = sk->__sk_common.skc_daddr;
        unsigned categorized = 0;
        __SUBNETS__
    }
    
    return 0;
}
"""


# 接受一个掩码并返回等效的整数
# mask_to_int(8) returns 4278190080
def mask_to_int(n):
    return ((1 << n) - 1) << (32 - n)


# 接受一个子网列表, 返回一个三元组列表
# 索引 0 的元素表示子网信息
# 索引 1 的元素表示地址部分转换为整数后的值
# 索引 2 的元素表示掩码部分转换为整数后的值
#
# parse_subnets([10.10.0.0/24]) returns
# [
#   ['10.10.0.0/24', 168427520, 4294967040],
# ]
def parse_subnets(subnets):
    m = []

    for s in subnets:
        parts = s.split("/")

        if len(parts) != 2:
            msg = f"子网 [{s}] 无效."
            raise ValueError(msg)

        netaddr_int = 0
        mask_int = 0

        try:
            netaddr_int = struct.unpack("!I", socket.inet_aton(parts[0]))[0]
        except:
            msg = f"子网 [{s}] 的网络地址无效"
            raise ValueError(msg)
        try:
            mask_int = int(parts[1])
        except:
            msg = f"子网 [{s}] 的掩码无效, 必须为 int 类型"
            raise ValueError(msg)

        if mask_int < 0 or mask_int > 32:
            msg = "子网 [{s}] 的掩码无效, 必须是 int 类型且位于 0 和 32 之间."
            raise ValueError(msg)

        mask_int = mask_to_int(int(parts[1]))
        m.append([s, netaddr_int, mask_int])

    return m


def generate_bpf_subnets(subnets):
    template = """
        if (!categorized && (__NET_ADDR__ & __NET_MASK__) == (dst & __NET_MASK__)) {
          struct index_key_t key = {
            .index = __POS__
          };

          ipv4_send_bytes.atomic_increment(key, size);

          // 这个用来判断是否已经被分到某个子网中了, 不需要继续分类了
          categorized = 1;
        }
    """

    bpf = ""

    for i, s in enumerate(subnets):
        branch = template
        # 网络地址
        branch = branch.replace("__NET_ADDR__", str(socket.htonl(s[1])))
        # 掩码
        branch = branch.replace("__NET_MASK__", str(socket.htonl(s[2])))
        # 子网在 subnets 中的索引
        branch = branch.replace("__POS__", str(i))
        bpf += branch

    return bpf


subnets = []

if args.subnets:
    subnets = args.subnets.split(",")

subnets = parse_subnets(subnets)

logging.debug("数据包将被分类到以下子网中:")
logging.debug(subnets)

bpf_subnets = generate_bpf_subnets(subnets)

# initialize BPF
prog = prog.replace("__SUBNETS__", bpf_subnets)

logging.debug("完成 BPF 程序的预处理后, 实际执行的程序:")
logging.debug(prog)

if args.ebpf:
    print(prog)
    exit()

b = BPF(text=prog)

ipv4_send_bytes = b["ipv4_send_bytes"]

if not args.json:
    print(f"Tracing... Output every {args.interval} secs. Hit Ctrl-C to end")

# output
exiting = False

while True:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True

    keys = ipv4_send_bytes

    for k, v in ipv4_send_bytes.items():
        if k not in keys:
            keys[k] = v

    data = {}

    now = dt.now()
    data["date"] = now.strftime("%x")
    data["time"] = now.strftime("%X")
    data["entries"] = {}

    if not args.json:
        print(now.strftime("[%x %X]"))

    for k, v in reversed(sorted(keys.items(), key=lambda keys: keys[1].value)):
        send_bytes = 0

        if k in ipv4_send_bytes:
            send_bytes = int(ipv4_send_bytes[k].value)

        subnet = subnets[k.index][0]
        send = formatFn(send_bytes)

        if args.json:
            data["entries"][subnet] = send
        else:
            print(f"{subnet:<21} {send:<6}")

    if args.json:
        print(json.dumps(data))

    ipv4_send_bytes.clear()

    if exiting:
        exit(0)
