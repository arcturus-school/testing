"""
跟踪 TCP 连接情况

sudo python ./tcpconnect.py

本程序不含建连时间, 可能需要改一下才能支持

output:
    Tracing connect ... Hit Ctrl-C to end
    PID  COMM  IP SADDR  DADDR  DPORT(目的)
    158  init  6  ::1    ::1    8083   
    158  init  6  ::1    ::1    8083 
"""

from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import printb
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
from time import sleep
from datetime import datetime
import argparse

# arguments
examples = """
examples:
    ./tcpconnect           # 跟踪所有 TCP connect()
    ./tcpconnect -t        # 包括时间戳
    ./tcpconnect -d        # 包括与 connects 相关的 DNS 查询
    ./tcpconnect -p 181    # 只跟踪 PID 181
    ./tcpconnect -P 80     # 只跟踪端口 80
    ./tcpconnect -P 80,81  # 只跟踪端口 80 和 81
    ./tcpconnect -4        # 只跟踪 IPv4 地址族
    ./tcpconnect -6        # 只跟踪 IPv6 地址族
    ./tcpconnect -U        # 包括 UID
    ./tcpconnect -u 1000   # 只跟踪 UID 1000
    ./tcpconnect -c        # 统计每个源 IP 地址和目的 IP 地址/端口的连接数
    ./tcpconnect -L        # 在打印时包括 LPORT
    ./tcpconnect --cgroupmap mappath  # 只跟踪 BPF 映射中的 cgroups
    ./tcpconnect --mntnsmap mappath   # 只跟踪 BPF 映射中的 mount namespaces
"""

parser = argparse.ArgumentParser(
    description="跟踪 TCP 连接情况",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-t", "--timestamp", action="store_true", help="输出包含时间戳")
parser.add_argument("-p", "--pid", help="仅跟踪此 PID")
parser.add_argument("-P", "--port", help="要跟踪的目标端口列表, 以逗号分隔")

group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true", help="仅跟踪 IPv4 地址族")
group.add_argument("-6", "--ipv6", action="store_true", help="仅跟踪 IPv6 地址族")
parser.add_argument("-L", "--lport", action="store_true", help="输出中包括 LPORT")
parser.add_argument("-U", "--print-uid", action="store_true", help="输出中包括 UID")
parser.add_argument("-u", "--uid", help="仅跟踪指定的用户 ID")
parser.add_argument(
    "-c", "--count", action="store_true", help="统计源 IP 地址和目的 IP 地址/端口的连接数"
)
parser.add_argument("--cgroupmap", help="仅跟踪 BPF 映射中的 cgroups")
parser.add_argument("--mntnsmap", help="仅跟踪 BPF 映射中的 mount namespaces")
parser.add_argument("-d", "--dns", action="store_true", help="在每个连接中包括可能的 DNS 查询")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

debug = False

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv6_events);

struct ipv4_flow_key_t {
    u32 saddr; // 源地址
    u32 daddr; // 目的地址
    u16 dport; // 目的端口
};

BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 dport;
};

BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    if (container_should_be_filtered()) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    // 过滤 PID
    FILTER_PID

    u32 uid = bpf_get_current_uid_gid();
    
    // 过滤 UID
    FILTER_UID

    // 将 socket 指针保存起来
    currsock.update(&tid, &sk);

    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short ipver) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;

    struct sock **skpp;

    // 根据 tid 找 socket 指针
    skpp = currsock.lookup(&tid);
    
    if (skpp == 0) {
        return 0;
    }

    if (ret != 0) {
        currsock.delete(&tid);
        return 0;
    }

    // 获取 scoket 的细节
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;

    // 过滤端口
    FILTER_PORT

    // 过滤协议族
    FILTER_FAMILY

    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        IPV6_CODE
    }

    currsock.delete(&tid);

    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx) {
    return trace_connect_return(ctx, 6);
}
"""

ipv4_init_count = """
        struct ipv4_flow_key_t flow_key = {};
        
        flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
        flow_key.daddr = skp->__sk_common.skc_daddr;
        flow_key.dport = ntohs(dport);
        
        ipv4_count.increment(flow_key);
"""

ipv4_init_trace = """
        struct ipv4_data_t data4 = {
            .pid = pid, 
            .ip = ipver
        };
        
        data4.uid = bpf_get_current_uid_gid();
        data4.ts_us = bpf_ktime_get_ns() / 1000; // 微秒
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = ntohs(dport);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
"""

ipv6_init_count = """
        struct ipv6_flow_key_t flow_key = {};
        
        bpf_probe_read_kernel(&flow_key.saddr, sizeof(flow_key.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&flow_key.daddr, sizeof(flow_key.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        flow_key.dport = ntohs(dport);
        
        ipv6_count.increment(flow_key);
"""

ipv6_init_trace = """
        struct ipv6_data_t data6 = {
            .pid = pid, 
            .ip = ipver
        };

        data6.uid = bpf_get_current_uid_gid();
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.lport = lport;
        data6.dport = ntohs(dport);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
"""


dns_prog = """
#include <net/inet_sock.h>
#include <uapi/linux/udp.h>

#define MAX_PKT 512

struct dns_data_t {
    u8  pkt[MAX_PKT];
};

BPF_PERF_OUTPUT(dns_events);

BPF_HASH(tbl_udp_msg_hdr, u64, struct msghdr *);

BPF_PERCPU_ARRAY(dns_data, struct dns_data_t, 1);

int trace_udp_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *is = inet_sk(sk);

    // 检查该事件是否为目标端口(53)
    if (is->inet_dport == 13568) {
        struct msghdr *msghdr = (struct msghdr *)PT_REGS_PARM2(ctx);
        tbl_udp_msg_hdr.update(&pid_tgid, &msghdr);
    }

    return 0;
}

int trace_udp_ret_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 zero = 0;
    struct msghdr **msgpp = tbl_udp_msg_hdr.lookup(&pid_tgid);
    
    if (msgpp == 0)
        return 0;

    struct msghdr *msghdr = (struct msghdr *)*msgpp;
    
    if (msghdr->msg_iter.TYPE_FIELD != ITER_IOVEC) {
        tbl_udp_msg_hdr.delete(&pid_tgid);
        return 0;
    }

    int copied = (int)PT_REGS_RC(ctx);
    
    if (copied < 0) {
        tbl_udp_msg_hdr.delete(&pid_tgid);
        return 0;
    }
    
    size_t buflen = (size_t)copied;

    if (buflen > msghdr->msg_iter.iov->iov_len) {
        tbl_udp_msg_hdr.delete(&pid_tgid);
        return 0;
    }

    if (buflen > MAX_PKT)
        buflen = MAX_PKT;

    struct dns_data_t *data = dns_data.lookup(&zero);
    if (!data) {
        return 0;
    }

    void *iovbase = msghdr->msg_iter.iov->iov_base;
    bpf_probe_read(data->pkt, buflen, iovbase);
    dns_events.perf_submit(ctx, data, buflen);

    tbl_udp_msg_hdr.delete(&pid_tgid);
    return 0;
}

int trace_udpv6_recvmsg(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct udphdr *hdr = (void*)skb->head + skb->transport_header;
    struct dns_data_t *event;
    int zero = 0;
    void *data;

    if (hdr->source != 0x3500)
        return 0;

    // 跳过 UDP 头
    data = skb->data + 8;

    event = dns_data.lookup(&zero);
    
    if (!event)
        return 0;

    bpf_probe_read(event->pkt, sizeof(event->pkt), data);
    dns_events.perf_submit(ctx, event, sizeof(*event));
    
    return 0;
}
"""

if args.count and args.dns:
    print("Error: 不能同时指定 -d/--dns 和 -c/--count.")
    exit()

# code substitutions
if args.count:
    prog = prog.replace("IPV4_CODE", ipv4_init_count)
    prog = prog.replace("IPV6_CODE", ipv6_init_count)
else:
    prog = prog.replace("IPV4_CODE", ipv4_init_trace)
    prog = prog.replace("IPV6_CODE", ipv6_init_trace)

# pid 过滤
if args.pid:
    prog = prog.replace("FILTER_PID", f"if (pid != {args.pid}) {{ return 0; }}")
else:
    prog = prog.replace("FILTER_PID", "")

# 端口过滤
if args.port:
    dports = [int(dport) for dport in args.port.split(",")]
    dports_if = " && ".join([f"dport != {ntohs(dport)}" for dport in dports])
    prog = prog.replace(
        "FILTER_PORT", f"if ({dports_if}) {{ currsock.delete(&tid); return 0; }}"
    )
else:
    prog = prog.replace("FILTER_PORT", "")

# 协议族过滤
if args.ipv4:
    prog = prog.replace("FILTER_FAMILY", "if (ipver != 4) { return 0; }")
elif args.ipv6:
    prog = prog.replace("FILTER_FAMILY", "if (ipver != 6) { return 0; }")
else:
    prog = prog.replace("FILTER_FAMILY", "")

# uid 过滤
if args.uid:
    prog = prog.replace("FILTER_UID", f"if (uid != {args.uid}) {{ return 0; }}")
else:
    prog = prog.replace("FILTER_UID", "")

prog = filter_by_containers(args) + prog


if args.dns:
    if BPF.kernel_struct_has_field(b"iov_iter", b"iter_type") == 1:
        dns_prog = dns_prog.replace("TYPE_FIELD", "iter_type")
    else:
        dns_prog = dns_prog.replace("TYPE_FIELD", "type")

    prog += dns_prog

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()


# 打印 IPv4 信息
def print_ipv4_event(cpu, data, size):
    global start_ts

    event = b["ipv4_events"].event(data)

    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us

        dt = (float(event.ts_us) - start_ts) / 1000000
        printb(b"%-9.3f" % dt, nl="")

    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")

    # 目的 IP
    dest_ip = inet_ntop(AF_INET, pack("I", event.daddr)).encode()

    if args.lport:
        printb(
            b"%-7d %-12.12s %-2d %-16s %-6d %-16s %-6d %s"
            % (
                event.pid,
                event.task,
                event.ip,
                inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
                event.lport,
                dest_ip,
                event.dport,
                print_dns(dest_ip),
            )
        )
    else:
        printb(
            b"%-7d %-12.12s %-2d %-16s %-16s %-6d %s"
            % (
                event.pid,
                event.task,
                event.ip,
                inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
                dest_ip,
                event.dport,
                print_dns(dest_ip),
            )
        )


def print_ipv6_event(cpu, data, size):
    global start_ts

    event = b["ipv6_events"].event(data)

    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us

        dt = (float(event.ts_us) - start_ts) / 1000000
        printb(b"%-9.3f" % dt, nl="")

    if args.print_uid:
        printb(b"%-6d" % event.uid, nl="")

    dest_ip = inet_ntop(AF_INET6, event.daddr).encode()

    if args.lport:
        printb(
            b"%-7d %-12.12s %-2d %-16s %-6d %-16s %-6d %s"
            % (
                event.pid,
                event.task,
                event.ip,
                inet_ntop(AF_INET6, event.saddr).encode(),
                event.lport,
                dest_ip,
                event.dport,
                print_dns(dest_ip),
            )
        )
    else:
        printb(
            b"%-7d %-12.12s %-2d %-16s %-16s %-6d %s"
            % (
                event.pid,
                event.task,
                event.ip,
                inet_ntop(AF_INET6, event.saddr).encode(),
                dest_ip,
                event.dport,
                print_dns(dest_ip),
            )
        )


# 直方图输出
def depict_cnt(counts_tab, l3prot="ipv4"):
    items = sorted(counts_tab.items(), key=lambda counts: counts[1].value, reverse=True)

    for k, v in items:
        depict_key = ""

        if l3prot == "ipv4":
            saddr = inet_ntop(AF_INET, pack("I", k.saddr))
            daddr = inet_ntop(AF_INET, pack("I", k.daddr))

            depict_key = f"{saddr:<25} {daddr:<25} {k.dport:<20}"
        else:
            saddr = inet_ntop(AF_INET6, k.saddr)
            daddr = inet_ntop(AF_INET6, k.daddr)

            depict_key = f"{saddr:<25} {daddr:<25} {k.dport:<20}"

        print(f"{depict_key} {v.value:<10}")


def print_dns(dest_ip):
    if not args.dns:
        return b""

    dnsname, timestamp = dns_cache.get(dest_ip, (None, None))

    if timestamp is not None:
        diff = datetime.now() - timestamp
        diff = float(diff.seconds) * 1000 + float(diff.microseconds) / 1000
    else:
        diff = 0

    if dnsname is None:
        dnsname = b"No DNS Query"

        if dest_ip == b"127.0.0.1" or dest_ip == b"::1":
            dnsname = b"localhost"

    retval = b"%s" % dnsname

    if diff > DELAY_DNS:
        retval += b" (%.3fms)" % diff

    return retval


if args.dns:
    try:
        import dnslib
        from cachetools import TTLCache
    except ImportError:
        print("Error: 在使用 -d/--dns 选项时缺少 dnslib and cachetools 包.")
        print("根据命令安装包:")
        print("\tpip3 install dnslib cachetools")
        print("   或者")
        print(
            "\t$ sudo apt-get install python3-dnslib python3-cachetools(on Ubuntu 18.04+)"
        )

        exit(1)

    # 24 小时
    DEFAULT_TTL = 86400

    # 缓存大小
    DNS_CACHE_SIZE = 10240

    # DNS 延迟
    DELAY_DNS = 100

    dns_cache = TTLCache(maxsize=DNS_CACHE_SIZE, ttl=DEFAULT_TTL)

    # 保存 dns 数据
    def save_dns(cpu, data, size):
        event = b["dns_events"].event(data)
        payload = event.pkt[:size]

        # 解析 dns 包
        dnspkt = dnslib.DNSRecord.parse(payload)

        if dnspkt.header.qr != 1:
            return

        if dnspkt.header.q != 1:
            return

        if dnspkt.header.a == 0 and dnspkt.header.aa == 0:
            return

        question = (str(dnspkt.q.qname))[:-1].encode("utf-8")

        for answer in dnspkt.rr:
            # 跳过除 A 和 AAAA 外的所有数据
            if answer.rtype == 1 or answer.rtype == 28:
                dns_cache[str(answer.rdata).encode("utf-8")] = (
                    question,
                    datetime.now(),
                )


# initialize BPF
b = BPF(text=prog)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

if args.dns:
    b.attach_kprobe(event="udp_recvmsg", fn_name="trace_udp_recvmsg")
    b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_ret_recvmsg")
    b.attach_kprobe(event="udpv6_queue_rcv_one_skb", fn_name="trace_udpv6_recvmsg")

print("Tracing connect ... Hit Ctrl-C to end")

if args.count:
    try:
        while True:
            sleep(99999999)
    except KeyboardInterrupt:
        pass

    # header
    print(f"\n{'LADDR':<25} {'RADDR':<25} {'RPORT':<20} {'CONNECTS':<10}")

    depict_cnt(b["ipv4_count"])
    depict_cnt(b["ipv6_count"], l3prot="ipv6")
else:
    # header
    if args.timestamp:
        print(f"{'TIME(s)':<9}", end="")

    if args.print_uid:
        print("{'UID':<6}", end="")

    if args.lport:
        print(
            f"{'PID':<7} {'COMM':<12} IP {'SADDR':<12} LPORT  {'DADDR':<16} DPORT ",
            end="",
        )
    else:
        print(
            f"{'PID':<7} {'COMM':<12} IP {'SADDR':<16} {'DADDR':<16} DPORT",
            end="",
        )

    if args.dns:
        print(" QUERY")
    else:
        print()

    start_ts = 0

    # read events
    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)

    if args.dns:
        b["dns_events"].open_perf_buffer(save_dns)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
