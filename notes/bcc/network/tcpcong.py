"""
跟踪内核中 TCP 拥塞控制状态变化函数

sudo python ./tcpcong.py

不知道怎么测试拥塞 ╯︿╰
"""

from bcc import BPF
from time import sleep, strftime
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import argparse

examples = """
examples:
    ./tcpcong                 # 显示 tcp 拥塞状态持续时间
    ./tcpcong 1 10            # 展示 1 秒钟内的分析结果, 共 10 次
    ./tcpcong -L 3000-3006 1  # 本地端口 3000-3006
    ./tcpcong -R 5000-5005 1  # 远程端口 5000-5005
    ./tcpcong -uT 1           # 微秒单位, 并显示时间戳
    ./tcpcong -d              # 以直方图的形式显示
"""

parser = argparse.ArgumentParser(
    description="总结 tcp 套接字拥塞控制状态的持续时间",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-L", "--localport", help="仅跟踪本地端口")
parser.add_argument("-R", "--remoteport", help="仅跟踪目的端口")
parser.add_argument("-T", "--timestamp", action="store_true", help="输出包含时间戳")
parser.add_argument("-d", "--dist", action="store_true", help="以直方图的形势显示分布")
parser.add_argument("-u", "--microseconds", action="store_true", help="微妙为单位输出")
parser.add_argument("interval", nargs="?", default=99999999, help="输出间隔, 以秒为单位")
parser.add_argument("outputs", nargs="?", default=99999999, help="输出数量")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

countdown = int(args.outputs)

debug = False

start_rport = end_rport = -1

if args.remoteport:
    rports = args.remoteport.split("-")

    if (len(rports) != 2) and (len(rports) != 1):
        print("无法识别远程端口范围")
        exit(1)

    if len(rports) == 2:
        start_rport = int(rports[0])
        end_rport = int(rports[1])
    else:
        start_rport = int(rports[0])
        end_rport = int(rports[0])

if start_rport > end_rport:
    start_rport, end_rport = end_rport, start_rport


start_lport = end_lport = -1

if args.localport:
    lports = args.localport.split("-")

    if (len(lports) != 2) and (len(lports) != 1):
        print("无法识别本地端口范围")
        exit(1)

    if len(lports) == 2:
        start_lport = int(lports[0])
        end_lport = int(lports[1])
    else:
        start_lport = int(lports[0])
        end_lport = int(lports[0])

if start_lport > end_lport:
    start_lport, end_lport = end_lport, start_lport


# define BPF program
bpf_head_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

typedef struct ipv4_flow_key {
    u32 saddr; // 源地址
    u32 daddr; // 目的地址
    u16 lport; // 本地端口
    u16 dport; // 目的端口
} ipv4_flow_key_t;

typedef struct ipv6_flow_key {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
} ipv6_flow_key_t;

typedef struct data_val {
    DEF_TEXT
    u64  last_ts;
    u16  last_cong_stat;
} data_val_t;

BPF_HASH(ipv4_stat, ipv4_flow_key_t, data_val_t);
BPF_HASH(ipv6_stat, ipv6_flow_key_t, data_val_t);

// 根据是否需要 dist 来替换
HIST_TABLE
"""

bpf_extra_head = """
typedef struct process_key {
    char comm[TASK_COMM_LEN]; // 进程名
    u32  tid;                 // 进程 ID
} process_key_t;

typedef struct ipv4_flow_val {
    ipv4_flow_key_t ipv4_key;
    u16  cong_state;          // 拥塞状态
} ipv4_flow_val_t;

typedef struct ipv6_flow_val {
    ipv6_flow_key_t ipv6_key;
    u16  cong_state;
} ipv6_flow_val_t;

// 记录进程和状态信息, 完整状态信息需要查表 ipv4_stat 和 ipv6_stat
BPF_HASH(start_ipv4, process_key_t, ipv4_flow_val_t);
BPF_HASH(start_ipv6, process_key_t, ipv6_flow_val_t);

// 根据是否支持 kfuncs 来替换
SOCK_STORE_DEF

// 结构体的位域表示
typedef struct cong {
    u8 cong_stat: 5,  // 占 5 位, 表示拥塞状态
    ca_inited: 1,     // 占 1 位, 表示是否已初始化
    ca_setsockopt: 1,
    ca_dstlocked: 1;
} cong_status_t;
"""

# 不支持 kfuncs 时的代码
bpf_no_ca_tp_body_text = """
static int entry_state_update_func(struct sock *sk) {
    u16 dport = 0, lport = 0;
    u32 tid = bpf_get_current_pid_tgid(); // 获取进程 ID
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm)); // 获取进程名
    key.tid = tid;

    u64 family = sk->__sk_common.skc_family;           // 获取协议族
    struct inet_connection_sock *icsk = inet_csk(sk);
    cong_status_t cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status), (void *)((long)&icsk->icsk_retransmits) - 1);
    
    if (family == AF_INET) {
        // IPv4
        ipv4_flow_val_t ipv4_val = {0};
        ipv4_val.ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_val.ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_val.ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv4_val.ipv4_key.lport;
        
        // 用于过滤某些本地端口
        FILTER_LPORT
        
        // 用于过滤某些目的端口
        FILTER_DPORT
        
        ipv4_val.ipv4_key.dport = dport;
        ipv4_val.cong_state = cong_status.cong_stat + 1;

        // 更新进程-拥塞状态哈希表
        start_ipv4.update(&key, &ipv4_val);
    } else if (family == AF_INET6) {
        // IPv6
        ipv6_flow_val_t ipv6_val = {0};
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.saddr, sizeof(ipv6_val.ipv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.daddr, sizeof(ipv6_val.ipv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_val.ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv6_val.ipv6_key.lport;
        
        FILTER_LPORT
        
        FILTER_DPORT
        
        ipv6_val.ipv6_key.dport = dport;
        ipv6_val.cong_state = cong_status.cong_stat + 1;
        
        // 更新哈希表
        start_ipv6.update(&key, &ipv6_val);
    }

    // 依据是否支持 kfuncs 而定
    SOCK_STORE_ADD
    
    return 0;
}

static int ret_state_update_func(struct sock *sk) {
    u64 ts, ts1;
    u16 family, last_cong_state;
    u16 dport = 0, lport = 0;
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.tid = tid;

    struct inet_connection_sock *icsk = inet_csk(sk);
    cong_status_t cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status), (void *)((long)&icsk->icsk_retransmits) - 1);
    data_val_t *datap, data = {0};
    
    STATE_KEY
    
    // 获取协议族
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    
    if (family == AF_INET) {
        // IPv4
        ipv4_flow_val_t *val4 = start_ipv4.lookup(&key);
        
        if (val4 == 0) {
            // 当前进程不存在状态信息, 从 sock_store 中删除
            SOCK_STORE_DEL
            return 0;
        }
        
        // 当前进程存在状态信息
        ipv4_flow_key_t keyv4 = {0};
        bpf_probe_read_kernel(&keyv4, sizeof(ipv4_flow_key_t), &(val4->ipv4_key));
        dport = keyv4.dport;
        lport = keyv4.lport;
        
        FILTER_LPORT
        
        FILTER_DPORT
        
        // 查找当前 IPv4 状态信息
        datap = ipv4_stat.lookup(&keyv4);
        
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();      // 当前时间戳
            data.last_cong_stat = val4->cong_state; // 当前拥塞状态

            // 当前进程 IP 的状态信息不存在, 则存入状态表
            ipv4_stat.update(&keyv4, &data);
        } else {
            last_cong_state = val4->cong_state;
            
            // 之前状态和现在的不相等
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;                         // 计算时间差
                datap->last_ts = ts1;                              // 更新时间戳
                datap->last_cong_stat = cong_status.cong_stat + 1; // 更新状态
                ts /= 1000;

                // 存储为直方图或者普通
                STORE
            }
        }

        start_ipv4.delete(&key);
    } else if (family == AF_INET6) {
        ipv6_flow_val_t *val6 = start_ipv6.lookup(&key);
        
        if (val6 == 0) {
            SOCK_STORE_DEL
            return 0; //missed
        }
        
        ipv6_flow_key_t keyv6 = {0};
        bpf_probe_read_kernel(&keyv6, sizeof(ipv6_flow_key_t), &(val6->ipv6_key));
        dport = keyv6.dport;
        lport = keyv6.lport;
        
        FILTER_LPORT
        
        FILTER_DPORT
        
        datap = ipv6_stat.lookup(&keyv6);
        
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val6->cong_state;
            ipv6_stat.update(&keyv6, &data);
        } else {
            last_cong_state = val6->cong_state;
            
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = (cong_status.cong_stat + 1);
                ts /= 1000;
                
                STORE
            }
        }
        
        start_ipv6.delete(&key);
    }

    SOCK_STORE_DEL
    
    return 0;
}
"""

# 支持 kfuncs 时的代码
bpf_ca_tp_body_text = """
TRACEPOINT_PROBE(tcp, tcp_cong_state_set) {
    u64 ts, ts1;
    u16 family, last_cong_state, dport = 0, lport = 0;
    u8 cong_state;
    const struct sock *sk = (const struct sock *)args->skaddr;
    data_val_t *datap, data = {0};

    family = sk->__sk_common.skc_family;
    dport = args->dport;
    lport = args->sport;
    cong_state = args->cong_state;

    STATE_KEY
    
    if (family == AF_INET) {
        ipv4_flow_key_t key4 = {0};
        key4.saddr = sk->__sk_common.skc_rcv_saddr;
        key4.daddr = sk->__sk_common.skc_daddr;
        
        FILTER_LPORT
        
        FILTER_DPORT
        
        key4.lport = lport;
        key4.dport = dport;
        
        datap = ipv4_stat.lookup(&key4);
        
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = cong_state + 1;
            ipv4_stat.update(&key4, &data);
        } else {
            last_cong_state = datap->last_cong_stat;
            
            if ((cong_state + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_state + 1;
                ts /= 1000;
                
                STORE
            }
        }
    } else if (family == AF_INET6) {
        ipv6_flow_key_t key6 = {0};
        
        bpf_probe_read_kernel(&key6.saddr, sizeof(key6.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&key6.daddr, sizeof(key6.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        
        FILTER_LPORT
        
        FILTER_DPORT
        
        key6.lport = lport;
        key6.dport = dport;
        
        datap = ipv6_stat.lookup(&key6);
        
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = cong_state + 1;
            ipv6_stat.update(&key6, &data);
        } else {
            last_cong_state = datap->last_cong_stat;
            
            if ((cong_state + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_state + 1;
                ts /= 1000;
                
                STORE
            }
        }
    }
    
    return 0;
}
"""

# 不支持 kfuncs 的代码
kprobe_program = """
int entry_func(struct pt_regs *ctx, struct sock *sk) {
    // 更新网络状态信息
    return entry_state_update_func(sk);
}

int ret_func(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm)); // 进程名
    key.tid = tid;
    struct sock **sockpp;
    sockpp = sock_store.lookup(&key);
    
    // 没有找到相关状态信息
    if (sockpp == 0) {
        return 0;
    }
    
    // 找到相关信息就更新状态
    struct sock *sk = *sockpp;
    return ret_state_update_func(sk);
}
"""

# 支持 kfuncs 时的代码
kfunc_program = """
KFUNC_PROBE(tcp_fastretrans_alert, struct sock *sk) {
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_fastretrans_alert, struct sock *sk) {
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_enter_cwr, struct sock *sk) {
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_enter_cwr, struct sock *sk) {
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_enter_loss, struct sock *sk) {
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_enter_loss, struct sock *sk) {
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_enter_recovery, struct sock *sk) {
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_enter_recovery, struct sock *sk) {
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_process_tlp_ack, struct sock *sk) {
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_process_tlp_ack, struct sock *sk) {
    return ret_state_update_func(sk);
}
"""

# code replace
is_support_tp_ca = BPF.tracepoint_exists("tcp", "tcp_cong_state_set")

if is_support_tp_ca:
    prog = bpf_head_text + bpf_ca_tp_body_text
else:
    prog = bpf_head_text + bpf_extra_head
    prog += bpf_no_ca_tp_body_text

    is_support_kfunc = BPF.support_kfunc()

    if is_support_kfunc:
        prog += kfunc_program
        prog = prog.replace("SOCK_STORE_DEF", "")
        prog = prog.replace("SOCK_STORE_ADD", "")
        prog = prog.replace("SOCK_STORE_DEL", "")
    else:
        prog += kprobe_program
        prog = prog.replace(
            "SOCK_STORE_DEF", "BPF_HASH(sock_store, process_key_t, struct sock *);"
        )
        prog = prog.replace("SOCK_STORE_ADD", "sock_store.update(&key, &sk);")
        prog = prog.replace("SOCK_STORE_DEL", "sock_store.delete(&key);")

if args.localport:
    prog = prog.replace(
        "FILTER_LPORT",
        f"if (lport < {start_lport} || lport > {end_lport}) {{ return 0; }}",
    )
else:
    prog = prog.replace("FILTER_LPORT", "")

if args.remoteport:
    prog = prog.replace(
        "FILTER_DPORT",
        f"if (dport < {start_rport} || dport > {end_rport}) {{ return 0; }}",
    )
else:
    prog = prog.replace("FILTER_DPORT", "")

# 各个状态的持续时间
table_def_text = """
    u64  open_dura;
    u64  loss_dura;
    u64  disorder_dura;
    u64  recover_dura;
    u64  cwr_dura;
    u64  total_changes;
"""

store_text = """
                datap->total_changes += 1;
                
                // 更新状态持续时间
                if (last_cong_state == (TCP_CA_Open + 1)) {
                    datap->open_dura += ts;
                } else if (last_cong_state == (TCP_CA_Disorder + 1)) {
                    datap->disorder_dura += ts;
                } else if (last_cong_state == (TCP_CA_CWR + 1)) {
                    datap->cwr_dura += ts;
                } else if (last_cong_state == (TCP_CA_Recovery + 1)) {
                    datap->recover_dura += ts;
                } else if (last_cong_state == (TCP_CA_Loss + 1)) {
                    datap->loss_dura += ts;
                }
"""

store_dist_text = """
                // TCP 的拥塞状态机
                if (last_cong_state == (TCP_CA_Open + 1)) {
                    // 正常状态
                    key_s.state = TCP_CA_Open;
                } else if (last_cong_state == (TCP_CA_Disorder + 1)) {
                    // 检测到重复的 ACK 或选择性确认时
                    key_s.state = TCP_CA_Disorder;
                } else if (last_cong_state == (TCP_CA_CWR + 1)) {
                    // 拥塞窗口减少的状态
                    key_s.state = TCP_CA_CWR;
                } else if (last_cong_state == (TCP_CA_Recovery + 1)) {
                    // 连续收到多个(默认3) ack 时, 进入快速重传
                    key_s.state = TCP_CA_Recovery;
                } else if (last_cong_state == (TCP_CA_Loss + 1)) {
                    // 出现丢包, 拥塞窗口降至 1
                    key_s.state = TCP_CA_Loss;
                }
                
                // 是否将 ts 换成微秒
                TIME_UNIT
                
                key_s.slot = bpf_log2l(ts);
                dist.atomic_increment(key_s);
"""

hist_table_text = """
// TCP 拥塞状态
typedef struct congest_state_key {
    u32  state;
    u64  slot;
} congest_state_key_t;

BPF_HISTOGRAM(dist, congest_state_key_t);
"""

if args.dist:
    prog = prog.replace("DEF_TEXT", "")
    prog = prog.replace("STORE", store_dist_text)
    prog = prog.replace("STATE_KEY", "congest_state_key_t key_s = {0};")
    prog = prog.replace("HIST_TABLE", hist_table_text)

    if args.microseconds:
        prog = prog.replace("TIME_UNIT", "")
    else:
        prog = prog.replace("TIME_UNIT", "ts /= 1000;")
else:
    prog = prog.replace("DEF_TEXT", table_def_text)
    prog = prog.replace("STORE", store_text)
    prog = prog.replace("STATE_KEY", "")
    prog = prog.replace("HIST_TABLE", "")


if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=prog)

if not is_support_tp_ca and not is_support_kfunc:
    # 所有 TCP 拥塞控制状态更新函数
    b.attach_kprobe(event="tcp_fastretrans_alert", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_fastretrans_alert", fn_name="ret_func")

    b.attach_kprobe(event="tcp_enter_cwr", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_enter_cwr", fn_name="ret_func")

    b.attach_kprobe(event="tcp_process_tlp_ack", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_process_tlp_ack", fn_name="ret_func")

    b.attach_kprobe(event="tcp_enter_loss", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_enter_loss", fn_name="ret_func")

    b.attach_kprobe(event="tcp_enter_recovery", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_enter_recovery", fn_name="ret_func")

print("Tracing tcp congestion control status duration... Hit Ctrl-C to end.")


def cong_state_to_name(state):
    # 状态需要与内核状态匹配
    state_name = ["open", "disorder", "cwr", "recovery", "loss"]
    return state_name[state]


# output
exiting = 0 if args.interval else 1
ipv6_stat = b.get_table("ipv6_stat")
ipv4_stat = b.get_table("ipv4_stat")

if args.dist:
    dist = b.get_table("dist")

label = "ms"

if args.microseconds:
    label = "us"

while True:
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    if args.timestamp:
        print(f"{strftime('%H:%M:%S'): <8}\n", end="")

    if args.dist:
        if args.microseconds:
            dist.print_log2_hist(
                "usecs", "tcp_congest_state", section_print_fn=cong_state_to_name
            )
        else:
            dist.print_log2_hist(
                "msecs", "tcp_congest_state", section_print_fn=cong_state_to_name
            )
        dist.clear()
    else:
        if ipv4_stat:
            content = f"{'LAddrPort': <21} {'RAddrPort': <21} {f'Open_' + label: <7} {'Dod_' + label: <6} {'Rcov_' + label: <7} {'Cwr_' + label: <7} {'Los_' + label: <6} {'Chgs': <5}"
            print(content)

        laddr = ""
        raddr = ""

        for k, v in sorted(ipv4_stat.items(), key=lambda ipv4_stat: ipv4_stat[0].lport):
            laddr = inet_ntop(AF_INET, pack("I", k.saddr))
            raddr = inet_ntop(AF_INET, pack("I", k.daddr))
            open_dura = v.open_dura
            disorder_dura = v.disorder_dura
            recover_dura = v.recover_dura
            cwr_dura = v.cwr_dura
            loss_dura = v.loss_dura

            if not args.microseconds:
                open_dura /= 1000
                disorder_dura /= 1000
                recover_dura /= 1000
                cwr_dura /= 1000
                loss_dura /= 1000

            if v.total_changes != 0:
                content = f"{ laddr + '/' + k.lport: <21} {raddr + '/' + k.dport: <21} {open_dura: <7} {disorder_dura: <6} {recover_dura: <7} {cwr_dura: <7} {loss_dura: <6} {v.total_changes: <5}"
                print(content)

        if ipv6_stat:
            content = f"{'LAddrPort6': <32} {'RAddrPort6': <32} {'Open_' + label: <7} {'Dod_' + label: <6} {'cov_' + label: <7} {'Cwr_' + label: <7} {'Los_' + label: <6} {'Chgs': <5}"
            print(content)

        for k, v in sorted(ipv6_stat.items(), key=lambda ipv6_stat: ipv6_stat[0].lport):
            laddr = inet_ntop(AF_INET6, bytes(k.saddr))
            raddr = inet_ntop(AF_INET6, bytes(k.daddr))
            open_dura = v.open_dura
            disorder_dura = v.disorder_dura
            recover_dura = v.recover_dura
            cwr_dura = v.cwr_dura
            loss_dura = v.loss_dura

            if not args.microseconds:
                open_dura /= 1000
                disorder_dura /= 1000
                recover_dura /= 1000
                cwr_dura /= 1000
                loss_dura /= 1000

            if v.total_changes != 0:
                content = f"{laddr + '/' + str(k.lport): <32} {raddr + '/' + str(k.dport): <32} {open_dura:<7} {disorder_dura: <7} {recover_dura :<7} {cwr_dura: <6} {loss_dura: <6} {v.total_changes: <5}"
                print(content)

    ipv4_stat.clear()
    ipv6_stat.clear()
    countdown -= 1

    if exiting or countdown == 0:
        exit()
