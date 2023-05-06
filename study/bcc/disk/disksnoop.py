"""
磁盘 I/O 跟踪程序

sudo python ./disksnoop.py

output:
    TIME(s)            T         BYTES    LAT(ms)
    7886.584024000     W(write)  0           0.96
    7886.587900000     R(read)   0           3.76
    7886.588202000     W         0           0.18
    7886.589722000     R         0           1.44
"""

from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1  # 写请求

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request *);

// 磁盘 I/O 请求开始时被调用, 记录调用开始时间
void trace_start(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();

    start.update(&req, &ts);
}

// 磁盘 I/O 请求完成时被调用
void trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;

    tsp = start.lookup(&req);
    
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;

        // __data_len: 请求数据的长度
        // cmd__flags: 命令
        // delta / 1000: 请求耗时(ms)
        bpf_trace_printk("%d %x %d\\n", req->__data_len, req->cmd_flags, delta / 1000);
        start.delete(&req);
    }
}
"""

# load BPF program
b = BPF(text=prog)

if BPF.get_kprobe_functions(b"blk_start_request"):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_start")

b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")

if BPF.get_kprobe_functions(b"__blk_account_io_done"):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")

# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()

        # 分割 bpf_trace_printk 消息
        (bytes_s, bflags_s, us_s) = msg.split()

        if int(bflags_s, 16) & REQ_WRITE:
            type_s = b"W"
        elif bytes_s == "0":
            type_s = b"M"
        else:
            type_s = b"R"

        ms = float(int(us_s, 10)) / 1000

        printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
    except KeyboardInterrupt:
        exit()
