"""
使用直方图显示 I/O 调用情况

sudo python ./bitehist.py

output:
    Tracing... Hit Ctrl-C to end.
    ^C
    log2 histogram
    ~~~~~~~~~~~~~~
    kbytes              : count     distribution
        0 -> 1          : 33       |****************************************|

    linear histogram
    ~~~~~~~~~~~~~~~~
    kbytes              : count     distribution
        0               : 33       |****************************************|
"""

from bcc import BPF
from time import sleep

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

// 新建两个直方图
BPF_HISTOGRAM(dist);        // log2 形式的直方图
BPF_HISTOGRAM(dist_linear); // 线性直方图

int trace_req_done(struct pt_regs *ctx, struct request *req) {
    // 存储请求的数据长度
    dist.increment(bpf_log2l(req->__data_len / 1024));
    dist_linear.increment(req->__data_len / 1024);
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

if BPF.get_kprobe_functions(b"__blk_account_io_done"):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_done")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    print()

# output
print("log2 histogram")
print("~~~~~~~~~~~~~~")
b["dist"].print_log2_hist("kbytes")

print("\nlinear histogram")
print("~~~~~~~~~~~~~~~~")
b["dist_linear"].print_linear_hist("kbytes")
