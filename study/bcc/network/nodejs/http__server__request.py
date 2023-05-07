from bcc import BPF, USDT
from bcc.utils import printb
import sys

if len(sys.argv) < 2:
    print("Missing PID")
    exit()

pid = int(sys.argv[1])


# load BPF program
prog = """
#include <uapi/linux/ptrace.h>

int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={0};
    
    // 获取第 6 个参数地址
    bpf_usdt_readarg(6, ctx, &addr);

    // 从用户态中获取第 6 个参数内容
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    
    bpf_trace_printk("path:%s\\n", path);
    
    return 0;
};
"""

# enable USDT probe from given PID
u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")

# initialize BPF
b = BPF(text=prog, usdt_contexts=[u])

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "ARGS"))

# format output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()

        printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except KeyboardInterrupt:
        exit()
