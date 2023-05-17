"""
sudo python ./sync_timing.py

sync
sync

output:
  Tracing for quick sync's... Ctrl-C to end
  At time 0.00 s: multiple syncs detected, last 449 ms ago
"""

from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>

BPF_HASH(last); // 新建一个哈希表

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // 寻找时间戳
    tsp = last.lookup(&key);
    
    if (tsp != NULL) {
        // 计算当前调用距离上次调用时间差
        delta = bpf_ktime_get_ns() - *tsp;
        
        if (delta < 1000000000) {
            // 时间差小于 1s 则输出信息
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        
        last.delete(&key);
    }

    // 更新时间戳
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

event = b.get_syscall_fnname("sync")

print(event)

b.attach_kprobe(event, fn_name="do_trace")

print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0

while True:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()

        if start == 0:
            start = ts

        ts = ts - start

        printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
    except KeyboardInterrupt:
        exit()
