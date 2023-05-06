"""
使用 perf 缓冲区代替 bpf_trace_printk 传输消息

sudo ./hello_perf_output.py

output:
    TIME(s)       COMM    PID    MESSAGE
    0.000000000   node    1426   Hello, perf_output!
    0.012263100   node    1426   Hello, perf_output!
    0.019888800   node    1426   Hello, perf_output!
"""

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

// 自定义结构体
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events); // 新建 perf 缓冲区

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();  // 进程 ID
    data.ts = bpf_ktime_get_ns();  // 当前时间戳
    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // 进程名称

    // 加入缓冲区
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0


def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)

    if start == 0:
        start = event.ts

    # 计算上一次输出到本次输出的时间差
    time_s = (float(event.ts - start)) / 1000000000

    printb(
        b"%-18.9f %-16s %-6d %s"
        % (time_s, event.comm, event.pid, b"Hello, perf_output!")
    )


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
