from bcc import BPF
from bcc.utils import printb

prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)

event = b.get_syscall_fnname("clone")  # 获取本系统中系统调用 clone 对应的名称

print(event)  # __x64_sys_clone

b.attach_kprobe(event=event, fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()

    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
