from bcc import BPF

# BPF program
program = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# Load BPF program
b = BPF(text=program)

# Attach hello() function to sys_exit tracepoint
b.attach_kprobe(event=b"__x64_sys_exit", fn_name=b"hello")

# Run forever
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
    except KeyboardInterrupt:
        exit()
