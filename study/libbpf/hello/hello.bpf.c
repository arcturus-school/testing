#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

char LICENSE[] SEC("license") = "GPL";

int PID = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void* ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != PID) return 0;

    bpf_printk("[%d] hello world.\n", pid);

    return 0;
}