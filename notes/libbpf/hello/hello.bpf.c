#include "../common/vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void* ctx) {
    bpf_printk("hello world.\n");

    return 0;
}