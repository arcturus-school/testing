#include "./dist/hello.skel.h"
#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char** argv) {
    struct hello_bpf* skel;
    int               err;

    // 捕获 libbpf 调试日志
    libbpf_set_print(libbpf_print_fn);

    // 打开 BPF 应用程序
    skel = hello_bpf__open();

    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 加载并验证 BPF 应用程序
    err = hello_bpf__load(skel);

    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        hello_bpf__destroy(skel);
        return -err;
    }

    // 将 handle_tp 附加到内核跟踪点上
    err = hello_bpf__attach(skel);

    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        hello_bpf__destroy(skel);
        return -err;
    }

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.\n");

    // 触发 sys_enter_write
    fprintf(stderr, ".\n");

    hello_bpf__destroy(skel);

    return -err;
}