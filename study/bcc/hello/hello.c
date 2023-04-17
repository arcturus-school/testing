#include <bcc/libbpf.h>    // bcc 库, 用于加载和运行 eBPF 程序
#include <bpf/bpf.h>       // eBPF 头文件
#include <errno.h>         // 错误码定义
#include <linux/version.h> // Linux 内核版本定义
#include <stdio.h>         // 标准输入输出
#include <stdlib.h>        // 标准库函数, 例如 system() 函数
#include <string.h>        // 字符串操作函数
#include <unistd.h>        // Unix 标准库, 包含 close() 函数

#define DEBUGFS "/sys/kernel/debug/tracing" // 调试文件系统路径

char bpf_log_buf[BPF_LOG_BUF_SIZE]; // eBPF 日志缓冲区

// eBPF 程序代码数组
struct bpf_insn program[] = {
    BPF_MOV64_IMM(BPF_REG_1, 0xa21),                // 将 '!\n' 移动到寄存器 BPF_REG_1 中
    BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -4),  // 将 BPF_REG_1 中的值写入寄存器 BPF_REG_10 的内存中, 偏移量为 -4
    BPF_MOV64_IMM(BPF_REG_1, 0x646c726f),           // 将 'orld' 移动到寄存器 BPF_REG_1 中
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8),  // 将 BPF_REG_1 中的值写入寄存器 BPF_REG_10 的内存中, 偏移量为 -8
    BPF_MOV64_IMM(BPF_REG_1, 0x57202c6f),           // 将 'o, W' 移动到寄存器 BPF_REG_1 中
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -12), // 将 BPF_REG_1 中的值写入寄存器 BPF_REG_10 的内存中, 偏移量为 -12
    BPF_MOV64_IMM(BPF_REG_1, 0x6c6c6548),           // 将 'Hell' 移动到寄存器 BPF_REG_1 中
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -16), // 将 BPF_REG_1 中的值写入寄存器 BPF_REG_10 的内存中, 偏移量为 -16
    BPF_MOV64_IMM(BPF_REG_1, 0),                    // 将 0 移动到寄存器 BPF_REG_1 中
    BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -2),  // 将 BPF_REG_1 中的值写入寄存器 BPF_REG_10 的内存中, 偏移量为 -2
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),           // 将寄存器 BPF_REG_10 的值移动到寄存器 BPF_REG_1 中
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -16),         // 将寄存器 BPF_REG_1 的值减去 16, 并将结果存储回寄存器 BPF_REG_1 中
    BPF_MOV64_IMM(BPF_REG_2, 15),                   // 将 15 移动到寄存器 BPF_REG_2 中
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_trace_printk), // 调用 trace_printk() 函数, 打印到 trace 文件中
    BPF_MOV64_IMM(BPF_REG_0, 0),                                      // 将 0 移动到寄存器 BPF_REG_0 中
    BPF_EXIT_INSN(),                                                  // 退出 eBPF 程序
};

int main() {
    int prog_fd, probe_fd;

    size_t insns_cnt = sizeof(program) / sizeof(struct bpf_insn); // eBPF 程序指令数量

    // 加载 eBPF 程序, 将其附加到一个 kprobe 上
    prog_fd = bpf_load_program(BPF_PROG_TYPE_KPROBE, program, insns_cnt, "GPL", LINUX_VERSION_CODE, bpf_log_buf, BPF_LOG_BUF_SIZE);

    if (prog_fd < 0) {
        printf("ERROR: failed to load program '%s'\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // 将 eBPF 程序附加到内核函数 __x64_sys_exit 的入口点处, 从而允许捕获该函数的调用参数和返回值等信息
    probe_fd = bpf_attach_kprobe(prog_fd, BPF_PROBE_ENTRY, "hello_world", "__x64_sys_exit", 0, 0);

    if (probe_fd < 0) {
        printf("ERROR: failed to attach probe '%s'\n", strerror(errno));
        return EXIT_FAILURE;
    }

    system("cat " DEBUGFS "/trace_pipe"); // 读取内核跟踪信息

    close(probe_fd);

    bpf_detach_kprobe("hello_world"); // 分离一个已附加的 kprobe

    close(prog_fd);

    return EXIT_SUCCESS;
}