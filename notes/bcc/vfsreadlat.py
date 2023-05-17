"""
跟踪 vfs_read 系统调用耗时

sudo ./vfsreadlat.py 5 1

Tracing... Hit Ctrl-C to end.
^C     
    usecs           : count     distribution
    0 -> 1          : 353      |****************************************|
    2 -> 3          : 161      |******************                      |
    4 -> 7          : 145      |****************                        |
    8 -> 15         : 53       |******                                  |
    16 -> 31        : 35       |***                                     |
    32 -> 63        : 15       |*                                       |
    64 -> 127       : 17       |*                                       |
"""

from bcc import BPF
from time import sleep
from sys import argv


def usage():
    print("USAGE: %s [interval [count]]" % argv[0])
    exit()


# arguments
interval = 5
count = -1

if len(argv) > 1:
    try:
        interval = int(argv[1])

        # 跟踪间隔
        if interval == 0:
            raise

        # 跟踪次数
        if len(argv) > 2:
            count = int(argv[2])
    except:
        usage()

prog = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32); // 哈希表
BPF_HISTOGRAM(dist);  // 直方图

int do_entry(struct pt_regs *ctx) {
	u32 pid;
	u64 ts;

	pid = bpf_get_current_pid_tgid(); // 进程 ID
	ts = bpf_ktime_get_ns();          // 当前时间戳
	start.update(&pid, &ts);          // 存储当前时间戳, pid 作为建
	return 0;
}

int do_return(struct pt_regs *ctx) {
	u32 pid;
	u64 *tsp, delta;

	pid = bpf_get_current_pid_tgid();
	tsp = start.lookup(&pid);         // 搜索某个上次进程执行时间

	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		dist.increment(bpf_log2l(delta / 1000)); // 将两次执行的时间差存入直方图
		start.delete(&pid);
	}

	return 0;
}
"""

# load BPF program
b = BPF(text=prog)

# vfs_read 系统调用开始时调用 do_entry
b.attach_kprobe(event="vfs_read", fn_name="do_entry")

# vfs_read 系统调用结束时调用 do_return
b.attach_kretprobe(event="vfs_read", fn_name="do_return")

# header
print("Tracing... Hit Ctrl-C to end.")

# output
loop = 0  # 当前循环次数
do_exit = False  # 是否退出循环

while True:
    if count > 0:
        loop += 1

        if loop > count:
            exit()

    try:
        sleep(interval)
    except KeyboardInterrupt:
        pass
        do_exit = True

    b["dist"].print_log2_hist("usecs")
    b["dist"].clear()

    if do_exit:
        exit()
