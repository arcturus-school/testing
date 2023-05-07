"""
以直方图的形式显示调度程序运行队列延迟

sudo python ./runqlat.py

output:
    Tracing run queue latency... Hit Ctrl-C to end.
    ^C    
    usecs(延迟) : count   distribution
    0 -> 1      : 58     |****                                    |
    2 -> 3      : 109    |********                                |
    4 -> 7      : 340    |***************************             |
    8 -> 15     : 494    |****************************************|
    16 -> 31    : 291    |***********************                 |
    32 -> 63    : 17     |*                                       |
    64 -> 127   : 17     |*                                       |
    128 -> 255  : 21     |*                                       |
"""

from bcc import BPF
from time import sleep, strftime
import argparse

# arguments
examples = """
examples:
    ./runqlat            # 以直方图显示运行队列的延迟
    ./runqlat 1 10       # 隔 1 秒打印一次, 共 10 次
    ./runqlat -mT 1      # 毫秒级别, 带时间戳
    ./runqlat -P         # 每个进程单独打印
    ./runqlat -p 185     # 仅打印进程号 185 的信息
"""
parser = argparse.ArgumentParser(
    description="以直方图的形式显示调度程序运行队列延迟",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-T", "--timestamp", action="store_true", help="输出带有时间戳")
parser.add_argument("-m", "--milliseconds", action="store_true", help="毫秒级的直方图")
parser.add_argument("-P", "--pids", action="store_true", help="每个进程单独打印直方图")
parser.add_argument("--pidnss", action="store_true", help="每个进程命名空间单独打印直方图")
parser.add_argument("-L", "--tids", action="store_true", help="每个线程单独打印直方图")
parser.add_argument("-p", "--pid", help="仅跟踪某个进程")
parser.add_argument("interval", nargs="?", default=99999999, help="输出时间间隔")
parser.add_argument("count", nargs="?", default=99999999, help="输出数量")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

countdown = int(args.count)

debug = False

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/init_task.h>

typedef struct pid_key {
    u32 id;
    u64 slot;
} pid_key_t;

typedef struct pidns_key {
    u32 id;
    u64 slot;
} pidns_key_t;

BPF_HASH(start, u32);

// 将放置进程命名空间或进程的哈希表
STORAGE

// 跟踪进程的启动时间
static int trace_enqueue(u32 tgid, u32 pid) {
    if (FILTER || pid == 0)
        return 0;
    
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    
    return 0;
}

// 获取 pid 命名空间
static __always_inline unsigned int pid_namespace(struct task_struct *task) {

#ifdef INIT_PID_LINK
    struct pid_link pids;
    unsigned int level;
    struct upid upid;
    struct ns_common ns;

    // 使用 pids[] 获取 pid 命名空间
    bpf_probe_read_kernel(&pids, sizeof(pids), &task->pids[PIDTYPE_PID]);
    bpf_probe_read_kernel(&level, sizeof(level), &pids.pid->level);
    bpf_probe_read_kernel(&upid, sizeof(upid), &pids.pid->numbers[level]);
    bpf_probe_read_kernel(&ns, sizeof(ns), &upid.ns->ns);

    return ns.inum;
#else
    struct pid *pid;
    unsigned int level;
    struct upid upid;
    struct ns_common ns;

    // 使用 thread_pid 获取 pid 命名空间
    bpf_probe_read_kernel(&pid, sizeof(pid), &task->thread_pid);
    bpf_probe_read_kernel(&level, sizeof(level), &pid->level);
    bpf_probe_read_kernel(&upid, sizeof(upid), &pid->numbers[level]);
    bpf_probe_read_kernel(&ns, sizeof(ns), &upid.ns->ns);

    return ns.inum; // 命名空间标识符
#endif
}
"""

prog_kprobe = """
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p) {
    return trace_enqueue(p->tgid, p->pid);
}

int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p, int wake_flags) {
    return trace_enqueue(p->tgid, p->pid);
}

// 计算延迟
int trace_run(struct pt_regs *ctx, struct task_struct *prev) {
    u32 pid, tgid;

    // 进程在队列中
    if (prev->STATE_FIELD == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        
        // 进程不符合过滤条件或进程的 pid 不为 0, 则更新启动时间
        if (!(FILTER || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    
    // 进程符合过滤条件或 pid 为 0
    if (FILTER || pid == 0)
        return 0;
    
    u64 *tsp, delta;

    // 获取时间戳并计算延迟
    tsp = start.lookup(&pid);
    
    if (tsp == 0)
        return 0;

    delta = bpf_ktime_get_ns() - *tsp;
    
    FACTOR

    STORE

    start.delete(&pid);
    
    return 0;
}
"""

# 支持 raw tracepoint 时使用
prog_raw_tp = """
RAW_TRACEPOINT_PROBE(sched_wakeup) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_wakeup_new) {
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

RAW_TRACEPOINT_PROBE(sched_switch) {
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;

    if (prev->STATE_FIELD == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        
        if (!(FILTER || pid == 0)) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = next->tgid;
    pid = next->pid;
    
    if (FILTER || pid == 0)
        return 0;
    
    u64 *tsp, delta;

    tsp = start.lookup(&pid);
    
    if (tsp == 0) {
        return 0;
    }
    
    delta = bpf_ktime_get_ns() - *tsp;
    
    FACTOR

    STORE

    start.delete(&pid);
    
    return 0;
}
"""

# 是否支持原始跟踪点(https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracepoints)
is_support_raw_tp = BPF.support_raw_tracepoint()

if is_support_raw_tp:
    prog += prog_raw_tp
else:
    prog += prog_kprobe

# code substitutions
if BPF.kernel_struct_has_field(b"task_struct", b"__state") == 1:
    prog = prog.replace("STATE_FIELD", "__state")
else:
    prog = prog.replace("STATE_FIELD", "state")

if args.pid:
    prog = prog.replace("FILTER", f"tgid != {args.pid}")
else:
    prog = prog.replace("FILTER", "0")

if args.milliseconds:
    prog = prog.replace("FACTOR", "delta /= 1000000;")
    label = "msecs"
else:
    prog = prog.replace("FACTOR", "delta /= 1000;")
    label = "usecs"

if args.pids or args.tids:
    section = "pid"
    pid = "tgid"

    if args.tids:
        pid = "pid"
        section = "tid"

    prog = prog.replace("STORAGE", "BPF_HISTOGRAM(dist, pid_key_t);")
    prog = prog.replace(
        "STORE",
        f"pid_key_t key = {{.id = {pid}, .slot = bpf_log2l(delta)}}; dist.increment(key);",
    )
elif args.pidnss:
    section = "pidns"
    prog = prog.replace("STORAGE", "BPF_HISTOGRAM(dist, pidns_key_t);")
    prog = prog.replace(
        "STORE",
        "pidns_key_t key = {.id = pid_namespace(prev), .slot = bpf_log2l(delta)}; dist.atomic_increment(key);",
    )
else:
    section = ""
    prog = prog.replace("STORAGE", "BPF_HISTOGRAM(dist);")
    prog = prog.replace("STORE", "dist.atomic_increment(bpf_log2l(delta));")

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=prog)

if not is_support_raw_tp:
    b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
    b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
    b.attach_kprobe(
        event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$",
        fn_name="trace_run",
    )

print("Tracing run queue latency... Hit Ctrl-C to end.")

# output
exiting = 0 if args.interval else 1
dist = b.get_table("dist")

while True:
    try:
        # 模拟任务调度
        sleep(int(args.interval))
    except KeyboardInterrupt:
        # ctrl + c 中断
        exiting = True

    if args.timestamp:
        print(f"{strftime('%H:%M:%S'):<8}\n", end="")

    dist.print_log2_hist(label, section, section_print_fn=int)
    dist.clear()

    countdown -= 1  # 输出次数

    if exiting or countdown == 0:
        exit()
