"""
统计每个任务切换事件的次数

sudo ./task_switch.py

output:
    task_switch[    0->10603]=2
    task_switch[  662->    0]=4
    task_switch[  292->    0]=4
    task_switch[  809->    0]=1
    task_switch[  666->    0]=6
    task_switch[    0->  101]=1
    task_switch[  139->    0]=1
    task_switch[    0->10598]=3
    ...
"""

from bcc import BPF
from time import sleep

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
    u32 curr_pid;
};

BPF_HASH(stats, struct key_t, u64, 1024);

int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.curr_pid = bpf_get_current_pid_tgid(); // 当前进程号
    key.prev_pid = prev->pid;                  // 前一个进程号

    val = stats.lookup_or_try_init(&key, &zero);
    
    if (val) {
      (*val)++;
    }
    
    return 0;
}
"""


b = BPF(text=prog)
b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

# generate many schedule events
for i in range(0, 100):
    sleep(0.01)

for k, v in b["stats"].items():
    print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))
