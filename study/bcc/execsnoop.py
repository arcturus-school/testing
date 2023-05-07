"""
跟踪 exec() 系统调用 --> 创建新进程

sudo python ./execsnoop.py

output:
    PCOMM  PID     PPID    RET ARGS
    sed    8639    8632      0 /usr/bin/sed -n s/^cpu\s//p /proc/stat
    cat    8640    8632      0 /usr/bin/cat /proc/8029/stat
    cat    8642    8632      0 /usr/bin/cat /proc/8098/stat
    cat    8644    8632      0 /usr/bin/cat /proc/8099/stat
"""

from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
from collections import defaultdict
from time import strftime
import argparse
import re
import time
import pwd


def parse_uid(user):
    try:
        result = int(user)
    except ValueError:
        try:
            user_info = pwd.getpwnam(user)
        except KeyError:
            raise argparse.ArgumentTypeError(f"{user!s} is not valid UID or user entry")
        else:
            return user_info.pw_uid
    else:
        return result


# arguments
examples = """
examples:
    ./execsnoop                      # 跟踪所有 exec() 系统调用
    ./execsnoop -x                   # 包括失败的 exec() 调用
    ./execsnoop -T                   # 包括时间戳(HH:MM:SS)
    ./execsnoop -P 181               # 只跟踪父进程 PID 为 181 的新进程
    ./execsnoop -U                   # 包括 UID
    ./execsnoop -u 1000              # 只跟踪 UID 为 1000 的进程
    ./execsnoop -u user              # 获取用户 UID 并仅跟踪该用户的进程
    ./execsnoop -t                   # 包括时间戳
    ./execsnoop -q                   # 在参数周围添加引号
    ./execsnoop -n main              # 只打印包含 "main" 的命令行
    ./execsnoop -l tpkg              # 只打印参数中包含 "tpkg" 的命令行
    ./execsnoop --cgroupmap mappath  # 仅跟踪指定的 cgroups
    ./execsnoop --mntnsmap mappath   # 仅跟踪指定的挂载命名空间
"""

parser = argparse.ArgumentParser(
    description="跟踪 exec() 系统调用",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-T", "--time", action="store_true", help="输出包含时间(HH:MM:SS)")
parser.add_argument("-t", "--timestamp", action="store_true", help="输出包含时间戳")
parser.add_argument("-x", "--fails", action="store_true", help="包含失败的 exec() 调用")
parser.add_argument("--cgroupmap", help="只跟踪 BPF map 中指定的 cgroups")
parser.add_argument("--mntnsmap", help="只跟踪 BPF map 中指定的挂载命名空间")
parser.add_argument("-u", "--uid", type=parse_uid, metavar="USER", help="只跟踪这个 uid")
parser.add_argument("-q", "--quote", action="store_true", help='参数添加 (")')
parser.add_argument("-n", "--name", type=ArgString, help="仅打印命令行中包含指定名称(正则表达式)的命令")
parser.add_argument("-l", "--line", type=ArgString, help="仅打印命令行中的参数包含指定行(正则表达式)的命令")
parser.add_argument("-U", "--print-uid", action="store_true", help="print UID column")
parser.add_argument("--max-args", default="20", help="指定解析和显示的参数的最大数量")
parser.add_argument("-P", "--ppid", help="仅跟踪这个父进程")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128

enum event_type {
    EVENT_ARG, // 参数
    EVENT_RET, // 返回值
};

struct data_t {
    u32 pid;                  // 进程 ID
    u32 ppid;                 // 父进程 ID
    u32 uid;                  // 用户 ID
    char comm[TASK_COMM_LEN]; // 命令名
    enum event_type type;     // 事件类型
    char argv[ARGSIZE];       // 参数
    int retval;               // exec() 返回值
};

BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    
    return 0;
}

// 系统调用开始时执行
int syscall__execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *__argv, const char __user *const __user *__envp) {

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    UID_FILTER

    if (container_should_be_filtered()) {
        return 0;
    }

    // 获取 exec() 调用时的一些信息
    struct data_t data = {};
    struct task_struct *task;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    PPID_FILTER

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    // 提交信息至 perf 缓存
    __submit_arg(ctx, (void *)filename, &data);

    // 跳过第一个参数, 因为是文件名
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0) {
            return 0;
        }
    }

    // 超过参数限制的使用 ... 代替
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);

    return 0;
}

// 系统调用返回时执行
int do_ret_sys_execve(struct pt_regs *ctx) {
    if (container_should_be_filtered()) {
        return 0;
    }

    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    UID_FILTER

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    PPID_FILTER

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

prog = prog.replace("MAXARG", args.max_args)

if args.uid:
    prog = prog.replace("UID_FILTER", f"if (uid != {args.uid}) {{ return 0; }}")
else:
    prog = prog.replace("UID_FILTER", "")

if args.ppid:
    prog = prog.replace("PPID_FILTER", f"if (data.ppid != {args.ppid}) {{ return 0; }}")
else:
    prog = prog.replace("PPID_FILTER", "")

prog = filter_by_containers(args) + prog

if args.ebpf:
    print(prog)

    exit()

# initialize BPF
b = BPF(text=prog)
execve_fnname = b.get_syscall_fnname("execve")  # 获取系统调用名称
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

# header
if args.time:
    print(f"{'TIME': <9}", end="")

if args.timestamp:
    print(f"{'TIME(s)': <8}", end="")

if args.print_uid:
    print(f"{'UID': <6}", end="")

print(f"{'PCOMM':<16} {'PID':<7} {'PPID':<7} {'RET':<3} ARGS")


class EventType:
    EVENT_ARG = 0
    EVENT_RET = 1


start_ts = time.time()
argv = defaultdict(list)


def get_ppid(pid):
    try:
        with open(f"/proc/{pid}/status") as status:
            for line in status:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except IOError:
        pass

    return 0


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    skip = False

    if event.type == EventType.EVENT_ARG:
        # 此时是 syscall__execve 执行, 记录参数即可
        argv[event.pid].append(event.argv)
    elif event.type == EventType.EVENT_RET:
        # 此时是 do_ret_sys_execve 执行, 输出全部信息
        if event.retval != 0 and not args.fails:
            skip = True

        # 只打印指定名称的命令
        if args.name and not re.search(bytes(args.name), event.comm):
            skip = True

        if args.line and not re.search(bytes(args.line), b" ".join(argv[event.pid])):
            skip = True

        # 参数是否加引号
        if args.quote:
            argv[event.pid] = [
                b'"' + arg.replace(b'"', b'\\"') + b'"' for arg in argv[event.pid]
            ]

        if not skip:
            if args.time:
                printb(b"%-9s" % strftime("%H:%M:%S").encode("ascii"), nl="")

            if args.timestamp:
                printb(b"%-8.3f" % (time.time() - start_ts), nl="")

            if args.print_uid:
                printb(b"%-6d" % event.uid, nl="")

            ppid = event.ppid if event.ppid > 0 else get_ppid(event.pid)
            ppid = b"%d" % ppid if ppid > 0 else b"?"
            argv_text = b" ".join(argv[event.pid]).replace(b"\n", b"\\n")

            printb(
                b"%-16s %-7d %-7s %3d %s"
                % (event.comm, event.pid, ppid, event.retval, argv_text)
            )
        try:
            del argv[event.pid]
        except Exception:
            pass


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
