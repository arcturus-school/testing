"""
跟踪磁盘 I/O 延迟(从设备发出到完成的时间)

sudo python ./biolatency.py

output:
    Tracing block device I/O... Hit Ctrl-C to end.
    ^C     
    usecs         : count  distribution
    0 -> 1        : 0     |                                        |
    2 -> 3        : 0     |                                        |
    4 -> 7        : 0     |                                        |
    8 -> 15       : 0     |                                        |
    16 -> 31      : 0     |                                        |
    32 -> 63      : 0     |                                        |
    64 -> 127     : 1     |**********                              |
    128 -> 255    : 0     |                                        |
    256 -> 511    : 1     |**********                              |
    512 -> 1023   : 0     |                                        |
    1024 -> 2047  : 4     |****************************************|
    2048 -> 4095  : 0     |                                        |
    4096 -> 8191  : 2     |********************                    |
"""

from bcc import BPF
from time import sleep, strftime
import argparse
import os

# arguments
examples = """
examples:
    ./biolatency         # 以直方图形式总结块 I/O 延迟
    ./biolatency 1 10    # 打印 1 秒内信息, 共 10 次
    ./biolatency -mT 1   # 以毫秒为单位显示时间戳, 每秒总结 1 次
    ./biolatency -Q      # I/O 时间中包括操作系统的排队时间
    ./biolatency -D      # 每个磁盘设备分开显示
    ./biolatency -F      # 将 I/O 标志单独显示
    ./biolatency -j      # 打印字典
    ./biolatency -e      # 显示更多信息(总数、平均值)
    ./biolatency -d sdc  # 仅跟踪 sdc 设备
"""

parser = argparse.ArgumentParser(
    description="以直方图的形式显示块设备 I/O 延迟",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-T", "--timestamp", action="store_true", help="输出包含时间戳")
parser.add_argument("-Q", "--queued", action="store_true", help="I/O 时间中包括操作系统的排队时间")
parser.add_argument("-m", "--milliseconds", action="store_true", help="直方图时间以毫秒为单位")
parser.add_argument("-D", "--disks", action="store_true", help="每个设备单独打印直方图")
parser.add_argument("-F", "--flags", action="store_true", help="每个 I/O 标志单独打印直方图")
parser.add_argument("-e", "--extension", action="store_true", help="显示更多信息(总数、平均值)")
parser.add_argument("interval", nargs="?", default=99999999, help="输出间隔(秒)")
parser.add_argument("count", nargs="?", default=99999999, help="输出次数")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
parser.add_argument("-j", "--json", action="store_true", help="以 json 形式输出")
parser.add_argument("-d", "--disk", type=str, help="仅跟踪当前磁盘设备")

args = parser.parse_args()

countdown = int(args.count)

debug = False

if args.flags and args.disks:
    print("ERROR: -D 与 -F 不能同时使用")
    exit()

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN]; // 设备名
    u64 slot;                 // 延迟信息
} disk_key_t;

typedef struct flag_key {
    u64 flags;
    u64 slot;
} flag_key_t;

typedef struct ext_val {
    u64 total;
    u64 count;
} ext_val_t;

BPF_HASH(start, struct request *);

STORAGE

int trace_req_start(struct pt_regs *ctx, struct request *req) {
    DISK_FILTER

    // 记录请求开始时间
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

int trace_req_done(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;

    // 计算延迟
    tsp = start.lookup(&req);
    
    if (tsp == 0) {
        return 0;
    }
    
    delta = bpf_ktime_get_ns() - *tsp;

    FACTOR

    // 是否存储为直方图
    STORE

    start.delete(&req);
    
    return 0;
}
"""

# code substitutions
if args.milliseconds:
    prog = prog.replace("FACTOR", "delta /= 1000000;")
    label = "msecs"
else:
    prog = prog.replace("FACTOR", "delta /= 1000;")
    label = "usecs"

storage_str = ""
store_str = ""

if args.disks:
    storage_str += "BPF_HISTOGRAM(dist, disk_key_t);"

    disks_str = """
    disk_key_t key = {
        .slot = bpf_log2l(delta)
    };

    void *__tmp = (void *)req->__RQ_DISK__->disk_name;
    bpf_probe_read(&key.disk, sizeof(key.disk), __tmp);
    
    dist.atomic_increment(key);
    """

    if BPF.kernel_struct_has_field(b"request", b"rq_disk") == 1:
        store_str += disks_str.replace("__RQ_DISK__", "rq_disk")
    else:
        store_str += disks_str.replace("__RQ_DISK__", "q->disk")
elif args.flags:
    storage_str += "BPF_HISTOGRAM(dist, flag_key_t);"

    store_str += """
    flag_key_t key = {
        .slot = bpf_log2l(delta)
    };

    key.flags = req->cmd_flags;
    
    dist.atomic_increment(key);
    """
else:
    storage_str += "BPF_HISTOGRAM(dist);"
    store_str += "dist.atomic_increment(bpf_log2l(delta));"

if args.disk is not None:
    disk_path = os.path.join("/dev", args.disk)

    if not os.path.exists(disk_path):
        print(f"no such disk '{args.disk}'")
        exit(1)

    stat_info = os.stat(disk_path)
    major = os.major(stat_info.st_rdev)
    minor = os.minor(stat_info.st_rdev)

    disk_field_str = ""

    if BPF.kernel_struct_has_field(b"request", b"rq_disk") == 1:
        disk_field_str = "req->rq_disk"
    else:
        disk_field_str = "req->q->disk"

    disk_filter_str = f"""
    struct gendisk *disk = {disk_field_str};
    
    // 过滤磁盘设备
    if (!(disk->major == {major} && disk->first_minor == {minor})) {{
        return 0;
    }}
    """

    prog = prog.replace("DISK_FILTER", disk_filter_str)
else:
    prog = prog.replace("DISK_FILTER", "")

if args.extension:
    storage_str += "BPF_ARRAY(extension, ext_val_t, 1);"

    store_str += """
    u32 index = 0;
    ext_val_t *ext_val = extension.lookup(&index);
    
    if (ext_val) {
        lock_xadd(&ext_val->total, delta);
        lock_xadd(&ext_val->count, 1);
    }
    """

prog = prog.replace("STORAGE", storage_str)
prog = prog.replace("STORE", store_str)

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=prog)

if args.queued:
    if BPF.get_kprobe_functions(b"__blk_account_io_start"):
        b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_req_start")
    else:
        b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
else:
    if BPF.get_kprobe_functions(b"blk_start_request"):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")

    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

if BPF.get_kprobe_functions(b"__blk_account_io_done"):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_done")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")

if not args.json:
    print("Tracing block device I/O... Hit Ctrl-C to end.")


def disk_print(s):
    disk = s.decode("utf-8", "replace")

    if not disk:
        disk = "<unknown>"

    return disk


# 标志位 -> 操作
req_opf = {
    0: "Read",
    1: "Write",
    2: "Flush",
    3: "Discard",
    5: "SecureErase",
    6: "ZoneReset",
    7: "WriteSame",
    9: "WriteZeros",
}

REQ_OP_BITS = 8
REQ_OP_MASK = (1 << REQ_OP_BITS) - 1
REQ_SYNC = 1 << (REQ_OP_BITS + 3)
REQ_META = 1 << (REQ_OP_BITS + 4)
REQ_PRIO = 1 << (REQ_OP_BITS + 5)
REQ_NOMERGE = 1 << (REQ_OP_BITS + 6)
REQ_IDLE = 1 << (REQ_OP_BITS + 7)
REQ_FUA = 1 << (REQ_OP_BITS + 9)
REQ_RAHEAD = 1 << (REQ_OP_BITS + 11)
REQ_BACKGROUND = 1 << (REQ_OP_BITS + 12)
REQ_NOWAIT = 1 << (REQ_OP_BITS + 13)


def flags_print(flags):
    desc = ""

    if flags & REQ_OP_MASK in req_opf:
        desc = req_opf[flags & REQ_OP_MASK]
    else:
        desc = "Unknown"

    if flags & REQ_SYNC:
        desc = f"Sync-{desc}"

    if flags & REQ_META:
        desc = f"Metadata-{desc}"

    if flags & REQ_FUA:
        desc = f"ForcedUnitAccess-{desc}"

    if flags & REQ_PRIO:
        desc = f"Priority-{desc}"

    if flags & REQ_NOMERGE:
        desc = f"NoMerge-{desc}"

    if flags & REQ_IDLE:
        desc = f"Idle-{desc}"

    if flags & REQ_RAHEAD:
        desc = f"ReadAhead-{desc}"

    if flags & REQ_BACKGROUND:
        desc = f"Background-{desc}"

    if flags & REQ_NOWAIT:
        desc = f"NoWait-{desc}"

    return desc


# output
exiting = False if args.interval else True
dist = b.get_table("dist")

if args.extension:
    extension = b.get_table("extension")

while True:
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = True

    if args.json:
        if args.timestamp:
            print(f"{strftime('%H:%M:%S'):<8}\n", end="")

        if args.flags:
            dist.print_json_hist(label, "flags", flags_print)
        else:
            dist.print_json_hist(label, "disk", disk_print)

    else:
        if args.timestamp:
            print(f"{strftime('%H:%M:%S'):<8}\n", end="")

        if args.flags:
            dist.print_log2_hist(label, "flags", flags_print)
        else:
            dist.print_log2_hist(label, "disk", disk_print)

        if args.extension:
            total = extension[0].total
            count = extension[0].count

            if count > 0:
                print(
                    f"\navg = {total / count} {label}, total: {total} {label}, count: {count}\n"
                )

            extension.clear()

    dist.clear()

    countdown -= 1

    if exiting or countdown == 0:
        exit()
