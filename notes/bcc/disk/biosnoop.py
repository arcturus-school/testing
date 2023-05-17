"""
跟踪磁盘 I/O 延迟(从设备发出到完成的时间)

sudo python ./biosnoop.py
"""

from bcc import BPF
import argparse
import os

# arguments
examples = """examples:
    ./biosnoop           # 跟踪所有块设备的 I/O
    ./biosnoop -Q        # 包括操作系统排队时间
    ./biosnoop -d sdc    # 仅跟踪 sdc 设备
    ./biosnoop -P        # 显示块设备 I/O 模式
"""

parser = argparse.ArgumentParser(
    description="跟踪块设备 I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)

parser.add_argument("-Q", "--queue", action="store_true", help="包括系统排队时间")
parser.add_argument("-d", "--disk", type=str, help="仅跟踪此块设备")
parser.add_argument("-P", "--pattern", action="store_true", help="显示块 I/O 模式(顺序或随机)")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()
debug = False

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
"""

if args.pattern:
    prog += "#define INCLUDE_PATTERN\n"

prog += """
// 用于保存每个请求的时间戳和数据长度
struct start_req_t {
    u64 ts;
    u64 data_len;
};

struct val_t {
    u64 ts;                    // 时间戳
    u32 pid;                   // 进程名 ID
    char name[TASK_COMM_LEN];  // 进程/指令名
};

#ifdef INCLUDE_PATTERN

struct sector_key_t {
    u32 dev_major; // 主设备号
    u32 dev_minor; // 次设备号
};

enum bio_pattern {
    UNKNOWN,
    SEQUENTIAL, // 顺序访问
    RANDOM,     // 随机访问
};

#endif

struct data_t {
    u32 pid;
    u64 rwflag;                     // 读写标志
    u64 delta;                      // 读写操作时间
    u64 qdelta;                     // 等待时间 
    u64 sector;                     // 起始扇区号
    u64 len;                        // 数据长度
#ifdef INCLUDE_PATTERN
    enum bio_pattern pattern;       // 访问模式
#endif
    u64 ts;                         // 时间戳
    char disk_name[DISK_NAME_LEN];  // 设备名
    char name[TASK_COMM_LEN];       // 进程/指令名
};

#ifdef INCLUDE_PATTERN
// 保存上一次操作的扇区
BPF_HASH(last_sectors, struct sector_key_t, u64);
#endif

// 记录请求开始
BPF_HASH(start, struct request *, struct start_req_t);

// 保存请求的进程信息
BPF_HASH(infobyreq, struct request *, struct val_t);

BPF_PERF_OUTPUT(events);

int trace_pid_start(struct pt_regs *ctx, struct request *req) {
    // 设备过滤
    DISK_FILTER

    struct val_t val = {};
    u64 ts;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        
        if (##QUEUE##) {
            // 更新时间戳
            val.ts = bpf_ktime_get_ns();
        }
        
        infobyreq.update(&req, &val);
    }

    return 0;
}

// I/O 操作起始
int trace_req_start(struct pt_regs *ctx, struct request *req) {
    DISK_FILTER

    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };

    start.update(&req, &start_req);
    
    return 0;
}

// I/O 操作完成
int trace_req_completion(struct pt_regs *ctx, struct request *req) {
    struct start_req_t *startp;
    struct val_t *valp;
    struct data_t data = {};
    struct gendisk *rq_disk;
    u64 ts;

    // 计算耗时
    startp = start.lookup(&req);
    
    if (startp == 0) {
        return 0;
    }
    
    ts = bpf_ktime_get_ns();
    rq_disk = req->__RQ_DISK__;
    data.delta = ts - startp->ts;
    data.ts = ts / 1000;
    data.qdelta = 0;
    data.len = startp->data_len;

    valp = infobyreq.lookup(&req);
    
    if (valp == 0) {
        // 当前操作进程/指令未知
        data.name[0] = '?';
        data.name[1] = 0;
    } else {
        if (##QUEUE##) {
            data.qdelta = startp->ts - valp->ts;
        }
        
        data.pid = valp->pid;
        data.sector = req->__sector;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
        bpf_probe_read_kernel(&data.disk_name, sizeof(data.disk_name), rq_disk->disk_name);
    }

#ifdef INCLUDE_PATTERN
    data.pattern = UNKNOWN;

    u64 *sector, last_sector;

    struct sector_key_t sector_key = {
        .dev_major = rq_disk->major,
        .dev_minor = rq_disk->first_minor
    };

    sector = last_sectors.lookup(&sector_key);
    
    // 根据上一次扇区确定访问模式
    if (sector != 0) {
        data.pattern = req->__sector == *sector ? SEQUENTIAL : RANDOM;
    }

    last_sector = req->__sector + data.len / 512;
    last_sectors.update(&sector_key, &last_sector);
#endif

#ifdef REQ_WRITE
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif

    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&req);
    infobyreq.delete(&req);

    return 0;
}
"""

if args.queue:
    prog = prog.replace("##QUEUE##", "1")
else:
    prog = prog.replace("##QUEUE##", "0")

if BPF.kernel_struct_has_field(b"request", b"rq_disk") == 1:
    prog = prog.replace("__RQ_DISK__", "rq_disk")
else:
    prog = prog.replace("__RQ_DISK__", "q->disk")

if args.disk is not None:
    disk_path = os.path.join("/dev", args.disk)

    if not os.path.exists(disk_path):
        # 未找到指定设备
        print("no such disk '%s'" % args.disk)
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
    
    if (!(disk->major == {major} && disk->first_minor == {minor})) {{
        return 0;
    }}
    """

    prog = prog.replace("DISK_FILTER", disk_filter_str)
else:
    prog = prog.replace("DISK_FILTER", "")

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=prog)

if BPF.get_kprobe_functions(b"__blk_account_io_start"):
    b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
else:
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")

if BPF.get_kprobe_functions(b"blk_start_request"):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")

b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")

if BPF.get_kprobe_functions(b"__blk_account_io_done"):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")

# header
print(
    "%-11s %-14s %-7s %-9s %-1s %-10s %-7s"
    % ("TIME(s)", "COMM", "PID", "DISK", "T", "SECTOR", "BYTES"),
    end="",
)

if args.pattern:
    print("P ", end="")

if args.queue:
    print(f"{'QUE(ms)':<7} ", end="")

print(f"{'LAT(ms)':<7}")

rwflg = ""
pattern = ""
start_ts = 0
prev_ts = 0
delta = 0

P_SEQUENTIAL = 1
P_RANDOM = 2


# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    global start_ts

    if start_ts == 0:
        start_ts = event.ts

    if event.rwflag == 1:
        rwflg = "W"
    else:
        rwflg = "R"

    delta = float(event.ts) - start_ts

    disk_name = event.disk_name.decode("utf-8", "replace")

    if not disk_name:
        disk_name = "<unknown>"

    print(
        "%-11.6f %-14.14s %-7s %-9s %-1s %-10s %-7s"
        % (
            delta / 1000000,
            event.name.decode("utf-8", "replace"),
            event.pid,
            disk_name,
            rwflg,
            event.sector,
            event.len,
        ),
        end="",
    )

    if args.pattern:
        if event.pattern == P_SEQUENTIAL:
            pattern = "S"
        elif event.pattern == P_RANDOM:
            pattern = "R"
        else:
            pattern = "?"

        print(f"{pattern:<1} ", end="")

    if args.queue:
        print(f"{float(event.qdelta) / 1000000:7.2f} ", end="")

    print(f"{float(event.delta) / 1000000:7.2f}")


# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
