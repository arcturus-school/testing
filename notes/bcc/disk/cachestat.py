"""
跟踪缓存函数调用情况

sudo python ./cachestat.py

output:
    HITS     MISSES   DIRTIES  HITRATIO BUFFERS_MB   CACHED_MB 
    7276     0        0        100.00 %          136 1020      
    8040     0        0        100.00 %          136 1020      
    30       0        5        100.00 %          136 1020      
    33       0        0        100.00 %          136 1020      
    33       0        0        100.00 %          136 1020      
    7275     0        0        100.00 %          136 1020 
"""

from bcc import BPF
from time import sleep, strftime
import argparse
import signal


# signal handler
def signal_ignore(signal, frame):
    print()


# 从 /proc/meminfo 收集数据的函数, 返回 dictionary 以便更快地查找这两个值
def get_meminfo():
    result = dict()

    for line in open("/proc/meminfo"):
        k = line.split(":", 3)
        v = k[1].split()
        result[k[0]] = int(v[0])

    return result


mpa = 0
mbd = 0
apcl = 0
apd = 0
total = 0
misses = 0
hits = 0
debug = False

# arguments
parser = argparse.ArgumentParser(
    description="记录内核缓存函数调用次数",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("-T", "--timestamp", action="store_true", help="输出包含时间戳")
parser.add_argument("interval", nargs="?", default=1, help="输出时间间隔, 秒")
parser.add_argument("count", nargs="?", default=-1, help="输出次数")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)

args = parser.parse_args()

count = int(args.count)
tstamp = args.timestamp
interval = int(args.interval)

# define BPF program
prog = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 nf;
};

enum {
    NF_APCL,
    NF_MPA,
    NF_MBD,
    NF_APD,
};

BPF_HASH(counts, struct key_t);

static int __do_count(void *ctx, u32 nf) {
    struct key_t key = {};
    u64 ip;

    key.nf = nf;
    counts.atomic_increment(key);
    return 0;
}

// 新增的
int do_count_apcl(struct pt_regs *ctx) {
    return __do_count(ctx, NF_APCL);
}

// 标记为访问的
int do_count_mpa(struct pt_regs *ctx) {
    return __do_count(ctx, NF_MPA);
}

// 标记为脏的
int do_count_mbd(struct pt_regs *ctx) {
    return __do_count(ctx, NF_MBD);
}

// 统计为脏的
int do_count_apd(struct pt_regs *ctx) {
    return __do_count(ctx, NF_APD);
}

int do_count_apd_tp(void *ctx) {
    return __do_count(ctx, NF_APD);
}
"""

if debug or args.ebpf:
    print(prog)

    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=prog)

# 新增的页面
b.attach_kprobe(event="add_to_page_cache_lru", fn_name="do_count_apcl")

# 标记为访问的
b.attach_kprobe(event="mark_page_accessed", fn_name="do_count_mpa")


if BPF.get_kprobe_functions(b"folio_account_dirtied"):
    b.attach_kprobe(event="folio_account_dirtied", fn_name="do_count_apd")
elif BPF.get_kprobe_functions(b"account_page_dirtied"):
    # 统计为脏的页面
    b.attach_kprobe(event="account_page_dirtied", fn_name="do_count_apd")
elif BPF.tracepoint_exists("writeback", "writeback_dirty_folio"):
    b.attach_tracepoint(tp="writeback:writeback_dirty_folio", fn_name="do_count_apd_tp")
elif BPF.tracepoint_exists("writeback", "writeback_dirty_page"):
    b.attach_tracepoint(tp="writeback:writeback_dirty_page", fn_name="do_count_apd_tp")
else:
    raise Exception(
        "Failed to attach kprobe folio_account_dirtied or account_page_dirtied or any tracepoint"
    )


# 标记为脏的
b.attach_kprobe(event="mark_buffer_dirty", fn_name="do_count_mbd")

# header
if tstamp:
    print(f"{'TIME':<8} ", end="")

print(
    f"{'HITS':<8} {'MISSES':<8} {'DIRTIES':<8} {'HITRATIO':<8} {'BUFFERS_MB':<12} {'CACHED_MB':<10}"
)

loop = 0
exiting = False

while True:
    if count > 0:
        loop += 1

        if loop > count:
            exit()

    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = True
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)

    counts = b["counts"]

    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        if k.nf == 0:    # NF_APCL
            apcl = max(0, v.value)
        elif k.nf == 1:  # NF_MPA
            mpa = max(0, v.value)
        elif k.nf == 2:  # NF_MBD
            mbd = max(0, v.value)
        elif k.nf == 3:  # NF_APD
            apd = max(0, v.value)

    total = mpa - mbd  # 访问 - 脏 = 总数
    misses = apcl - apd  # 新增 - 脏 = 缺失

    if misses < 0:
        misses = 0

    if total < 0:
        total = 0

    # 总数 - 缺失 = 命中数
    hits = total - misses

    if hits < 0:
        misses = total
        hits = 0

    # 计算命中率
    ratio = 0

    if total > 0:
        ratio = float(hits) / total

    if debug:
        print(mpa, mbd, apcl, apd, total, misses, hits)

    counts.clear()

    # Get memory info
    mem = get_meminfo()
    cached = int(mem["Cached"]) / 1024
    buff = int(mem["Buffers"]) / 1024

    if tstamp:
        print("{strftime('%H:%M:%S'):<8} ", end="")

    print(
        f"{hits:<8} {misses:<8} {mbd:<8} {100 * ratio:<7.2f}% {buff:<12.0f} {cached:<10.0f}"
    )

    mpa = mbd = apcl = apd = total = misses = hits = cached = buff = 0

    if exiting:
        exit()
