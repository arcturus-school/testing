"""
跟踪 strlen() 的调用情况

sudo python ./strlen_count.py
"""

from bcc import BPF
from bcc.utils import printb
from time import sleep

prog = """
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};

BPF_HASH(counts, struct key_t); // 以结构体为键的哈希表

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    // 从用户态读取字符串到 key
    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));

    // 哈希表中寻找或初始化字符串个数
    val = counts.lookup_or_try_init(&key, &zero);
    
    if (val) {
      (*val)++;
    }
    
    return 0;
};
"""

# load BPF program
b = BPF(text=prog)
b.attach_uprobe(name="c", sym="strlen", fn_name="count")

# header
print("Tracing strlen()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass


counts = b.get_table("counts")  # 获取哈希表表

# print output
print("%10s %s" % ("COUNT", "STRING"))

for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    printb(b'%10d "%s"' % (v.value, k.c))
