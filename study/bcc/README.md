# BCC ( [官方文档](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) )

## Python

### BPF

```python
from bcc import BPF


b = BPF(text='int do_trace(void *ctx) { bpf_trace_printk("hit!\\n"); return 0; }');
```

```python
prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

b = BPF(text=prog)
```

```python
b = BPF(src_file = "vfsreadlat.c")
```

使用 cflags 告诉编译器需要访问特殊的库

```python
from bcc import BPF

prog = """
#include <linux/bpf.h>
#include <pcap.h>

int my_prog(struct xdp_md *ctx) {
    // use libpcap functions here
}
"""

bpf = BPF(text=prog, cflags=["-I/usr/include/pcap"])
```

使用 debug 控制调试输出, 使用或运算进行组合

<table>
  <tr>
    <th>debug</th>
    <th>value</th>
    <th>description</th>
  </tr>
  <tr>
    <td>DEBUG_LLVM_IR</td>
    <td>0x1</td>
    <td>编译的 LLVM IR</td>
  </tr>
  <tr>
    <td>DEBUG_BPF</td>
    <td>0x2</td>
    <td>加载分支上的 BPF 字节码和注册器状态</td>
  </tr>
  <tr>
    <td>DEBUG_PREPROCESSOR</td>
    <td>0x4</td>
    <td>预处理结果</td>
  </tr>
  <tr>
    <td>DEBUG_SOURCE</td>
    <td>0x8</td>
    <td>内嵌的 ASM 指令</td>
  </tr>
  <tr>
    <td>DEBUG_BPF_REGISTER_STATE</td>
    <td>0x10</td>
    <td>除 DEBUG_BPF 之外, 所有指令的注册状态</td>
  </tr>
  <tr>
    <td>DEBUG_BTF</td>
    <td>0x20</td>
    <td>打印来至 libbpf 的消息</td>
  </tr>
</table>

### Events

#### attach_kprobe

对内核函数 event 进行插桩, 使得我们定义的 C 函数 fn_name 当内核函数调用时被调用

```python
b.attach_kprobe(event="sys_clone", fn_name="do_trace")
```

#### detach_kprobe

分离指定事件的处理程序

```python
b.detach_kprobe(event="sys_clone", fn_name="do_trace")
```

#### attach_kretprobe

与 attach_kprobe 类似, 在内核函数返回时被调用

```python
b.attach_kretprobe(event="vfs_read", fn_name="do_return")
```

#### detach_kretprobe

```python
b.detach_kretprobe(event="vfs_read", fn_name="do_return")
```

#### attach_tracepoint

检测由 tracepoint 描述的内核原始跟踪点, 在命中时调用

查看内核事件( tracepoint )

```
/sys/kernel/debug/tracing/events
```

```python
prog = """
#include <uapi/linux/ptrace.h>

struct urandom_read_args {
    u64 __unused__;
    u32 got_bits;
    u32 pool_left;
    u32 input_left;
};

int printarg(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
};
"""

b = BPF(text=prog)
b.attach_tracepoint("random:urandom_read", "printarg")
```

#### attach_raw_tracepoint

同 attach_tracepoint

```python
b.attach_raw_tracepoint(tp="sched_switch", fn_name="do_trace")
```

#### attach_uprobe

当 `libc` 内的 `strlen` 函数被调用时调用自定义的 `count` 函数

```python
b.attach_uprobe(name="c", sym="strlen", fn_name="count")
```

#### attach_uretprobe

类似 attach_uprobe , 当函数返回时调用

```python
b.attach_uretprobe(name="c", sym="strlen", fn_name="count")
```

#### USDT.enable_probe

跟踪 pid 进程, 当处理 probe 时调用

```python
pid = sys.argv[1]

u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")

b = BPF(text=prog, usdt_contexts=[u])
```

#### attach_raw_socket

```c
// http-parse-simple.c

int http_filter(struct __sk_buff *skb) {
  // ...
}
```

```python
# http-parse-simple.py

interface="eth0"

b = BPF(src_file="http-parse-simple.c")

# 加载 http_filter 程序
func = b.load_func("http_filter", BPF.SOCKET_FILTER)

# 创建原始套接字, 并将 BPF 附加到特定的网络接口(如 eth0)
BPF.attach_raw_socket(fn=func, dev=interface)

# 获取套接字描述符
socket_fd = function_http_filter.sock

# 创建 python 套接字对象
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)

# 设置为阻塞模式
sock.setblocking(True)
```

#### attach_xdp

检测网络驱动 dev, 接收数据包并运行自定义函数

<table>
  <tr>
    <th>flags</th>
    <th>value</th>
    <th>description</th>
  </tr>
  <tr>
    <td>XDP_FLAGS_UPDATE_IF_NOEXIST</td>
    <td>1 << 0</td>
    <td>如果已将 XDP 程序附加到指定的驱动程序, 再次附加将失败</td>
  </tr>
  <tr>
    <td>XDP_FLAGS_SKB_MODE</td>
    <td>1 << 1</td>
    <td>驱动程序不支持 XDP, 但是内核可以伪造它, 数据包交给内核堆栈</td>
  </tr>
  <tr>
    <td>XDP_FLAGS_DRV_MODE</td>
    <td>1 << 2</td>
    <td>一个驱动程序支持 XDP, 并且可以在没有内核堆栈交互的情况下交给 XDP</td>
  </tr>
  <tr>
    <td>XDP_FLAGS_HW_MODE</td>
    <td>1 << 3</td>
    <td>XDP 可以直接在 NIC 上加载和执行</td>
  </tr>
  <tr>
    <td>XDP_FLAGS_REPLACE</td>
    <td>1 << 4</td>
    <td>description</td>
  </tr>
</table>

```c
// prog.c
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>

// 创建一个名为 tx_port 的映射, 用于将数据包重定向到特定的网络接口
BPF_DEVMAP(tx_port, 1);

// 创建一个名为 rxcnt 的 per-CPU 数组, 用于存储每个 CPU 特定的数据
BPF_PERCPU_ARRAY(rxcnt, long, 1);

// 交换源和目标 MAC 地址
static inline void swap_src_dst_mac(void *data) {
    // ...
}

// 将数据包重定向到特定的网络接口
int xdp_redirect_map(struct xdp_md *ctx) {
    // ...
}

int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
```

```python
flags = 0

# 网络接口
in_if = sys.argv[1]
out_if = sys.argv[2]

# 获取指定网络接口索引
ip = pyroute2.IPRoute()
out_idx = ip.link_lookup(ifname=out_if)[0]

b = BPF(src_file="prog.c", cflags=["-w"])

tx_port = b.get_table("tx_port")
tx_port[0] = ct.c_int(out_idx)

# 加载两个函数的字节码
in_fn = b.load_func("xdp_redirect_map", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)

# 将函数绑定到指定的网络接口上
b.attach_xdp(in_if, in_fn, flags)
b.attach_xdp(out_if, out_fn, flags)
```

#### attach_func

将指定类型的 BPF 函数附加到特定的文件描述符上

```c
#include <net/sock.h>
#define MAX_SOCK_OPS_MAP_ENTRIES 65535 // hash 表容量

struct sock_key {
    u32 remote_ip4;  // 远程 IP 地址
    u32 local_ip4;   // 本地 IP 地址
    u32 remote_port; // 远程端口
    u32 local_port;  // 本地端口
    u32 family;      // 协议族
};

// 定义 sock_hash 表
BPF_SOCKHASH(sock_hash, struct sock_key, MAX_SOCK_OPS_MAP_ENTRIES);

static __always_inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops) {
    // ...
}

// 数据包过滤, 如只处理 ipv4
int bpf_sockhash(struct bpf_sock_ops *skops) {
    // ...
}

// 对数据包进行重定向
int bpf_redir(struct sk_msg_md *msg) {
    // ...
}
```

```python
# 解析参数, 类似 sys.args
# ./xx.py --cgroup /root/cgroup
args = parser.parse_args()

# ...

# 加载两个函数的字节码
func_sock_ops = b.load_func("bpf_sockhash", b.SOCK_OPS)
func_sock_redir = b.load_func("bpf_redir", b.SK_MSG)

# 打开 cgroup 文件
fd = os.open(args.cgroup, os.O_RDONLY)

# 获取 sock_hash 表(BPF中定义的表)文件描述符
map_fd = lib.bpf_table_fd(b.module, b"sock_hash")

b.attach_func(func_sock_ops, fd, BPFAttachType.CGROUP_SOCK_OPS)
b.attach_func(func_sock_redir, map_fd, BPFAttachType.SK_MSG_VERDICT)
```

#### detach_func

分离指定类型的 BPF 函数

```python
b.detach_func(fn, fd, BPFAttachType.CGROUP_SOCK_OPS)
b.detach_func(fn, map_fd, BPFAttachType.SK_MSG_VERDICT)
```

### Debug

#### trace_print

持续读取全局共享的 `/sys/kernel/debug/tracing/trace_pipe` 文件的内容, 并将其打印出来

```python
# 输出 task, pid, cpu, flags, ts, msg
b.trace_print()
```

```python
b.trace_print(fmt="{1} {5}")
```

#### trace_fields

```python
while True:
    try:
        # 任务名、进程、CPU、标志、时间戳和消息
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
```

```python
b.trace_fields(nonblocking=True) # 非阻塞式输出
```

### Output

#### perf_buffer_poll

内核态与用户态传输数据

```c
#include <linux/sched.h>

struct data_t {
    u32 pid;                  // 进程 id
    u64 ts;                   // 时间戳
    char comm[TASK_COMM_LEN]; // 进程名
};

BPF_PERF_OUTPUT(events); // 定义 perf 事件流

int hello(struct pt_regs *ctx) {
    // 修改结构体数据...

    // 将结构体提交到 perf 事件流中
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
```

```python
from bcc.utils import printb

start = 0

# 回调函数
def print_event(cpu, data, size):
    global start

    event = b["events"].event(data) # 从 perf 事件流中读取数据

    if start == 0:
        start = event.ts

    time_s = (float(event.ts - start)) / 1000000000

    # 打印字节数据
    printb(b"%-18.9f %-16s %-6d" % (time_s, event.comm, event.pid))

# 注册回调函数
b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll() # 监听
    except KeyboardInterrupt:
        exit()
```

#### ring_buffer_poll

从环形缓冲区中读取数据, 可设置超时参数(ms), 不设置的话会不断轮询, 直到没有数据或回调返回负值

```c
// 16 字节的环形缓冲区
BPF_RINGBUF_OUTPUT(buffer, 1 << 4);

struct event {
    char filename[16]; // 文件名
    int dfd;           // 文件描述符
    int flags;         // 标志
    int mode;          // 访问模式
};

// 跟踪点 sys_enter_openat
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    // 修改结构体数据...

    // 将结构体写入缓冲区
    buffer.ringbuf_output(&event, sizeof(event), 0);

    return 0;
}
```

```python
# 回调函数
def callback(ctx, data, size):
    event = b['buffer'].event(data) # 从缓冲区中读取数据

    filename = event.filename.decode('utf-8')

    print("%-16s %10d %10d %10d" % (filename, event.dfd, event.flags, event.mode))

b['buffer'].open_ring_buffer(callback)

while True:
    try:
        # 当缓冲区中有数据时触发回调
        b.ring_buffer_poll()

        time.sleep(0.5)
    except KeyboardInterrupt:
        exit()
```

#### ring_buffer_consume

从环形缓冲区中读取数据, 用法与 ring_buffer_poll 一样, 但是使用时不轮询

### Map APIs

#### get_table

```python
counts = b.get_table("counts") # no longer used

# or

counts = b["counts"]
```

#### open_perf_buffer

```python
# 注册回调函数, 当缓冲区可用时执行回调
b["events"].open_perf_buffer(print_event)
```

#### items

```c
#include <uapi/linux/ptrace.h>

// hash 表的 key 是一个结构体
struct key_t {
    char c[80];
};

// hash 表
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};

    u64 zero = 0, *val;

    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));

    // 查找或初始化 key 的 value
    val = counts.lookup_or_try_init(&key, &zero);

    if (val) {
      (*val)++;
    }

    return 0;
};
```

```python
b.attach_uprobe(name="c", sym="strlen", fn_name="count")

# ...

counts = b["counts"]

for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    printb(b"%10d \"%s\"" % (v.value, k.c))
```

#### values

```python
counts.values()
```

#### clear

```c
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist); // 定义一个直方图

int count(struct pt_regs *ctx) {
    // 计算 strlen 函数返回值的对数值
    // 将计算出的对数值加入到直方图 dist 中
    dist.increment(bpf_log2l(PT_REGS_RC(ctx)));
    return 0;
}
```

```python
sym = "strlen"

b.attach_uretprobe(name="c", sym=sym, fn_name="count")

dist = b["dist"]

while True:
    try:
        time.sleep(1) # 间隔 1s 统计一次
        print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
        dist.print_log2_hist(f"{sym} return:") # 输出直方图
        dist.clear() # 清空直方图数据
    except KeyboardInterrupt:
        exit()
```

#### items_lookup_and_delete_batch

相当于同时使用 table.items() 以及 table.clear() , 优先使用 items_lookup_and_delete_batch

```python
def sort_f(kv):
    return (kv[0]).pid


while True:
    for k, v in sorted(b["map"].items_lookup_and_delete_batch(), key=sort_f):
        print("%9s-%9s-%8s-%9d" % (k.pid, k.comm, k.fname, v.counter))

    sleep(1)
```

#### items_lookup_batch

优先使用 items_lookup_batch 而不是 items ( 作用一样 )

```python
def sort_f(kv):
    return (kv[0]).pid


while True:
    for k, v in sorted(b["map"].items_lookup_batch(), key=sort_f):
        print("%9s-%9s-%8s-%9d" % (k.pid, k.comm, k.fname, v.counter))
```

#### items_delete_batch

keys 为 null 时效果与 clear 一致, 优先使用 items_delete_batch

```python
b["map"].items_delete_batch(keys)
```

#### items_update_batch

批量更新键值对, 要求两个数组等长

```python
keys = [1, 2, 3]
values = [4, 5, 6]

b["map"].items_update_batch(keys, values)
```

#### print_log2_hist

输出直方图, 要求数据存储为 log2 的形式

```c
BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req) {
	dist.increment(bpf_log2l(req->__data_len / 1024));
	return 0;
}
```

```python
dist.print_log2_hist(f"{sym} return:")
```

```
strlen return:  : count     distribution
    0 -> 1      : 2106     |****************                        |
    2 -> 3      : 1172     |*********                               |
    4 -> 7      : 3892     |******************************          |
    8 -> 15     : 5096     |****************************************|
    16 -> 31    : 2201     |*****************                       |
    32 -> 63    : 547      |****                                    |
    ...
```

#### print_linear_hist

输出线性直方图

```c
BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req) {
	dist.increment(req->__data_len / 1024);
	return 0;
}
```

```python
b["dist"].print_linear_hist("kbytes")
```

```
kbytes  : count     distribution
  0     : 3        |******                                  |
  1     : 0        |                                        |
  2     : 0        |                                        |
  3     : 0        |                                        |
  4     : 19       |****************************************|
  5     : 0        |                                        |
```

