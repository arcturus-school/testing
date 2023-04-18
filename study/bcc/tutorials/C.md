# C

## Events & Arguments

### kprobes

形式为 `kprobe__内核函数名`

```c
// prog.c

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    // ...
}
```

```python
b = BPF(src_file="prog.c")
# 这里不用显式的绑定回调函数(即不用 attach_kprobe)
```

或者可以声明为一个普通的 C 函数, 然后使用 attach_kprobe 绑定

```c
int handle(struct pt_regs *ctx, struct sock *sk) {
    // ...
}
```

```python
b = BPF(src_file="prog.c")
b.attach_kprobe(event="tcp_v4_connect", fn_name="handle")
```

### kretprobe

```c
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    // ...
}
```

效果同 `attach_kretprobe`

### kfuncs

与 `kprobe__xxx` 类似, 不过是使用宏来定义的

```c
KFUNC_PROBE(vfs_read) {
    stats_try_increment(S_READ);
    return 0;
}
```

### kretfuncs

```c
KRETFUNC_PROBE(vfs_read) {
    // ...
}
```

### Tracepoints

```c
// /sys/kernel/debug/tracing/events/random/urandom_read/format
TRACEPOINT_PROBE(random, urandom_read) {
    // 不需要指定 args 参数
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
```

效果同 `attach_tracepoint`

```c
// 需要指定 args 参数
int handle(struct urandom_read_args *args) {
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
};
```

```python
b.attach_tracepoint("random:urandom_read", "handle")
```

### Raw Tracepoints

```c
// 跟踪 sched_switch 事件
RAW_TRACEPOINT_PROBE(sched_switch) {
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];

    s32 prev_tgid, next_tgid;

    // 从内核空间中读取 prev 和 next 进程的 tgid(组ID) 信息
    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);

    // 打印信息
    bpf_trace_printk("%d -> %d\\n", prev_tgid, next_tgid);
}
```

### uprobes

当 `libc` 内的 `strlen` 函数被调用时调用自定义的 `count` 函数

```c
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};

BPF_HASH(counts, struct key_t); // 创建 hash 表

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx))
        return 0;

    struct key_t key = {};

    u64 zero = 0, *val;

    // 从用户态读取数据
    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM2(ctx));

    // 如果 key 存在则返回 value, 不存在则初始化为 zero 再返回 value
    val = counts.lookup_or_init(&key, &zero);

    (*val)++;

    return 0;
};
```

```python
# libc 中 lib 可以省略, 写一个 c 即可
b.attach_uprobe(name="c", sym="strlen", fn_name="count")
```

### uretprobes

同 `uprobes` , 函数返回时调用

### USDT probes

```c
#include <uapi/linux/ptrace.h>

int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={ 0 };

    // 获取第 6 个参数并存储到 addr 中
    bpf_usdt_readarg(6, ctx, &addr);

    // 从用户态中读取文件路径
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);

    bpf_trace_printk("path:%s\\n", path);

    return 0;
};
```

```python
# 关联 User Statically-Defined Tracing
u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")

b = BPF(src_file="prog.c", usdt_contexts=[u])
```

### system call tracepoints

```c
// syscall__xx 没什么特别的, 和普通函数一样, 但能区分是否是系统调用的处理函数
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    // ...
}
```

```python
b = BPF(src_file="prog.c")
evt = b.get_syscall_fnname("execve")
b.attach_kprobe(event=evt, fn_name="syscall__execve")
```

### lsm probes

暂时看不懂

### bpf iterators

暂时看不懂

## Data

### bpf_probe_read_kernel

```c
// 从内核地址 &inet->inet_sport 复制 sizeof(sport) 字节到 &sport
int status = bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);

if (status != 0) {
    // 失败...
}
```

### bpf_probe_read_kernel_str

结尾以 NULL 填充

```c
// 将内核地址上的字符串复制到地址 newvs.driver
int len = bpf_probe_read_kernel_str(newvs.driver, sizeof(newvs.driver), vq->vdev->dev.driver->name);

if (len < 0) {
    // 失败...
}
```

### bpf_ktime_get_ns

```c
int do_entry(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns(); // 获取内核时间(纳秒级)
    // ...
}

```

### bpf_get_current_pid_tgid

```c
u64 id  = bpf_get_current_pid_tgid();
u32 pid = id >> 32; // 高 32 位为 进程ID(PID)(或线程组ID(TGID))
u32 tid = id;       // 低 32 位为 线程ID(TID)
```

### bpf_get_current_uid_gid

```c
u64 id  = bpf_get_current_uid_gid();
u32 gid = id >> 32; // 用户组 ID
u32 uid = id;       // 用户 ID
```

### bpf_get_current_comm

```c
#include <linux/sched.h>

int do_trace(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    int status = bpf_get_current_comm(&comm, sizeof(comm)); // 获取进程名

    if (status != 0) {
        // 失败...
    }

    // ...
}
```

### bpf_get_current_task

```c
// 获取当前任务的 task_struct 结构体
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
u32 ppid = task->real_parent->tgid; // 父进程 ID

if (ppid != FILTER_PPID) {
    return 0;
}
```

### bpf_log2l

```c
unsigned int res = bpf_log2l(4) // 获取 log2 值, 接收 unsigned long 类型
```

### bpf_get_prandom_u32

```c
u32 res = bpf_get_prandom_u32() // 获取一个伪随机数
```

### bpf_probe_read_user

```c
int status = bpf_probe_read_user(&key, sizeof(key), (void*)pid_data->tls_key_addr); // 从用户空间读取数据

if (status != 0) {
    // 失败...
}
```

### bpf_probe_read_user_str

```c
int len = bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename); // 从用户空间读取数据

if (len < 0) {
    // 失败...
}
```

### bpf_get_ns_current_pid_tgid

```c
struct bpf_pidns_info ns = {};

// 获取当前命名空间的 pid 和 tgid
int status = bpf_get_ns_current_pid_tgid(DEV, INO, &ns, sizeof(struct bpf_pidns_info));

if (status != 0) {
    // 失败...
}
```

## Debugging

### bpf_override_return

暂时不知道

## Output

### bpf_trace_printk

```c
int status = bpf_trace_printk("Hello, world!\\n");

if (status != 0) {
    // 失败...
}
```

### BPF_PERF_OUTPUT

```c
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

// 创建一个名为 events 的 BPF 表
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();               // 获取进程 id
    data.ts = bpf_ktime_get_ns();                        // 获取内核时间
    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // 获取进程名

    // 向用户空间提交自定义数据
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
```

### perf_submit

```c
int status = events.perf_submit(ctx, &data, sizeof(data));

if (status != 0) {
    // 失败...
}
```

### perf_submit_skb

当程序为 SCHED_CLS 或 SOCKET_FILTER 时使用

```c
int handle(struct __sk_buff *skb) {
    // ...

    skb_events.perf_submit_skb(skb, skb->len, &magic, sizeof(magic));
}
```

```python
b = BPF(src_file="prog.c")

fn = b.load_func("handle", BPF.SCHED_CLS)
```

### BPF_RINGBUF_OUTPUT

```c
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

// 具有 8 页空间, 在所有 CPU 之间共享, 名为 events 的表
BPF_RINGBUF_OUTPUT(events, 8);

int first(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 将自定义数据提交到用户空间, 不需要 ctx
    events.ringbuf_output(&data, sizeof(data), 0 /* flags */);

    return 0;
}

int second(struct pt_regs *ctx) {
    // 在环形缓冲区中预留一定的空间
    struct data_t *data = events.ringbuf_reserve(sizeof(struct data_t));

    if (!data) {
        return 1;
    }

    data->pid = bpf_get_current_pid_tgid();
    data->ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    events.ringbuf_submit(data, 0 /* flags */);

    return 0;
}
```

### ringbuf_output

| flags               | description                |
| :------------------ | :------------------------- |
| BPF_RB_NO_WAKEUP    | 不发送新数据可用性通知     |
| BPF_RB_FORCE_WAKEUP | 无条件发送新数据可用性通知 |

```c
int status = events.ringbuf_output(&data, sizeof(data), 0 /* flags */);

if (status != 0) {
    // 失败...
}
```

### ringbuf_submit

必须配合 `ringbuf_reserve` 使用, 无返回值, 总是成功, `flags` 同 `ringbuf_output`

### ringbuf_discard

```c
// 丢弃自定义事件数据, 用户态会忽略这个数据, 需要配合 ringbuf_reserve
buffer.ringbuf_discard(event, 0 /* flags */);
```

## Maps

### BPF_TABLE

```c
// 创建一个名为 table 的表
// 键的类型为 u32, 值的类型为 u64, 最大条目 1024
BPF_TABLE("hash", u32, u64, table, 1024);
```

### BPF_HASH

```c
// 创建一个名为 map 的哈希表
BPF_HASH(map, u64, u64, 1024);
```

### BPF_ARRAY

```c
// 创建一个名为 counts 的数组
BPF_ARRAY(counts, u64, 1024);
```

等价于

```c
BPF_TABLE("array", u32, u64, counts, 32);
```

### BPF_HISTOGRAM

```c
// 创建一个直方图映射
BPF_HISTOGRAM(dists, int, 64);
```

等价于

```c
BPF_TABLE("histgram", );
```

### BPF_STACK_TRACE

```c
// 创建一个堆栈跟踪表, 最大条目 1024
BPF_STACK_TRACE(stack_traces, 1024);
```

等价于

```c
BPF_TABLE("stacktrace", );
```

### BPF_PERF_ARRAY

```python
# 最大条目数必须等于 CPU 数
text="BPF_PERF_ARRAY(cpu_cycles, NUM_CPUS);"

b = bcc.BPF(text=text, cflags=["-DNUM_CPUS=%d" % multiprocessing.cpu_count()])
b["cpu_cycles"].open_perf_event(b["cpu_cycles"].HW_CPU_CYCLES)
```

### BPF_PERCPU_HASH

```c
// 每个 CPU 都存在单独的副本
BPF_PERCPU_HASH(name, u64, u64, 10240);
```

等价于

```c
BPF_TABLE("percpu_hash", u64, u64, name, 10240);
```

### BPF_PERCPU_ARRAY

```c
// 每个 CPU 都存在单独的副本
BPF_PERCPU_ARRAY(counts, u64, 32);
```

等价于

```c
BPF_TABLE("percpu_array", );
```

### BPF_LPM_TRIE

```c
// 创建一个最长前缀匹配 Trie Map
BPF_LPM_TRIE(name, u64, u64, 10240);
```

等价于

```c
BPF_F_TABLE("lpm_trie", , BPF_F_NO_PREALLOC);
```

### BPF_PROG_ARRAY

```c
// 存储 bpf 程序的文件描述符
BPF_PROG_ARRAY(name, size);
```

等价于

```c
BPF_TABLE("prog", )
```

### BPF_DEVMAP

```c
// 存储网络接口的 ifindex
BPF_DEVMAP(devmap, 10);
```

### BPF_CPUMAP

```c
// 存储给 CPU 分配的环形缓冲区大小, index 代表 CPU 的 id
BPF_CPUMAP(cpumap, 16);
```

### BPF_XSKMAP

```c
BPF_XSKMAP(xsks_map, 8);
```

### BPF_ARRAY_OF_MAPS

```c
BPF_TABLE("hash", int, int, ex1, 1024);
BPF_TABLE("hash", int, int, ex2, 1024);

// 使用数组存储哈希表
BPF_ARRAY_OF_MAPS(maps_array, "ex1", 10);
```

### BPF_HASH_OF_MAPS

```c
BPF_ARRAY(ex1, int, 1024);
BPF_ARRAY(ex2, int, 1024);

// 使用哈希表存储哈希表
BPF_HASH_OF_MAPS(maps_hash, struct custom_key, "ex1", 10);
```

### BPF_STACK

```c
// 创建一个栈
BPF_STACK(stack, struct event, 10240);
```

### BPF_QUEUE

```c
// 创建一个队列
BPF_QUEUE(queue, struct event, 10240);
```

### BPF_SOCKHASH

暂时不懂

### lookup

```c
u64* val = data.lookup(&key); // 查找
```

### lookup_or_try_init

```c
u64 zero = 0, *val;
val = data.lookup_or_try_init(&key, &zero); // 查找, 找不到则初始化
```

### delete

```c
data.delete(&key); // 删除
```

### update

```c
data.update(&key, &value); // 更新
```

### insert

```c
data.insert(&key, &value); // 插入
```

### increment

```c
data.increment(key, 1); // 增加 1
```

### get_stackid

```c
// 获取当前程序执行的堆栈 ID
int id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
```

### perf_read

```c
// 读取硬件性能计数器
u64 res =  map.perf_read(/* u32 */cpu);
```

### call

```c
BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("Tail-call\n");
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("Original program\n");
    prog_array.call(ctx, 2); // 调用 tail_call 函数
    return 0;
}
```

```python
b = BPF(src_file="prog.c")

tail_fn = b.load_func("tail_call", BPF.KPROBE) # 获取尾调用

prog_array = b.get_table("prog_array")

prog_array[c_int(2)] = c_int(tail_fn.fd) # 插入尾调用程序的文件描述符

b.attach_kprobe(event="xx", fn_name="do_tail_call")
```

### redirect_map

```c
BPF_DEVMAP(devmap, 1);

int redirect_example(struct xdp_md *ctx) {
    return devmap.redirect_map(0, 0);
}

int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}
```

```python
ip = pyroute2.IPRoute()
idx = ip.link_lookup(ifname="eth1")[0]

b = bcc.BPF(src_file="prog.c")

devmap = b.get_table("devmap")
devmap[c_uint32(0)] = c_int(idx)

in_fn = b.load_func("redirect_example", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)

b.attach_xdp("eth0", in_fn, 0)
b.attach_xdp("eth1", out_fn, 0)
```

### push

```c
int status = map.push(&val, BPF_EXIST/* 满了就弹出最旧的元素 */);

if (status != 0) {
    // 失败...
}
```

### pop

```c
// 弹出一个元素, 保存到 val 里
int status = map.pop(&val);

if (status < 0) {
    // 失败...
}
```

### peek

```c
// 查看头部元素, 不会删除元素
int status = map.peek(&val);

if (status < 0) {
    // 失败...
}
```

### sock_hash_update

| flags       | description              |
| :---------- | :----------------------- |
| BPF_NOEXIST | 键的条目不能存在于地图中 |
| BPF_EXIST   | 键的条目必须存在于地图中 |
| BPF_ANY     | 无限制                   |

```c
BPF_SOCKMAP(sk_map2, 10);

int test(struct bpf_sock_ops *skops) {
  u32 key = 0, val = 0;
  sk_map2.update(&key, &val);
  sk_map2.delete(&key);

  int status = sk_map2.sock_map_update(skops, &key, 0);

  if (status < 0) {
    // 失败...
  }

  return 0;
}
```

### msg_redirect_hash

暂时不懂

### sk_redirect_hash

暂时不懂
