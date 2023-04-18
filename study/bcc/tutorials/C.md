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
# 这里不用显示的绑定回调函数(即不用 attach_kprobe)
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

## Debugging

## Output

## Maps
