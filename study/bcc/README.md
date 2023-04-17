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
    <th>name</th>
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

#### attach_kretprobe

与 attach_kprobe 类似, 在内核函数返回时被调用

```python
b.attach_kretprobe(event="vfs_read", fn_name="do_return")
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

#### attach_func

#### detach_func

#### detach_kprobe

#### detach_kretprobe

####

### Debug

#### trace_print

#### trace_fields

### Map APIs

#### get_table

#### open_perf_buffer

#### items

#### values

#### clear

#### items_lookup_and_delete_batch

#### items_lookup_batch

#### items_delete_batch

#### items_update_batch

#### print_log2_hist

#### print_linear_hist

#### push

#### pop

#### peek
