## BCC( [官方文档](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) )

### Tutorials

- [Python](./tutorials/PYTHON.md)

- [C](./tutorials/C.md)

### Examples

本部分来自官方案例, 做了一些注释 (╹ڡ╹ )

- [hello](./hello)

  - [hello](./hello/hello_world/hello.py) hello world

  - [hello_fields](./hello/hello_fields.py) 跟踪系统调用 clone

  - [hello_perf](./hello/hello_perf_output.py) bpf_perf_output 的使用

- [disk](./disk)

  - [disksnoop](./disk/disksnoop.py) 跟踪磁盘读写情况

  - [bitehist](./disk/bitehist.py) 分析磁盘读写数据大小的分布

  - [biolatency](./disk/biolatency.py)

  - [biosnoop](./disk/biosnoop.py)

  - [cachestat](./disk/cachestat.py)

  - [ext4slower](./disk/ext4slower.py)

  - [opensnoop](./disk/opensnoop.py)

- [sync_timing](./sync_timing.py) 监听 sync 指令调用

- [task_switch](./task_switch.py) 进程切换检测

- [execsnoop](./execsnoop.py) 跟踪 exec() 调用情况, 返回进程调用参数等信息

- [runqlat](./runqlat.py) 显示调度程序运行队列延迟

- [tplist](./tplist.py) 显示跟踪点或进程/库的 usdt 信息

- [network](./network)

  - [tcpaccept](./network/tcpaccept.py) 跟踪 TCP 主动连接情况

  - [tcpcong](./network/tcpcong.py) 跟踪拥塞控制情况

  - [tcpconnect](./network/tcpconnect.py) 跟踪 TCP 连接情况

  - [tcpdrop](./network/tcpdrop.py)

  - [tcplife](./network/tcplife.py)

  - [tcpretrans](./network/tcpretrans.py)

  - [tcprtt](./network/tcprtt.py)

  - [tcpstates](./network/tcpstates.py)

  - [tcpsubnet](./network/tcpsubnet.py)

  - [tcpsynbl](./network/tcpsynbl.py)

  - [tcptop](./network/tcptop.py)

  - [tcptracer](./network/tcptracer.py)
