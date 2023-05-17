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

  - [biolatency](./disk/biolatency.py) 以直方图的形式显示块设备 I/O 延迟

  - [biosnoop](./disk/biosnoop.py) 跟踪磁盘 I/O 延迟

  - [cachestat](./disk/cachestat.py) 跟踪缓存函数调用情况(命中/未命中)

- [sync_timing](./sync_timing.py) 监听 sync 指令调用

- [task_switch](./task_switch.py) 进程切换检测

- [execsnoop](./execsnoop.py) 跟踪 exec() 调用情况, 返回进程调用参数等信息

- [runqlat](./runqlat.py) 显示调度程序运行队列延迟

- [tplist](./tplist.py) 显示跟踪点或进程/库的 usdt 信息

- [network](./network)

  - [http_server_request](./network/nodejs/http__server__request.py) 监控 nodejs 服务请求

  - [tcpaccept](./network/tcpaccept.py) 跟踪 TCP 主动连接情况

  - [tcpcong](./network/tcpcong.py) 跟踪拥塞控制情况

  - [tcpconnect](./network/tcpconnect.py) 跟踪 TCP 连接情况

  - [tcpdrop](./network/tcpdrop.py) 跟踪 TCP 数据包丢弃情况

  - [tcplife](./network/tcplife.py) 跟踪 TCP 生命周期事件

  - [tcpretrans](./network/tcpretrans.py) 跟踪 TCP 重传情况

  - [tcprtt](./network/tcprtt.py) 跟踪 TCP 往返延时

  - [tcpstates](./network/tcpstates.py) 跟踪 TCP 状态变化

  - [tcpsubnet](./network/tcpsubnet.py) 跟踪发送至子网的 TCP 数据包大小

  - [tcpsynbl](./network/tcpsynbl.py) 直方图显示半连接队列的大小

  - [tcptop](./network/tcptop.py) 跟踪 TCP 连接的吞吐量

  - [tcptracer](./network/tcptracer.py) 跟踪 TCP 状态
