## BCC( [官方文档](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md) )

### Tutorials

- [Python](./tutorials/PYTHON.md)

- [C](./tutorials/C.md)

### Examples

本部分来自官方案例, 做了一些注释 (╹ڡ╹ )

- [hello](./hello)

  - [hello](./hello/hello_world/hello.py) hello world

  - [hello_fields](./hello/hello_fields.py) 监听系统调用 clone

  - [hello_perf](./hello/hello_perf_output.py) bpf_perf_output 的使用

- [disk](./disk)

  - [disksnoop](./disk/disksnoop.py) 监听磁盘读写

  - [bitehist](./disk/bitehist.py) 分析磁盘读写数据大小的分布

- [sync_timing](./sync_timing.py) 监听 sync 指令调用

- network
