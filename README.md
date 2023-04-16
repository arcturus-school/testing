# 软件测试课设

## Requirements

1. 基于 `ebpf` 对 linux 内核常规的指标进行监控

2. 需要收集该领域的相关研究前沿资料( word/ppt/pdf 等 )

3. 内置实现若干常规监控指标, 至少包括以下指标: `进程 tcp 建连耗时` `网络重传次数` `tcprtt` `biolatency`

4. 实现对监控指标的前端展示, 要具备选择展示的监控指标和观察的时间段

5. 监控指标可配置化, 可以通过配置文件指定既有指标, 也可以通过配置文件扩展新指标

6. 监控数据支持定制化落地到指定的数据库, 如 `Promethus` `Elasticsearch` 等

7. 要求监控 `agent` 本身部署配置简单, 一个可执行文件和一个配置文件

## Setup

### EBPF && BBC

```bash
wsl --install # install wsl2
```

```bash
wsl -l -v # see the wsl version
```

```
NAME      STATE           VERSION
Ubuntu    Running         2           ---> 2 is ok
```

```bash
uname -a # check the kernel version to make sure you are currently in wsl2
```

```
Linux DESKTOP-ECSI4FJ 5.15.90.1-microsoft-standard-WSL2 ...
```

```bash
lsb_release -a # my ubuntu version
```

```
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
```

then follow the official [document](https://github.com/iovisor/bcc/blob/master/INSTALL.md#wslwindows-subsystem-for-linux---binary) for compiling new kernel.

installing the bcc tools package according to this [document](https://github.com/iovisor/bcc/blob/master/INSTALL.md#install-and-compile-bcc-1).

