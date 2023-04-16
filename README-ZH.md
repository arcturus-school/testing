<div align="center">

<h1>软件测试课设</h1>

<a href="./README.md">English</a> | <span>中文文档</span>

</div>

## 要求

1. 基于 `ebpf` 对 linux 内核常规的指标进行监控

2. 需要收集该领域的相关研究前沿资料( word/ppt/pdf 等 )

3. 实现若干常规监控指标, 至少包括以下指标: `进程 tcp 建连耗时` `网络重传次数` `tcprtt` `biolatency`

4. 实现对监控指标的前端展示, 要具备选择展示的监控指标和观察的时间段

5. 监控指标可配置化, 可以通过配置文件指定既有指标, 也可以通过配置文件扩展新指标

6. 监控数据支持定制化落地到指定的数据库, 如 `Promethus` `Elasticsearch` 等

7. 要求监控 `agent` 本身部署配置简单, 一个可执行文件和一个配置文件

## 环境搭建

### 安装 WSL2

```bash
wsl --install
```

查看 WSL 版本

```bash
wsl -l -v
```

```
NAME      STATE           VERSION
Ubuntu    Running         2           ---> 2 is ok
```

检查内核版本确保当前处于 WSL2

```bash
uname -r
```

```
5.15.90.1-microsoft-standard-WSL2
```

### 编译 WSL 内核 ( [官方文档](https://github.com/iovisor/bcc/blob/master/INSTALL.md#wslwindows-subsystem-for-linux---binary) )

安装依赖

```bash
apt-get install flex bison libssl-dev libelf-dev dwarves
```

下载特定分支代码

```bash
KERNEL_VERSION=$(uname -r | cut -d '-' -f 1)
```

```bash
git clone --depth 1 git@github.com:microsoft/WSL2-Linux-Kernel.git -b linux-msft-wsl-$KERNEL_VERSION
```

```bash
cd WSL2-Linux-Kernel
```

```bash
cp Microsoft/config-wsl .config
```

```bash
make oldconfig && make prepare
```

```bash
make scripts
```

```bash
make modules
```

```bash
sudo make modules_install
```

```bash
mv /lib/modules/$KERNEL_VERSION-microsoft-standard-WSL2+/ /lib/modules/$KERNEL_VERSION-microsoft-standard-WSL2
```

### 安装 BCC 工具包 ( [官方文档](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source) )

查看 Ubuntu 版本

```bash
lsb_release -a
```

```
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
```

根据文档说明 jammy 需要安装如下依赖

```bash
sudo apt install -y bison build-essential cmake flex git libedit-dev \
libllvm14 llvm-14-dev libclang-14-dev \
python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools
```

下载 BCC 源码

```bash
git clone --recursive https://github.com/iovisor/bcc.git
```

```bash
mkdir bcc/build; cd bcc/build
```

```bash
cmake ..
```

处理一些可能出现的警告

```bash
sudo apt install libdebuginfod-dev # Could NOT find LibDebuginfod
```

```bash
sudo apt install liblzma-dev # Could NOT find LibLzma
```

```bash
sudo apt-get -y install luajit luajit-5.1-dev # Could NOT find LuaJIT
```

```
CMake Warning at tests/python/CMakeLists.txt:6 (message):
  Recommended test program 'arping' not found


CMake Warning at tests/python/CMakeLists.txt:10 (message):
  Recommended test program 'netperf' not found


CMake Warning at tests/python/CMakeLists.txt:16 (message):
  Recommended test program 'iperf' or 'iperf3' not found
```

```bash
sudo apt-get install -y iperf iperf3 netperf arping
```

编译 BCC 源码

```bash
make
```

```bash
sudo apt-get install zip -y # 如果出现 /bin/sh: 1: zip: not found 的话
```

```bash
sudo make install
```

```bash
cmake -DPYTHON_CMD=python3 ..
```

```bash
pushd src/python/
```

```bash
make
```

```bash
sudo make install
```

```bash
popd
```

默认的安装目录

```
/usr/share/bcc
```

测试效果 ( 需要安装 python-is-python3, 因为 WSL 里面不存在 python 命令 )

```bash
sudo /usr/share/bcc/tools/execsnoop
```
