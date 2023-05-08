# Setup

## eBPF

### Install WSL2

```bash
wsl --install
```

See WSL version

```bash
wsl -l -v
```

```
NAME      STATE           VERSION
Ubuntu    Running         2           ---> 2 is ok
```

Check kernel version to make sure you are currently in WSL2

```bash
uname -r
```

```
5.15.90.1-microsoft-standard-WSL2
```

### Compile WSL ( [document](https://github.com/iovisor/bcc/blob/master/INSTALL.md#wslwindows-subsystem-for-linux---binary) )

Install dependencies

```bash
apt-get install flex bison libssl-dev libelf-dev dwarves
```

Download code

```bash
KERNEL_VERSION=$(uname -r | cut -d '-' -f 1)
```

```bash
git clone --depth 1 https://github.com/microsoft/WSL2-Linux-Kernel.git -b linux-msft-wsl-$KERNEL_VERSION
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

### Install BCC tools packages ( [document](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source) )

See Ubuntu version

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

According to the documentation, need to install the following dependencies for jammy.

```bash
sudo apt install -y bison build-essential cmake flex git libedit-dev \
libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev \
libfl-dev python3-setuptools libbpf-dev
```

Download BCC code

```bash
git clone --recursive https://github.com/iovisor/bcc.git
```

```bash
mkdir bcc/build; cd bcc/build
```

```bash
cmake ..
```

Handle some possible warnings

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

Compile BCC

```bash
make
```

```bash
sudo apt-get install zip -y # If encounter /bin/sh: 1: zip: not found
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

The default installation directory is

```
/usr/share/bcc
```

Test ( you need to install python-is-python3, because the python command does not exist in WSL )

```bash
sudo /usr/share/bcc/tools/execsnoop
```
