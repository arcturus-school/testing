#!/bin/bash

sudo apt-get update

# 安装 libbpf 环境
sudo apt install clang cmake llvm git libelf-dev libfl-dev make \
	pkg-config curl libcurl4-openssl-dev gcc-multilib -y 

git clone https://github.com/libbpf/libbpf.git

cd libbpf/src

make

sudo make install

## bpftool
## https://github.com/libbpf/bpftool/blob/master/README.md

git clone --recurse-submodules https://github.com/libbpf/bpftool.git

cd bpftool

git submodule update --init

cd src

sudo make install

# 这步可能不需要, 如果运行程序时出现 
# error while loading shared libraries: libbpf.so.1: cannot open shared object file: No such file or directory
# 可能是 libbpf.so.1 被装到 /usr/lib64 下了, 而非 /usr/lib 里, 
# 因此将新的共享文件目录 /usr/lib64 加入 /etc/ld.so.conf 里
sudo sh -c "echo /usr/lib64 >> /etc/ld.so.conf"

## g++
sudo apt install g++

# 安装 yaml-cpp
git clone https://github.com/jbeder/yaml-cpp.git

cd yaml-cpp

mkdir build; cd build

cmake ..

cmake --build .

sudo cmake --install .

# 安装 Prometheus-CPP
git clone https://github.com/jupp0r/prometheus-cpp.git

cd prometheus-cpp

# 更新子模块
git submodule init
git submodule update

mkdir build; cd build

cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PUSH=OFF -DENABLE_COMPRESSION=OFF

cmake --build .

sudo cmake --install .

sudo ldconfig

# 安装 Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.44.0/prometheus-2.44.0.linux-amd64.tar.gz

tar -zxvf prometheus-2.44.0.linux-amd64.tar.gz

# 复制配置文件
cp prometheus.yml prometheus-2.44.0.linux-amd64/prometheus.yml

# 编译 libbpf 程序
make bpf

# 编译 ecli 代码
make

# 执行 exporter
sudo ./ecli -v -c config.yaml &

# 运行 prometheus
./prometheus-2.44.0.linux-amd64/prometheus --config.file=prometheus.yml &

# 访问 localhost:9090
