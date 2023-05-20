#!/bin/bash

sudo apt-get update

# 安装 libbpf 环境
sudo apt install clang cmake llvm git libelf-dev libfl-dev make \
  pkg-config curl libcurl4-openssl-dev gcc-multilib -y 

git clone https://github.com/libbpf/libbpf.git

if [ ! -d "libbpf" ]; then
  echo "clone libbpf failed."
  exit
fi

cd libbpf/src

make

sudo make install

## bpftool
## https://github.com/libbpf/bpftool/blob/master/README.md

git clone --recurse-submodules https://github.com/libbpf/bpftool.git

if [ ! -d "bpftool" ]; then
  echo "clone bpftool failed."
  exit
fi

cd bpftool

git submodule update --init

cd src

sudo make install

# error while loading shared libraries: libbpf.so.1: cannot open shared object file: No such file or directory
# 可能是 libbpf.so.1 被装到 /usr/lib64 下了, 而非 /usr/lib 里, 
# 因此将新的共享文件目录 /usr/lib64 加入 /etc/ld.so.conf 里
sudo sh -c "echo /usr/lib64 >> /etc/ld.so.conf"

## g++
sudo apt install g++

# 安装 yaml-cpp
git clone https://github.com/jbeder/yaml-cpp.git

if [ ! -d "yaml-cpp" ]; then
  echo "clone yaml-cpp failed."
  exit
fi

cd yaml-cpp

mkdir build; cd build

cmake ..

cmake --build .

sudo cmake --install .

# 安装 Prometheus-CPP
git clone --recurse-submodules https://github.com/jupp0r/prometheus-cpp.git

if [ ! -d "prometheus-cpp" ]; then
  echo "clone prometheus-cpp failed."
  exit
fi

cd prometheus-cpp

git submodule update --init

mkdir build; cd build

cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PUSH=OFF -DENABLE_COMPRESSION=OFF

cmake --build .

sudo cmake --install .

sudo ldconfig

# 安装 Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.44.0/prometheus-2.44.0.linux-amd64.tar.gz

if [ ! "prometheus-2.44.0.linux-amd64.tar.gz" ]; then
  echo "prometheus-2.44.0.linux-amd64.tar.gz download failed."
  exit
fi

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
echo "Server is running at localhost:9090"