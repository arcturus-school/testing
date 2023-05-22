#!/bin/bash
sudo apt-get update

# install libbpf
sudo apt install clang cmake llvm git libelf-dev libfl-dev make \
  pkg-config curl libcurl4-openssl-dev gcc-multilib -y 

(cd ./dependencies/libbpf/src && make && sudo make install)

## bpftool( https://github.com/libbpf/bpftool/blob/master/README.md )

(cd ./dependencies/bpftool/src && sudo make install)

# error while loading shared libraries: libbpf.so.1: cannot open shared object file: No such file or directory
# maybe libbpf.so.1 was installed in /usr/lib64 instead of /usr/lib, 
# so we need to add /usr/lib64 to /etc/ld.so.conf
sudo sh -c "echo /usr/lib64 >> /etc/ld.so.conf"

## g++
sudo apt install g++

# install yaml-cpp

(
cd ./dependencies/yaml-cpp
mkdir build
cd build
cmake ..
cmake --build .
sudo cmake --install .
)

# install Prometheus-CPP

(
cd ./dependencies/prometheus-cpp
mkdir build; cd build
cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PUSH=OFF -DENABLE_COMPRESSION=OFF
cmake --build .
sudo cmake --install .
)

sudo ldconfig

# compile libbpf
make bpf

# compile ecli
make

# run exporter
sudo ./ecli -v -c config.yaml
