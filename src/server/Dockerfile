FROM ubuntu:23.10

LABEL maintainer="1638330246@qq.com"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update

RUN apt-get install -y \
    clang \
    cmake \
    llvm \
    git \
    libelf-dev \
    libfl-dev \
    make \
    pkg-config \
    curl \
    libcurl4-openssl-dev \
    gcc-multilib \
    g++
    
# set work directory
WORKDIR /app

# copy code to container
COPY . .

# install libbpf
RUN cd dependencies/libbpf/src && make && make install

# install bpftool
RUN cd dependencies/bpftool/src && make install

RUN echo "/usr/lib64" >> /etc/ld.so.conf

# install yaml-cpp
RUN cd dependencies/yaml-cpp && \
    mkdir build && \
    cd build && \
    cmake .. && \
    cmake --build . && \
    cmake --install .

# install prometheus-cpp
RUN cd dependencies/prometheus-cpp && \
    mkdir build; cd build && \
    cmake .. -DBUILD_SHARED_LIBS=ON -DENABLE_PUSH=OFF -DENABLE_COMPRESSION=OFF && \
    cmake --build . && \
    cmake --install .

RUN ldconfig

# compile code
RUN make bpf && make

ENTRYPOINT ["/app/ecli"]
