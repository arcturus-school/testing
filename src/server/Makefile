CLAND  := clang
CPP    := g++
CFLAGS := -O2 -g -Wall

ARCH := $(shell uname -m \
		| sed 's/x86_64/x86/' \
		| sed 's/aarch64/arm64/' \
		| sed 's/ppc64le/powerpc/' \
		| sed 's/mips.*/mips/' \
		| sed 's/riscv64/riscv/' \
		| sed 's/loongarch.*/loongarch/')

APP    := ecli
OUTPUT := dist

# 创建文件夹
$(shell mkdir -p $(OUTPUT))

# 生成 vmlinux.h
$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h)

.PHONY: all
all: $(APP)

EXPORTER_C := $(wildcard exporter/*.cpp)
EXPORTER_H := $(wildcard exporter/*.hpp)
UTILS_C    := $(wildcard utils/*.cpp)
UTILS_H    := $(wildcard utils/*.hpp)
PARSE_C    := $(wildcard parse/*.cpp)
PARSE_H    := $(wildcard parse/*.hpp)
CONFIG_C   := $(wildcard config/*.cpp)
CONFIG_H   := $(wildcard config/*.hpp)

SRC_C := $(UTILS_C) $(PARSE_C) $(CONFIG_C) $(EXPORTER_C)
SRC_H := $(UTILS_H) $(PARSE_H) $(CONFIG_H) $(EXPORTER_H)

LIBS  := -lyaml-cpp -lprometheus-cpp-pull -lprometheus-cpp-core -lz

$(APP): main.cpp $(SRC_C) $(SRC_H)
	$(CPP) $(CFLAGS) -std=c++17 -o $@ $< $(SRC_C) $(LIBS) -lbpf

BPF_FILE := $(wildcard bpf/*.bpf.c)

# 根据 patsubst 中定义的规则将 BPF_FILE 转成 BPF_OBJ
BPF_OBJ  := $(patsubst bpf/%.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_FILE))

$(OUTPUT)/%.bpf.o: bpf/%.bpf.c bpf/bpf.h
	$(CLAND) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

bpf: $(BPF_OBJ)

clean:
	if [ -d $(OUTPUT) ]; then rm -rf $(OUTPUT); fi
	if [ -r $(APP) ]; then rm -f $(APP); fi