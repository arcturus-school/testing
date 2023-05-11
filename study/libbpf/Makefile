CLAND   := clang
CC      := gcc
CFLAGS  := -O2 -g -Wall -I/usr/include/$(shell uname -m)-linux-gnu
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' \
			 				| sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' \
			 				| sed 's/riscv64/riscv/' | sed 's/loongarch.*/loongarch/')
BPF     := -target bpf -D__TARGET_ARCH_$(ARCH)
VMLINUX := ./common/vmlinux.h
INCLUDE := -I$(dir $(VMLINUX))

target  := hello
OUTPUT  := $(target)/dist
PREFIX  := $(OUTPUT)/$(target)

$(shell mkdir -p $(OUTPUT))

.PHONY: all
all: $(target)

# Build BPF code
$(PREFIX).bpf.o: $(target)/$(target).bpf.c
	$(CLAND) $(CFLAGS) $(BPF) -c $< -o $@

# Generate BPF skeletons
$(PREFIX).skel.h: $(PREFIX).bpf.o
	bpftool gen skeleton $< > $@

# Build user-space code
$(PREFIX).o: $(target)/$(target).c $(PREFIX).skel.h
	$(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

# Build application binary
$(target): $(PREFIX).o
	$(CC) $(CFLAGS) $< -lbpf -o $(OUTPUT)/$@


clean:
	if [ -d $(OUTPUT) ]; then rm -rf $(OUTPUT); fi