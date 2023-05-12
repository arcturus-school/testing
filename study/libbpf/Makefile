CLAND    := clang
CC       := gcc
CFLAGS   := -O2 -g -Wall 
PLATFORM := $(shell uname -m)
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' \
			| sed 's/aarch64/arm64/' \
			| sed 's/ppc64le/powerpc/' \
			| sed 's/mips.*/mips/' \
			| sed 's/riscv64/riscv/' \
			| sed 's/loongarch.*/loongarch/')

BPF      := -target bpf -D__TARGET_ARCH_$(ARCH)

target   := hello
OUTPUT   := $(target)/dist
PREFIX   := $(OUTPUT)/$(target)
COMMON   := ./common
COMMON_D := $(COMMON)/dist

VMLINUX  := $(COMMON)/vmlinux.h

INCLUDE  := -I$(dir $(VMLINUX))

$(shell mkdir -p $(OUTPUT))
$(shell mkdir -p $(COMMON_D))

$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(COMMON)/vmlinux.h)

.PHONY: all
all: $(target)

COMMON_C   := $(wildcard $(COMMON)/*.c)
COMMON_OBJ := $(patsubst $(COMMON)/%.c,$(COMMON_D)/%.o,$(COMMON_C))

# Build common
$(COMMON_D)/%.o: $(COMMON)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

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
$(target): $(PREFIX).o $(COMMON_OBJ)
	$(CC) $(CFLAGS) $< $(COMMON_OBJ) -lbpf -o $(OUTPUT)/$@


clean:
	if [ -d $(OUTPUT) ]; then rm -rf $(OUTPUT); fi
	if [ -d $(COMMON_D) ]; then rm -rf $(COMMON_D); fi