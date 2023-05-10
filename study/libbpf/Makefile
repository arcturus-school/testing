CLAND   := clang
CC      := gcc
CFLAGS  := -O2 -g -Wall
BPF     := -target bpf
VMLINUX := ./vmlinux.h
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