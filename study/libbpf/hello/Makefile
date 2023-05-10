CLAND   = clang
CC      = gcc
CFLAGS  = -O2 -g -Wall
BPF     = -target bpf
NAME    = hello
OUTPUT  = dist
VMLINUX = ../vmlinux.h
INCLUDE = -I$(dir $(VMLINUX))

$(shell mkdir -p $(OUTPUT))

# Build BPF code
$(OUTPUT)/$(NAME).bpf.o: $(NAME).bpf.c
	$(CLAND) $(CFLAGS) $(BPF) -c $< -o $@

# Generate BPF skeletons
$(OUTPUT)/$(NAME).skel.h: $(OUTPUT)/$(NAME).bpf.o
	bpftool gen skeleton $< > $@

# Build user-space code
$(OUTPUT)/$(NAME).o: $(NAME).c $(OUTPUT)/$(NAME).skel.h
	$(CC) $(CFLAGS) -c $(filter %.c,$^) -o $@

# Build application binary
$(OUTPUT)/$(NAME): $(OUTPUT)/$(NAME).o
	$(CC) $(CFLAGS) $< -lbpf -o $@

all: $(OUTPUT)/$(NAME)

clean:
	if [ -d $(OUTPUT) ]; then rm -rf $(OUTPUT); fi