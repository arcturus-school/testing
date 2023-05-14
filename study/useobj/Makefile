CLAND  := clang
CFLAGS := -O2 -g -Wall 
CPP    := g++

$(shell bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)

all: main

hello.bpf.o: hello.bpf.c
	$(CLAND) $(CFLAGS) -target bpf -c $< -o $@

main: hello.bpf.o main.cpp
	$(CPP) $(CFLAGS) -o main main.cpp -lbpf

clean:
	rm -f hello.bpf.o main
