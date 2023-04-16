## build

```bash
make
```

```bash
sudo ./hello
```

可能出现下面的报错, 修改 LIBS 变量, 选择正确的链接库即可

```
/usr/bin/ld: /tmp/hello-6bbc16.o: in function `main':
hello.c:(.text+0x44): undefined reference to `bpf_load_program'
/usr/bin/ld: hello.c:(.text+0x9b): undefined reference to `bpf_attach_kprobe'
/usr/bin/ld: hello.c:(.text+0xd4): undefined reference to `bpf_detach_kprobe'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
make: *** [Makefile:10: hello] Error 1
```
