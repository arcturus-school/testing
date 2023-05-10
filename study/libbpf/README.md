## Libbpf

### Reference

- [bcc/libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools)

- [bpf-core-reference](https://nakryiko.com/posts/bpf-core-reference-guide/)

- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

- [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main)

### Examples

- [hello](./hello) hello world demo

### Other

Generate `vmlinux.h`

```sh
# Make sure you have installed bpftool already.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

If you encounter the following error:

```
/usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
#include <asm/types.h>
         ^~~~~~~~~~~~~
1 error generated.
```

Create a symbolic Link to asm ( you need to have `asm-generic` )

```sh
sudo ln -s /usr/include/asm-generic /usr/include/asm
```
