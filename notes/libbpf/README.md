## Libbpf

### Reference

- [bcc/libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools)

- [bpf-core-reference](https://nakryiko.com/posts/bpf-core-reference-guide/)

- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

- [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main)

- [ebpf_exporter](https://github.com/cloudflare/ebpf_exporter)

- [libbpf-API](https://libbpf.readthedocs.io/en/latest/api.html)

### Examples

- [hello](./hello) hello world demo

- [tcprtt](./tcprtt) TCP Round-Trip Time

- [biolatency](./biolatency) I/O latency

- [tcpconnlat](./tcpconnlat) TCP connection latency

- [tcpretrans](./tcpretrans) TCP retransmission

#### Usage

```sh
make target=hello
```

```sh
make clean target=hello
```

### Other

Generate `vmlinux.h`

```sh
# Make sure you have installed bpftool already.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

If you encounter the following error:

(Why wsl has too many problem... <( \_ \_ )>):

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

Header files missing:

```
/usr/include/features-time64.h:20:10: fatal error: 'bits/wordsize.h' file not found
#include <bits/wordsize.h>
         ^~~~~~~~~~~~~~~~~
1 error generated.
```

```
/usr/include/features.h:486:12: fatal error: 'sys/cdefs.h' file not found
#  include <sys/cdefs.h>
           ^~~~~~~~~~~~~
1 error generated.
```

```
/usr/include/features.h:510:10: fatal error: 'gnu/stubs.h' file not found
#include <gnu/stubs.h>
         ^~~~~~~~~~~~~
1 error generated.
```

Add compile options:

```
-I/usr/include/x86_64-linux-gnu
```

32bit header file missing:

```
/usr/include/features.h:486:12: fatal error: 'sys/cdefs.h' file not found
#  include <sys/cdefs.h>
           ^~~~~~~~~~~~~
1 error generated.
```

```sh
sudo apt-get install libc6-dev-i386
```
