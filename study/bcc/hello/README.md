## C

```bash
make
```

```bash
sudo ./hello
```

## Python

```bash
sudo python ./hello.py
```

## Problems

### one

```
create_probe_event: open(/sys/kernel/tracing/kprobe_events): No such file or directory
```

```bash
sudo mount -t debugfs debugfs /sys/kernel/debug
```

Automatically mount when boot

```bash
sudo vim /etc/fstab
```

```
debugfs  /sys/kernel/debug  debugfs  defaults  0  0
```

### two

```
cannot attach kprobe, probe entry may not exist
```

```bash
grep sys_exit /proc/kallsyms
```

```
0000000000000000 T __x64_sys_exit
0000000000000000 T __ia32_sys_exit
0000000000000000 T __x64_sys_exit_group
0000000000000000 T __ia32_sys_exit_group
0000000000000000 T __traceiter_sys_exit
0000000000000000 t perf_trace_sys_exit
0000000000000000 t trace_raw_output_sys_exit
0000000000000000 t __bpf_trace_sys_exit
0000000000000000 t trace_event_raw_event_sys_exit
0000000000000000 T __SCT__tp_func_sys_exit
0000000000000000 t trace_init_flags_sys_exit
```

Use event `__x64_sys_exit` instead of `sys_exit`
