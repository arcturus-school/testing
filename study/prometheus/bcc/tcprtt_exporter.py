from prometheus_client import start_http_server, Gauge
from socket import inet_ntop, AF_INET
from bcc import BPF
import struct

# 加载 ebpf 程序
b = BPF(src_file="tcprtt.bcc.c")

# 插入探针
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_send")
b.attach_kprobe(event="tcp_ack", fn_name="trace_tcp_ack")

# 定义 Prometheus 指标
arg = "tcprtt_ns", "TCP往返延迟(纳秒)", ["src_ip", "dest_ip", "src_port", "dest_port"]
tcp_rtt_gauge = Gauge(*arg)


def ip_to_str(addr):
    return inet_ntop(AF_INET, struct.pack("I", addr))


def handle_event(cpu, data, size):
    event = b["events"].event(data)

    tcp_rtt_gauge.labels(
        src_ip=ip_to_str(event.src_ip),
        dest_ip=ip_to_str(event.dest_ip),
        src_port=event.src_port,
        dest_port=event.dest_port,
    ).set(event.rtt_ns)


b["events"].open_perf_buffer(handle_event)

if __name__ == "__main__":
    start_http_server(8000)

    print("Server is start at http://127.0.0.1:8000")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nexiting...")
