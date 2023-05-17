<div align="center">

<h1>EBPF Study</h1>

[环境搭建](./SETUP.md) | [BCC](./bcc) | [Libbpf](./libbpf) | [Prometheus](./prometheus)

<( \_ \_ )>

</div>

## tcprtt

### BCC & Prometheus

#### Setup

```sh
sudo pip install prometheus-client
```

#### Start exporter

```sh
sudo python ./prometheus/bcc/tcprtt_exporter.py
```

Now you can access `http://127.0.0.1:8000/metrics` to see the metrics.

#### edit config file

```yml
# prometheus.yml
scrape_configs:
  - job_name: "prometheus"

    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "tcprtt"

    static_configs:
      - targets: ["localhost:8000"]
```

start prometheus server

```sh
# In your prometheus installation path
./prometheus --config.file=prometheus.yml
```

### Libbpf & Prometheus

#### Setup

Follow [this steps](https://jupp0r.github.io/prometheus-cpp/#autotoc_md4) to install `Prometheus-CPP`.

If following situation happens while running your project:

```
libprometheus-cpp-pull.so.1.1: cannot open shared object file
```

This might happen if you have recently installed a shared library and didn't run ldconfig

```sh
sudo ldconfig
```

You can also install as a static library

```sh
cmake .. -DBUILD_SHARED_LIBS=OFF
```

### Build exporter

```sh
cd ./prometheus/libbpf
```

```sh
make
```

```sh
sudo ./prometheus/dist/tcprtt
```

```
# HELP tcp_rtt Round Trip Time
# TYPE tcp_rtt histogram
tcp_rtt_count{address="all"} 313
tcp_rtt_sum{address="all"} 1022544
tcp_rtt_bucket{address="all",le="1"} 0
tcp_rtt_bucket{address="all",le="2"} 0
tcp_rtt_bucket{address="all",le="4"} 0
tcp_rtt_bucket{address="all",le="8"} 0
tcp_rtt_bucket{address="all",le="16"} 38
tcp_rtt_bucket{address="all",le="32"} 107
tcp_rtt_bucket{address="all",le="64"} 152
tcp_rtt_bucket{address="all",le="128"} 158
tcp_rtt_bucket{address="all",le="256"} 158
tcp_rtt_bucket{address="all",le="512"} 158
tcp_rtt_bucket{address="all",le="1024"} 161
tcp_rtt_bucket{address="all",le="2048"} 167
tcp_rtt_bucket{address="all",le="4096"} 192
tcp_rtt_bucket{address="all",le="8192"} 267
tcp_rtt_bucket{address="all",le="16384"} 313
tcp_rtt_bucket{address="all",le="32768"} 313
tcp_rtt_bucket{address="all",le="65536"} 313
tcp_rtt_bucket{address="all",le="131072"} 313
tcp_rtt_bucket{address="all",le="262144"} 313
tcp_rtt_bucket{address="all",le="524288"} 313
tcp_rtt_bucket{address="all",le="1048576"} 313
tcp_rtt_bucket{address="all",le="2097152"} 313
tcp_rtt_bucket{address="all",le="4194304"} 313
tcp_rtt_bucket{address="all",le="8388608"} 313
tcp_rtt_bucket{address="all",le="16777216"} 313
tcp_rtt_bucket{address="all",le="33554432"} 313
tcp_rtt_bucket{address="all",le="67108864"} 313
tcp_rtt_bucket{address="all",le="134217728"} 313
tcp_rtt_bucket{address="all",le="+Inf"} 313
```
