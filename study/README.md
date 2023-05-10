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
