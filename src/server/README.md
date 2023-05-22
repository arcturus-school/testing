## Use shell

```sh
chmod +x ./run.sh
```

```sh
./run.sh
```

## Use docker

```sh
docker build -t ebpf-exporter .
```

```sh
docker run --rm -itd --privileged -p 8089:8089 \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    ebpf-exporter -v -c config.yaml
```

server is running at `127.0.0.1:8089/metrics` .
