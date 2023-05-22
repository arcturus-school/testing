## Build

Generate `*.bpf.o` files before make.

```sh
make bpf
```

then

```sh
make
```

Make sure there is a `*.bpf.o` file in `dist` with the same name as the metrics in `config.yaml`.

Now you can run this exporter via

```sh
sudo ./ecli -c config.yaml -v
```

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
docker run --rm -it --privileged -p 8090:8090 \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    ebpf-exporter -v -c config.yaml
```
