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
