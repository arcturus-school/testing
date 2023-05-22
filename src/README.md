## Download

```sh
git clone --recurse-submodules https://github.com/arcturus-school/testing.git
```

### Prometheus

```sh
wget https://github.com/prometheus/prometheus/releases/download/v2.44.0/prometheus-2.44.0.linux-amd64.tar.gz
```

```sh
tar -zxvf prometheus-2.44.0.linux-amd64.tar.gz
```

```sh
mv prometheus-2.44.0.linux-amd64 prometheus
```

```sh
# 复制配置文件
cp prometheus.yml prometheus/prometheus.yml
```

## Run

```sh
cd server
```

```sh
chmod +x ./run.sh && ./run.sh
```

and then

```sh
cd - && cd prometheus
```

```sh
./prometheus --config.file=prometheus.yml
```
