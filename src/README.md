## Download

```sh
git clone --recurse-submodules https://github.com/arcturus-school/testing.git
```

## Run with Docker

### Install Docker

```sh
curl -fsSL https://get.docker.com | bash -s docker
```

```sh
sudo groupadd docker # create docker user group
```

```sh
sudo usermod -aG docker $USER # add current user to docker user group
```

```sh
reboot
```

### Install Docker-compose

see the latest version via this [address](https://github.com/docker/compose/releases).

```sh
curl -L https://github.com/docker/compose/releases/download/v2.14.0/docker-compose-linux-`uname -m` \
    > ./docker-compose
```

```sh
chmod +x ./docker-compose
```

```sh
sudo mv ./docker-compose /usr/local/bin/docker-compose
```

### Run with Grafana

```sh
sudo docker-compose -f docker-compose-grafana.yml up -d
```

visit `localhost:3000` to see the panels.

prometheus data source url is `http://prometheus:9090` .

### Run with custom frontend

```sh
sudo docker-compose up -d
```
