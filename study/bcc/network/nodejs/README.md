## 实验步骤

```sh
sudo apt-get install systemtap-sdt-dev
```

```sh
wget https://nodejs.org/dist/v18.16.0/node-v18.16.0.tar.gz # 下载源码
```

```sh
tar -xvf node-v18.16.0-linux-x64.tar.xz # 解压文件
```

```sh
cd node-v18.16.0
```

```sh
./configure --with-dtrace
```

```sh
make
```

```sh
sudo make install
```

```sh
node --version # 查看是否安装成功
```

```sh
npm install # 安装依赖
```

```sh
node index.js # 运行后端程序
```

```sh
sudo lsof -t -i:8083 # 查看进程号
```

```sh
sudo python ./http__server__request.py 19387 # 运行自定义脚本
```

## output

```
TIME(s)            COMM    PID    ARGS
8510.180134000     <...>   19723  path:/
8551.131897000     node    19723  path:/
8555.107198000     node    19723  path:/test
```
