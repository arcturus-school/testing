## Test

```sh
sudo ./dist/tcpretrans
```

## Result

```
Tracing tcp retransmission... Hit Ctrl-C to end.
LADDR                LPORT  RADDR                RPORT  RETRANSMITS
^C
172.18.246.19        43680  117.18.232.200       443    6
172.18.246.19        48036  202.160.129.36       443    6
172.18.246.19        55720  151.101.64.223       443    5
```

```
TIME      PID    COMM         IP LADDR                LPORT  T> DADDR                DPORT  STATE
00:08:53  0      swapper/6    4  172.18.246.19        41846  L>  20.189.173.3         443    ESTABLISHED
00:08:53  0      swapper/7    4  172.18.246.19        41846  R>  20.189.173.3         443    ESTABLISHED
00:08:53  0      swapper/7    4  172.18.246.19        41846  R>  20.189.173.3         443    ESTABLISHED
00:08:54  0      swapper/6    4  172.18.246.19        41846  L>  20.189.173.3         443    LAST_ACK
```

测试本程序可以使用 linux 自带的 `tc` , 也可以使用 `MNemu`

```sh
git clone https://github.com/Corefracture/mnemu.git
```

```sh
cd mnemu; python ./mnemu_web.py
```

打开 mnenu 页面, 对 `Known IPs` 上的 IP 进行请求, 如

```sh
wget 192.168.1.0
```
