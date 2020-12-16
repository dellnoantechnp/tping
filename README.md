# tping
A simple tcp RTT test program by Python.
tping 程序测试网络连通性以及tcp往返延时。

release version: 1.8.2

## Python version Install
```shell
$ git clone https://github.com/dellnoantechnp/tping.git
$ cd tping
$ sudo pip install -r requirements.txt
$ python3 tping.py -d www.amazon.com -p 443
.....
```

## Binary version download
Into `Releases` page, download Linux/Windows version.
```shell
./tping -h
```

## Usage：
eg:
```
# ./tping -h
usage: tping [-h] [-d DESTINATION] [-p PORT] [-c COUNT] [-v] [-q] [-t TIMEOUT]
             [-P PROMISE] [--socks5 <address:port>]
             [--proxy <HTTP_PROXY_address:port>] [-U <user:password>] [-4]
             [-6] [--laddr LADDR] [--lport LPORT] [-V]

Detect network tcp connection validity and packet delay time.

optional arguments:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        ip_addr|hostname|DomainName
  -p PORT, --port PORT  tcp port number, or multiport number Ex:
                        80|80,443|1-65535
  -c COUNT, --count COUNT
                        Check ping count
  -v, --verbose         more verbose message, [-v|-vv|-vvv]
  -q, --quiet           Silent or quiet mode.
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout seconds. [default timeout 3s]
  -P PROMISE, --promise PROMISE
                        保证结果返回的时间 seconds，设置此参数后 -c|--count 将失效
  --socks5 <address:port>
                        set socks5 proxy address:port [default port 1080]
  --proxy <HTTP_PROXY_address:port>
                        set HTTP Proxy address:port [default port 8080]
  -U <user:password>, --proxy-user <user:password>
                        Specify the user name and password to use for proxy
                        authentication.
  -4                    use IPv4 transport only [Default ipv4]
  -6                    use IPv6 transport only
  --laddr LADDR         Source address use, default local Main IP.
  --lport LPORT         Source port use, default System allocation.
                        <unrecommended!>
  -V, --version         show program's version number and exit
```

#### Normal Connect RTT Test
```
# ./tping -d www.amazon.com -p 443
239.8 ms
239.4 ms
243.2 ms
481.4 ms
234.9 ms
236.1 ms
1239.6 ms
232.1 ms
241.4 ms
235.6 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 210.92 ms   p50: 239.58 p90: 860.50 p99: 1239.62
```

#### Detail information
```
# ./tping -d www.amazon.com -p 443 -v
99.84.198.32    <- 190.9 ms
99.84.198.32    <- 195.0 ms
99.84.198.32    <- 198.1 ms
99.84.198.32    <- 198.7 ms
99.84.198.32    <- 1194.1 ms
99.84.198.32    <- 197.2 ms
99.84.198.32    <- 199.2 ms
99.84.198.32    <- 199.4 ms
99.84.198.32    <- 192.8 ms
99.84.198.32    <- 190.0 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 295.53 ms p50: 197.62 p90: 696.76 p99: 1194.08

# ./tping -d www.amazon.com -p 443 --count 3 -vv
[2020-12-11 12:31:32.967200]  99.84.198.32:443     <- 172.17.20.21:6209 199.5 ms
[2020-12-11 12:31:33.167248]  99.84.198.32:443     <- 172.17.20.21:18812  194.3 ms
[2020-12-11 12:31:33.361985]  99.84.198.32:443     <- 172.17.20.21:7677 1192.0 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 528.62 ms p50: 199.50 p90: 1192.00 p99: 1192.00

# tping.exe -d www.amazon.com -p 443 --count 3 -vvv
[2020-12-11 12:31:32.967200]  99.84.198.32:443     <- 172.17.20.21:6209 199.5 ms
[2020-12-11 12:31:33.167248]  99.84.198.32:443     <- 172.17.20.21:18812  194.3 ms
[2020-12-11 12:31:33.361985]  99.84.198.32:443     <- 172.17.20.21:7677 1192.0 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 528.62 ms p50: 199.50 p90: 1192.00 p99: 1192.00

```

#### Multiport Test
```shell
./tping -d www.bestbuy.com -p 80,443 -vv
23.44.52.214:443     <- 172.17.20.21:27849  95.0  ms
23.44.52.214:80      <- 172.17.20.21:2127 1093.8 ms
23.44.52.214:443     <- 172.17.20.21:22335  1091.3 ms
23.44.52.214:443     <- 172.17.20.21:10730  1089.2 ms
23.44.52.214:80      <- 172.17.20.21:13862  83.8  ms
23.44.52.214:443     <- 172.17.20.21:29566  1089.0 ms
23.44.52.214:443     <- 172.17.20.21:2968 90.1  ms
23.44.52.214:443     <- 172.17.20.21:9972 90.1  ms
23.44.52.214:80      <- 172.17.20.21:19536  89.8  ms
23.44.52.214:443     <- 172.17.20.21:15409  95.5  ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 490.76 ms p50: 95.28 p90: 1092.58 p99: 1093.83
```

#### count 3
```
# ./tping -d www.amazon.com -p 443 -c 3
201.8 ms
205.8 ms
202.8 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 203.50 ms p50: 202.84 p90: 205.84 p99: 205.84
```

#### use socks5 proxy
```
# ./tping --socks5 127.0.0.1 -d www.amazon.com -p 443 -c 3
201.8 ms
205.8 ms
202.8 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 203.50 ms p50: 202.84 p90: 205.84 p99: 205.84
```

#### use socks5 Authentication
```
# ./tping --socks5 x.x.x.x:1080 -U foo:bar -d www.baidu.com -p 443
239.8 ms
239.4 ms
243.2 ms
481.4 ms
234.9 ms
236.1 ms
1239.6 ms
232.1 ms
241.4 ms
235.6 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 210.92 ms   p50: 239.58 p90: 860.50 p99: 1239.62
```

#### use HTTP_PROXY
```
# ./tping --proxy x.x.x.x:8080 --proxy-user foo:bar -d www.baidu.com -p 443
239.8 ms
239.4 ms
243.2 ms
481.4 ms
234.9 ms
236.1 ms
1239.6 ms
232.1 ms
241.4 ms
235.6 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 210.92 ms   p50: 239.58 p90: 860.50 p99: 1239.62

# ./tping --proxy x.x.x.x:8081 -U user:wrong_pass -d www.baidu.com -p 443 -c 4
Socket error: 407: Proxy Authentication Required
Socket error: 407: Proxy Authentication Required
Socket error: 407: Proxy Authentication Required
Socket error: 407: Proxy Authentication Required
total: 4  success: 0  failure: 4  s_rate: 0.00  f_rate: 1.00  avg_ms: 0.00 ms
```

#### quiet return (end info on stderr)
```
# python3 tping.py -d www.amazon.com -p 443 -c 20 -q
total: 20  success: 20  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 211.00 ms
```

#### Return within the promised time
```
# time python3 tping.py -d www.amazon.com -p 443 -c 20 --promise 1
warning: you have specified the PROMISE option, COUNT option was invalid.
209.7 ms
211.5 ms
213.8 ms
212.3 ms
210.5 ms
total: 5  success: 5  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 211.55 ms

real    0m1.210s
user    0m0.129s
sys     0m0.024s
```

## Windows Platform:
```
> tping.exe -d www.amazon.com -p 80
201.5 ms
197.5 ms
221.5 ms
214.6 ms
196.5 ms
188.6 ms
205.5 ms
198.5 ms
200.5 ms
198.5 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 202.29 ms

> tping.exe -d www.amazon.com -p 80  -c 1 -v
13.35.122.164   < 187.5 ms
total: 1  success: 1  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 187.50 ms   p50: 187.5 p90: 187.5 p99: 187.5
```
