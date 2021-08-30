# tping
A simple tcp RTT test program by Python.
tping 程序测试网络连通性以及tcp往返延时。

release version: 1.8.3

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
  -h, --help            show this help message and exit.
  -d DESTINATION, --destination DESTINATION
                        ip_addr|hostname|DomainName
  -p PORT, --port PORT  tcp port number, or multiport number. Example:
                        80|80,443|1-65535
  -c COUNT, --count COUNT
                        Check tping count
  -v, --verbose         more verbose message, [-v|-vv|-vvv]
  -q, --quiet           Silent or quiet mode.
  -t TIMEOUT, --timeout TIMEOUT
                        Connection timeout seconds. [default 3s]
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
291.8 ms
timeout
235.9 ms
244.6 ms
294.9 ms
timeout
361.7 ms
306.8 ms
306.3 ms
306.3 ms
total: 10  success: 8  failure: 2  s_rate: 0.80  f_rate: 0.20  avg_ms: 293.54 ms         p50: 300.58  p80: 306.57  p90: 323.23  p99: 357.83
```

#### Detail information
```
# ./tping -d www.amazon.com -p 443 -v
13.224.162.195  <- timeout          ## Red
13.224.162.195  <- 264.7 ms         ## Green
13.224.162.195  <- timeout          ## Red
13.224.162.195  <- 260.1 ms         ## Green
13.224.162.195  <- 307.2 ms         ## Green
13.224.162.195  <- 248.3 ms
13.224.162.195  <- 295.1 ms
13.224.162.195  <- 240.9 ms
13.224.162.195  <- 339.7 ms
13.224.162.195  <- 306.5 ms
total: 10  success: 8  failure: 2  s_rate: 0.80  f_rate: 0.20  avg_ms: 282.82 ms         p50: 279.92  p80: 306.91  p90: 316.94  p99: 337.45


# ./tping -d www.amazon.com -p 443 --count 3 -vv
13.224.162.195:443   <- 192.168.22.5:61486      241.5 ms
13.224.162.195:443   <- 192.168.22.5:61489      238.1 ms
13.224.162.195:443   <- 192.168.22.5:61490      1288.8 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 589.47 ms  p50: 241.49  p80: 869.89  p90: 1079.35  p99: 1267.87


# tping.exe -d www.amazon.com -p 443 --count 3 -vvv
[2021-08-31 02:47:51.287668]    13.224.162.195:443   <- 192.168.22.5:61491      320.2 ms
[2021-08-31 02:47:51.608686]    13.224.162.195:443   <- 192.168.22.5:61492      239.9 ms
[2021-08-31 02:47:51.849079]    13.224.162.195:443   <- 192.168.22.5:61495      244.7 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 268.30 ms  p50: 244.74  p80: 290.03  p90: 305.12  p99: 318.71
```

#### Multiport Test
```shell
./tping -d www.bestbuy.com -p 80,443 -vv
13.224.162.195:80    <- 192.168.22.5:61506      233.5 ms        ## Port 80
13.224.162.195:443   <- 192.168.22.5:61508      323.0 ms        ## Port 443
13.224.162.195:443   <- 192.168.22.5:61509      241.7 ms        ## Green
13.224.162.195:443   <- 192.168.22.5:61510      236.5 ms
13.224.162.195:443   <- 192.168.22.5:61511      339.0 ms
13.224.162.195:80    <- 192.168.22.5:61512      1248.3 ms
13.224.162.195:443   <- 192.168.22.5:61513      240.4 ms
13.224.162.195:80    <- 192.168.22.5:61514      244.4 ms
13.224.162.195:80    <- 192.168.22.5:61515      236.7 ms
13.224.162.195:80    <- 192.168.22.5:61516      240.8 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 358.44 ms        p50: 241.27  p80: 326.18  p90: 429.93  p99: 1166.51
```

#### count 3
```
# ./tping -d www.amazon.com -p 443 -c 3
309.3 ms
233.0 ms
238.6 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 260.29 ms  p50: 238.62  p80: 281.01  p90: 295.13  p99: 307.85
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
