# tping
tping 程序测试网络连通性以及tcp往返延时。
release version: 1.6.4

eg:
```
# ./tping -h
usage: tping [-h] [-d DESTINATION] [-p PORT] [-c COUNT] [-v] [-q] [-P PROMISE]
             [--socks5 <address:port>] [--proxy <HTTP_PROXY_address:port>]
             [-U <user:password>] [-4] [-6] [-V]

Detect network tcp connection validity and packet delay time.

optional arguments:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        ip_addr. hostname. DomainName
  -p PORT, --port PORT  Port
  -c COUNT, --count COUNT
                        Check ping count
  -v, --verbose         more verbose message, [-v -vv]
  -q, --quiet           Silent or quiet mode.
  -P PROMISE, --promise PROMISE
                        保证结果返回的时间 seconds，设置此参数后 -c --count 将失效
  --socks5 <address:port>
                        set socks5 proxy address:port [default port 1080]
  --proxy <HTTP_PROXY_address:port>
                        set HTTP Proxy address:port [default port 8080]
  -U <user:password>, --proxy-user <user:password>
                        Specify the user name and password to use for proxy
                        authentication.
  -4                    use IPv4 transport only [Default ipv4]
  -6                    use IPv6 transport only
  -V, --version         show program's version number and exit


# ./tping -d www.amazon.com -p 443
213.4 ms
211.5 ms
207.6 ms
210.1 ms
212.1 ms
212.6 ms
210.0 ms
213.0 ms
211.1 ms
207.8 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 210.92 ms
```

#### Detail information
```
# ./tping -d www.amazon.com -p 443 -v
54.192.138.90   < 212.4 ms
54.192.138.90   < 211.4 ms
54.192.138.90   < 209.5 ms
54.192.138.90   < 213.4 ms
54.192.138.90   < 207.5 ms
54.192.138.90   < 209.4 ms
54.192.138.90   < 210.6 ms
54.192.138.90   < 210.8 ms
54.192.138.90   < 209.9 ms
54.192.138.90   < 211.5 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 210.63 ms

# ./tping -d www.amazon.com -p 443 -c 3 -vv
54.192.150.165:443   <- 10.7.97.1:42020  112.6 ms
54.192.150.165:443   <- 10.7.97.1:42034  106.3 ms
54.192.150.165:443   <- 10.7.97.1:42048  101.2 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 106.71 ms

# tping.exe -d www.amazon.com -p 443 -c 3 -vvv
[2018-12-20 16:21:43.423170]    54.192.150.165:443   <- 10.7.97.1:42580  112.6 ms
[2018-12-20 16:21:43.537178]    54.192.150.165:443   <- 10.7.97.1:42584  101.5 ms
[2018-12-20 16:21:43.639743]    54.192.150.165:443   <- 10.7.97.1:42592  104.2 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 106.09 ms

```
#### count 3
```
# ./tping -d www.amazon.com -p 443 -c 3
211.7 ms
210.7 ms
212.3 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 211.57 ms
```

#### use socks5 proxy
```
# ./tping --socks5 127.0.0.1 -d www.amazon.com -p 443 -c 3
221.1 ms
219.7 ms
232.5 ms
total: 3  success: 3  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 223.53 ms
```

#### use socks5 Authentication
```
# ./tping --socks5 x.x.x.x:1080 -U foo:bar -d www.baidu.com -p 443
434.6 ms
428.0 ms
421.5 ms
456.2 ms
416.3 ms
457.9 ms
459.1 ms
424.9 ms
423.6 ms
424.5 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 434.67 ms
```

#### use HTTP_PROXY
```
# ./tping --proxy x.x.x.x:8080 --proxy-user foo:bar -d www.baidu.com -p 443
305.3 ms
305.7 ms
296.2 ms
298.4 ms
291.9 ms
335.1 ms
294.4 ms
308.9 ms
295.1 ms
266.5 ms
total: 10  success: 10  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 299.77 ms

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
total: 1  success: 1  failure: 0  s_rate: 1.00  f_rate: 0.00  avg_ms: 187.50 ms
```