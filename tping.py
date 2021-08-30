#!/usr/bin/env python3
try:
    import subprocess
    import time
    import socket
    import random
    import argparse
    from color import *
    import threading
    #from tdigest import TDigest
    import random
    import socks
    import sys
    from datetime import datetime
    from math import trunc
    #import traceback
except:
    exit(130)
# author: Eric.Ren
# prog: tping.exe
__version__="1.8.3"

has_percentile = 0
try:
    # from tdigest import TDigest
    from numpy import percentile
    has_percentile = 1
except:
    pass

class Check_Network:
    STATUS_CODE_SUCCESS=0
    STATUS_CODE_DNS_FAIL=1
    STATUS_CODE_TCP_TIMEOUT=2
    STATUS_CODE_UDP_FAIL=3
    STATUS_CODE_DOMAIN_VALUE_ERROR=4
    STATUS_CODE_CONNECT_REFUSED=5
    STATUS_CODE_SOCKS5_CONNECT_REFUSED=15
    STATUS_CODE_HTTP_PROXY_CONNECT_ERROR=25
    STATUS_CODE_UDP_TIMEOUT=6
    STATUS_CODE_PROMISE_TIMEOUT=7
    __CHECK_DOMAIN_LIST=['www.baidu.com', 'www.microsoft.com', 'www.apple.com']

    def __init__(self, verbose, family_IPv4=True, quiet=False, promise=False, socks5:str=False,
                 HTTP_PROXY:str=False, proxy_user=None, laddr='', lport=0, timeout=3):
        self.family=socket.AF_INET if family_IPv4 else socket.AF_INET6
        # IP 协议栈版本, 默认 IPv4.
        self.verbose=verbose
        self.quiet=quiet
        self.promise=promise
        # 拆分 socks5 proxy 信息。
        self.laddr=laddr
        self.lport=lport
        self.connection_timeout=timeout
        if socks5:
            socks5_info=socks5.split(":")
            if len(socks5_info) == 1:
                self.socks5_addr=socks5_info[0]
                self.socks5_port=1080
            elif len(socks5_info) == 2:
                self.socks5_addr=socks5_info[0]
                self.socks5_port=int(socks5_info[1])
            else:
                raise Exception("socks5 addr was wrong!!")
        else:
            self.socks5_addr=False

        # 拆分 HTTP_PROXY 信息。
        if HTTP_PROXY:
            HTTP_PROXY_info=HTTP_PROXY.split(':')
            if len(HTTP_PROXY_info) == 1:
                self.http_proxy_addr=HTTP_PROXY_info[0]
                self.http_proxy_port=8080
            elif len(HTTP_PROXY_info) == 2:
                self.http_proxy_addr=HTTP_PROXY_info[0]
                self.http_proxy_port=int(HTTP_PROXY_info[1])
            else:
                raise Exception('HTTP_Proxy addr was wrong!!')
        else:
            self.http_proxy_addr=False

        # 拆分proxy user 信息。
        if proxy_user:
            PROXY_USER_info=proxy_user.split(':')
            if len(PROXY_USER_info) == 2:
                self.proxy_user=PROXY_USER_info[0]
                self.proxy_password=PROXY_USER_info[1]
            else:
                raise Exception('Proxy authentication was wrong!! -> %s' % repr(proxy_user))
        else:
            self.proxy_user=None
            self.proxy_password=None

    def __check_dns_resolve(self):
        for domain in self.__CHECK_DOMAIN_LIST:
            proc=subprocess.Popen("nslookup -",
                                    shell=True,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            stdout, stderr=proc.communicate(domain)
            stderr=stderr.replace("> ", '')
            if len(stderr) > 0:
                raise Exception('%s check_dns_resolve has a error\n  %s  --> %s' % (
                self.color_msg('Error:', 'red', True), stderr, domain))
        return "%s DNS check is OK" % self.color_msg('INFO:', 'green')

    def __str__(self):
        try:
            return self.__check_dns_resolve()
        except Exception as err:
            return str(err)

    def check_dns_status(self):
        resp=self.__check_dns_resolve()
        return self.STATUS_CODE_SUCCESS, resp

    def _check_tcp_status(self, host, port, protect=True):
        '''
        :param host: 主机，IP地址 或 主机名字符串
        :param port: 端口, 数值
        :param protect: 添加最短时间的保护功能,布尔值
        :return:
        '''
        if self.socks5_addr and self.socks5_port:
            sock=socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.set_proxy(socks.SOCKS5, self.socks5_addr, self.socks5_port,
                           username=self.proxy_user, password=self.proxy_password)
        elif self.http_proxy_addr and self.http_proxy_port:
            sock=socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.set_proxy(socks.HTTP, self.http_proxy_addr, self.http_proxy_port,
                           username=self.proxy_user, password=self.proxy_password)
        else:
            sock=socket.socket(self.family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.laddr, self.lport))
        except OSError as err:
            if err.strerror == 'Address already in use':
                print('Address or port already in use')
            elif err.strerror == 'Cannot assign requested address':
                print('-> %s <- laddr was wrong!' % self.laddr)
            exit(10)
        except (OverflowError, TypeError):
            print('-> %s <- lport was wrong!' % self.lport)
            exit(10)

        sock.settimeout(self.connection_timeout)
        ip_addr=self.to_ipaddr(host)
        if ip_addr[0] != self.STATUS_CODE_SUCCESS:
            return ip_addr
        dest_ip=random.sample(ip_addr[1], 1)[0]

        start=time.time()
        try:
            sock.connect((dest_ip, int(port)))
            # blocking
            # 设置 socks5 代理过后，这里的connect 是连接到 socks5 地址，并不是连接到真是目标地址。


            if self.family == socket.AF_INET6:          # IPv6 getsockname() return 4 item tuple
                local_sock_ip, local_sock_port, *other=sock.getsockname()
            else:
                local_sock_ip, local_sock_port=sock.getsockname()

            if (self.socks5_addr and self.socks5_port) or (self.http_proxy_addr and self.http_proxy_port):
                connect_end=time.time()
                # 代理模式探测数据包
                if port in [80, 443]:
                    sock.sendall(b'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' % host.encode())
                else:
                    sock.sendall(b"\0")
                sock.recv(100)
                end=time.time()
            else:
                end=time.time()
            # 取连接后的时间戳
            time_consuming=(end - start) * 1000
            # 取两次时间戳的差值，并转换为 ms
            if time_consuming < 10 and protect is True:
                # 判断时间差值，以及是否设置最小值保护
                time.sleep(0.01 - time_consuming / 1000)
                # 保持两次检测时间最小时间差为 10ms
            return self.STATUS_CODE_SUCCESS, time_consuming, 'ms', dest_ip, \
                   int(port), local_sock_ip, local_sock_port, datetime.fromtimestamp(start)
        except (
                socket.timeout,
                ConnectionRefusedError,
                socks.ProxyConnectionError,
                socks.GeneralProxyError,
                socks.HTTPError, socket.timeout
                ) as err:
            # traceback.print_exc()
            time.sleep(0.01)

            # connect 方法报错，让然获取该 socket 的 laddr 信息。
            if self.family == socket.AF_INET6:          # IPv6 getsockname() return 4 item tuple
                local_sock_ip, local_sock_port, *other=sock.getsockname()
            else:
                # import traceback
                # print(err)
                # print(dir(err))
                # traceback.print_tb(sys.exc_info()[2])
                if (self.socks5_addr and self.socks5_port) or (self.http_proxy_addr and self.http_proxy_port) and \
                        isinstance(err, socks.ProxyConnectionError):
                    local_sock_ip="0.0.0.0"
                    local_sock_port=0
                else:
                    local_sock_ip, local_sock_port=sock.getsockname()

            if err.errno == 61 or err.errno == 113 or err.errno == 111:
                return self.STATUS_CODE_CONNECT_REFUSED, err.strerror, None, dest_ip, \
                       int(port), local_sock_ip, local_sock_port, datetime.fromtimestamp(start)

            elif 'socket_err' in dir(err) and isinstance(err.socket_err, ConnectionRefusedError):
                # 两种代理模式，连接被重置
                return self.STATUS_CODE_CONNECT_REFUSED, err.msg.strip(), None, dest_ip, \
                       int(port), local_sock_ip, local_sock_port, datetime.fromtimestamp(start)

            elif 'socket_err' in dir(err) and isinstance(err.socket_err, socks.HTTPError):
                # 通过代理连接目标服务器，认证失败后，代理服务器告知认证失败
                return self.STATUS_CODE_HTTP_PROXY_CONNECT_ERROR, err.msg.strip(), None, dest_ip, \
                       int(port), local_sock_ip, local_sock_port, datetime.fromtimestamp(start)
            elif isinstance(err, socks.GeneralProxyError) and \
                    'socket_err' in dir(err) and \
                    'msg' in dir(err.socket_err) and \
                    err.socket_err.msg == "0x06: TTL expired":
                # 通过代理连接目标服务器，认证失败后，被代理服务端主动断开连接

                return self.STATUS_CODE_SOCKS5_CONNECT_REFUSED, "SOCKS5 Authenticate failure", None, dest_ip, \
                       int(port), local_sock_ip, local_sock_port, datetime.fromtimestamp(start)
            else:
                return self.STATUS_CODE_TCP_TIMEOUT, self.connection_timeout, "ms", dest_ip, \
                       int(port), local_sock_ip, local_sock_port, datetime.fromtimestamp(start)
        except OSError as err:
            print(dest_ip, err.strerror)
            raise SystemExit(126)
        finally:
            sock.close()

    def to_ipaddr(self, host, family=socket.AF_UNSPEC):
        """
        dns 解析地址
        :param host:
        :param family:
        :return:
        """
        if hasattr(self, "ipaddrs"):
            # 一次解析，多次使用
            return self.STATUS_CODE_SUCCESS, self.ipaddrs
        else:
            ipaddrs=set()
        try:
            # getaddrinfo query all sock_type address.
            resolv=socket.getaddrinfo(host, None,
                                        family=family,
                                        type=socket.SOCK_STREAM,
                                        proto=0,
                                        flags=socket.AI_ADDRCONFIG)
        except socket.gaierror:
            return self.STATUS_CODE_DOMAIN_VALUE_ERROR, "--> %s <-- host or address syntax error." % host
        else:
            for item in resolv:
               if item[0] == self.family:
                   ipaddrs.add(item[-1][0])
            if len(ipaddrs) > 0:
                self.ipaddrs=tuple(ipaddrs)
                return self.STATUS_CODE_SUCCESS, tuple(ipaddrs)
            else:
                return self.STATUS_CODE_DOMAIN_VALUE_ERROR, "--> %s <-- host or address not resolved." % host

    def to_ipaddr_use_socks5(self, host):
        pass

    def get_local_addr(self):
        return socket.gethostbyname(socket.gethostname())

    def get_tcp_status(self, host, port=80, count=10):
        self.check_count=0
        self.check_success_count=0
        self.check_failure_count=0
        self.ms_list=[]
        if self.promise:
            count=0
            self.check_progress=True

        def _print_ms(host, port):
            """
            single loop & output
            :return:
            """
            conn=self._check_tcp_status(host, port=port)
            self.check_count += 1
            if conn[0] == self.STATUS_CODE_SUCCESS:
                self.check_success_count += 1
                self.ms_list.append(conn[1])
                # 延时添加到延时列表

                if self.verbose == 1:
                    printGreen('%-15s <- %-5.1f %s' %
                               (conn[3], conn[1], conn[2]))
                elif self.verbose == 2:
                    # add client ip:port
                    printGreen('%-20s <- %s:%i\t%-5.1f %s' %
                               (conn[3] + ":" + str(conn[4]), conn[5], conn[6], conn[1], conn[2]))
                elif self.verbose >= 3:
                    # add ISO time
                    printGreen('[%s]\t%-20s <- %s:%i\t%-5.1f %s' %
                               (conn[7], conn[3] + ":" + str(conn[4]), conn[5], conn[6], conn[1], conn[2]))
                elif self.quiet:
                    pass
                else:
                    print("%-5.1f %s" % (conn[1], conn[2]), flush=True)
            elif conn[0] in [self.STATUS_CODE_CONNECT_REFUSED, self.STATUS_CODE_SOCKS5_CONNECT_REFUSED,
                             self.STATUS_CODE_HTTP_PROXY_CONNECT_ERROR]:
                self.check_failure_count += 1
                if self.verbose == 1:
                    printRed('%-15s <- %s' % (conn[3], conn[1]))
                elif self.verbose == 2:
                    # add client ip:port
                    printRed('%-20s <- %s:%i  %s' %
                             (conn[3] + ":" + str(conn[4]), conn[5], conn[6], conn[1]))
                elif self.verbose >= 3:
                    # add ISO time
                    printRed('[%s]\t%-20s <- %s:%i  %s' %
                             (conn[7], conn[3] + ":" + str(conn[4]), conn[5], conn[6], conn[1]))
                elif self.quiet:
                    pass
                else:
                    print(conn[1], flush=True)
            elif conn[0] == self.STATUS_CODE_DOMAIN_VALUE_ERROR:
                self.check_failure_count += 1
                if self.verbose:
                    printRed('%-30s <- %s' % (conn[1], 'invalid destination'))
                elif self.quiet:
                    pass
                else:
                    print("invalid destination", flush=True)
            else:
                self.check_failure_count += 1
                if self.verbose == 1:
                    printRed('%-15s <- timeout' % conn[3])
                elif self.verbose == 2:
                    # add client ip:port
                    printRed('%-20s <- %s:%i  timeout' %
                             (conn[3] + ":" + str(conn[4]), conn[5], conn[6]))
                elif self.verbose >= 3:
                    # add ISO time
                    printRed('[%s]\t%-20s <- %s:%i  timeout' %
                             (conn[7], conn[3] + ":" + str(conn[4]), conn[5], conn[6]))
                elif self.quiet:
                    pass
                else:
                    print("timeout", flush=True)

        try:
            if port.find("-") >= 0 or port.find(",") >= 0:
                # [80-65535 | 80,443] 多端口范围类型
                port = port.strip(",-")
                port_range = []
                if port.find(',') > -1:
                    for i in port.split(','):
                        try:
                            port_range.append(int(i))
                        except ValueError:
                            if i.find("-") > -1:
                                i = i.strip("-")
                                ports = i.split("-")
                                port_start = int(ports[0])
                                port_end = int(ports[1])
                                port_range += range(port_start, port_end + 1)
                if port.find("-") > -1 and port.find(',') < 0:
                    ports = port.split("-")
                    port_start = int(ports[0])
                    port_end = int(ports[1])
                    port_range += range(port_start, port_end + 1)
                port_range = list(set(port_range))
            else:
                port_range=[int(port)]

            if count <= 0:
                while not self.promise or self.check_progress:
                    # 当promise选项未设置，且 count 为 0 的时候，无限检测。
                    _print_ms(host=host, port=random.choice(port_range))
            else:
                while count > 0:
                    count -= 1
                    _print_ms(host=host, port=random.choice(port_range))
        except Exception as err:
            # print(dir(err))
            # traceback.print_exc()
            print(repr(err), flush=True)
        finally:
            self.get_footer_stats()

    def get_footer_stats(self):
        try:
            self.check_progress=False
            try:
                avg_ms=sum(self.ms_list) / len(self.ms_list)
            except ZeroDivisionError:
                # 捕获全部检测失败的情况。
                avg_ms=0

            # 打印百分比分布信息 percentile
            # if sys.modules.get("tdigest"):
            if has_percentile:
                # digest = TDigest()
                # for item in self.ms_list:
                #     digest.update(item)
                # p50 = digest.percentile(50)
                # p90 = digest.percentile(90)
                # p99 = di
                # gest.percentile(99)
                p50 = percentile(self.ms_list, 50)
                p80 = percentile(self.ms_list, 80)
                p90 = percentile(self.ms_list, 90)
                p99 = percentile(self.ms_list, 99)
                percentile_string = "\t p50: %.2f  p80: %.2f  p90: %.2f  p99: %.2f" % (
                    p50, p80, p90, p99
                )
            else:
                percentile_string = ""

            footer="\rtotal: %d  success: %d  failure: %d  s_rate: %.2f  f_rate: %.2f  avg_ms: %.2f ms" % (
                self.check_count,
                self.check_success_count,
                self.check_failure_count,
                self.check_success_count / self.check_count,
                self.check_failure_count / self.check_count,
                avg_ms
            )
            print(footer + percentile_string, file=sys.stderr, flush=True)
            if self.check_success_count / self.check_count == 0:
                # 如果一个都没有成功，则返回状态码 1.
                exit(1)
            elif self.check_success_count / self.check_count < 1:
                # 返回成功率的整数状态码
                exit(trunc(self.check_success_count / self.check_count * 100))
            else:
                # 全部成功，退出状态码 0。
                #exit(0)
                pass
        except Exception:
            # 指定 Exception 不捕获 exit 退出异常动作。
            pass

    def end_promise(self):
        # 结束 promise 保证时间，终止网络延时检测，打印结果
        self.check_progress=False

    def check_tcp_status(self, host, port=80, count=1):
        return tuple([self._check_tcp_status(host, port=port)[0] for i in range(count)])

    def __get_udp_snmp_status(self, community, host, oid='.1.3.6.1.2', version="2c"):
        '''
        调用 snmpget 程序获取主机的固定 oid，snmp 版本为 v2c。
        :param community: snmp 团体名
        :param host: 要查询的snmp server
        :param oid: 默认 oid 为查询网络接口信息。
        :param version: snmp 版本信息，默认版本 2
        :return: 返回元组。
        '''
        ip_addr=self.to_ipaddr(host)
        ip=random.sample(ip_addr, 1)[0]
        try:
            # 修复系统未安装 net-snmp-utils 的错误。
            is_install_snmp_utils=subprocess.Popen('snmpget', shell=True, stdout=subprocess.PIPE,
                                                     stderr=subprocess.PIPE)
            stdout, stderr=is_install_snmp_utils.communicate()
            if "command not found" in stderr:
                raise subprocess.CalledProcessError(1, 'snmpget')
        except subprocess.CalledProcessError:
            install_snmp_utils=subprocess.Popen("yum install -y -q net-snmp-utils",
                                                  shell=True,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE)
            install_snmp_utils.communicate()
        start=time.time()
        proc=subprocess.Popen("snmpget -r 0 -t 1 -c {} -v {} -O n {} {}".format(community, version, ip, oid),
                                shell=True,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        end=time.time()
        stdout, stderr=proc.communicate()
        time_consuming=(end - start) * 1000
        if stderr.startswith('Timeout'):
            return self.STATUS_CODE_UDP_TIMEOUT, None, None, ip
        else:
            return self.STATUS_CODE_SUCCESS, time_consuming, 'ms', ip

    def __get_udp_dns_status(self, host):
        '''
        构造 udp 数据报文，查询主机 l.root-server.net. 的 A 记录，class 为 IN。
        :param host: dns server
        :return: 返回元组类型
        '''
        connection_timeout=1
        domain='l.root-servers.net.'
        data=self.__get_dns_hex_data("7d", "f1", '01', '00', '00', '01',
                                       '00', '00', '00', '00', '00', '00', "01", '6c',
                                       '0c', '72', '6f', '6f', '74', '2d', '73', '65',
                                       '72', '76', '65', '72', '73', '03', '6e', '65',
                                       '74', '00', "00", '01', '00', '01')
        ip_addr=self.to_ipaddr(host)
        ip=random.sample(ip_addr, 1)[0]
        sock=socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.settimeout(connection_timeout)
        start=time.time()
        sock.sendto(data, (ip, 53))
        try:
            data, address=sock.recvfrom(65530)
        except socket.timeout:
            return self.STATUS_CODE_UDP_TIMEOUT, None, None, ip
        end=time.time()
        time_consuming=(end - start) * 1000
        if time_consuming < 50:
            time.sleep((50 - time_consuming) / 1000)
        return self.STATUS_CODE_SUCCESS, time_consuming, 'ms', ip

    def __get_dns_hex_data(self, *string):
        if string.__class__ is str:
            ret=""
            for i in string:
                ret += chr(eval("0x" + i))
            return ret
        return chr(eval("0x" + string))

    def get_udp_dns_status(self, dns_server, count=10):
        for i in range(count):
            resp=self.__get_udp_dns_status(dns_server)
            if resp[1] == 'timeout':
                print(resp)
            print(resp[0], "%-5.1f" % resp[1], resp[2], resp[3])

    def check_udp_status(self, host, check_type='dns', snmp_community=None, snmp_version='2c'):
        if check_type == 'dns':
            resp=self.__get_udp_dns_status(host)
        elif check_type == 'snmp':
            resp=self.__get_udp_snmp_status(community=snmp_community, host=host, version=snmp_version)
        if resp[0] != 0:
            return resp[0], 'timeout', resp[2], resp[3]
        return resp

parser=argparse.ArgumentParser(prog='tping', description="Detect network tcp connection validity and packet delay time.")
parser.add_argument("-d", "--destination", action='store', help='ip_addr|hostname|DomainName')
parser.add_argument("-p", '--port', action='store', type=str, default='', help='tcp port number, or multiport number\nEx: 80|80,443|1-65535')
parser.add_argument("-c", '--count', action='store', type=int, default=10, help='Check ping count')
parser.add_argument('-v', '--verbose', action='count', default=0, help='more verbose message, [-v|-vv|-vvv]')
parser.add_argument('-q', '--quiet', action='store_true', default=False, help='Silent or quiet mode.')
parser.add_argument('-t', '--timeout', action='store', type=int, default=3, help='Connection timeout seconds. [default timeout 3s]')
parser.add_argument('-P', '--promise', action='store', type=int, default=0, help='保证结果返回的时间 seconds，设置此参数后 -c|--count 将失效')
parser.add_argument('--socks5', action='store', type=str, required=False, metavar="<address:port>",
                    default=False, help='set socks5 proxy address:port [default port 1080]')
parser.add_argument('--proxy', action='store', type=str, required=False, metavar="<HTTP_PROXY_address:port>",
                    default=False, help='set HTTP Proxy address:port [default port 8080]')
parser.add_argument('-U', '--proxy-user', action='store', type=str, required=False, metavar="<user:password>",
                    dest='proxy_user', default=False, help='Specify the user name and password to use for proxy authentication.')
parser.add_argument('-4', action='store_true', dest='family', default=True, help='use IPv4 transport only [Default ipv4]')
parser.add_argument('-6', action='store_false', dest='family', default=False, help='use IPv6 transport only')
parser.add_argument('--laddr', action='store', type=str, default='', help='Source address use, default local Main IP.')
parser.add_argument('--lport', action='store', type=int, default=0,
                    help='Source port use, default System allocation. <unrecommended!>')
parser.add_argument('-V', '--version', action='version', version='%(prog)s {}'.format(__version__))
args=parser.parse_args()

if args.socks5:
    instance=Check_Network(verbose=args.verbose, family_IPv4=args.family, quiet=args.quiet,
                             promise=args.promise, socks5=args.socks5, proxy_user=args.proxy_user,
                             laddr=args.laddr, lport=args.lport, timeout=args.timeout)
elif args.proxy:
    instance=Check_Network(verbose=args.verbose, family_IPv4=args.family, quiet=args.quiet,
                             promise=args.promise, HTTP_PROXY=args.proxy, proxy_user=args.proxy_user,
                             laddr=args.laddr, lport=args.lport, timeout=args.timeout)
else:
    instance=Check_Network(verbose=args.verbose, family_IPv4=args.family, quiet=args.quiet,
                             promise=args.promise, laddr=args.laddr, lport=args.lport, timeout=args.timeout)

try:
    if args.promise:
        try:
            t1=threading.Timer(args.promise, instance.end_promise)
            t1.setName("Promise thread")
            t1.start()
        except KeyboardInterrupt:
            # 修复 Promise 线程等待期间，由于 ctrl - C 造成的异常抛错问题。
            exit(130)
        if args.count != 10:
            print('warning: you have specified the PROMISE option, COUNT option was invalid.', file=sys.stderr)
        instance.get_tcp_status(host=args.destination, port=args.port)
    else:
        instance.get_tcp_status(host=args.destination, port=args.port, count=args.count)
except (Exception, KeyboardInterrupt):
    pass
