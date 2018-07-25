#!/bin/env python3
import subprocess, time, socket, random
import argparse
from color import *
# author: guisheng.ren
# version: 1.2
# prog: tping.exe

class Check_Network:
    STATUS_CODE_SUCCESS = 0
    STATUS_CODE_DNS_FAIL = 1
    STATUS_CODE_TCP_TIMEOUT = 2
    STATUS_CODE_UDP_FAIL = 3
    STATUS_CODE_DOMAIN_VALUE_ERROR = 4
    STATUS_CODE_CONNECT_REFUSED = 5
    STATUS_CODE_UDP_TIMEOUT = 6
    __CHECK_DOMAIN_LIST = ['www.baidu.com', 'www.sina.com.cn', 'mirrors.aliyun.com']

    def __init__(self, verbose, quiet = False):
        self.verbose = verbose
        self.quiet = quiet

    def __check_dns_resolve(self):
        for domain in self.__CHECK_DOMAIN_LIST:
            proc = subprocess.Popen("nslookup -",
                                    shell = True,
                                    stdin = subprocess.PIPE,
                                    stdout = subprocess.PIPE,
                                    stderr = subprocess.PIPE)
            stdout, stderr = proc.communicate(domain)
            stderr = stderr.replace("> ", '')
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
        resp = self.__check_dns_resolve()
        return self.STATUS_CODE_SUCCESS, resp

    def _check_tcp_status(self, host, port, protect = True):
        '''
        :param host: 主机，IP地址 或 主机名字符串
        :param port: 端口, 数值
        :param protect: 添加最短时间的保护功能,布尔值
        :return:
        '''
        connect_timeout = 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(connect_timeout)
        ip_addr = self.to_ipaddr(host)
        if ip_addr[0] != self.STATUS_CODE_SUCCESS:
            return ip_addr
        ip = random.sample(ip_addr[1], 1)[0]
        start = time.time()
        try:
            sock.connect((ip, int(port)))
            # blocking
            end = time.time()
            # 取连接后的时间戳
            time_consuming = (end - start) * 1000
            # 取两次时间戳的差值，并转换为 ms
            if time_consuming < 10 and protect is True:
                # 判断时间差值，以及是否设置最小值保护
                time.sleep(0.01 - time_consuming / 1000)
                # 保持两次检测时间最小时间差为 10ms
            return self.STATUS_CODE_SUCCESS, time_consuming, 'ms', ip
        except (socket.timeout, ConnectionRefusedError) as err:
            time.sleep(0.01)
            if err.errno == 61 or err.errno == 113 or err.errno == 111:
                return self.STATUS_CODE_CONNECT_REFUSED, err.strerror, None, ip
            else:
                return self.STATUS_CODE_TCP_TIMEOUT, connect_timeout, None, ip
        finally:
            sock.close()

    def to_ipaddr(self, host):
        ipaddrs = set()
        try:
            resolv = socket.getaddrinfo(host, None, family = socket.AF_INET, type = socket.SOCK_DGRAM)
        except socket.gaierror:
            #raise ValueError("--> %s <-- host syntax error." % repr(host))
            return self.STATUS_CODE_DOMAIN_VALUE_ERROR, "--> %s <-- host syntax error." % repr(host)
        else:
            for item in resolv:
               ipaddrs.add(item[-1][0])
            return self.STATUS_CODE_SUCCESS, tuple(ipaddrs)

    def get_local_addr(self):
        return socket.gethostbyname(socket.gethostname())

    def get_tcp_status(self, host, port = 80, count = 10):
        check_count = 0
        check_success_count = 0
        check_failure_count = 0
        ms_list = []
        try:
            if count == 0 or count < 0:
                while True:
                    conn = self._check_tcp_status(host, port = port)
                    check_count += 1
                    if conn[0] == 0:
                        check_success_count += 1
                        ms_list.append(conn[1])
                        # 延时添加到延时列表

                        if self.verbose:
                            printGreen('%-15s < %-5.1f %s' % (conn[3], conn[1], conn[2]))
                        elif self.quiet:
                            pass
                        else:
                            print("%-5.1f %s" % (conn[1], conn[2]))
                    elif conn[0] == self.STATUS_CODE_CONNECT_REFUSED:
                        check_failure_count += 1
                        if self.verbose:
                            printRed('%-15s < %s' % (conn[3], conn[1]))
                        elif self.quiet:
                            pass
                        else:
                            print(conn[1])
                    elif conn[0] == self.STATUS_CODE_DOMAIN_VALUE_ERROR:
                        check_failure_count += 1
                        if self.verbose:
                            printRed('%-30s < %s' % (conn[1], 'invalid destination'))
                        elif self.quiet:
                            pass
                        else:
                            print("invalid destination")
                    else:
                        check_failure_count += 1
                        if self.verbose:
                            printRed('%-15s < timeout' % conn[3])
                        elif self.quiet:
                            pass
                        else:
                            print("timeout")
            else:
                while count > 0:
                    count -= 1
                    conn = self._check_tcp_status(host, port = port)
                    check_count += 1
                    if conn[0] == 0:
                        check_success_count += 1
                        ms_list.append(conn[1])
                        # 延时添加到延时列表

                        if self.verbose:
                            printGreen('%-15s < %-5.1f %s' % (conn[3], conn[1], conn[2]))
                        elif self.quiet:
                            pass
                        else:
                            print("%-5.1f %s" % (conn[1], conn[2]))
                    elif conn[0] == self.STATUS_CODE_CONNECT_REFUSED:
                        check_failure_count += 1
                        if self.verbose:
                            printRed('%-15s < %s' % (conn[3], conn[1]))
                        elif self.quiet:
                            pass
                        else:
                            print(conn[1])
                    elif conn[0] == self.STATUS_CODE_DOMAIN_VALUE_ERROR:
                        check_failure_count += 1
                        if self.verbose:
                            printRed('%-30s < %s' % (conn[1], 'invalid destination'))
                        elif self.quiet:
                            pass
                        else:
                            print("invalid destination")
                    else:
                        check_failure_count += 1
                        if self.verbose:
                            printRed('%-15s < timeout' % conn[3])
                        elif self.quiet:
                            pass
                        else:
                            print("timeout")
        finally:
            try:
                avg_ms = sum(ms_list) / len(ms_list)
            except ZeroDivisionError:
                # 捕获全部检测失败的情况。
                avg_ms = 0

            footer = "\rtotal: %d  success: %d  failure: %d  s_rate: %.2f  f_rate: %.2f  avg_ms: %.2f ms" % (
                check_count,
                check_success_count,
                check_failure_count,
                check_success_count / check_count,
                check_failure_count / check_count,
                avg_ms
            )
            print(footer)

    def check_tcp_status(self, host, port = 80, count = 1):
        return tuple([self._check_tcp_status(host, port = port)[0] for i in range(count)])

    def __get_udp_snmp_status(self, community, host, oid = '.1.3.6.1.2', version = "2c"):
        '''
        调用 snmpget 程序获取主机的固定 oid，snmp 版本为 v2c。
        :param community: snmp 团体名
        :param host: 要查询的snmp server
        :param oid: 默认 oid 为查询网络接口信息。
        :param version: snmp 版本信息，默认版本 2
        :return: 返回元组。
        '''
        ip_addr = self.to_ipaddr(host)
        ip = random.sample(ip_addr, 1)[0]
        try:
            # 修复系统未安装 net-snmp-utils 的错误。
            is_install_snmp_utils = subprocess.Popen('snmpget', shell = True, stdout = subprocess.PIPE,
                                                     stderr = subprocess.PIPE)
            stdout, stderr = is_install_snmp_utils.communicate()
            if "command not found" in stderr:
                raise subprocess.CalledProcessError(1, 'snmpget')
        except subprocess.CalledProcessError:
            install_snmp_utils = subprocess.Popen("yum install -y -q net-snmp-utils",
                                                  shell = True,
                                                  stdout = subprocess.PIPE,
                                                  stderr = subprocess.PIPE)
            install_snmp_utils.communicate()
        start = time.time()
        proc = subprocess.Popen("snmpget -r 0 -t 1 -c {} -v {} -O n {} {}".format(community, version, ip, oid),
                                shell = True,
                                stdin = subprocess.PIPE,
                                stdout = subprocess.PIPE,
                                stderr = subprocess.PIPE)
        end = time.time()
        stdout, stderr = proc.communicate()
        time_consuming = (end - start) * 1000
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
        connection_timeout = 1
        domain = 'l.root-servers.net.'
        data = self.__get_dns_hex_data("7d", "f1", '01', '00', '00', '01',
                                       '00', '00', '00', '00', '00', '00', "01", '6c',
                                       '0c', '72', '6f', '6f', '74', '2d', '73', '65',
                                       '72', '76', '65', '72', '73', '03', '6e', '65',
                                       '74', '00', "00", '01', '00', '01')
        ip_addr = self.to_ipaddr(host)
        ip = random.sample(ip_addr, 1)[0]
        sock = socket.socket(family = socket.AF_INET, type = socket.SOCK_DGRAM)
        sock.settimeout(connection_timeout)
        start = time.time()
        sock.sendto(data, (ip, 53))
        try:
            data, address = sock.recvfrom(65530)
        except socket.timeout:
            return self.STATUS_CODE_UDP_TIMEOUT, None, None, ip
        end = time.time()
        time_consuming = (end - start) * 1000
        if time_consuming < 50:
            time.sleep((50 - time_consuming) / 1000)
        return self.STATUS_CODE_SUCCESS, time_consuming, 'ms', ip

    def __get_dns_hex_data(self, *string):
        if string.__class__ is str:
            ret = ""
            for i in string:
                ret += chr(eval("0x" + i))
            return ret
        return chr(eval("0x" + string))

    def get_udp_dns_status(self, dns_server, count = 10):
        for i in range(count):
            resp = self.__get_udp_dns_status(dns_server)
            if resp[1] == 'timeout':
                print(resp)
            print(resp[0], "%-5.1f" % resp[1], resp[2], resp[3])

    def check_udp_status(self, host, check_type = 'dns', snmp_community = None, snmp_version = '2c'):
        if check_type == 'dns':
            resp = self.__get_udp_dns_status(host)
        elif check_type == 'snmp':
            resp = self.__get_udp_snmp_status(community = snmp_community, host = host, version = snmp_version)
        if resp[0] != 0:
            return resp[0], 'timeout', resp[2], resp[3]
        return resp

parser = argparse.ArgumentParser(prog = 'tping', description = "检测网络 tcp 连接有效性以及往返延时时间。")
parser.add_argument("-d", "--destination", action = 'store', help = 'ip_addr. hostname. DomainName')
parser.add_argument("-p", '--port', action = 'store', type = int, help = 'Port')
parser.add_argument("-c", '--count', action = 'store', type = int, default = 10, help = 'Check pin count')
parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = 'more verbose message')
parser.add_argument('-q', '--quiet', action = 'store_true', default = False, help = 'Silent or quiet mode.')
parser.add_argument('-V', '--version', action = 'version', version = '%(prog)s v1.2')
args = parser.parse_args()

instance = Check_Network(args.verbose, args.quiet)
try:
    instance.get_tcp_status(host = args.destination, port = args.port, count = args.count)
except KeyboardInterrupt:
    pass
