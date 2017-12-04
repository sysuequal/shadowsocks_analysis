#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import struct
import re
import logging


from shadowsocks import common, lru_cache, eventloop, shell


CACHE_SWEEP_INTERVAL = 30

VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

# 添加inet_pton和inet_ntop到socket当中
common.patch_socket()

# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# DNS报文的question的查询类型
QTYPE_ANY = 255 # 任意类型
QTYPE_A = 1 # 查询域名ipv4 地址
QTYPE_AAAA = 28 # 查询域名 ipv6 地址
QTYPE_CNAME = 5 # 别名记录
QTYPE_NS = 2 # 查询权威DNS服务器
QCLASS_IN = 1 # 表示查询的协议类，比如，IN代表Internet


def build_address(address):
    """
    该方法主要是构建DNS报文中的域名信息，即DNS请求报文中的QNAME部分。

    :param address: 域名。

    :return: DNS报文中的域名信息，即DNS请求报文中的QNAME部分。
    """
    # DNS报文中的域名信息格式为“\x01w\x02ww\00”
    address = address.strip(b'.')
    labels = address.split(b'.')
    results = []
    for label in labels:
        l = len(label)
        if l > 63:
            return None
        results.append(common.chr(l))
        results.append(label)
    results.append(b'\0')
    return b''.join(results)


def build_request(address, qtype):
    """
    该方法主要是构建DNS请求报文，其中包含了Header和Question部分。

    :param address: 域名地址。

    :param qtype: 域名请求的类型，如询问域名的ipv4地址等等。

    :return: DNS请求报文。
    """
    request_id = os.urandom(2) # 随机返回2个字节的byte代表DNS报文的ID

    # !代表network， B代表unsigned char， H代表unsigned short
    # 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    # 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 # RD标志位置为1，代表着递归查询
    # 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 # 代表只有一个查询请求
    # 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    # 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    # 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)

    # request_id + header: Header ；addr + qtype_qclass: Question
    return request_id + header + addr + qtype_qclass


def parse_ip(addrtype, data, length, offset):
    """
    该方法主要是从得到DNS应答报文中解析出ipv4、ipv6地址或者域名信息。
    :param addrtype: 域名请求的类型
    :param data: DNS应答报文
    :param length: ip地址或者域名信息的长度
    :param offset: ip地址或者域名信息的起始位置
    :return: ip地址或者域名信息
    """
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


def parse_name(data, offset):
    """
    该方法主要是解析DNS报文中的域名信息。

    :param data: DNS报文。

    :param offset: 域名信息起始位置。

    :return: 域名信息。
    """
    p = offset
    labels = []
    l = common.ord(data[p])
    while l > 0:
        if (l & (128 + 64)) == (128 + 64):
            # pointer
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            pointer &= 0x3FFF
            r = parse_name(data, pointer)
            labels.append(r[1])
            p += 2
            # pointer is the end
            return p - offset, b'.'.join(labels)
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l
        l = common.ord(data[p])
    return p - offset + 1, b'.'.join(labels)


# rfc1035
# record
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def parse_record(data, offset, question=False):
    """
    该方法主要是对DNS报文中的记录部分进行解析。DNS报文的记录是指除去Header的剩余部分。记录包括了NAME、TYPE、CLASS、TTL、RDLENGTH
    和 RDATA。其中RDATA部分包含了ip地址。

    :param data: DNS报文

    :param offset: 记录部分的起始位置。

    :param question: 判断方法是用来解析DNS请求报文还是DNS应答报文。

    :return: 返回记录解析的元组。(长度，(name, ip, type, class, ttl))
    """
    nlen, name = parse_name(data, offset)
    if not question:
        #     H         H               i           H
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


def parse_header(data):
    """
    该方法主要是解析DNS报文的头部。DNS请求报文和DNS应答报文的头部大小一致，因此可以用同一个方法来解析。

    :param data: DNS报文。

    :return: DNS报文的头部解析结果。
    """
    if len(data) >= 12: # 只有长度大于等于12个字节才有可能是一个头部
        header = struct.unpack('!HBBHHHH', data[:12])
        res_id = header[0]
        res_qr = header[1] & 128
        res_tc = header[1] & 2
        res_ra = header[2] & 128
        res_rcode = header[2] & 15
        # assert res_tc == 0
        # assert res_rcode in [0, 3]
        res_qdcount = header[3]
        res_ancount = header[4]
        res_nscount = header[5]
        res_arcount = header[6]
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)
    return None


def parse_response(data):
    """
    该方法主要是解析DNS报文。

    :param data: DNS报文。

    :return: DNS报文解析结果。
    """
    try:
        if len(data) >= 12:
            header = parse_header(data)
            if not header:
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = header

            qds = [] # 储存请求报文
            ans = [] # 储存应答报文
            offset = 12
            for i in range(0, res_qdcount): # 先解析请求报文
                l, r = parse_record(data, offset, True) # r的格式为 (name, None, type, class, None, None)
                offset += l
                if r:
                    qds.append(r)
            for i in range(0, res_ancount):# 再解析应答报文
                l, r = parse_record(data, offset) # r的格式为 (name, ip, type, class, ttl)
                if r:
                    ans.append(r)
            for i in range(0, res_nscount): # 跳过权威域名服务器部分
                l, r = parse_record(data, offset)
                offset += l
            for i in range(0, res_arcount): # 跳过额外部分
                l, r = parse_record(data, offset)
                offset += l
            response = DNSResponse() # 构建DNSresponse部分
            if qds:
                response.hostname = qds[0][0]
            for an in qds:
                response.questions.append((an[1], an[2], an[3])) # None, type, class
            for an in ans:
                response.answers.append((an[1], an[2], an[3])) # ip, type, class
            return response
    except Exception as e:
        shell.print_exception(e)
        return None


def is_valid_hostname(hostname):
    """
    该方法主要是判断一个域名字符串的格式是否正确。

    :param hostname: 域名字符串。

    :return: True代表域名正确。反之，不正确。
    """
    if len(hostname) > 255:# DNS域名长度不大于255
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


class DNSResponse(object):
    """
    该类主要是储存DNS域名，以及相应的请求和应答报文里面的地址类型、查询类型和记录类型。
    """
    def __init__(self):
        self.hostname = None
        self.questions = []  # each: (addr, type, class)
        self.answers = []  # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_IPV4 = 0
STATUS_IPV6 = 1


class DNSResolver(object):
    """
    该类为DNS解析类，主要是用来进行异步DNS解析。
    """

    def __init__(self):
        self._loop = None
        self._hosts = {}

        # 正在发起的host 的dns请求的地址解析类型，即正在对这个域名进行ipv4解析还是ipv6的解析。DNSResolver默认先进行ipv4的解析，当
        # ipv4解析失败后再发起一次ipv6的解析。两次都解析失败才算是真正的失败
        self._hostname_status = {}

        # dns解析服务和回调的对应关系，可能出现一个host解析请求对应多个回调的情况，当host请求解析有结果了，回调所有对应的回调。
        # 回调函数的参数格式为callback((hostname,ip),error=None)
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}
        self._cache = lru_cache.LRUCache(timeout=300) # dns解析结果缓存
        self._sock = None
        self._servers = None
        # _parse_resolv是解析/etc/resolv.conf文件，得到dns服务器的ip地址，如果没有配置，则默认使用google的dns服务器
        self._parse_resolv()
        self._parse_hosts() # _parse_hosts则是解析本地的hosts文件配置，将配置的ip和域名映射起来
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    def _parse_resolv(self):
        """
        该方法主要是解析/etc/resolv.conf文件，得到dns服务器的ip地址，如果没有配置，则默认使用google的dns服务器。

        :return: None。
        """
        self._servers = []
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if line:
                        if line.startswith(b'nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                server = parts[1]
                                if common.is_ip(server) == socket.AF_INET:
                                    if type(server) != str:
                                        server = server.decode('utf8')
                                    self._servers.append(server)
        except IOError:
            pass
        if not self._servers:
            self._servers = ['8.8.4.4', '8.8.8.8']

    def _parse_hosts(self):
        """
        该方法主要是解析本地的hosts文件配置，将配置的ip和域名映射起来。

        :return: None。
        """
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if common.is_ip(ip):
                            for i in range(1, len(parts)):
                                hostname = parts[i]
                                if hostname:
                                    self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    def add_to_loop(self, loop):
        """
        该方法主要是把当前的DNSResolver加入到Eventloop来进行异步DNS解析。
        :param loop: 一个Eventloop对象，用来分配任务给相应的对象来处理。
        :return: None。
        """
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP) # DNS查询
        self._sock.setblocking(False)
        loop.add(self._sock, eventloop.POLL_IN, self)
        loop.add_periodic(self.handle_periodic)

    def _call_callback(self, hostname, ip, error=None):
        """
        该方法主要是调用该域名对应的所有的回调函数。

        :param hostname: 一个域名字符串。

        :param ip: 该域名字符串对应的ip地址。

        :param error: 解析域名时候发生的错误。

        :return: None。
        """
        callbacks = self._hostname_to_cb.get(hostname, [])
        for callback in callbacks:
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    def _handle_data(self, data):
        """
        该方法主要是处理DNS请求返回的数据。

        :param data: DNS请求与返回的数据。

        :return: None。
        """
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]
                    break
            if not ip and self._hostname_status.get(hostname, STATUS_IPV6) \
                    == STATUS_IPV4: # 若请求ipv4失败，则请求ipv6
                self._hostname_status[hostname] = STATUS_IPV6
                self._send_req(hostname, QTYPE_AAAA)
            else:
                if ip: # 若查询成功，则执行相应的回调
                    self._cache[hostname] = ip
                    self._call_callback(hostname, ip)
                elif self._hostname_status.get(hostname, None) == STATUS_IPV6:
                    for question in response.questions:
                        if question[1] == QTYPE_AAAA:
                            self._call_callback(hostname, None)
                            break

    def handle_event(self, sock, fd, event):
        """
        该方法主要是处理DNS请求得到应答以后的事件。

        :param sock: 本次DNS请求的套接字对象。

        :param fd: 套接字标识符。

        :param event: 事件类型，如POLL_IN和POLL_OUT。

        :return: None。
        """
        if sock != self._sock:
            return
        if event & eventloop.POLL_ERR:
            logging.error('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            # TODO when dns server is IPv6
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.SOL_UDP)
            self._sock.setblocking(False)
            self._loop.add(self._sock, eventloop.POLL_IN, self)
        else:
            data, addr = sock.recvfrom(1024)
            if addr[0] not in self._servers: # 防止DNS劫持或者DNS污染。
                logging.warn('received a packet other than our dns')
                return
            self._handle_data(data)

    def handle_periodic(self):
        """
        定时清除DNS缓存。

        :return: None。
        """
        self._cache.sweep() # 在eventloop.py中的TIME_PRECISION定义每隔10秒清理一下缓冲

    def remove_callback(self, callback):
        """
        移除回调函数。

        :param callback: 回调函数。

        :return: None。
        """
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

    def _send_req(self, hostname, qtype):
        """
        向DNS服务器发送DNS解析请求。

        :param hostname: 一个域名字符串。

        :param qtype: 查询的地址类型。

        :return: None。
        """
        req = build_request(hostname, qtype)
        for server in self._servers:
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            self._sock.sendto(req, (server, 53))

    def resolve(self, hostname, callback):
        """
        解析域名并执行相应的回调函数。

        :param hostname: 一个域名字符串。

        :param callback: 该域名对应的回调函数。回调函数格式为callback((hostname, ip), error=None)。

        :return: None。
        """
        if type(hostname) != bytes: # string转bytes
            hostname = hostname.encode('utf8')
        if not hostname: # 域名为空
            callback(None, Exception('empty hostname'))
        elif common.is_ip(hostname): # 若本身已经是ip地址了
            callback((hostname, hostname), None)
        elif hostname in self._hosts: # 若系统的hosts文件里面已经存在了映射
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)
        elif hostname in self._cache: # 若缓存里面存有域名解析的结果
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        else:
            if not is_valid_hostname(hostname): # 若域名格式不合法。
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)
            if not arr:
                self._hostname_status[hostname] = STATUS_IPV4
                self._send_req(hostname, QTYPE_A)
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_req(hostname, QTYPE_A)

    def close(self):
        """
        关闭socket请求。

        :return: None。
        """
        if self._sock:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None


def test():
    dns_resolver = DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)

    global counter
    counter = 0

    # 在这里实现异步发送请求，因为每次make_callback的调用都会返回不同地址的callback
    def make_callback():
        global counter

        def callback(result, error):
            global counter
            # TODO: what can we assert?
            print(result, error)
            counter += 1
            if counter == 9:
                dns_resolver.close()
                loop.stop()
        a_callback = callback
        return a_callback

    assert(make_callback() != make_callback())

    dns_resolver.resolve(b'google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())

    loop.run()


if __name__ == '__main__':
    test()
