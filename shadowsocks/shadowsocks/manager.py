#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
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

import errno
import traceback
import socket
import logging
import json
import collections

from shadowsocks import common, eventloop, tcprelay, udprelay, asyncdns, shell


BUF_SIZE = 1506
STAT_SEND_LIMIT = 100


class Manager(object):

    def __init__(self, config):

        """
        初始化Manager的配置参数，进入循环事件

        :param config: 配置信息
        """

        self._config = config
        self._relays = {}  # (tcprelay, udprelay)
        self._loop = eventloop.EventLoop()
        self._dns_resolver = asyncdns.DNSResolver()
        self._dns_resolver.add_to_loop(self._loop)

        self._statistics = collections.defaultdict(int)
        self._control_client_addr = None
        try:
            manager_address = config['manager_address']
            if ':' in manager_address:
                addr = manager_address.rsplit(':', 1)
                addr = addr[0], int(addr[1])
                addrs = socket.getaddrinfo(addr[0], addr[1])
                if addrs:
                    family = addrs[0][0]
                else:
                    logging.error('invalid address: %s', manager_address)
                    exit(1)
            else:
                addr = manager_address
                family = socket.AF_UNIX
            self._control_socket = socket.socket(family,
                                                 socket.SOCK_DGRAM)
            self._control_socket.bind(addr)
            self._control_socket.setblocking(False)
        except (OSError, IOError) as e:
            logging.error(e)
            logging.error('can not bind to manager address')
            exit(1)
        self._loop.add(self._control_socket,
                       eventloop.POLL_IN, self)
        self._loop.add_periodic(self.handle_periodic)

        port_password = config['port_password']
        del config['port_password']
        for port, password in port_password.items():
            a_config = config.copy()
            a_config['server_port'] = int(port)
            a_config['password'] = password
            self.add_port(a_config)

    def add_port(self, config):

        """
        添加服务端口，并保持只有一个服务端，同时监听tcp和udp的数据包

        :param config: 配置信息

        :return: 如果已存在服务端则返回
        """

        port = int(config['server_port'])
        servers = self._relays.get(port, None)
        if servers:
            logging.error("server already exists at %s:%d" % (config['server'],
                                                              port))
            return
        logging.info("adding server at %s:%d" % (config['server'], port))
        t = tcprelay.TCPRelay(config, self._dns_resolver, False,
                              self.stat_callback)
        u = udprelay.UDPRelay(config, self._dns_resolver, False,
                              self.stat_callback)
        t.add_to_loop(self._loop)
        u.add_to_loop(self._loop)
        self._relays[port] = (t, u)

    def remove_port(self, config):

        """
        删除服务端口，并结束端口监听

        :param config: 配置信息

        :return: 无
        """

        port = int(config['server_port'])
        servers = self._relays.get(port, None)
        if servers:
            logging.info("removing server at %s:%d" % (config['server'], port))
            t, u = servers
            t.close(next_tick=False)
            u.close(next_tick=False)
            del self._relays[port]
        else:
            logging.error("server not exist at %s:%d" % (config['server'],
                                                         port))

    def handle_event(self, sock, fd, event):

        """
        处理事件，根据端口号读取监听到的数据，从中读取控制指令，更新配置信息，处理相应的控制指令

        :param sock: 监听到信息的端口号

        :param fd: 文件描述符

        :param event: 事件

        :return:
        """

        if sock == self._control_socket and event == eventloop.POLL_IN:
            data, self._control_client_addr = sock.recvfrom(BUF_SIZE)
            parsed = self._parse_command(data)
            if parsed:
                command, config = parsed
                a_config = self._config.copy()
                if config:
                    # let the command override the configuration file
                    a_config.update(config)
                if 'server_port' not in a_config:
                    logging.error('can not find server_port in config')
                else:
                    if command == 'add':
                        self.add_port(a_config)
                        self._send_control_data(b'ok')
                    elif command == 'remove':
                        self.remove_port(a_config)
                        self._send_control_data(b'ok')
                    elif command == 'ping':
                        self._send_control_data(b'pong')
                    else:
                        logging.error('unknown command %s', command)

    def _parse_command(self, data):

        """
        从接收数据中获取控制指令命令和配置信息

        :param data: 包含控制指令和配置信息的数据

        :return: 如果数据长度少于2，直接返回原数据；如果数据长度等于2，返回command和config
        """

        # commands:
        # add: {"server_port": 8000, "password": "foobar"}
        # remove: {"server_port": 8000"}
        data = common.to_str(data)
        parts = data.split(':', 1)
        if len(parts) < 2:
            return data, None
        command, config_json = parts
        try:
            config = shell.parse_json_in_str(config_json)
            return command, config
        except Exception as e:
            logging.error(e)
            return None

    def stat_callback(self, port, data_len):

        """
        统计监听得到的数据长度（或者数据量）

        :param port: 监听端口

        :param data_len: 监听得到的数据长度

        :return: 无
        """

        self._statistics[port] += data_len

    def handle_periodic(self):

        """
        当统计发送数据量到达限制后，发送数据

        :return: 无
        """

        r = {}
        i = 0

        def send_data(data_dict):
            if data_dict:
                # use compact JSON format (without space)
                data = common.to_bytes(json.dumps(data_dict,
                                                  separators=(',', ':')))
                self._send_control_data(b'stat: ' + data)

        for k, v in self._statistics.items():
            r[k] = v
            i += 1
            # split the data into segments that fit in UDP packets
            if i >= STAT_SEND_LIMIT:
                send_data(r)
                r.clear()
        send_data(r)
        self._statistics.clear()

    def _send_control_data(self, data):

        """
        向客户端发送数据

        :param data: 发送数据

        :return: 如果出现错误，退出发送
        """

        if self._control_client_addr:
            try:
                self._control_socket.sendto(data, self._control_client_addr)
            except (socket.error, OSError, IOError) as e:
                error_no = eventloop.errno_from_exception(e)
                if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                                errno.EWOULDBLOCK):
                    return
                else:
                    shell.print_exception(e)
                    if self._config['verbose']:
                        traceback.print_exc()

    def run(self):

        """
        运行端口管理程序

        :return: 无
        """

        self._loop.run()


def run(config):

    """
    传入配置参数，运行端口管理程序

    :return: 无
    """
    
    Manager(config).run()


def test():
    import time
    import threading
    import struct
    from shadowsocks import encrypt

    logging.basicConfig(level=5,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    enc = []
    eventloop.TIMEOUT_PRECISION = 1

    def run_server():
        config = {
            'server': '127.0.0.1',
            'local_port': 1081,
            'port_password': {
                '8381': 'foobar1',
                '8382': 'foobar2'
            },
            'method': 'aes-256-cfb',
            'manager_address': '127.0.0.1:6001',
            'timeout': 60,
            'fast_open': False,
            'verbose': 2
        }
        manager = Manager(config)
        enc.append(manager)
        manager.run()

    t = threading.Thread(target=run_server)
    t.start()
    time.sleep(1)
    manager = enc[0]
    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cli.connect(('127.0.0.1', 6001))

    # test add and remove
    time.sleep(1)
    cli.send(b'add: {"server_port":7001, "password":"asdfadsfasdf"}')
    time.sleep(1)
    assert 7001 in manager._relays
    data, addr = cli.recvfrom(1506)
    assert b'ok' in data

    cli.send(b'remove: {"server_port":8381}')
    time.sleep(1)
    assert 8381 not in manager._relays
    data, addr = cli.recvfrom(1506)
    assert b'ok' in data
    logging.info('add and remove test passed')

    # test statistics for TCP
    header = common.pack_addr(b'google.com') + struct.pack('>H', 80)
    data = encrypt.encrypt_all(b'asdfadsfasdf', 'aes-256-cfb', 1,
                               header + b'GET /\r\n\r\n')
    tcp_cli = socket.socket()
    tcp_cli.connect(('127.0.0.1', 7001))
    tcp_cli.send(data)
    tcp_cli.recv(4096)
    tcp_cli.close()

    data, addr = cli.recvfrom(1506)
    data = common.to_str(data)
    assert data.startswith('stat: ')
    data = data.split('stat:')[1]
    stats = shell.parse_json_in_str(data)
    assert '7001' in stats
    logging.info('TCP statistics test passed')

    # test statistics for UDP
    header = common.pack_addr(b'127.0.0.1') + struct.pack('>H', 80)
    data = encrypt.encrypt_all(b'foobar2', 'aes-256-cfb', 1,
                               header + b'test')
    udp_cli = socket.socket(type=socket.SOCK_DGRAM)
    udp_cli.sendto(data, ('127.0.0.1', 8382))
    tcp_cli.close()

    data, addr = cli.recvfrom(1506)
    data = common.to_str(data)
    assert data.startswith('stat: ')
    data = data.split('stat:')[1]
    stats = json.loads(data)
    assert '8382' in stats
    logging.info('UDP statistics test passed')

    manager._loop.stop()
    t.join()


if __name__ == '__main__':
    test()
