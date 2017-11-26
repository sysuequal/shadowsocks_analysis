#!/usr/bin/env python
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

import sys
import os
import logging
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, \
    asyncdns, manager


def main():
    """
    启动服务器主函数 

    :return: None
    """
    shell.check_python()
    config = shell.get_config(False)
    daemon.daemon_exec(config)
    if config['port_password']:
        if config['password']:
	    # 提示：端口密码不能用服务器端口号和密码
            logging.warn('warning: port_password should not be used with '
                         'server_port and password. server_port and password '
                         'will be ignored')
    else:
        # 清空端口密码
        config['port_password'] = {}
	# 提取服务器端口
        server_port = config['server_port']
	# 如果是列表形式
        if type(server_port) == list:
	# 给每个port赋password
            for a_server_port in server_port:
                config['port_password'][a_server_port] = config['password']
        else:
	# 只有1个port，单独赋值
            config['port_password'][str(server_port)] = config['password']

    if config.get('manager_address', 0):
	# 管理模式
        logging.info('entering manager mode')
        manager.run(config)
        return

    tcp_servers = []
    udp_servers = []
    dns_resolver = asyncdns.DNSResolver()
    # 得到每个端口的密码
    port_password = config['port_password']
    del config['port_password']
    # 对每个端口及其对应的密码
    for port, password in port_password.items():
        a_config = config.copy()
	# 记录当前端口和密码
        a_config['server_port'] = int(port)
        a_config['password'] = password
	# 开启服务器
        logging.info("starting server at %s:%d" %
                     (a_config['server'], int(port)))
        tcp_servers.append(tcprelay.TCPRelay(a_config, dns_resolver, False))
        udp_servers.append(udprelay.UDPRelay(a_config, dns_resolver, False))

    def run_server():
        """
        服务器运行
        
        :return: None
        """
        def child_handler(signum, _):
            """
            子程序要求关闭 
            
            :param signum: 信号值
            
            :param _: 不明
            
            :return: None 
            """
            logging.warn('received SIGQUIT, doing graceful shutting down..')
            list(map(lambda s: s.close(next_tick=True),
                     tcp_servers + udp_servers))
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM),
                      child_handler)

        def int_handler(signum, _):
            """
            强制退出程序，意义不明 
            
            :param signum: 信号值
            
            :param _: 不明
            
            :return: None
            """
            sys.exit(1)
        signal.signal(signal.SIGINT, int_handler)

        try:
            loop = eventloop.EventLoop()
	    # 用addtoloop把dnsresolver添加到eventloop里，当DNSResolver对应的socket有dns解析结果可以读取的时候，eventloop会自动调用其handle_event方法将就绪的socket递给DNSResolver，DNSResolver就可以从其中读取dns应答数据了。
            dns_resolver.add_to_loop(loop)
            list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))

            daemon.set_user(config.get('user', None))
            loop.run()
        except Exception as e:
            shell.print_exception(e)
            sys.exit(1)

    # workers<=1时开启服务器，>1时检查
    if int(config['workers']) > 1:
        if os.name == 'posix':
            children = []
            is_child = False
            for i in range(0, int(config['workers'])):
                r = os.fork()
                if r == 0:
                    logging.info('worker started')
                    is_child = True
                    run_server()
                    break
                else:
                    children.append(r)
            if not is_child:
                # 不是子进程
                def handler(signum, _):
                    """
                    关闭所有子进程
                    
                    :param signum: 信号值 
                    
                    :param _: 不明 
                    
                    :return: None
                    
                    :raises OSError: 子进程已经退出
                    """
                    for pid in children:
                        try:
                            os.kill(pid, signum)
                            os.waitpid(pid, 0)
                        except OSError:  # child may already exited
                            pass
                    sys.exit()
                signal.signal(signal.SIGTERM, handler)
                signal.signal(signal.SIGQUIT, handler)
                signal.signal(signal.SIGINT, handler)

                # 关闭所有服务器
                for a_tcp_server in tcp_servers:
                    a_tcp_server.close()
                for a_udp_server in udp_servers:
                    a_udp_server.close()
                dns_resolver.close()

                for child in children:
                    os.waitpid(child, 0)
        else:
            logging.warn('worker is only available on Unix/Linux')
            run_server()
    else:
        run_server()


if __name__ == '__main__':
    main()
