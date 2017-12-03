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

import os
import json
import sys
import getopt
import logging
from shadowsocks.common import to_bytes, to_str, IPNetwork
from shadowsocks import encrypt


VERBOSE_LEVEL = 5

verbose = 0

def check_python():
    """
    检查python版本，需要2.6和3.3以上版本 

    :return: None
    """
    info = sys.version_info
    if info[0] == 2 and not info[1] >= 6:
        print('Python 2.6+ required')
        sys.exit(1)
    elif info[0] == 3 and not info[1] >= 3:
        print('Python 3.3+ required')
        sys.exit(1)
    elif info[0] not in [2, 3]:
        print('Python version not supported')
        sys.exit(1)


def print_exception(e):
    """
    打印错误信息 

    :param e: 错误信息内容 

    :return: None 
    """
    global verbose
    logging.error(e)
    if verbose > 0:
        import traceback
        traceback.print_exc()


def print_shadowsocks():
    """
    打印shadowsocks版本 

    :return: None
    """
    version = ''
    try:
        import pkg_resources
        version = pkg_resources.get_distribution('shadowsocks').version
    except Exception:
        pass
    print('Shadowsocks %s' % version)


def find_config():
    """
    寻找json配置，默认或者指定文件 

    :return: 存在config.json时，返回该配置 
    """
    config_path = 'config.json'
    if os.path.exists(config_path):
        return config_path
    config_path = os.path.join(os.path.dirname(__file__), '../', 'config.json')
    if os.path.exists(config_path):
        return config_path
    return None


def check_config(config, is_local):
    """
    检查配置 

    :param config: 配置设置 

    :param is_local: 是否客户端（否则为服务器端） 

    :return: None
    """
    if config.get('daemon', None) == 'stop':
        # no need to specify configuration for daemon stop
        return

    #密码未指定
    if is_local and not config.get('password', None):
        logging.error('password not specified')
        print_help(is_local)
        sys.exit(2)

    #密码或端口密码未指定
    if not is_local and not config.get('password', None) \
            and not config.get('port_password', None):
        logging.error('password or port_password not specified')
        print_help(is_local)
        sys.exit(2)

    #端口号转为数值型？
    if 'local_port' in config:
        config['local_port'] = int(config['local_port'])

    #服务器端口单转
    if 'server_port' in config and type(config['server_port']) != list:
        config['server_port'] = int(config['server_port'])

    #本地监听全零地址警告
    if config.get('local_address', '') in [b'0.0.0.0']:
        logging.warn('warning: local set to listen on 0.0.0.0, it\'s not safe')
    #服务器监听提示
    if config.get('server', '') in ['127.0.0.1', 'localhost']:
        logging.warn('warning: server set to listen on %s:%s, are you sure?' %
                     (to_str(config['server']), config['server_port']))
    #table型不安全提示
    if (config.get('method', '') or '').lower() == 'table':
        logging.warn('warning: table is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    #RC4算法不安全提示
    if (config.get('method', '') or '').lower() == 'rc4':
        logging.warn('warning: RC4 is not safe; please use a safer cipher, '
                     'like AES-256-CFB')
    #延时太短
    if config.get('timeout', 300) < 100:
        logging.warn('warning: your timeout %d seems too short' %
                     int(config.get('timeout')))
    #延时太长
    if config.get('timeout', 300) > 600:
        logging.warn('warning: your timeout %d seems too long' %
                     int(config.get('timeout')))
    #使用默认密码提示
    if config.get('password') in [b'mypassword']:
        logging.error('DON\'T USE DEFAULT PASSWORD! Please change it in your '
                      'config.json!')
        sys.exit(1)
    #获取用户名失败
    if config.get('user', None) is not None:
        if os.name != 'posix':
            logging.error('user can be used only on Unix')
            sys.exit(1)

    encrypt.try_cipher(config['password'], config['method'])


def get_config(is_local):
    """
    获得配置（额外指令） 

    :param is_local: 是否客户端操作（否则使用服务器端那一套指令） 

    :return: None
    """
    global verbose

    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)-s: %(message)s')
    # 客户端使用if成立的指令，否则使用else的
    if is_local:
        shortopts = 'hd:s:b:p:k:l:m:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'user=',
                    'version']
    else:
        shortopts = 'hd:s:p:k:m:c:t:vq'
        longopts = ['help', 'fast-open', 'pid-file=', 'log-file=', 'workers=',
                    'forbidden-ip=', 'user=', 'manager-address=', 'version']
    try:
        config_path = find_config()
        optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
        for key, value in optlist:
            if key == '-c':
                config_path = value

        if config_path:
            logging.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = parse_json_in_str(f.read().decode('utf8'))
                except ValueError as e:
                    logging.error('found an error in config.json: %s',
                                  e.message)
                    sys.exit(1)
        else:
            config = {}

        v_count = 0
        for key, value in optlist:
	    #服务器端口
            if key == '-p':
                config['server_port'] = int(value)
	    #密码
            elif key == '-k':
                config['password'] = to_bytes(value)
	    #客户端端口号
            elif key == '-l':
                config['local_port'] = int(value)
	    #服务器的地址，服务器端默认0.0.0.0
            elif key == '-s':
                config['server'] = to_str(value)
	    #加密模式，默认AES-256
            elif key == '-m':
                config['method'] = to_str(value)
	    #客户端独有，客户端绑定地址
            elif key == '-b':
                config['local_address'] = to_str(value)
	    #verbose模式
            elif key == '-v':
                v_count += 1
                # '-vv' turns on more verbose mode
                config['verbose'] = v_count
	    #设置timeout，默认300
            elif key == '-t':
                config['timeout'] = int(value)
	    #tcp快速打开，需要python3.7以上
            elif key == '--fast-open':
                config['fast_open'] = True
	    #同时允许接入的客户端数？
            elif key == '--workers':
                config['workers'] = int(value)
	    #服务器管理员UDP地址
            elif key == '--manager-address':
                config['manager_address'] = value
	    #打印用户列表
            elif key == '--user':
                config['user'] = to_str(value)
	    #服务器端，打印被禁止的ip列表
            elif key == '--forbidden-ip':
                config['forbidden_ip'] = to_str(value).split(',')
	    #打印帮助
            elif key in ('-h', '--help'):
                if is_local:
                    print_local_help()
                else:
                    print_server_help()
                sys.exit(0)
	    #打印版本号
            elif key == '--version':
                print_shadowsocks()
                sys.exit(0)
	    #开启/停止/重启daemon模式
            elif key == '-d':
                config['daemon'] = to_str(value)
	    #daemon模式，pid文件
            elif key == '--pid-file':
                config['pid-file'] = to_str(value)
	    #daemon模式，log文件
            elif key == '--log-file':
                config['log-file'] = to_str(value)
	    #安静模式
            elif key == '-q':
                v_count -= 1
                config['verbose'] = v_count
    except getopt.GetoptError as e:
        print(e, file=sys.stderr)
        print_help(is_local)
        sys.exit(2)

    if not config:
        logging.error('config not specified')
        print_help(is_local)
        sys.exit(2)

    config['password'] = to_bytes(config.get('password', b''))
    config['method'] = to_str(config.get('method', 'aes-256-cfb'))
    config['port_password'] = config.get('port_password', None)
    config['timeout'] = int(config.get('timeout', 300))
    config['fast_open'] = config.get('fast_open', False)
    config['workers'] = config.get('workers', 1)
    config['pid-file'] = config.get('pid-file', '/var/run/shadowsocks.pid')
    config['log-file'] = config.get('log-file', '/var/log/shadowsocks.log')
    config['verbose'] = config.get('verbose', False)
    config['local_address'] = to_str(config.get('local_address', '127.0.0.1'))
    config['local_port'] = config.get('local_port', 1080)
    if is_local:
	#服务器未指定，打印客户端帮助
        if config.get('server', None) is None:
            logging.error('server addr not specified')
            print_local_help()
            sys.exit(2)
        else:
            config['server'] = to_str(config['server'])
    else:
        config['server'] = to_str(config.get('server', '0.0.0.0'))
        try:
            config['forbidden_ip'] = \
                IPNetwork(config.get('forbidden_ip', '127.0.0.0/8,::1/128'))
        except Exception as e:
            logging.error(e)
            sys.exit(2)
    config['server_port'] = config.get('server_port', 8388)

    logging.getLogger('').handlers = []
    logging.addLevelName(VERBOSE_LEVEL, 'VERBOSE')
    if config['verbose'] >= 2:
        level = VERBOSE_LEVEL
    elif config['verbose'] == 1:
        level = logging.DEBUG
    elif config['verbose'] == -1:
        level = logging.WARN
    elif config['verbose'] <= -2:
        level = logging.ERROR
    else:
        level = logging.INFO
    verbose = config['verbose']
    logging.basicConfig(level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    check_config(config, is_local)

    return config

def print_help(is_local):
    """
    打印帮助（本机，服务器） 

    :param is_local: 是否客户端（是则打印客户端的help，否则打印服务器端的） 

    :return: None
    """
    if is_local:
        print_local_help()
    else:
        print_server_help()

def print_local_help():
    """
    控制台打印客户端操作帮助 

    :return: None
    """
    print('''usage: sslocal [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.
You can supply configurations via either config file or command line arguments.
Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address
  -p SERVER_PORT         server port, default: 8388
  -b LOCAL_ADDR          local binding address, default: 127.0.0.1
  -l LOCAL_PORT          local port, default: 1080
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information
Online help: <https://github.com/shadowsocks/shadowsocks>
''')

def print_server_help():
    """
    控制台打印服务器操作帮助 

    :return: None
    """
    print('''usage: ssserver [OPTION]...
A fast tunnel proxy that helps you bypass firewalls.
You can supply configurations via either config file or command line arguments.
Proxy options:
  -c CONFIG              path to config file
  -s SERVER_ADDR         server address, default: 0.0.0.0
  -p SERVER_PORT         server port, default: 8388
  -k PASSWORD            password
  -m METHOD              encryption method, default: aes-256-cfb
  -t TIMEOUT             timeout in seconds, default: 300
  --fast-open            use TCP_FASTOPEN, requires Linux 3.7+
  --workers WORKERS      number of workers, available on Unix/Linux
  --forbidden-ip IPLIST  comma seperated IP list forbidden to connect
  --manager-address ADDR optional server manager UDP address, see wiki
General options:
  -h, --help             show this help message and exit
  -d start/stop/restart  daemon mode
  --pid-file PID_FILE    pid file for daemon mode
  --log-file LOG_FILE    log file for daemon mode
  --user USER            username to run as
  -v, -vv                verbose mode
  -q, -qq                quiet mode, only show warnings/errors
  --version              show version information
Online help: <https://github.com/shadowsocks/shadowsocks>
''')

def _decode_list(data):
    """
    解码数据列表（筛选出list或dict的对象或者有encode方法的对象） 

    :param data: 待筛选列表 

    :return: 返回满足的对象列表 
    """
    rv = []
    for item in data:
        # item对象是否有encode属性或方法
        if hasattr(item, 'encode'):
            item = item.encode('utf-8')
        # item是否list或dict的实例对象
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
        rv.append(item)
    return rv


def _decode_dict(data):
    """
    和_decode_list基本一致（但数列以key为下标，每个key对应的value在以key为下标的位置内） 

    :param data: 待筛选列表 

    :return: 返回满足的对象列表 
    """
    rv = {}
    for key, value in data.items():
        if hasattr(value, 'encode'):
            value = value.encode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


def parse_json_in_str(data):
    """
    转换unicode到string 

    :param data: 待转换数据 
    
    :return: 转换后的结果 
    """
    # parse json and convert everything from unicode to str
    return json.loads(data, object_hook=_decode_dict)
