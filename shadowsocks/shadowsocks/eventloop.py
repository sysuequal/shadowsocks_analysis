#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2013-2015 clowwindy
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

# from ssloop
# https://github.com/clowwindy/ssloop

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import time
import socket
import select
import errno
import logging
from collections import defaultdict

from shadowsocks import shell


__all__ = ['EventLoop', 'POLL_NULL', 'POLL_IN', 'POLL_OUT', 'POLL_ERR',
           'POLL_HUP', 'POLL_NVAL', 'EVENT_NAMES']

POLL_NULL = 0x00
POLL_IN = 0x01
POLL_OUT = 0x04
POLL_ERR = 0x08
POLL_HUP = 0x10
POLL_NVAL = 0x20

# 定义6种不同事件
EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL',
}

# we check timeouts every TIMEOUT_PRECISION seconds
TIMEOUT_PRECISION = 10 # 每过10秒就检查一次是否有IO事件到来


# IO复用接口 kqueue
class KqueueLoop(object):
    """
    重写kqueue IO复用，使接口统一。
    """
    # 最大事件数
    MAX_EVENTS = 1024

    def __init__(self):
        """
        调用select.kqueue获取IO复用接口kqueue，并初始化socket文件描述符字典fds
        """
        self._kqueue = select.kqueue()
        self._fds = {}

    def _control(self, fd, mode, flags):
        """
        在系统IO复用接口中处理socket侦听事件的增加或删除

        :param fd: socket文件描述符

        :param mode: 所侦听的事件

        :param flags: select.KQ_EV_ADD或者select.KQ_EV_DELETE

        :return: none
        """
        events = []
        if mode & POLL_IN:
            events.append(select.kevent(fd, select.KQ_FILTER_READ, flags))
        if mode & POLL_OUT:
            events.append(select.kevent(fd, select.KQ_FILTER_WRITE, flags))
        for e in events:
            self._kqueue.control([e], 0)

    def poll(self, timeout):
        """
        等待事件触发，返回触发的事件

        :param timeout: 最长等待时间

        :return: 触发的事件
        """
        if timeout < 0:
            timeout = None  # kqueue behaviour
        events = self._kqueue.control(None, KqueueLoop.MAX_EVENTS, timeout)
        results = defaultdict(lambda: POLL_NULL)
        for e in events:
            fd = e.ident
            if e.filter == select.KQ_FILTER_READ:
                results[fd] |= POLL_IN
            elif e.filter == select.KQ_FILTER_WRITE:
                results[fd] |= POLL_OUT
        return results.items()


    def register(self, fd, mode):
        """
        为socket注册侦听事件

        :param fd: socket文件描述符

        :param mode: 所侦听的事件

        :return: none
        """
        self._fds[fd] = mode
        self._control(fd, mode, select.KQ_EV_ADD)

    def unregister(self, fd):
        """
        移除socket所注册的事件

        :param fd: socket文件描述符

        :return: none
        """
        self._control(fd, self._fds[fd], select.KQ_EV_DELETE)
        del self._fds[fd]

    def modify(self, fd, mode):
        """
        修改socket所侦听的事件

        :param fd: socket文件描述符

        :param mode: 修改后所侦听的事件

        :return: none
        """
        self.unregister(fd)
        self.register(fd, mode)

    def close(self):
        """
        关闭IO复用接口kqueue

        :return: none
        """
        self._kqueue.close()


# IO复用接口 select
class SelectLoop(object):
    """
    重写select IO复用，使接口统一。
    """
    def __init__(self):
        """
        初始化三个事件侦听集合：读事件集合、写事件集合和出错事件集合
        """
        self._r_list = set()
        self._w_list = set()
        self._x_list = set()

    def poll(self, timeout):
        """
        等待时间触发，返回所触发的事件

        :param timeout: 最长等待时间

        :return: 所侦听的事件
        """
        r, w, x = select.select(self._r_list, self._w_list, self._x_list,
                                timeout)
        results = defaultdict(lambda: POLL_NULL)
        for p in [(r, POLL_IN), (w, POLL_OUT), (x, POLL_ERR)]:
            for fd in p[0]:
                results[fd] |= p[1]
        return results.items()

    def register(self, fd, mode):
        """
        为socket注册侦听事件

        :param fd: socket文件描述符

        :param mode: 所侦听的事件

        :return: none
        """
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)

    def unregister(self, fd):
        """
        移除socket所注册的侦听事件

        :param fd: socket文件描述符

        :return: none
        """
        if fd in self._r_list:
            self._r_list.remove(fd)
        if fd in self._w_list:
            self._w_list.remove(fd)
        if fd in self._x_list:
            self._x_list.remove(fd)

    def modify(self, fd, mode):
        """
        修改socket所侦听事件

        :param fd: socket文件描述符

        :param mode: 修改后所侦听的事件

        :return: none
        """
        self.unregister(fd)
        self.register(fd, mode)

    def close(self):
        """
        pass

        :return: none
        """
        pass


class EventLoop(object):
    """
    IO复用类。本软件采用的IO复用接口都由这个类来定义。
    """
    def __init__(self):
        """
        选择IO复用模式，初始化参数
        """
        if hasattr(select, 'epoll'):
            self._impl = select.epoll()
            model = 'epoll'
        elif hasattr(select, 'kqueue'):
            self._impl = KqueueLoop()
            model = 'kqueue'
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
            model = 'select'
        else:
            raise Exception('can not find any available functions in select '
                            'package')
        self._fdmap = {}  # (f, handler)
        self._last_time = time.time()
        self._periodic_callbacks = []
        self._stopping = False
        logging.debug('using event model: %s', model)

    def poll(self, timeout=None):
        """
        等待事件触发，并返回触发的事件

        :param timeout: 最长等待时间

        :return: events元组socket，fd和event
        """
        events = self._impl.poll(timeout)
        return [(self._fdmap[fd][0], fd, event) for fd, event in events]

    def add(self, f, mode, handler):
        """
        将socket与对应的处理对象handler加到字典中，并在相关IO复用接口中为socket注册侦听事件

        :param f: socket

        :param mode: 所侦听的事件

        :param handler: 事件处理对象，当socket注册的侦听事件mode发生时，会调用handler.handler_event(...)

        :return: none
        """
        fd = f.fileno() # fileno返回套接字标识符
        self._fdmap[fd] = (f, handler) # 建立套接字标识符和套接字和文件句柄的映射
        self._impl.register(fd, mode) # 注册IO复用事件

    def remove(self, f):
        """
        将socket从字典中移除，并移除注册的侦听事件

        :param f: socket

        :return: none
        """
        fd = f.fileno()
        del self._fdmap[fd]
        self._impl.unregister(fd)

    def add_periodic(self, callback):
        """
        增加周期性回调函数

        :param callback: 回调函数

        :return: none
        """
        self._periodic_callbacks.append(callback)

    def remove_periodic(self, callback):
        """
        移除周期性回调函数

        :param callback: 周期性回调函数

        :return: none
        """
        self._periodic_callbacks.remove(callback)

    def modify(self, f, mode):
        """
        修改socket所侦听的事件

        :param f: socket

        :param mode: 所侦听的事件

        :return: none
        """
        fd = f.fileno()
        self._impl.modify(fd, mode)

    def stop(self):
        """
        暂停IO接口复用

        :return: none
        """
        self._stopping = True

    def run(self):
        """
        等待注册事件发生，然后通过事件对应的文件描述符 fd 找到 handler，并将事件交给 handler 处理。
        同时每个一定时间调用 handle_periodic 函数处理超时或者清除缓存。

        :return:none
        """
        events = []
        while not self._stopping:
            asap = False
            # 获取事件
            try:
                events = self.poll(TIMEOUT_PRECISION)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    # EPIPE: Happens when the client closes the connection
                    # EINTR: Happens when received a signal
                    # handles them as soon as possible
                    asap = True
                    logging.debug('poll:%s', e)
                else:
                    logging.error('poll:%s', e)
                    import traceback
                    traceback.print_exc()
                    continue
            # 遍历被激活的事件
            for sock, fd, event in events:
                # 通过 fd 找到对应的 handler
                # 一个 handler 可能对应多个 fd （reactor 模式）
                handler = self._fdmap.get(fd, None)
                if handler is not None:
                    handler = handler[1]
                    try:
                        # 调用相关_handle_event方法，处理事件
                        # handler 可能是 TCPRelay、UDPRelay 或 DNSResolver
                        handler.handle_event(sock, fd, event)
                    except (OSError, IOError) as e:
                        shell.print_exception(e)
            # 计时器： 每隔TIMEOUT_PRECISION秒调用注册的 handle_periodic 函数
            now = time.time()
            if asap or now - self._last_time >= TIMEOUT_PRECISION:
                for callback in self._periodic_callbacks:
                    callback()
                self._last_time = now

    def __del__(self):
        """
        关闭IO复用接口

        :return: none
        """
        self._impl.close()


# from tornado
def errno_from_exception(e):
    """
    Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.

    :param e: 异常对象

    :return: errno或者None
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None


# from tornado
def get_sock_error(sock):
    """
    获取socket错误信息

    :param sock: socket

    :return: socket中的error信息
    """
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))
