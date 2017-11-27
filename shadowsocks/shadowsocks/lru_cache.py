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

import collections
import logging
import time


# this LRUCache is optimized for concurrency, not QPS
# n: concurrency, keys stored in the cache
# m: visits not timed out, proportional to QPS * timeout
# get & set is O(1), not O(n). thus we can support very large n
# TODO: if timeout or QPS is too large, then this cache is not very efficient,
#       as sweep() causes long pause


class LRUCache(collections.MutableMapping):
    """This class is not thread safe"""
    
    """
    清除最近最久未使用的缓存数据
    """
    
    def __init__(self, timeout=60, close_callback=None, *args, **kwargs):
        """
        初始化整个类的参数

        :param timeout: 定时清除缓存数据的时长设置

        :param close_callback: 将缓存里的数据标志关闭的回调函数

        :param args: 任何多个无名参任何多个无名参，是一个元组

        :param kwargs: 关键字参数，是一个字典
        """
        self.timeout = timeout
        self.close_callback = close_callback
        self._store = {}
        self._time_to_keys = collections.defaultdict(list)
        self._keys_to_last_time = {}
        self._last_visits = collections.deque()
        self._closed_values = set()
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        # O(1)

        """
        将这一次的时间保存为下来，作为未来的过去时间，返回index对应的缓存数据

        :param key: 此时刻下对应的键值

        :return: 键值对应的缓存数据
        """

        t = time.time()
        self._keys_to_last_time[key] = t
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)
        return self._store[key]

    def __setitem__(self, key, value):
        # O(1)

        """
        将键值所对应的缓存数据保存下来

        :param key: 需要缓存的数据所对应的键值

        :param value: 键值所对应缓存数据的值

        :return: 无
        """

        t = time.time()
        self._keys_to_last_time[key] = t
        self._store[key] = value
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)

    def __delitem__(self, key):
        # O(1)

        """
        删除缓存数据

        :param key: 需要删除的缓存数据的键值

        :return: 无
        """

        del self._store[key]
        del self._keys_to_last_time[key]

    def __iter__(self):

        """
        遍历缓存数据

        :return: 遍历缓存数据
        """

        return iter(self._store)

    def __len__(self):

        """
        获取缓存数据的数据长度

        :return: 缓存数据的长度
        """

        return len(self._store)

    def sweep(self):
        # O(m)

        """
        清除最近这段时间内的最少被使用的缓存数据

        :return: 无
        """

        now = time.time()
        c = 0
        while len(self._last_visits) > 0:
            least = self._last_visits[0]
            if now - least <= self.timeout:
                break
            if self.close_callback is not None:
                for key in self._time_to_keys[least]:
                    if key in self._store:
                        if now - self._keys_to_last_time[key] > self.timeout:
                            value = self._store[key]
                            if value not in self._closed_values:
                                self.close_callback(value)
                                self._closed_values.add(value)
            for key in self._time_to_keys[least]:
                self._last_visits.popleft()
                if key in self._store:
                    if now - self._keys_to_last_time[key] > self.timeout:
                        del self._store[key]
                        del self._keys_to_last_time[key]
                        c += 1
            del self._time_to_keys[least]
        if c:
            self._closed_values.clear()
            logging.debug('%d keys swept' % c)


def test():
    
    c = LRUCache(timeout=0.3)

    c['a'] = 1
    assert c['a'] == 1

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c

    c['a'] = 2
    c['b'] = 3
    time.sleep(0.2)
    c.sweep()
    assert c['a'] == 2
    assert c['b'] == 3

    time.sleep(0.2)
    c.sweep()
    c['b']
    time.sleep(0.2)
    c.sweep()
    assert 'a' not in c
    assert c['b'] == 3

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c
    assert 'b' not in c

    global close_cb_called
    close_cb_called = False

    def close_cb(t):
        global close_cb_called
        assert not close_cb_called
        close_cb_called = True

    c = LRUCache(timeout=0.1, close_callback=close_cb)
    c['s'] = 1
    c['s']
    time.sleep(0.1)
    c['s']
    time.sleep(0.3)
    c.sweep()

if __name__ == '__main__':
    test()
