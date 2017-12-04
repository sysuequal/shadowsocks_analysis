#!/usr/bin/env python
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

import hashlib

from shadowsocks.crypto import openssl

__all__ = ['ciphers']


def create_cipher(alg, key, iv, op, key_as_bytes=0, d=None, salt=None,
                  i=1, padding=1):
    """
    
    创建密码
    
    :param alg：算法名字
    
    :param key：加密所用的密码
    
    :param iv: 初始向量
    
    :param op: 加密或者加密操作
    
    :param key_as_bytes: 生成密码方法选择
    
    :param d: 散列算法
    
    :param salt: 生成密码所用的参数
    
    :param i: 生成密码所用的迭代次数
    
    :param padding: 填充加密块
    
    :return: 创建后的密码
    """
    md5 = hashlib.md5()
    md5.update(key)
    md5.update(iv)
    rc4_key = md5.digest()
    return openssl.OpenSSLCrypto(b'rc4', rc4_key, b'', op)


ciphers = {
    'rc4-md5': (16, 16, create_cipher),
}


def test():
    from shadowsocks.crypto import util

    cipher = create_cipher('rc4-md5', b'k' * 32, b'i' * 16, 1)
    decipher = create_cipher('rc4-md5', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


if __name__ == '__main__':
    test()
