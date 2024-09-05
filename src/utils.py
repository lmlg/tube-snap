#! /usr/bin/env python3
#
# Copyright 2024 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import string
import time
import uuid

# Useful constants.
RADIX_CHARS = string.digits + string.ascii_lowercase + string.ascii_uppercase
NQN_BASE = 'nqn.2014-08.org.nvmexpress:uuid:'
SNAP_PATH = '/var/snap/tube/common/'


class RPC:
    """
    See https://spdk.io/doc/jsonrpc_proxy.html
    for the format used in RPC.
    """
    id_ = 1

    def __getattr__(self, name):
        def _inner(**kwargs):
            id_ = self.id_
            self.id_ = (id_ + 1) % 100
            base = {'id': id_, 'method': name}
            if kwargs:
                base['params'] = kwargs
            return base

        return _inner


def unique_id():
    ftime = int(str(time.clock_gettime(time.CLOCK_BOOTTIME)).replace('.', ''))
    base = RADIX_CHARS
    blen = len(base)
    result = ''
    while ftime:
        result += base[ftime % blen]
        ftime //= blen
    return result


def gen_nqn():
    return NQN_BASE + str(uuid.uuid4())


def parse_memsize(size):
    for i, suffix in enumerate(('M', 'G', 'T', 'P')):
        if size.endswith(suffix):
            size = size[:-1]
            return float(size) * (1024 ** (2 + i))

    return size


def format_size(size):
    for unit in ('', 'K', 'M', 'G', 'T', 'P'):
        if size < 1024:
            return '%3.1f%s' % (size, unit)
        size /= 1024
    return '%f%s' % (size, 'Y')
