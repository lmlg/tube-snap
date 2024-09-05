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

import json
import logging
import multiprocessing
import os
import select
import socket
import unittest

from src.base import BackendBase


class MockSPDK:
    def __init__(self, sock):
        new_sock, _ = sock.accept()
        sock.close()
        self.sock = new_sock
        self.bdevs = []
        self.controllers = {}
        self.ublks = []
        self.nvme_cntlid = 0
        self.mallocs = {}
        self.ocfs = {}
        self.nbds = {}
        self.crypto_keys = set()
        self.logger = logging.getLogger('spdk')

    def close(self):
        self.sock.close()

    def clear(self, **kwargs):
        self.bdevs.clear()
        self.controllers.clear()
        self.ublks.clear()

    def bdev_get_bdevs(self, **kwargs):
        return self.bdevs

    @staticmethod
    def _list_remove(lst, ix):
        return lst[:ix] + lst[ix + 1:]

    def _bdev_remove(self, bdev):
        for i, elem in enumerate(self.bdevs):
            if elem['name'] == bdev:
                break
        else:
            raise ValueError('bdev not found %s' % bdev)

        self.bdevs = self._list_remove(self.bdevs, i)

    def bdev_nvme_get_controllers(self, **kwargs):
        return [elem for _, elem in self.controllers.items()]

    def bdev_nvme_attach_controller(self, name, **kwargs):
        nqn = kwargs['subnqn']
        ctrl = {'trid': {key: kwargs[key]
                         for key in ('trtype', 'adrfam', 'traddr',
                                     'trsvcid', 'subnqn')},
                'cntlid': self.nvme_cntlid}
        self.nvme_cntlid += 1
        new_name = name + 'n1'

        prev = self.controllers.get(nqn)
        if prev is not None:
            if prev['name'] != name:
                raise ValueError("controller names must match")
            for path in prev['ctrlrs']:
                if path == ctrl:
                    raise ValueError('path already exists')
            prev['ctrlrs'].append(ctrl)

            for bdev in self.bdevs:
                if bdev['name'] == new_name:
                    bdev['driver_specific']['nvme'].append(ctrl)
                    break
            else:
                raise KeyError('bdev %s not found' % new_name)

            return [new_name]

        self.controllers[nqn] = {'name': name, 'ctrlrs': [ctrl]}
        bdev = {'name': new_name,
                'driver_specific': {'nvme': [ctrl]}}
        self.bdevs.append(bdev)

        return [new_name]

    def bdev_nvme_detach_controller(self, name, **kwargs):
        dict_eq = BackendBase.dict_ieq
        empty = False

        for nqn, elem in self.controllers.items():
            if elem['name'] != name:
                continue
            elif 'traddr' not in kwargs:
                # Delete all controllers.
                empty = True
                break

            # Lookup the controller with a transport ID.
            ctls = elem['ctrlrs']
            for idx, ctl in enumerate(ctls):
                if dict_eq(ctl['trid'], kwargs,
                           ('trtype', 'traddr', 'adrfam', 'trsvcid')):
                    break
            else:
                raise ValueError('path not found')

            elem['ctrlrs'] = ctls[:idx] + ctls[idx + 1:]
            empty = len(ctls) == 1
            break
        else:
            raise ValueError('controller not found')

        if empty:
            del self.controllers[nqn]
            self._bdev_remove(name + 'n1')
            self._ublk_remove(name + 'n1')

    def ublk_start_disk(self, ublk_id, **kwargs):
        dev = '/dev/ublkb' + str(ublk_id)
        for ublk in self.ublks:
            if ublk['ublk_device'] == dev:
                raise KeyError('device already exists')

        self.ublks.append({'ublk_device': dev, 'ublk_id': ublk_id, **kwargs})

    def ublk_get_disks(self, **kwargs):
        return self.ublks

    def ublk_stop_disk(self, ublk_id, **kwargs):
        device = '/dev/ublkb' + str(ublk_id)
        for i, elem in enumerate(self.ublks):
            if elem['ublk_device'] == device:
                break
        else:
            raise KeyError('device not found')

        self.ublks = self.ublks[:i] + self.ublks[i + 1:]

    def _ublk_remove(self, bdev):
        for i, elem in enumerate(self.ublks):
            if elem['bdev_name'] == bdev:
                break
        else:
            raise ValueError('ublk bdev not found: %s' % bdev)

        self.ublks = self.ublks[:i] + self.ublks[i + 1:]

    def bdev_malloc_create(self, name=None, **kwargs):
        if name is None:
            name = 'malloc%d' % len(self.mallocs)
        block_size = kwargs['block_size']
        num_blocks = kwargs['num_blocks']

        if (block_size * num_blocks) <= 0:
            raise ValueError('invalid numbers')

        bdev = {'name': name, **kwargs}
        self.mallocs[name] = bdev
        self.bdevs.append(bdev)
        return name

    def bdev_malloc_delete(self, name, **kwargs):
        del self.mallocs[name]
        self._bdev_remove(name)
        self._ublk_remove(name)

    def bdev_ocf_create(self, name, cache_bdev_name, core_bdev_name, **kwargs):
        if name in self.ocfs:
            raise ValueError('OCF already exists')

        bdev = {'name': name,
                'driver_specific': dict(cache_device=cache_bdev_name,
                                        core_device=core_bdev_name),
                'cache_bdev_name': cache_bdev_name,
                'core_bdev_name': core_bdev_name}
        self.ocfs[name] = bdev
        self.bdevs.append(bdev)
        return name

    def bdev_ocf_delete(self, name, **kwargs):
        del self.ocfs[name]
        self._bdev_remove(name)
        self._ublk_remove(name)

    def bdev_ocf_flush_start(self, name, **kwargs):
        self.ocfs[name]

    def bdev_ocf_set_cache_mode(self, name, **kwargs):
        self.ocfs[name]

    def bdev_ocf_get_bdevs(self, name, **kwargs):
        bdev = self.ocfs[name]
        return [{'cache': {'name': bdev['cache_bdev_name']},
                 'core': {'name': bdev['core_bdev_name']}}]

    def nbd_start_disk(self, device, bdev_name, **kwargs):
        if device in self.nbds:
            raise KeyError('device already present')
        self.nbds[device] = bdev_name

    def nbd_stop_disk(self, nbd_device, **kwargs):
        del self.nbds[nbd_device]

    def nbd_get_disks(self, **kwargs):
        return [{'nbd_device': key, 'bdev_name': val}
                for key, val in self.nbds]

    def accel_crypto_key_create(self, cipher, name, **kwargs):
        if cipher not in ('AES_CBX', 'AES_XTS'):
            raise ValueError('invalid cipher')
        elif name in self.crypto_keys:
            raise KeyError('key already exists')
        self.crypto_keys.add(name)

    def bdev_crypto_create(self, key_name, base_bdev_name, name, **kwargs):
        if key_name not in self.crypto_keys:
            raise KeyError('key does not exist')

        for bdev in self.bdevs:
            if bdev['name'] == base_bdev_name:
                break
            elif bdev['name'] == name:
                raise ValueError('bdev name taken')
        else:
            raise KeyError('bdev does not exist')

        self.bdevs.append(dict(name=name, driver_specific=dict(
            base_bdev_name=base_bdev_name)))

    def accel_crypto_key_destroy(self, name, **kwargs):
        self.crypto_keys.remove(name)

    def bdev_crypto_delete(self, name, **kwargs):
        self._bdev_remove(name)
        self._ublk_remove(name)

    def loop(self, timeout=None):
        rd, _, _ = select.select([self.sock], [], [], timeout)
        if not rd:
            return False

        buf = self.sock.recv(2048)
        obj = json.loads(buf)

        name = obj['method']
        method = getattr(self, name, None)
        if method is None:
            err = {'error': 'method %s not found' % name}
            self.sock.sendall(json.dumps(err).encode('utf8'))
            return True

        try:
            ret = {'result': method(**obj.get('params', {}))}
        except Exception as exc:
            ret = {'error': str(exc)}

        if not isinstance(ret, dict):
            ret = {'result': 1}

        self.sock.sendall(json.dumps(ret).encode('utf8'))
        return True


class BaseTest(unittest.TestCase):
    SOCK_PATH = '/tmp/tube-test-%s.sock'
    OBJ_ATTR = None
    OBJ_CLS = None

    def setUp(self):
        path = self.SOCK_PATH % self.OBJ_ATTR
        if os.path.exists(path):
            os.unlink(path)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        sock.listen(1)

        def _mp_loop(sock):
            spdk = MockSPDK(sock)
            while True:
                spdk.loop()

        self.proc = multiprocessing.Process(target=_mp_loop, args=(sock,))
        self.proc.start()
        setattr(self, self.OBJ_ATTR, self.OBJ_CLS(path))

    def tearDown(self):
        self.proc.kill()
        self.proc.join()
