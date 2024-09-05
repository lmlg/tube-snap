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

from . import base
from . import utils


class CryptBackend(base.BackendBase):
    BDEV_PREFIX = 'cr'
    BDEV_CLS = 'crypt'

    def __init__(self, path=None):
        super().__init__(path)

    @staticmethod
    def get_description():
        return "Encrypt managed devices"

    def _key_create(self, uid, key2=None, tweak_mode=None, **kwargs):
        name = self.BDEV_PREFIX + '.key-' + uid
        msg = self.rpc.accel_crypto_key_create(name=name, **kwargs)
        if key2 is not None:
            msg['params']['key2'] = key2
        if tweak_mode is not None:
            msg['params']['tweak_mode'] = tweak_mode

        self.msgloop(msg)
        return name

    @base.cliwrapper(
        ('device', 'block device to use as a base'),
        ('-c', '--cipher', {'help': 'Cipher to use',
                            'choices': ['AES_CBC', 'AES_XTS']}),
        ('-k', '--key', 'crypto key in hex form'),
        ('-e', '--key2', 'second part of key or tweak in hex form (optional)'),
        ('-t', '--tweak-mode', {'help': 'tweak mode to use (optional)',
                                'choices': ['SIMPLE_LBA', 'INCR_512_FULL_LBA',
                                            'JOIN_NEG_LBA_WITH_LBA',
                                            'INCR_512_UPPER_LBA'],
                                'default': 'SIMPLE_LBA'}))
    def create(self, device, key, cipher, key2=None, tweak_mode=None):
        """
        Encrypt a managed block device.

        As a result of this command, a new block device will be allocated.
        """
        bdev = self.lookup_device(device, prefix=None)
        uid = utils.unique_id()
        key = self._key_create(uid, cipher=cipher, key=key, key2=key2,
                               tweak_mode=tweak_mode)
        try:
            new_bdev = self.BDEV_PREFIX + '-' + uid
            msg = self.rpc.bdev_crypto_create(
                base_bdev_name=bdev, key_name=key,
                name=new_bdev)
            self.msgloop(msg)
            return self.make_blockdev(new_bdev)
        except Exception:
            self.msgloop(self.rpc.bdev_crypto_delete(name=new_bdev),
                         default=None)
            self.msgloop(self.rpc.accel_crypto_key_destroy(name=key),
                         default=None)
            raise

    @base.cliwrapper(
        ('device', 'encrypted block device'))
    def delete(self, device):
        """Delete a managed encrypted block device."""
        bdev = self.lookup_device(device)
        plen = len(self.BDEV_PREFIX)
        key = bdev[:plen] + '.key' + bdev[plen:]
        self.msgloop(self.rpc.bdev_crypto_delete(name=bdev))
        self.msgloop(self.rpc.accel_crypto_key_destroy(name=key))

    @base.cliwrapper()
    def list(self):
        """List all managed encrypted devices."""
        bdevs = self.msgloop(self.rpc.bdev_get_bdevs(), default=())
        blks = self.list_blks()
        ret = []

        for bdev in bdevs:
            name = bdev['name']
            if not name.startswith(self.BDEV_PREFIX):
                continue

            tmp = bdev['driver_specific']['base_bdev_name']
            dev1 = self.lookup_bdev(name, blks=blks)
            dev2 = self.lookup_bdev(tmp, blks=blks)

            if dev1 and dev2:
                ret.append({'device': dev1['block-device'],
                            'base': dev2['block-device']})

        return ret
