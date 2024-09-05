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


class RamdiskBackend(base.BackendBase):
    BDEV_PREFIX = 'rd'
    BDEV_CLS = 'ramdisk'
    BLOCK_SIZE = 4096

    def __init__(self, path=None):
        super().__init__(path)

    @staticmethod
    def get_description():
        return "Operate on ramdisk devices and manage caches"

    def _create(self, size):
        size = utils.parse_memsize(size)
        num_blocks = -(-size // self.BLOCK_SIZE)

        msg = self.rpc.bdev_malloc_create(
            name=self.BDEV_PREFIX + '-' + utils.unique_id(),
            block_size=self.BLOCK_SIZE,
            num_blocks=num_blocks)

        return self.msgloop(msg)

    def _remove(self, name):
        self.msgloop(self.rpc.bdev_malloc_delete(name=name))

    @base.cliwrapper(('size', 'size of the ramdisk device'))
    def create(self, size):
        """Create a block device backed by regular memory."""
        bdev = self._create(size)
        try:
            return self.make_blockdev(bdev)
        except Exception:
            self._remove(bdev)
            raise

    def _delete_ocf(self, name):
        rv = self.msgloop(self.rpc.bdev_ocf_get_bdevs(name=name))
        cache, core = rv[0]['cache']['name'], rv[0]['core']['name']
        self.msgloop(self.rpc.bdev_ocf_delete(name=name))
        return cache, core

    @base.cliwrapper(('device', 'ramdisk block device'))
    def delete(self, device):
        """delete a ramdisk block device."""
        bdev = self.lookup_device(device)
        if '.ocf-' in bdev:
            rv = self._delete_ocf(bdev)
            bdev = rv[0]

        return self._remove(bdev)

    @base.cliwrapper(
        ('device', 'managed block device'),
        ('-s', '--size', 'size of the cache'),
        ('-m', '--mode', {'help': 'cache mode (optional)',
                          'choices': ['wb', 'wt', 'pt', 'wa', 'wi', 'wo'],
                          'default': 'wb'}))
    def cache(self, device, size, mode='wb'):
        """
        Add an in-memory cache to a managed block device.

        As a result of this command, a new block device will be allocated.
        """
        bdev = self.lookup_device(device, prefix=None)
        malloc_name = self._create(size)

        ocf_name = self.BDEV_PREFIX + '.ocf-' + utils.unique_id()
        msg = self.rpc.bdev_ocf_create(
            name=ocf_name, mode=mode,
            cache_line_size=64,
            cache_bdev_name=malloc_name,
            core_bdev_name=bdev)

        try:
            self.msgloop(msg)
            return self.make_blockdev(ocf_name)
        except Exception:
            self.msgloop(self.rpc.bdev_ocf_delete(name=ocf_name), default=None)
            self.msgloop(self.rpc.bdev_malloc_delete(name=malloc_name),
                         default=None)
            raise

    def _lookup_ocf(self, device):
        bdev = self.lookup_device(device)
        if '.ocf-' not in bdev:
            raise base.TargetError('device does not have a ramdisk cache')
        return bdev

    @base.cliwrapper(('device', 'cached block device'))
    def uncache(self, device):
        """
        Remove the cache from a block device.

        If successful, this call will return the previous block device.
        """
        bdev = self._lookup_ocf(device)
        rv = self._delete_ocf(bdev)
        return {'previous': self.lookup_bdev(rv[1])['block-device']}

    @base.cliwrapper(('device', 'cached block device'))
    def cache_flush(self, device):
        """Force flusing of a cached block device."""
        bdev = self._lookup_ocf(device)
        return self.msgloop(self.rpc.bdev_ocf_flush_start(name=bdev))

    @base.cliwrapper(
        ('device', 'cached block device'),
        ('-m', '--mode', {'help': 'cache mode (optional)', 'default': 'wb',
                          'choices': ['wb', 'wt', 'pt', 'wa', 'wi', 'wo']}))
    def cache_set_mode(self, device, mode=None):
        """Change the caching mode of a cached block device."""
        bdev = self._lookup_ocf(device)
        return self.msgloop(self.rpc.bdev_ocf_set_cache_mode(
            name=bdev, mode=mode))

    @base.cliwrapper()
    def list(self, **kwargs):
        """List all ramdisk block devices."""
        bdevs = self.msgloop(self.rpc.bdev_get_bdevs(), default=())
        blks = self.list_blks()
        ret = []

        for elem in self.bdev_iter(bdevs=bdevs):
            name = elem['name']
            device = self.lookup_bdev(name, blks=blks)

            if not device:
                continue

            base = {}
            if '.ocf-' in name:
                ds = elem['driver_specific']
                core = self.lookup_bdev(ds['core_device'], blks=blks)
                cache_bdev = self.bdev_info(ds['cache_device'], bdevs=bdevs)

                if not core or not cache_bdev:
                    continue

                base['core'] = core['block-device']
                elem = cache_bdev


            size = elem['block_size'] * elem['num_blocks']
            base.update({'device': device['block-device'],
                         'size': utils.format_size(size)})
            ret.append(base)

        return ret
