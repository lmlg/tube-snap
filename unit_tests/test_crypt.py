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

import unittest.mock as mock

import src.base as base
from src.crypt import CryptBackend

from . import utils


class TestCrypt(utils.BaseTest):
    OBJ_ATTR = 'crypt'
    OBJ_CLS = CryptBackend

    @mock.patch.object(base.os, 'access')
    def test_crypt(self, access):
        access.return_value = True
        # Need to create a block device beforehand.
        self.crypt.msgloop(self.crypt.rpc.bdev_malloc_create(
            name='malloc1', block_size=4096, num_blocks=512 * 1024 * 1024))

        self.crypt.msgloop(self.crypt.rpc.ublk_start_disk(
            bdev_name='malloc1', ublk_id=1))

        # Now we can continue.
        rv = self.crypt.create(device='/dev/ublkb1', key='012345',
                               cipher='AES_XTS')
        self.assertEqual(rv['block-device'], '/dev/ublkb2')

        rv = self.crypt.list()
        self.assertEqual(len(rv), 1)
        self.assertEqual(rv[0]['device'], '/dev/ublkb2')
        self.assertEqual(rv[0]['base'], '/dev/ublkb1')

        with self.assertRaises(base.TargetError):
            self.crypt.delete(device='/dev/ublkb1')

        self.crypt.delete(device='/dev/ublkb2')
        rv = self.crypt.list()
        self.assertEqual(len(rv), 0)
