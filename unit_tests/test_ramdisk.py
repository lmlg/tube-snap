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
from src.ramdisk import RamdiskBackend

from . import utils


class TestRamdisk(utils.BaseTest):
    OBJ_ATTR = 'ramdisk'
    OBJ_CLS = RamdiskBackend

    @mock.patch.object(base.os, 'access')
    def test_ramdisk(self, access):
        access.return_value = True
        rv = self.ramdisk.create(size='1.2G')
        self.assertEqual(rv, {'block-device': '/dev/ublkb1'})

        prev = rv = self.ramdisk.list()
        self.assertFalse(self.ramdisk.is_error(rv))
        self.assertEqual(rv, [{'device': '/dev/ublkb1', 'size': '1.2G'}])

        rv = self.ramdisk.cache(device='/dev/ublkb1', size='1.5G', mode='wa')
        self.assertEqual({'block-device': '/dev/ublkb2'}, rv)

        rv = self.ramdisk.list()
        self.assertNotEqual(prev, rv)

        with self.assertRaises(base.TargetError):
            self.ramdisk.cache_flush(device='/dev/ublkb1')

        self.assertFalse(self.ramdisk.is_error(self.ramdisk.cache_flush(
            device='/dev/ublkb2')))

        with self.assertRaises(base.TargetError):
            self.ramdisk.cache_set_mode(device='/dev/ublkb1', mode='wb')

        self.assertFalse(self.ramdisk.is_error(self.ramdisk.cache_set_mode(
            device='/dev/ublkb2', mode='wb')))

        rv = self.ramdisk.uncache(device='/dev/ublkb2')
        self.assertEqual({'previous': '/dev/ublkb1'}, rv)
