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
from src.nvme import NVMEBackend

from . import utils


class NVME(NVMEBackend):
    def __init__(self, path):
        super().__init__(path)

    def discover(self, **kwargs):
        ret = [{'trtype': 'tcp', 'adrfam': 'ipv4', 'traddr': '10.122.104.30',
               'trsvcid': '53099', 'subnqn': 'nqn.1'},
               {'trtype': 'tcp', 'adrfam': 'ipv4', 'traddr': '10.122.104.97',
                'trsvcid': '33236', 'subnqn': 'nqn.1'}]
        return ret


class TestNVME(utils.BaseTest):
    OBJ_ATTR = 'nvme'
    OBJ_CLS = NVME

    @mock.patch.object(base.os, 'access')
    def test_nvme(self, access):
        access.return_value = True
        ctls = self.nvme.list()
        self.assertFalse(ctls)

        rv = self.nvme.connect(
            traddr='1.1.1.1', trsvcid='1',
            trtype='tcp', subnqn='nqn.1')
        self.assertTrue(isinstance(rv, dict))
        self.assertIn('block-device', rv)
        device = rv['block-device']

        rv = self.nvme.list()
        self.assertFalse(self.nvme.is_error(rv))
        self.assertEqual(len(rv), 1)

        rv = self.nvme.connect(
            traddr='2.2.2.2', trsvcid='2',
            trtype='tcp', subnqn='nqn.1')
        self.assertEqual(rv, {'block-device': device})
        rv = self.nvme.list()
        self.assertEqual(len(rv), 1)

        rv = self.nvme.connect(
            traddr='3.3.3.3', trsvcid='3',
            trtype='tcp', subnqn='nqn.1')
        self.assertEqual(rv, {'block-device': device})

        rv = self.nvme.disconnect(
            device=device, traddr='3.3.3.3', trsvcid='3', trtype='tcp')
        self.assertFalse(self.nvme.is_error(rv))

        rv = self.nvme.list()
        self.assertEqual(len(rv), 1)
        self.assertEqual(rv[0]['device'], device)
        self.assertEqual(len(rv[0]['paths']), 3)

        # Test a call via the cli
        method = base.cli_method(type(self.nvme), 'disconnect_all')
        self.assertIsNotNone(method)
        rv = base.cli_call(method, self.nvme, [device])
        self.assertFalse(self.nvme.is_error(rv))

        rv = self.nvme.list_blks()
        self.assertFalse(self.nvme.is_error(rv))
        self.assertEqual(len(rv), 0)

        rv = self.nvme.gen_dhchap_key(hf='none', nqn='nqn.1')
        self.assertFalse(self.nvme.is_error(rv))
        self.assertTrue(rv['key'].startswith('DHHC-1:00'))
        self.assertEqual(len(rv['key']), 48 + 11)
