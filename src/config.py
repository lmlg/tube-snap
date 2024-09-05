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

from collections import namedtuple
import json
import logging
import os
import uuid

from . import base
from . import utils


Option = namedtuple('Option', ['verify', 'default'])


def _verify_cpuset(spec, conf):
    cpuset = spec.strip()
    val = json.loads(cpuset)

    if isinstance(val, int):
        if val <= 0:
            raise ValueError('CPU count must be > 0')
        return conf.cpus[:val]
    elif isinstance(val, list):
        val = list(set(val).intersect(set(conf.cpus)))
        if not val:
            raise ValueError('CPU set did not specify any valid CPU')
        return val
    raise ValueError('CPU spec must be an integer or a list')


def _default_cpuset(conf):
    # By default, use a third of available cores.
    rlen = -(len(conf.cpus) // -3)
    return conf.cpus[:rlen]


def _verify_memsize(spec, conf):
    val = min(conf.total_mem, utils.parse_memsize(spec.strip()))
    return utils.format_size(val)


def _default_memsize(conf):
    # By default use 25% of available memory.
    return utils.format_size(conf.total_mem / 4.)


def _verify_nqn(spec):
    spec = spec.strip()
    if spec == 'nqn.2014-08.org.nvmexpress.discovery':
        raise ValueError('cannot use discovery NQN')
    elif spec.startswith(utils.NQN_BASE):
        spec = spec.replace(utils.NQN_BASE, '').replace('-', '')
        bstr = bytes.fromhex(spec)
        uuid.UUID(bytes=bstr)
    elif not spec.startswith('nqn.'):
        raise ValueError('invalid NQN')


def _default_nqn(conf):
    return utils.gen_nqn()


def _default_hostid(conf):
    return str(uuid.uuid4())


class ConfigHandler:

    def __init__(self, path, disable=True):
        self.logger = logging.getLogger('config')
        self.logger.disabled = disable
        self.conf_path = os.path.join(os.path.dirname(path), 'config.json')
        self.total_mem = (os.sysconf('SC_PAGE_SIZE') *
                          os.sysconf('SC_PHYS_PAGES'))
        self.cpus = list(os.sched_getaffinity(0))
        self.fields = {
            'cpuset': Option(_verify_cpuset, _default_cpuset),
            'memsize': Option(_verify_memsize, _default_memsize),
            'hostnqn': Option(_verify_nqn, _default_nqn),
            'hostid': Option(None, _default_hostid),
        }

        try:
            self.load_config()
            self._verify_config()
        except Exception:
            self.logger.warning('could not load config file')
            self.load_default_config()
            self.store_config()

    @staticmethod
    def get_description():
        return "Manage configuration values"

    def load_config(self):
        with open(self.conf_path, 'r') as file:
            self.config_map = json.loads(file)

    def load_default_config(self):
        self.config_map = {}
        for key, opt in self.fields.items():
            self.config_map[key] = opt.default(self)

    def store_config(self):
        try:
            with open(self.conf_path, 'w') as file:
                file.write(json.dumps(self.config_map))
                file.flush()
        except Exception:
            self.logger.warning('could not save configuration file')

    def _verify_config(self):
        if not isinstance(self.config_map, dict):
            self.logger.error('invalid JSON config - loading default')
            self.load_default_config()
            return

        for key, opt in self.fields.items():
            value = self.config_map.get(key)
            if value is None:
                self.config_map[key] = opt.default()
                continue

            try:
                opt.verify(value, self)
            except Exception:
                self.logger.warning('invalid value for config option %s -'
                                    'using default' % key)
                self.config_map[key] = opt.default()

    @base.cliwrapper(('key', 'configuration key to fetch'))
    def get(self, key=None):
        """Get the value of a configuration key."""
        try:
            return {'value': self.config_map[key]}
        except KeyError:
            return {'error': 'key %s not found' % key}

    @base.cliwrapper(
        ('key', 'configuration key to set'),
        ('value', 'the new value'))
    def set(self, key=None, value=None):
        """Set a configuration key to a value."""
        if key not in self.config_map:
            return {'error': 'key %s not found' % key}

        try:
            self.fields[key].verify(value)
        except Exception:
            self.logger.error('invalid value for key %s' % key)
            return

        self.config_map[key] = value
        self.store_config()

    @property
    def cpumask(self):
        mask = 0
        for cpu in self.cpuset:
            mask |= 1 << cpu
        return mask

    def __getitem__(self, key):
        return self.config_map[key]
