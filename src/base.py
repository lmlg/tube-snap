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

import argparse
import glob
import json
import logging
import os
import socket

from . import utils

SENTINEL = object()


class ArgsParsedFunction:
    """
    Helper class that is callable while at the same time keeping
    an argument parser so that the function it wraps around can
    maintain the semantics of a command-line interface.
    """
    def __init__(self, parser, fn):
        parser.prog = fn.__name__.replace('_', '-')
        parser.description = fn.__doc__
        self.parser = parser
        self.fn = fn

    def parse_args(self, args):
        return vars(self.parser.parse_args(args))

    def __get__(self, inst, cls):
        if inst is None:
            return self
        return lambda *args, **kwargs: self.fn(inst, *args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.fn(*args, **kwargs)


def _arg_required(docstr):
    return '(optional)' not in docstr


def cliwrapper(*args):
    parser = argparse.ArgumentParser()
    for arg in args:
        last = arg[-1]

        # We support 2 types of CLI specs. Both use the first 2 elements
        # of a tuple to specify short and long argumens. In the short form,
        # the third argument specifies the argument descriptor, whereas the
        # long form is a fully-fledged dictionary that is passed to the
        # 'argparse' module.

        if isinstance(last, dict):
            # Long form.
            if 'type' not in last:
                last['type'] = str
            last['required'] = _arg_required(last.get('help', ''))
            parser.add_argument(*arg[:-1], **last)
        else:
            # Short form.
            kwargs = ({'required': _arg_required(last)}
                      if len(arg) != 2 else {})
            parser.add_argument(*arg[:-1], help=last, **kwargs)

    return lambda f: ArgsParsedFunction(parser, f)


class TargetError(Exception):
    pass


def cli_method(cls, method):
    caller = getattr(cls, method.replace('-', '_'), None)
    if caller is not None and isinstance(caller, ArgsParsedFunction):
        return caller
    return None


def cli_call(caller, inst, args):
    try:
        args = caller.parse_args(args)
        return getattr(inst, caller.parser.prog.replace('-', '_'))(**args)
    except TargetError as exc:
        return {'error': str(exc)}
    except Exception as exc:
        inst.logger.exception(exc)


def get_cli_methods(cls):
    ret = []
    for key in cls.__dict__:
        member = getattr(cls, key)
        if isinstance(member, ArgsParsedFunction):
            ret.append(member)
    return ret


class BackendBase:

    BDEV_PREFIX = None
    BDEV_CLS = None

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.rpc = utils.RPC()
        self.logger = logging.getLogger(type(self).__name__)
        self._config = None

    def msgloop(self, msg, rcvsize=4096, default=SENTINEL):
        self.sock.sendall(json.dumps(msg).encode('utf8'))
        ret = json.loads(self.sock.recv(rcvsize))

        if not isinstance(ret, dict):
            raise TypeError('invalid response received')
        elif 'error' in ret:
            if default is not SENTINEL:
                return default
            raise TargetError(ret['error'])
        return ret['result']

    @staticmethod
    def _dict_eq(x, y, fn, keys):
        for k in keys:
            if k not in x or k not in y or fn(x[k]) != fn(y[k]):
                return False
        return True

    @staticmethod
    def dict_eq(x, y, keys):
        return BackendBase._dict_eq(x, y, lambda arg: arg, keys)

    @staticmethod
    def dict_ieq(x, y, keys):
        return BackendBase._dict_eq(x, y, lambda arg: arg.lower(), keys)

    @property
    def config(self):
        from . import config   # Avoid circular import
        if self._config is None:
            self._config = config.ConfigHandler(utils.SNAP_PATH, disable=False)
        return self._config

    def bdev_iter(self, bdevs=None, **kwargs):
        prefix = kwargs.get('prefix', self.BDEV_PREFIX)
        for elem in (bdevs or self.msgloop(self.rpc.bdev_get_bdevs())):
            name = elem['name']
            if name.startswith(prefix):
                yield elem

    def bdev_info(self, bdev_name, bdevs=None):
        for bdev in (bdevs or self.msgloop(self.rpc.bdev_get_bdevs())):
            if bdev['name'] == bdev_name:
                return bdev

    def lookup_bdev(self, bdev, filt=None, blks=None):
        for elem in (blks or self.list_blks()):
            name = elem['bdev_name']
            if filt is not None:
                name = filt(name)

            if name == bdev:
                return {'block-device': elem['blk_device']}

    def make_blockdev(self, bdev):
        if os.access('/dev/ublk-control', os.F_OK):
            # Use ublk if possible
            for i in range(1, 100):
                msg = self.rpc.ublk_start_disk(bdev_name=bdev, ublk_id=i)
                rv = self.msgloop(msg, default='')
                if rv != '':
                    return {'block-device': '/dev/ublkb%d' % i}

        # Otherwise, fall back to NBD.
        for file in glob.glob('/dev/nbd*'):
            msg = self.rpc.nbd_start_disk(bdev_name=bdev, nbd_device=file)
            rv = self.msgloop(msg, default='')
            if rv != '':
                return {'block-device': file}

        raise TargetError('no free block device found')

    def remove_blockdev(self, device):
        if device.startswith('/dev/nbd'):
            return self.msgloop(self.rpc.nbd_stop_disk(nbd_device=device))

        try:
            blkid = int(device.replace('/dev/ublkb', ''))
        except ValueError:
            raise TargetError('invalid block device: %s' % device)

        return self.msgloop(self.rpc.ublk_stop_disk(ublk_id=blkid))

    def list_blks(self):
        ublks = self.msgloop(self.rpc.ublk_get_disks(), default=())
        nbds = self.msgloop(self.rpc.nbd_get_disks(), default=())
        ret = [{'blk_device': x['ublk_device'],
                'bdev_name': x['bdev_name']} for x in ublks]

        ret.extend([{'blk_device': x['nbd_device'],
                     'bdev_name': x['bdev_name']} for x in nbds])
        return ret

    def lookup_device(self, device, blks=None, **kwargs):
        prefix = kwargs.get('prefix', self.BDEV_PREFIX)

        for elem in (blks or self.list_blks()):
            if elem['blk_device'] == device:
                bdev = elem['bdev_name']
                if prefix is not None and not bdev.startswith(prefix):
                    raise TargetError('device is not %s' % self.BDEV_CLS)
                return bdev

        raise TargetError('device %s not found' % device)

    @staticmethod
    def is_error(value):
        return isinstance(value, dict) and 'error' in value
