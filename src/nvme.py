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

try:
    from libnvme import nvme
except ImportError:
    pass

import base64
import hmac
import multiprocessing
import random
import socket
import uuid
import zlib

from . import base
from . import utils


class NVMEBackend(base.BackendBase):
    BDEV_PREFIX = 'nvme'
    BDEV_CLS = 'NVMe'
    KEYS_DIR = '/tmp/'

    def __init__(self, path=None):
        super().__init__(path)

    @staticmethod
    def get_description():
        return "Operate on NVMe-oF devices"

    @base.cliwrapper(
        ('-t', '--trtype', {'help': 'transport type (optional)',
                            'choices': ['tcp', 'rdma'], 'default': 'tcp'}),
        ('-a', '--traddr', 'transport address'),
        ('-s', '--trsvcid', 'transport service ID (i.e: TCP port)'),
        ('-q', '--hostnqn', 'host NQN (optional)'))
    def discover(self, traddr, trsvcid, hostnqn=None, trtype='tcp', **kwargs):
        """
        Run the discovery service on an address.

        This command will display all the subsystems to which an initiator
        may connect to.
        """
        def _discover(trtype, traddr, trsvcid, hostnqn, out):
            root = nvme.root()
            host = nvme.host(root, hostnqn, hostnqn[len(utils.NQN_BASE):])
            ctrl = nvme.ctrl(root, nvme.NVME_DISC_SUBSYS_NAME, trtype,
                             traddr, None, None, trsvcid)
            ctrl.connect(host)
            out.extend(ctrl.discover())

        # Need to do it in a separate process, as libnvme is very crash happy.
        mgr = multiprocessing.Manager()
        out = mgr.list()
        args = (trtype, traddr, trsvcid,
                hostnqn or self.config['hostnqn'], out)
        proc = multiprocessing.Process(target=_discover, args=args)
        proc.start()
        proc.join()

        return list(out)

    @staticmethod
    def _update_adrfam(kwargs, traddr):
        ret = kwargs.copy()
        ret['adrfam'] = NVMEBackend._adrfam(traddr)
        return ret

    @staticmethod
    def _adrfam(addr):
        try:
            socket.inet_pton(socket.AF_INET, addr)
            return 'ipv4'
        except OSError:
            socket.inet_pton(socket.AF_INET6, addr)
            return 'ipv6'

    @staticmethod
    def _filt_nvme(name):
        idx = name.rfind('n')
        return name[:idx] if idx >= 0 else name

    def _list(self):
        bdevs = self.msgloop(self.rpc.bdev_get_bdevs())
        blks = self.list_blks()
        ret = {}

        for bdev in bdevs:
            name = bdev['name']
            if not name.startswith(self.BDEV_PREFIX):
                continue

            for blk in blks:
                if blk['bdev_name'] != name:
                    continue

                spec = bdev['driver_specific']['nvme']
                base = {'name': name, 'nqn': spec[0]['trid']['subnqn']}
                out = ret.setdefault(blk['blk_device'], base).setdefault(
                    'paths', [])
                out.extend(x['trid'] for x in spec)

        return ret

    @base.cliwrapper()
    def list(self, **kwargs):
        """List all the NVMe block devices."""
        ret = []

        for device, elem in self._list().items():
            tmp = {'device': device, 'subsystem': elem.pop('nqn')}
            tmp.update(elem)
            ret.append(tmp)

        return ret

    @base.cliwrapper(
        ('-n', '--subnqn', 'subsystem NQN'),
        ('-t', '--trtype', {'help': 'transport type (optional)',
                            'choices': ['tcp', 'rdma'], 'default': 'tcp'}),
        ('-a', '--traddr', 'transport address'),
        ('-s', '--trsvcid', 'transport service ID (i.e: TCP port)'),
        ('-S', '--dhchap-key', 'DH-CHAP key (optional)'),
        ('-q', '--hostnqn', 'host NQN (optional)'))
    def connect_all(self, **kwargs):
        """
        Connect to all the NVMe-oF targets specified.

        This command works like a sequential call to several 'connect'
        commands, using the discovery mechanism to query what NVMe-oF
        targets are available.
        """
        endpoints = self.discover(**kwargs)
        if not endpoints:
            raise base.TargetError('no controllers found')

        nqn = endpoints[0]['subnqn']
        ret = {}
        err = None
        for elem in endpoints:
            if elem.get('subnqn') != nqn:
                continue

            try:
                rv = self.connect(**elem)
                ret['block-device'] = rv['block-device']
                ret.setdefault('targets', []).append(elem)
            except base.TargetError as exc:
                ret.setdefault('failed', []).append(elem)
                err = str(exc)

        if not ret.get('block-device'):
            raise base.TargetError('could not connect to any target: %s' % err)

        return ret

    @base.cliwrapper(
        ('-m', '--hf', {'help': 'HMAC function (optional)',
                        'choices': ['none', 'sha256', 'sha384', 'sha512'],
                        'default': 'none'}),
        ('-s', '--secret', 'secret key in hex bytes (optional)'),
        ('-l', '--length', {'type': int,
                            'help': 'size in bytes for the key (optional)'}),
        ('-n', '--nqn', 'NQN for the key (optional)'))
    def gen_dhchap_key(self, hf='none', secret=None, length=None, nqn=None):
        """Generate a DH-CHAP key to use in NVMe-oF connections."""
        algos = {'sha256': 32, 'sha384': 48, 'sha512': 64}
        if algos.get(hf) is None and hf != 'none':
            raise base.TargetError('invalid HMAC algorithm')

        expected_size = algos.get(hf, 32)
        if length is None:
            length = expected_size
        elif length != expected_size:
            raise base.TargetError('invalid key length - '
                                   'expected %d' % expected_size)

        if secret is None:
            secret = random.randbytes(length)
        else:
            secret = bytes.fromhex(secret)
            if len(secret) != length:
                raise base.TargetError('invalid secret length - '
                                       'must be %d bytes' % length)

        if hf == 'none':
            key = secret
        else:
            hm = hmac.new(secret, msg=None, digestmod=hf)
            hm.update((nqn or self.config['hostnqn']).encode('utf8'))
            hm.update(b'NVMe-over-Fabrics')
            key = hm.digest()

        crc = zlib.crc32(key) & 0xffffffff
        key += bytes([(crc >> shift) & 0xff for shift in (0, 8, 16, 24)])

        hmac_ix = ('none', 'sha256', 'sha384', 'sha512').index(hf)
        key = base64.b64encode(key).decode('utf8')

        return {'key': 'DHHC-1:%02x:%s:' % (hmac_ix, key)}

    @base.cliwrapper()
    def gen_nqn(self, **kwargs):
        """Generate a host NQN to use in NVMe-oF connections."""
        return {'nqn': utils.gen_nqn()}

    @base.cliwrapper()
    def gen_hostid(self, **kwargs):
        """Generate a host ID to use in NVMe-oF connections."""
        return {'hostid': str(uuid.uuid4())}

    def _ensure_key(self, key):
        fname = key.replace(':', '')
        fpath = NVMEBackend.KEYS_DIR + fname

        with open(fpath, 'a+') as file:
            if file.tell() != 0:
                return fname

            file.write(key)
            file.flush()
            msg = self.rpc.keyring_file_add_key(name=fname, path=fpath)
            rv = self.msgloop(msg, default=None)
            return None if rv is None else fname

    def _make_bdev_name(self, subnqn):
        # Note: Unlike other backends, we can't simply generate a
        # random bdev name, because NVMe controllers need to have
        # a specific convention (must end with a digit to be followed
        # by the namespace ID).
        def add_id(out, name):
            out.add(int(name[len(self.BDEV_PREFIX):]))

        ids = set()
        bdev = None
        blockdev_needed = False

        for elem in self.msgloop(self.rpc.bdev_nvme_get_controllers()):
            name = elem['name']
            ctls = elem.get('ctrlrs')
            if ctls[0]['trid']['subnqn'] == subnqn:
                bdev = name
                break

            add_id(ids, name)
        else:
            blockdev_needed = True
            idx = 1
            while idx in ids:
                idx += 1

            bdev = self.BDEV_PREFIX + str(idx)

        return bdev, blockdev_needed

    @base.cliwrapper(
        ('-n', '--subnqn', 'subsystem NQN'),
        ('-t', '--trtype', {'help': 'transport type (optional)',
                            'choices': ['tcp', 'rdma'], 'default': 'tcp'}),
        ('-a', '--traddr', 'transport address'),
        ('-s', '--trsvcid', 'transport service ID (i.e: TCP port)'),
        ('-S', '--dhchap-key', 'DH-CHAP key (optional)'),
        ('-q', '--hostnqn', 'host NQN (optional)'),
        ('-i', '--hostaddr', 'host address to use (optional)'),
        ('-c', '--hostsvcid', 'host service ID (i.e: TCP port) (optional)'))
    def connect(self, subnqn, traddr, trsvcid, trtype='tcp', dhchap_key=None,
                hostnqn=None, hostaddr=None, hostsvcid=None, **kwargs):
        """
        Connect to an NVMe-oF target.

        If the NQN is already being managed by a block device, then that
        device will add the target in a multipath mode. Otherwise, a new
        block device will be allocated.
        """
        bdev, blockdev_needed = self._make_bdev_name(subnqn)
        adrfam = self._adrfam(traddr)
        if hostnqn is None:
            hostnqn = self.config['hostnqn']

        msg = self.rpc.bdev_nvme_attach_controller(
            name=bdev, trtype=trtype, traddr=traddr, adrfam=adrfam,
            trsvcid=trsvcid, subnqn=subnqn,
            multipath='multipath', hostnqn=hostnqn)

        if dhchap_key is not None:
            key = self._ensure_key(dhchap_key)
            if key is None:
                raise base.TargetError('failed to add DH-CHAP key')

            msg['params']['dhchap_key'] = key

        if hostaddr is not None:
            msg['params']['hostaddr'] = hostaddr
        if hostsvcid is not None:
            msg['params']['hostsvcid'] = hostsvcid

        rv = self.msgloop(msg)
        if not blockdev_needed:
            return self.lookup_bdev(bdev, self._filt_nvme)

        try:
            return self.make_blockdev(rv[0])
        except Exception:
            msg = self.rpc.bdev_nvme_detach_controller(
                name=bdev, trtype=trtype, traddr=traddr,
                adrfam=adrfam, trsvcid=trsvcid, subnqn=subnqn)
            if hostaddr is not None:
                msg['params']['hostaddr'] = hostaddr
            if hostsvcid is not None:
                msg['params']['hostsvcid'] = hostsvcid

            self.msgloop(msg, default=None)
            raise

    @base.cliwrapper(
        ('device', 'NVMe-oF block device to disconnect'),
        ('-t', '--trtype', {'help': 'transport type (optional)',
                            'choices': ['tcp', 'rdma'], 'default': 'tcp'}),
        ('-a', '--traddr', 'transport address (optional)'),
        ('-s', '--trsvcid', 'transport service ID (i.e: TCP port) (optional)'))
    def disconnect(self, device, **kwargs):
        """
        Disconnect an NVMe-oF block device.

        If the device has a single path, then the transport parameters
        are not needed, and the device will be closed on success.

        If the device has multiple paths, then it is necessary to pass
        the trasnport options so that only that one path may be disconnected.
        Otherwise, if all paths must be disconnected, then it's necessary to
        call the 'disconnect-all' command.
        """

        devs = self._list()
        subsys = devs.get(device)

        if subsys is None:
            raise base.TargetError('NVMe device %s not found' % device)

        paths = subsys.get('paths', ())
        if not paths:
            raise base.TargetError('no valid paths to disconnect')

        if kwargs['traddr'] is None:
            if kwargs['trsvcid'] is not None:
                raise base.TargetError('missing `traddr`')
            elif len(paths) > 1:
                raise base.TargetError('multiple paths exist. '
                                       'please specify transport id')
            kwargs = paths[0]
        elif kwargs['trsvcid'] is None:
            raise base.TargetError('missing `trsvcid`')

        kwargs = self._update_adrfam(kwargs, kwargs['traddr'])
        bdev = self._filt_nvme(subsys['name'])
        paths = subsys.get('paths', ())

        for path in paths:
            if not self.dict_eq(path, kwargs,
                                ('trtype', 'traddr', 'trsvcid', 'adrfam')):
                continue

            msg = self.rpc.bdev_nvme_detach_controller(name=bdev, **kwargs)
            return self.msgloop(msg)

        raise base.TargetError('path not found for device %s' % device)

    @base.cliwrapper(('device', 'NVMe-oF block device'))
    def disconnect_all(self, device):
        """
        Disconnect all paths and close an NVMe-oF block device.
        """
        subsys = self._list().get(device)
        if subsys is None:
            raise base.TargetError('NVMe device not found')

        msg = self.rpc.bdev_nvme_detach_controller(
            name=self._filt_nvme(subsys['name']))
        return self.msgloop(msg)

    @base.cliwrapper(
        ('device', 'NVMe-oF block device'),
        ('-t', '--trtype', {'help': 'transport type (optional)',
                            'choices': ['tcp', 'rdma'], 'default': 'tcp'}),
        ('-a', '--traddr', 'transport address'),
        ('-s', '--trsvcid', 'transport service ID (i.e: TCP port)'))
    def set_preferred_path(self, device, **kwargs):
        """
        Set the preferred path for an NVMe-oF block device.

        The path specified by the transport options must be up for this
        call to have an effect (i.e: Its ANA state must not be 'inaccessible').
        """
        bdev = self.lookup_device(device)
        controller = self._filt_nvme(bdev)
        kwargs = self._update_adrfam(kwargs, kwargs['traddr'])

        for elem in self.msgloop(self.rpc.bdev_nvme_get_controllers()):
            if elem['name'] != controller:
                pass

            ctls = [x for x in elem['ctrlrs'] if x['state'] == 'enabled']
            for elem in ctls:
                if self.dict_ieq(elem['trid'], kwargs,
                                 ('trtype', 'traddr', 'trsvcid', 'adrfam')):
                    return self.msgloop(self.rpc.bdev_nvme_set_preferred_path(
                        name=bdev, cntlid=elem['cntlid']))
            raise base.TargetError('Transport ID not found for controller')

    @base.cliwrapper(
        ('device', 'NVMe-oF block device'),
        ('-s', '--selector', {'help': 'multipath selector (optional)',
                              'choices': ['round_robin', 'queue_depth'],
                              'default': 'round_robin'}),
        ('-p', '--policy', {'help': 'multipath policy (optional)',
                            'choices': ['active_active', 'active_passive'],
                            'default': 'active_active'}))
    def set_multipath_policy(self, device,
                             selector='round_robin', policy='active_active'):
        """
        Set the multipath policy of an NVMe-oF block device.
        """
        bdev = self.lookup_device(device)
        return self.msgloop(self.rpc.bdev_nvme_set_multipath_policy(
            name=bdev, policy=policy, selector=selector))
