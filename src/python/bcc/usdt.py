
# Copyright 2016 Sasha Goldshtein
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import ctypes as ct
import sys
from .libbcc import lib, _USDT_CB, _USDT_PROBE_CB, \
                    bcc_usdt_location, bcc_usdt_argument, \
                    BCC_USDT_ARGUMENT_FLAGS

class USDTException(Exception):
    pass

class USDTProbeArgument(object):
    def __init__(self, argument):
        self.signed = argument.size < 0
        self.size = abs(argument.size)
        self.valid = argument.valid
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.CONSTANT != 0:
            self.constant = argument.constant
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_OFFSET != 0:
            self.deref_offset = argument.deref_offset
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_IDENT != 0:
            self.deref_ident = argument.deref_ident
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.BASE_REGISTER_NAME != 0:
            self.base_register_name = argument.base_register_name
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.INDEX_REGISTER_NAME != 0:
            self.index_register_name = argument.index_register_name
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.SCALE != 0:
            self.scale = argument.scale

    def _size_prefix(self):
        return "%d %s bytes" % \
                (self.size, "signed  " if self.signed else "unsigned")

    def _format(self):
        # This mimics the logic in cc/usdt_args.cc that gives meaning to the
        # various argument settings. A change there will require a change here.
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.CONSTANT != 0:
            return "%d" % self.constant
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_OFFSET == 0:
            return "%s" % self.base_register_name.decode()
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_OFFSET != 0 and \
           self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_IDENT == 0:
            if self.valid & BCC_USDT_ARGUMENT_FLAGS.INDEX_REGISTER_NAME != 0:
                index_offset = " + %s" % self.index_register_name.decode()
                if self.valid & BCC_USDT_ARGUMENT_FLAGS.SCALE != 0:
                    index_offset += " * %d" % self.scale
            else:
                index_offset = ""
            sign = '+' if self.deref_offset >= 0 else '-'
            return "*(%s %s %d%s)" % (self.base_register_name.decode(),
                                      sign, abs(self.deref_offset), index_offset)
        if self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_OFFSET != 0 and \
           self.valid & BCC_USDT_ARGUMENT_FLAGS.DEREF_IDENT != 0 and \
           self.valid & BCC_USDT_ARGUMENT_FLAGS.BASE_REGISTER_NAME != 0 and \
           self.base_register_name == "ip":
            sign = '+' if self.deref_offset >= 0 else '-'
            return "*(&%s %s %d)" % (self.deref_ident.decode(),
                                     sign, abs(self.deref_offset))
        # If we got here, this is an unrecognized case. Doesn't mean it's
        # necessarily bad, so just provide the raw data. It just means that
        # other tools won't be able to work with this argument.
        return "unrecognized argument format, flags %d" % self.valid

    def __str__(self):
        return "%s @ %s" % (self._size_prefix(), self._format())

class USDTProbeLocation(object):
    def __init__(self, probe, index, location):
        self.probe = probe
        self.index = index
        self.num_arguments = probe.num_arguments
        self.address = location.address
        self.bin_path = location.bin_path

    def __str__(self):
        return "%s 0x%x" % (self.bin_path.decode(), self.address)

    def get_argument(self, index):
        arg = bcc_usdt_argument()
        res = lib.bcc_usdt_get_argument(self.probe.context, self.probe.provider,
                                        self.probe.name,
                                        self.index, index, ct.byref(arg))
        if res != 0:
            raise USDTException(
                    "error retrieving probe argument %d location %d" %
                    (index, self.index))
        return USDTProbeArgument(arg)

class USDTProbe(object):
    def __init__(self, context, probe):
        self.context = context
        self.provider = probe.provider
        self.name = probe.name
        self.bin_path = probe.bin_path
        self.semaphore = probe.semaphore
        self.num_locations = probe.num_locations
        self.num_arguments = probe.num_arguments

    def __str__(self):
        return "%s:%s [sema 0x%x]" % \
               (self.provider.decode(), self.name.decode(), self.semaphore)

    def short_name(self):
        return "%s:%s" % (self.provider.decode(), self.name.decode())

    def get_location(self, index):
        loc = bcc_usdt_location()
        res = lib.bcc_usdt_get_location(self.context, self.provider, self.name,
                                        index, ct.byref(loc))
        if res != 0:
            raise USDTException("error retrieving probe location %d" % index)
        return USDTProbeLocation(self, index, loc)

class USDT(object):
    def __init__(self, pid=None, path=None):
        if pid and pid != -1:
            self.pid = pid
            if path:
                self.context = lib.bcc_usdt_new_frompid(pid, path.encode('ascii'))
            else:
                self.context = lib.bcc_usdt_new_frompid(pid, ct.c_char_p(0))
            if self.context == None:
                raise USDTException("USDT failed to instrument PID %d" % pid)
        elif path:
            self.path = path
            self.context = lib.bcc_usdt_new_frompath(path.encode('ascii'))
            if self.context == None:
                raise USDTException("USDT failed to instrument path %s" % path)
        else:
            raise USDTException(
                    "either a pid or a binary path must be specified")

    def __del__(self):
        lib.bcc_usdt_close(self.context)

    def enable_probe(self, probe, fn_name):
        probe_parts = probe.split(":", 1)
        if len(probe_parts) == 1:
            ret = lib.bcc_usdt_enable_probe(
                self.context, probe.encode('ascii'), fn_name.encode('ascii'))
        else:
            (provider_name, probe_name) = probe_parts
            ret = lib.bcc_usdt_enable_fully_specified_probe(
                self.context, provider_name.encode('ascii'), probe_name.encode('ascii'),
                fn_name.encode('ascii'))

        if ret != 0:
            raise USDTException(
"""Failed to enable USDT probe '%s':
the specified pid might not contain the given language's runtime,
or the runtime was not built with the required USDT probes. Look
for a configure flag similar to --with-dtrace or --enable-dtrace.
To check which probes are present in the process, use the tplist tool.
""" % probe)

    def enable_probe_or_bail(self, probe, fn_name):
        try:
            self.enable_probe(probe, fn_name)
        except USDTException as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    def get_context(self):
        return self.context

    def get_text(self):
        ctx_array = (ct.c_void_p * 1)()
        ctx_array[0] = ct.c_void_p(self.context)
        return lib.bcc_usdt_genargs(ctx_array, 1).decode()

    def get_probe_arg_ctype(self, probe_name, arg_index):
        probe_parts = probe_name.split(":", 1)
        if len(probe_parts) == 1:
            return lib.bcc_usdt_get_probe_argctype(
                self.context, probe_name.encode('ascii'), arg_index).decode()
        else:
            (provider_name, probe) = probe_parts
            return lib.bcc_usdt_get_fully_specified_probe_argctype(
                self.context, provider_name.encode('ascii'), probe.encode('ascii'), arg_index).decode()

    def enumerate_probes(self):
        probes = []
        def _add_probe(probe):
            probes.append(USDTProbe(self.context, probe.contents))

        lib.bcc_usdt_foreach(self.context, _USDT_CB(_add_probe))
        return probes

    # This is called by the BPF module's __init__ when it realizes that there
    # is a USDT context and probes need to be attached.
    def attach_uprobes(self, bpf, attach_usdt_ignore_pid):
        probes = self.enumerate_active_probes()
        for (binpath, fn_name, addr, pid) in probes:
            if attach_usdt_ignore_pid:
                pid = -1
            bpf.attach_uprobe(name=binpath, fn_name=fn_name,
                              addr=addr, pid=pid)

    def enumerate_active_probes(self):
        probes = []
        def _add_probe(binpath, fn_name, addr, pid):
            probes.append((binpath, fn_name, addr, pid))

        lib.bcc_usdt_foreach_uprobe(self.context, _USDT_PROBE_CB(_add_probe))
        return probes