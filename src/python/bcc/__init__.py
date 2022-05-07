# Copyright 2015 PLUMgrid
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
import atexit
import ctypes as ct
import fcntl
import json
import os
import re
import errno
import sys
import platform

from .libbcc import lib, bcc_symbol, bcc_symbol_option, bcc_stacktrace_build_id, _SYM_CB_TYPE
from .table import Table, PerfEventArray, RingBuf, BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK
from .perf import Perf
from .utils import get_online_cpus, printb, _assert_is_bytes, ArgString, StrcmpRewrite
from .version import __version__
from .disassembler import disassemble_prog, decode_map
from .usdt import USDT, USDTException

try:
    basestring
except NameError:  # Python 3
    basestring = str

_default_probe_limit = 1000
_num_open_probes = 0

# for tests
def _get_num_open_probes():
    global _num_open_probes
    return _num_open_probes

DEBUGFS = "/sys/kernel/debug"
TRACEFS = os.path.join(DEBUGFS, "tracing")
if not os.path.exists(TRACEFS):
    TRACEFS = "/sys/kernel/tracing"

# Debug flags

# Debug output compiled LLVM IR.
DEBUG_LLVM_IR = 0x1
# Debug output loaded BPF bytecode and register state on branches.
DEBUG_BPF = 0x2
# Debug output pre-processor result.
DEBUG_PREPROCESSOR = 0x4
# Debug output ASM instructions embedded with source.
DEBUG_SOURCE = 0x8
# Debug output register state on all instructions in addition to DEBUG_BPF.
DEBUG_BPF_REGISTER_STATE = 0x10
# Debug BTF.
DEBUG_BTF = 0x20

class SymbolCache(object):
    def __init__(self, pid):
        self.cache = lib.bcc_symcache_new(
                pid, ct.cast(None, ct.POINTER(bcc_symbol_option)))

    def resolve(self, addr, demangle):
        """
        Return a tuple of the symbol (function), its offset from the beginning
        of the function, and the module in which it lies. For example:
            ("start_thread", 0x202, "/usr/lib/.../libpthread-2.24.so")
        If the symbol cannot be found but we know which module it is in,
        return the module name and the offset from the beginning of the
        module. If we don't even know the module, return the absolute
        address as the offset.
        """

        sym = bcc_symbol()
        if demangle:
            res = lib.bcc_symcache_resolve(self.cache, addr, ct.byref(sym))
        else:
            res = lib.bcc_symcache_resolve_no_demangle(self.cache, addr,
                                                       ct.byref(sym))
        if res < 0:
            if sym.module and sym.offset:
                return (None, sym.offset,
                        ct.cast(sym.module, ct.c_char_p).value)
            return (None, addr, None)
        if demangle:
            name_res = sym.demangle_name
            lib.bcc_symbol_free_demangle_name(ct.byref(sym))
        else:
            name_res = sym.name
        return (name_res, sym.offset, ct.cast(sym.module, ct.c_char_p).value)

    def resolve_name(self, module, name):
        module = _assert_is_bytes(module)
        name = _assert_is_bytes(name)
        addr = ct.c_ulonglong()
        if lib.bcc_symcache_resolve_name(self.cache, module, name,
                ct.byref(addr)) < 0:
            return -1
        return addr.value

class PerfType:
    # From perf_type_id in uapi/linux/perf_event.h
    HARDWARE = 0
    SOFTWARE = 1
    TRACEPOINT = 2
    HW_CACHE = 3
    RAW = 4
    BREAKPOINT = 5

class PerfHWConfig:
    # From perf_hw_id in uapi/linux/perf_event.h
    CPU_CYCLES = 0
    INSTRUCTIONS = 1
    CACHE_REFERENCES = 2
    CACHE_MISSES = 3
    BRANCH_INSTRUCTIONS = 4
    BRANCH_MISSES = 5
    BUS_CYCLES = 6
    STALLED_CYCLES_FRONTEND = 7
    STALLED_CYCLES_BACKEND = 8
    REF_CPU_CYCLES = 9

class PerfSWConfig:
    # From perf_sw_id in uapi/linux/perf_event.h
    CPU_CLOCK = 0
    TASK_CLOCK = 1
    PAGE_FAULTS = 2
    CONTEXT_SWITCHES = 3
    CPU_MIGRATIONS = 4
    PAGE_FAULTS_MIN = 5
    PAGE_FAULTS_MAJ = 6
    ALIGNMENT_FAULTS = 7
    EMULATION_FAULTS = 8
    DUMMY = 9
    BPF_OUTPUT = 10

class PerfEventSampleFormat:
    # from perf_event_sample_format in uapi/linux/bpf.h
    IP = (1 << 0)
    TID = (1 << 1)
    TIME = (1 << 2)
    ADDR = (1 << 3)
    READ = (1 << 4)
    CALLCHAIN = (1 << 5)
    ID = (1 << 6)
    CPU = (1 << 7)
    PERIOD = (1 << 8)
    STREAM_ID = (1 << 9)
    RAW = (1 << 10)
    BRANCH_STACK = (1 << 11)
    REGS_USER = (1 << 12)
    STACK_USER = (1 << 13)
    WEIGHT = (1 << 14)
    DATA_SRC = (1 << 15)
    IDENTIFIER = (1 << 16)
    TRANSACTION = (1 << 17)
    REGS_INTR = (1 << 18)
    PHYS_ADDR = (1 << 19)
    AUX = (1 << 20)
    CGROUP = (1 << 21)
    DATA_PAGE_SIZE = (1 << 22)
    CODE_PAGE_SIZE = (1 << 23)
    WEIGHT_STRUCT = (1 << 24)

class BPFProgType:
    # From bpf_prog_type in uapi/linux/bpf.h
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4
    TRACEPOINT = 5
    XDP = 6
    PERF_EVENT = 7
    CGROUP_SKB = 8
    CGROUP_SOCK = 9
    LWT_IN = 10
    LWT_OUT = 11
    LWT_XMIT = 12
    SOCK_OPS = 13
    SK_SKB = 14
    CGROUP_DEVICE = 15
    SK_MSG = 16
    RAW_TRACEPOINT = 17
    CGROUP_SOCK_ADDR = 18
    CGROUP_SOCKOPT = 25
    TRACING = 26
    LSM = 29

class BPFAttachType:
    # from bpf_attach_type uapi/linux/bpf.h
    CGROUP_INET_INGRESS = 0
    CGROUP_INET_EGRESS = 1
    CGROUP_INET_SOCK_CREATE = 2
    CGROUP_SOCK_OPS = 3
    SK_SKB_STREAM_PARSER = 4
    SK_SKB_STREAM_VERDICT = 5
    CGROUP_DEVICE = 6
    SK_MSG_VERDICT = 7
    CGROUP_INET4_BIND = 8
    CGROUP_INET6_BIND = 9
    CGROUP_INET4_CONNECT = 10
    CGROUP_INET6_CONNECT = 11
    CGROUP_INET4_POST_BIND = 12
    CGROUP_INET6_POST_BIND = 13
    CGROUP_UDP4_SENDMSG = 14
    CGROUP_UDP6_SENDMSG = 15
    LIRC_MODE2 = 16
    FLOW_DISSECTOR = 17
    CGROUP_SYSCTL = 18
    CGROUP_UDP4_RECVMSG = 19
    CGROUP_UDP6_RECVMSG = 20
    CGROUP_GETSOCKOPT = 21
    CGROUP_SETSOCKOPT = 22
    TRACE_RAW_TP = 23
    TRACE_FENTRY = 24
    TRACE_FEXIT  = 25
    MODIFY_RETURN = 26
    LSM_MAC = 27
    TRACE_ITER = 28
    CGROUP_INET4_GETPEERNAME = 29
    CGROUP_INET6_GETPEERNAME = 30
    CGROUP_INET4_GETSOCKNAME = 31
    CGROUP_INET6_GETSOCKNAME = 32
    XDP_DEVMAP = 33
    CGROUP_INET_SOCK_RELEASE = 34
    XDP_CPUMAP = 35
    SK_LOOKUP = 36
    XDP = 37
    SK_SKB_VERDICT = 38

class XDPAction:
    # from xdp_action uapi/linux/bpf.h
    XDP_ABORTED = 0
    XDP_DROP = 1
    XDP_PASS = 2
    XDP_TX = 3
    XDP_REDIRECT = 4

class XDPFlags:
    # from xdp_flags uapi/linux/if_link.h
    # unlike similar enum-type holder classes in this file, source for these
    # is #define XDP_FLAGS_UPDATE_IF_NOEXIST, #define XDP_FLAGS_SKB_MODE, ...
    UPDATE_IF_NOEXIST = (1 << 0)
    SKB_MODE = (1 << 1)
    DRV_MODE = (1 << 2)
    HW_MODE = (1 << 3)
    REPLACE = (1 << 4)

class BPF(object):
    # Here for backwards compatibility only, add new enum members and types
    # the appropriate wrapper class elsewhere in this file to avoid namespace
    # collision issues
    SOCKET_FILTER = BPFProgType.SOCKET_FILTER
    KPROBE = BPFProgType.KPROBE
    SCHED_CLS = BPFProgType.SCHED_CLS
    SCHED_ACT = BPFProgType.SCHED_ACT
    TRACEPOINT = BPFProgType.TRACEPOINT
    XDP = BPFProgType.XDP
    PERF_EVENT = BPFProgType.PERF_EVENT
    CGROUP_SKB = BPFProgType.CGROUP_SKB
    CGROUP_SOCK = BPFProgType.CGROUP_SOCK
    LWT_IN = BPFProgType.LWT_IN
    LWT_OUT = BPFProgType.LWT_OUT
    LWT_XMIT = BPFProgType.LWT_XMIT
    SOCK_OPS = BPFProgType.SOCK_OPS
    SK_SKB = BPFProgType.SK_SKB
    CGROUP_DEVICE = BPFProgType.CGROUP_DEVICE
    SK_MSG = BPFProgType.SK_MSG
    RAW_TRACEPOINT = BPFProgType.RAW_TRACEPOINT
    CGROUP_SOCK_ADDR = BPFProgType.CGROUP_SOCK_ADDR
    TRACING = BPFProgType.TRACING
    LSM = BPFProgType.LSM

    XDP_ABORTED = XDPAction.XDP_ABORTED
    XDP_DROP = XDPAction.XDP_DROP
    XDP_PASS = XDPAction.XDP_PASS
    XDP_TX = XDPAction.XDP_TX
    XDP_REDIRECT = XDPAction.XDP_REDIRECT

    XDP_FLAGS_UPDATE_IF_NOEXIST = XDPFlags.UPDATE_IF_NOEXIST
    XDP_FLAGS_SKB_MODE = XDPFlags.SKB_MODE
    XDP_FLAGS_DRV_MODE = XDPFlags.DRV_MODE
    XDP_FLAGS_HW_MODE = XDPFlags.HW_MODE
    XDP_FLAGS_REPLACE = XDPFlags.REPLACE
    # END enum backwards compat

    _probe_repl = re.compile(b"[^a-zA-Z0-9_]")
    _sym_caches = {}
    _bsymcache = lib.bcc_buildsymcache_new()

    _auto_includes = {
        "linux/time.h": ["time"],
        "linux/fs.h": ["fs", "file"],
        "linux/blkdev.h": ["bio", "request"],
        "linux/slab.h": ["alloc"],
        "linux/netdevice.h": ["sk_buff", "net_device"]
    }

    _syscall_prefixes = [
        b"sys_",
        b"__x64_sys_",
        b"__x32_compat_sys_",
        b"__ia32_compat_sys_",
        b"__arm64_sys_",
        b"__s390x_sys_",
        b"__s390_sys_",
    ]

    # BPF timestamps come from the monotonic clock. To be able to filter
    # and compare them from Python, we need to invoke clock_gettime.
    # Adapted from http://stackoverflow.com/a/1205762
    CLOCK_MONOTONIC = 1         # see <linux/time.h>

    class timespec(ct.Structure):
        _fields_ = [('tv_sec', ct.c_long), ('tv_nsec', ct.c_long)]

    _librt = ct.CDLL('librt.so.1', use_errno=True)
    _clock_gettime = _librt.clock_gettime
    _clock_gettime.argtypes = [ct.c_int, ct.POINTER(timespec)]

    @classmethod
    def monotonic_time(cls):
        """monotonic_time()
        Returns the system monotonic time from clock_gettime, using the
        CLOCK_MONOTONIC constant. The time returned is in nanoseconds.
        """
        t = cls.timespec()
        if cls._clock_gettime(cls.CLOCK_MONOTONIC, ct.byref(t)) != 0:
            errno = ct.get_errno()
            raise OSError(errno, os.strerror(errno))
        return t.tv_sec * 1e9 + t.tv_nsec

    @classmethod
    def generate_auto_includes(cls, program_words):
        """
        Generates #include statements automatically based on a set of
        recognized types such as sk_buff and bio. The input is all the words
        that appear in the BPF program, and the output is a (possibly empty)
        string of #include statements, such as "#include <linux/fs.h>".
        """
        headers = ""
        for header, keywords in cls._auto_includes.items():
            for keyword in keywords:
                for word in program_words:
                    if keyword in word and header not in headers:
                        headers += "#include <%s>\n" % header
        return headers

    # defined for compatibility reasons, to be removed
    Table = Table

    class Function(object):
        def __init__(self, bpf, name, fd):
            self.bpf = bpf
            self.name = name
            self.fd = fd

    @staticmethod
    def _find_file(filename):
        """ If filename is invalid, search in ./ of argv[0] """
        if filename:
            if not os.path.isfile(filename):
                argv0 = ArgString(sys.argv[0])
                t = b"/".join([os.path.abspath(os.path.dirname(argv0.__bytes__())), filename])
                if os.path.isfile(t):
                    filename = t
                else:
                    raise Exception("Could not find file %s" % filename)
        return filename

    @staticmethod
    def find_exe(bin_path):
        """
        find_exe(bin_path)

        Traverses the PATH environment variable, looking for the first
        directory that contains an executable file named bin_path, and
        returns the full path to that file, or None if no such file
        can be found. This is meant to replace invocations of the
        "which" shell utility, which doesn't have portable semantics
        for skipping aliases.
        """
        # Source: http://stackoverflow.com/a/377028
        def is_exe(fpath):
            return os.path.isfile(fpath) and \
                os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(bin_path)
        if fpath:
            if is_exe(bin_path):
                return bin_path
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path.encode(), bin_path)
                if is_exe(exe_file):
                    return exe_file
        return None

    def __init__(self, src_file=b"", hdr_file=b"", text=None, debug=0,
            cflags=[], usdt_contexts=[], allow_rlimit=True, device=None,
            attach_usdt_ignore_pid=False):
        """Create a new BPF module with the given source code.

        Note:
            All fields are marked as optional, but either `src_file` or `text`
            must be supplied, and not both.

        Args:
            src_file (Optional[str]): Path to a source file for the module
            hdr_file (Optional[str]): Path to a helper header file for the `src_file`
            text (Optional[str]): Contents of a source file for the module
            debug (Optional[int]): Flags used for debug prints, can be |'d together
                                   See "Debug flags" for explanation
        """

        src_file = _assert_is_bytes(src_file)
        hdr_file = _assert_is_bytes(hdr_file)
        text = _assert_is_bytes(text)

        assert not (text and src_file)

        self.kprobe_fds = {}
        self.uprobe_fds = {}
        self.tracepoint_fds = {}
        self.raw_tracepoint_fds = {}
        self.kfunc_entry_fds = {}
        self.kfunc_exit_fds = {}
        self.lsm_fds = {}
        self.perf_buffers = {}
        self.open_perf_events = {}
        self._ringbuf_manager = None
        self.tracefile = None
        atexit.register(self.cleanup)

        self.debug = debug
        self.funcs = {}
        self.tables = {}
        self.module = None
        cflags_array = (ct.c_char_p * len(cflags))()
        for i, s in enumerate(cflags): cflags_array[i] = bytes(ArgString(s))

        if src_file:
            src_file = BPF._find_file(src_file)
            hdr_file = BPF._find_file(hdr_file)

        if src_file:
            # Read the BPF C source file into the text variable. This ensures,
            # that files and inline text are treated equally.
            with open(src_file, mode="rb") as file:
                text = file.read()

        ctx_array = (ct.c_void_p * len(usdt_contexts))()
        for i, usdt in enumerate(usdt_contexts):
            ctx_array[i] = ct.c_void_p(usdt.get_context())
        usdt_text = lib.bcc_usdt_genargs(ctx_array, len(usdt_contexts))
        if usdt_text is None:
            raise Exception("can't generate USDT probe arguments; " +
                            "possible cause is missing pid when a " +
                            "probe in a shared object has multiple " +
                            "locations")
        text = usdt_text + text


        self.module = lib.bpf_module_create_c_from_string(text,
                                                          self.debug,
                                                          cflags_array, len(cflags_array),
                                                          allow_rlimit, device)
        if not self.module:
            raise Exception("Failed to compile BPF module %s" % (src_file or "<text>"))

        for usdt_context in usdt_contexts:
            usdt_context.attach_uprobes(self, attach_usdt_ignore_pid)

        # If any "kprobe__" or "tracepoint__" or "raw_tracepoint__"
        # prefixed functions were defined,
        # they will be loaded and attached here.
        self._trace_autoload()

    def load_funcs(self, prog_type=KPROBE):
        """load_funcs(prog_type=KPROBE)

        Load all functions in this BPF module with the given type.
        Returns a list of the function handles."""

        fns = []
        for i in range(0, lib.bpf_num_functions(self.module)):
            func_name = lib.bpf_function_name(self.module, i)
            fns.append(self.load_func(func_name, prog_type))

        return fns

    def load_func(self, func_name, prog_type, device = None, attach_type = -1):
        func_name = _assert_