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

import ctypes as ct

lib = ct.CDLL("libbcc.so.0", use_errno=True)

# needed for perf_event_attr() ctype
from .perf import Perf

# keep in sync with bcc_common.h
lib.bpf_module_create_c.restype = ct.c_void_p
lib.bpf_module_create_c.argtypes = [ct.c_char_p, ct.c_uint,
        ct.POINTER(ct.c_char_p), ct.c_int, ct.c_bool, ct.c_char_p]
lib.bpf_module_create_c_from_string.restype = ct.c_void_p
lib.bpf_module_create_c_from_string.argtypes = [ct.c_char_p, ct.c_uint,
        ct.POINTER(ct.c_char_p), ct.c_int, ct.c_bool, ct.c_char_p]
lib.bpf_module_rw_engine_enabled.restype = ct.c_bool
lib.bpf_module_rw_engine_enabled.argtypes = None
lib.bpf_module_destroy.restype = None
lib.bpf_module_destroy.argtypes = [ct.c_void_p]
lib.bpf_module_license.restype = ct.c_char_p
lib.bpf_module_license.argtypes = [ct.c_void_p]
lib.bpf_module_kern_version.restype = ct.c_uint
lib.bpf_module_kern_version.argtypes = [ct.c_void_p]
lib.bpf_num_functions.restype = ct.c_ulonglong
lib.bpf_num_functions.argtypes = [ct.c_void_p]
lib.bpf_function_name.restype = ct.c_char_p
lib.bpf_function_name.argtypes = [ct.c_void_p, ct.c_ulonglong]
lib.bpf_function_start.restype = ct.c_void_p
lib.bpf_function_start.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_function_size.restype = ct.c_size_t
lib.bpf_function_size.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_id.restype = ct.c_ulonglong
lib.bpf_table_id.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_fd.restype = ct.c_int
lib.bpf_table_fd.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_type_id.restype = ct.c_int
lib.bpf_table_type_id.argtypes = [ct.c_void_p, ct.c_ulonglong]
lib.bpf_table_max_entries_id.restype = ct.c_ulonglong
lib.bpf_table_max_entries_id.argtypes = [ct.c_void_p, ct.c_ulonglong]
lib.bpf_table_flags_id.restype = ct.c_int
lib.bpf_table_flags_id.argtypes = [ct.c_void_p, ct.c_ulonglong]
lib.bpf_table_key_desc.restype = ct.c_char_p
lib.bpf_table_key_desc.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_leaf_desc.restype = ct.c_char_p
lib.bpf_table_leaf_desc.argtypes = [ct.c_void_p, ct.c_char_p]
lib.bpf_table_key_snprintf.restype = ct.c_int
lib.bpf_table_key_snprintf.argtypes = [ct.c_void_p, ct.c_ulonglong,
        ct.c_char_p, ct.c_ulonglong, ct.c_void_p]
lib.bpf_table_leaf_snprintf.restype = ct.c_int