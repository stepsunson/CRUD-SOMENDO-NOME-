# Copyright 2020 Kinvolk GmbH
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

def _cgroup_filter_func_writer(cgroupmap):
    if not cgroupmap:
        return """
        static inline int _cgroup_filter() {
            return 0;
        }
        """

    text = """
    BPF_TABLE_PINNED("hash", u64, u64