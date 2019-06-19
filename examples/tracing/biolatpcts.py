
#!/usr/bin/python
#
# biolatpcts.py  IO latency percentile calculation example
#
# Copyright (C) 2020 Tejun Heo <tj@kernel.org>
# Copyright (C) 2020 Facebook

from __future__ import print_function
from bcc import BPF
from time import sleep