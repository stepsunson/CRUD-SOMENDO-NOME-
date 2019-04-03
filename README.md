![BCC Logo](images/logo2.png)
# BPF Compiler Collection (BCC)

BCC is a toolkit for creating efficient kernel tracing and manipulation
programs, and includes several useful tools and examples. It makes use of
extended BPF (Berkeley Packet Filters), formally known as eBPF, a new feature
that was first added to Linux 3.15. Much of what BCC uses requires Linux 4.1
and above.

eBPF was [described by](https://lkml.org/lkml/2015/4/14/232) Ingo Molnár as:

> One of the more interesting features in this cycle is the ability to attach eBPF programs (user-defined, sandboxed bytecode executed by the kernel) to kprobes. This allows user-defined instrumentation on a live kernel image that can never crash, hang or interfere with the kernel negatively.

BCC makes BPF programs easier to write, with kernel instrumentation in C
(and includes a C wrapper around LLVM), and front-ends in Python and lua.
It is suited for many tasks, including performance analysis and network
traffic control.

## Screenshot

This example traces a disk I/O kernel function, and populates an in-kernel
power-of-2 histogram of the I/O size. For efficiency, only the histogram
summary is returned to user-level.

```Shell
# ./bitehist.py
Tracing... Hit Ctrl-C to end.
^C
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

The above output shows a bimodal distribution, where the largest mode of
800 I/O was between 128 and 255 Kbytes in size.

See the source: [bitehist.py](examples/tracing/bitehist.py). What this traces,
what this stores, and how the data is presented, can be entirely customized.
This shows only some of many possible capabilities.

## Installing

See [INSTALL.md](INSTALL.md) for installation steps on your platform.

## FAQ

See [FAQ.txt](FAQ.txt) for the most common troubleshoot questions.

## Reference guide

See [docs/reference_guide.md](docs/reference_guide.md) for the reference guide to the bcc and bcc/BPF APIs.

## Contents

Some of these are single files that contain both C and Python, others have a
pair of .c and .py files, and some are directories of files.

### Tracing

#### Examples:

- examples/tracing/[bitehist.py](examples/tracing/bitehist.py): Block I/O size histogram. [Examples](examples/tracing/bitehist_example.txt).
- examples/tracing/[disksnoop.py](examples/tracing/disksnoop.py): Trace block device I/O latency. [Examples](examples/tracing/disksnoop_example.txt).
- examples/[hello_world.py](examples/hello_world.py): Prints "Hello, World!" for new processes.
- examples/tracing/[mysqld_query.py](examples/tracing/mysqld_query.py): Trace MySQL server queries using USDT probes. [Examples](examples/tracing/mysqld_query_example.txt).
- examples/tracing/[nodejs_http_server.py](examples/tracing/nodejs_http_server.py): Trace Node.js HTTP server requests using USDT probes. [Examples](examples/tracing/nodejs_http_server_example.txt).
- examples/tracing/[stacksnoop](examples/tracing/stacksnoop.py): Trace a kernel function and print all kernel stack traces. [Examples](examples/tracing/stacksnoop_example.txt).
- tools/[statsnoop](tools/statsnoop.py): Trace stat() syscalls. [Examples](tools/statsnoop_example.txt).
- examples/tracing/[task_switch.py](examples/tracing/task_switch.py): Count task switches with from and to PIDs.
- examples/tracing/[tcpv4connect.py](examples/tracing/tcpv4connect.py): Trace TCP IPv4 active connections. [Examples](examples/tracing/tcpv4connect_example.txt).
- examples/tracing/[trace_fields.py](examples/tracing/trace_fields.py): Simple example of printing fields from traced events.
- examples/tracing/[undump.py](examples/tracing/undump.py): Dump UNIX socket packets. [Examples](examples/tracing/undump_example.txt)
- examples/tracing/[urandomread.py](examples/tracing/urandomread.py): A kernel tracepoint example, which traces random:urandom_read. [Examples](examples/tracing/urandomread_example.txt).
- examples/tracing/[vfsreadlat.py](examples/tracing/vfsreadlat.py) examples/tracing/[vfsreadlat.c](examples/tracing/vfsreadlat.c): VFS read latency distribution. [Examples](examples/tracing/vfsreadlat_example.txt).
- examples/tracing/[kvm_hypercall.py](examples/tracing/kvm_hypercall.py): Conditional static kernel tracepoints for KVM entry, exit and hypercall [Examples](examples/tracing/kvm_hypercall.txt).

#### Tools:
<center><a href="images/bcc_tracing_tools_2019.png"><img src="images/bcc_tracing_tools_2019.png" border=0 width=700></a></center>


- tools/[argdist](tools/argdist.py): Display function parameter values as a histogram or frequency count. [Examples](tools/argdist_example.txt).
- tools/[bashreadline](tools/bashreadline.py): Print entered bash commands system wide. [Examples](tools/bashreadline_example.txt).
- tools/[bindsnoop](tools/bindsnoop.py): Trace IPv4 and IPv6 bind() system calls (bind()). [Examples](tools/bindsnoop_example.txt).
- tools/[biolatency](tools/biolatency.py): Summarize block device I/O latency as a histogram. [Examples](tools/biolatency_example.txt).
- tools/[biotop](tools/biotop.py): Top for disks: Summarize block device I/O by process. [Examples](tools/biotop_example.txt).
- tools/[biopattern](tools/biopattern.py): Identify random/sequential disk access patterns. [Examples](tools/biopattern_example.txt).
- tools/[biosnoop](tools/biosnoop.py): Trace block device I/O with PID and latency. [Examples](tools/biosnoop_example.txt).
- tools/[bitesize](tools/bitesize.py): Show per process I/O size histogram. [Examples](tools/bitesize_example.txt).
- tools/[bpflist](tools/bpflist.py): Display processes with active BPF programs and maps. [Examples](tools/bpflist_example.txt).
- tools/[btrfsdist](tools/btrfsdist.py): Summarize btrfs operation latency distribution as a histogram. [Examples](tools/btrfsdist_example.txt).
- tools/[btrfsslower](tools/btrfsslower.py): Trace slow btrfs operations. [Examples](tools/btrfsslower_example.txt).
- tools/[capable](tools/capable.py): Trace security capability checks. [Examples](tools/capable_example.txt).
- tools/[cachestat](tools/cachestat.py): Trace page cache hit/miss ratio. [Examples](tools/cachestat_example.txt).
- tools/[cachetop](tools/cachetop.py): Trace page cache hit/miss ratio by processes. [Examples](tools/cachetop_example.txt).
- tools/[compactsnoop](tools/compactsnoop.py): Trace compact zone events with PID and latency. [Examples](tools/compactsnoop_example.txt).
- tools/[cpudist](tools/cpudist.py): Summarize on- and off-CPU time per task as a histogram. [Examples](tools/cpudist_example.txt)
- tools/[cpuunclaimed](tools/cpuunclaimed.py): Sample CPU run queues and calculate unclaimed idle CPU. [Examples](tools/cpuunclaimed_example.txt)
- tools/[criticalstat](tools/criticalstat.py): Trace and report long atomic critical sections in the kernel. [Examples](tools/criticalstat_example.txt)
- tools/[dbslower](tools/dbslower.py): Trace MySQL/PostgreSQL queries slower than a threshold. [Examples](tools/dbslower_example.txt).
- tools/[dbstat](tools/dbstat.py): Summarize MySQL/PostgreSQL query latency as a histogram. [Examples](tools/dbstat_example.txt).
- tools/[dcsnoop](tools/dcsnoop.py): Trace directory entry cache (dcache) lookups. [Examples](tools/dcsnoop_example.txt).
- tools/[dcstat](tools/dcstat.py): Directory entry cache (dcache) stats. [Examples](tools/dcstat_example.txt).
- tools/[deadlock](tools/deadlock.py): Detect potential deadlocks on a running process. [Examples](tools/deadlock_example.txt).
- tools/[dirtop](tools/dirtop.py): File reads and writes by directory. Top for directories. [Examples](tools/dirtop_example.txt).
- tools/[drsnoop](tools/drsnoop.py): Trace direct reclaim events with PID and latency. [Examples](tools/drsnoop_example.txt).
- tools/[execsnoop](tools/execsnoop.py): Trace new processes via exec() syscalls. [Examples](tools/execsnoop_example.txt).
- tools/[exitsnoop](tools/exitsnoop.py): Trace process termination (exit and fatal signals). [Examples](tools/exitsnoop_example.txt).
- tools/[ext4dist](tools/ext4dist.py): Summarize ext4 operation latency distribution as a histogram. [Examples](tools/ext4dist_example.txt).
- tools/[ext4slower](tools/ext4slower.py): Trace slow ext4 operations. [Examples](tools/ext4slower_example.txt).
- tools/[filelife](tools/filelife.py): Trace the lifespan of short-lived files. [Examples](tools/filelife_example.txt).
- tools/[filegone](tools/filegone.py): Trace why file gone (deleted or renamed). [Examples](tools/filegone_example.txt).
- tools/[fileslower](tools/fileslower.py): Trace slow synchronous file reads and writes. [Examples](tools/fileslower_example.txt).
- tools/[filetop](tools/filetop.py): File reads and writes by filename and process. Top for files. [Examples](tools/filetop_example.txt).
- tools/[funccount](tools/funccount.py): Count kernel function calls. [Examples](tools/funccount_example.txt).
- tools/[funcinterval](tools/funcinterval.py): Time interval between the same function as a histogram. [Examples](tools/funcinterval_example.txt).
- tools/[funclatency](tools/funclatency.py): Time functions and show their latency distribution. [Examples](tools/funclatency_example.txt).
- tools/[funcslower](tools/funcslower.py): Trace slow kernel or user function calls. [Examples](tools/funcslower_example.txt).
- tools/[gethostlatency](tools/gethostlatency.py): Show latency for getaddrinfo/gethostbyname[2] calls. [Examples](tools/gethostlatency_example.txt).
- tools/[hardirqs](tools/hardirqs.py):  Measure hard IRQ (hard interrupt) event time. [Examples](tools/hardirqs_example.txt).
- tools/[inject](tools/inject.py): Targeted error injection with call chain and predicates [Examples](tools/inject_example.txt).
- tools/[killsnoop](tools/killsnoop.py): Trace signals issued by the kill() syscall. [Examples](tools/killsnoop_example.txt).
- tools/[klockstat](tools/klockstat.py): Traces kernel mutex lock events and dis