
# bcc Reference Guide

Intended for search (Ctrl-F) and reference. For tutorials, start with [tutorial.md](tutorial.md).

This guide is incomplete. If something feels missing, check the bcc and kernel source. And if you confirm we're missing something, please send a pull request to fix it, and help out everyone.

## Contents

- [BPF C](#bpf-c)
    - [Events & Arguments](#events--arguments)
        - [1. kprobes](#1-kprobes)
        - [2. kretprobes](#2-kretprobes)
        - [3. Tracepoints](#3-tracepoints)
        - [4. uprobes](#4-uprobes)
        - [5. uretprobes](#5-uretprobes)
        - [6. USDT probes](#6-usdt-probes)
        - [7. Raw Tracepoints](#7-raw-tracepoints)
        - [8. system call tracepoints](#8-system-call-tracepoints)
        - [9. kfuncs](#9-kfuncs)
        - [10. kretfuncs](#10-kretfuncs)
        - [11. lsm probes](#11-lsm-probes)
        - [12. bpf iterators](#12-bpf-iterators)
    - [Data](#data)
        - [1. bpf_probe_read_kernel()](#1-bpf_probe_read_kernel)
        - [2. bpf_probe_read_kernel_str()](#2-bpf_probe_read_kernel_str)
        - [3. bpf_ktime_get_ns()](#3-bpf_ktime_get_ns)
        - [4. bpf_get_current_pid_tgid()](#4-bpf_get_current_pid_tgid)
        - [5. bpf_get_current_uid_gid()](#5-bpf_get_current_uid_gid)
        - [6. bpf_get_current_comm()](#6-bpf_get_current_comm)
        - [7. bpf_get_current_task()](#7-bpf_get_current_task)
        - [8. bpf_log2l()](#8-bpf_log2l)
        - [9. bpf_get_prandom_u32()](#9-bpf_get_prandom_u32)
        - [10. bpf_probe_read_user()](#10-bpf_probe_read_user)
        - [11. bpf_probe_read_user_str()](#11-bpf_probe_read_user_str)
        - [12. bpf_get_ns_current_pid_tgid()](#12-bpf_get_ns_current_pid_tgid)
    - [Debugging](#debugging)
        - [1. bpf_override_return()](#1-bpf_override_return)
    - [Output](#output)
        - [1. bpf_trace_printk()](#1-bpf_trace_printk)
        - [2. BPF_PERF_OUTPUT](#2-bpf_perf_output)
        - [3. perf_submit()](#3-perf_submit)
        - [4. perf_submit_skb()](#4-perf_submit_skb)
        - [5. BPF_RINGBUF_OUTPUT](#5-bpf_ringbuf_output)
        - [6. ringbuf_output()](#6-ringbuf_output)
        - [7. ringbuf_reserve()](#7-ringbuf_reserve)
        - [8. ringbuf_submit()](#8-ringbuf_submit)
        - [9. ringbuf_discard()](#9-ringbuf_discard)
    - [Maps](#maps)
        - [1. BPF_TABLE](#1-bpf_table)
        - [2. BPF_HASH](#2-bpf_hash)
        - [3. BPF_ARRAY](#3-bpf_array)
        - [4. BPF_HISTOGRAM](#4-bpf_histogram)
        - [5. BPF_STACK_TRACE](#5-bpf_stack_trace)
        - [6. BPF_PERF_ARRAY](#6-bpf_perf_array)
        - [7. BPF_PERCPU_HASH](#7-bpf_percpu_hash)
        - [8. BPF_PERCPU_ARRAY](#8-bpf_percpu_array)
        - [9. BPF_LPM_TRIE](#9-bpf_lpm_trie)
        - [10. BPF_PROG_ARRAY](#10-bpf_prog_array)
        - [11. BPF_DEVMAP](#11-bpf_devmap)
        - [12. BPF_CPUMAP](#12-bpf_cpumap)
        - [13. BPF_XSKMAP](#13-bpf_xskmap)
        - [14. BPF_ARRAY_OF_MAPS](#14-bpf_array_of_maps)
        - [15. BPF_HASH_OF_MAPS](#15-bpf_hash_of_maps)
        - [16. BPF_STACK](#16-bpf_stack)
        - [17. BPF_QUEUE](#17-bpf_queue)
        - [18. BPF_SOCKHASH](#18-bpf_sockhash)
        - [19. map.lookup()](#19-maplookup)
        - [20. map.lookup_or_try_init()](#20-maplookup_or_try_init)
        - [21. map.delete()](#21-mapdelete)
        - [22. map.update()](#22-mapupdate)
        - [23. map.insert()](#23-mapinsert)
        - [24. map.increment()](#24-mapincrement)
        - [25. map.get_stackid()](#25-mapget_stackid)
        - [26. map.perf_read()](#26-mapperf_read)
        - [27. map.call()](#27-mapcall)
        - [28. map.redirect_map()](#28-mapredirect_map)
        - [29. map.push()](#29-mappush)
        - [30. map.pop()](#30-mappop)
        - [31. map.peek()](#31-mappeek)
        - [32. map.sock_hash_update()](#32-mapsock_hash_update)
        - [33. map.msg_redirect_hash()](#33-mapmsg_redirect_hash)
        - [34. map.sk_redirect_hash()](#34-mapsk_redirect_hash)
    - [Licensing](#licensing)
    - [Rewriter](#rewriter)

- [bcc Python](#bcc-python)
    - [Initialization](#initialization)
        - [1. BPF](#1-bpf)
        - [2. USDT](#2-usdt)
    - [Events](#events)
        - [1. attach_kprobe()](#1-attach_kprobe)
        - [2. attach_kretprobe()](#2-attach_kretprobe)
        - [3. attach_tracepoint()](#3-attach_tracepoint)
        - [4. attach_uprobe()](#4-attach_uprobe)
        - [5. attach_uretprobe()](#5-attach_uretprobe)
        - [6. USDT.enable_probe()](#6-usdtenable_probe)
        - [7. attach_raw_tracepoint()](#7-attach_raw_tracepoint)
        - [8. attach_raw_socket()](#8-attach_raw_socket)
        - [9. attach_xdp()](#9-attach_xdp)
        - [10. attach_func()](#10-attach_func)
        - [11. detach_func()](#11-detach_func)
        - [12. detach_kprobe()](#12-detach_kprobe)
        - [13. detach_kretprobe()](#13-detach_kretprobe)
    - [Debug Output](#debug-output)
        - [1. trace_print()](#1-trace_print)
        - [2. trace_fields()](#2-trace_fields)
    - [Output APIs](#output-apis)
        - [1. perf_buffer_poll()](#1-perf_buffer_poll)
        - [2. ring_buffer_poll()](#2-ring_buffer_poll)
        - [3. ring_buffer_consume()](#3-ring_buffer_consume)
    - [Map APIs](#map-apis)
        - [1. get_table()](#1-get_table)
        - [2. open_perf_buffer()](#2-open_perf_buffer)
        - [3. items()](#3-items)
        - [4. values()](#4-values)
        - [5. clear()](#5-clear)
        - [6. items_lookup_and_delete_batch()](#6-items_lookup_and_delete_batch)
        - [7. items_lookup_batch()](#7-items_lookup_batch)
        - [8. items_delete_batch()](#8-items_delete_batch)
        - [9. items_update_batch()](#9-items_update_batch)
        - [10. print_log2_hist()](#10-print_log2_hist)
        - [11. print_linear_hist()](#11-print_linear_hist)
        - [12. open_ring_buffer()](#12-open_ring_buffer)
        - [13. push()](#13-push)
        - [14. pop()](#14-pop)
        - [15. peek()](#15-peek)
    - [Helpers](#helpers)
        - [1. ksym()](#1-ksym)
        - [2. ksymname()](#2-ksymname)
        - [3. sym()](#3-sym)
        - [4. num_open_kprobes()](#4-num_open_kprobes)
        - [5. get_syscall_fnname()](#5-get_syscall_fnname)

- [BPF Errors](#bpf-errors)
    - [1. Invalid mem access](#1-invalid-mem-access)
    - [2. Cannot call GPL only function from proprietary program](#2-cannot-call-gpl-only-function-from-proprietary-program)

- [Environment Variables](#Environment-Variables)
    - [1. kernel source directory](#1-kernel-source-directory)
    - [2. kernel version overriding](#2-kernel-version-overriding)

# BPF C

This section describes the C part of a bcc program.

## Events & Arguments

### 1. kprobes

Syntax: kprobe__*kernel_function_name*

```kprobe__``` is a special prefix that creates a kprobe (dynamic tracing of a kernel function call) for the kernel function name provided as the remainder. You can also use kprobes by declaring a normal C function, then using the Python ```BPF.attach_kprobe()``` (covered later) to associate it with a kernel function.

Arguments are specified on the function declaration: kprobe__*kernel_function_name*(struct pt_regs *ctx [, *argument1* ...])

For example:

```C
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    [...]
}
```

This instruments the tcp_v4_connect() kernel function using a kprobe, with the following arguments:

- ```struct pt_regs *ctx```: Registers and BPF context.
- ```struct sock *sk```: First argument to tcp_v4_connect().

The first argument is always ```struct pt_regs *```, the remainder are the arguments to the function (they don't need to be specified, if you don't intend to use them).

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/tcpv4connect.py#L28) ([output](https://github.com/iovisor/bcc/blob/5bd0eb21fd148927b078deb8ac29fff2fb044b66/examples/tracing/tcpv4connect_example.txt#L8)),
[code](https://github.com/iovisor/bcc/commit/310ab53710cfd46095c1f6b3e44f1dbc8d1a41d8#diff-8cd1822359ffee26e7469f991ce0ef00R26) ([output](https://github.com/iovisor/bcc/blob/3b9679a3bd9b922c736f6061dc65cb56de7e0250/examples/tracing/bitehist_example.txt#L6))
<!--- I can't add search links here, since github currently cannot handle partial-word searches needed for "kprobe__" --->

### 2. kretprobes

Syntax: kretprobe__*kernel_function_name*

```kretprobe__``` is a special prefix that creates a kretprobe (dynamic tracing of a kernel function return) for the kernel function name provided as the remainder. You can also use kretprobes by declaring a normal C function, then using the Python ```BPF.attach_kretprobe()``` (covered later) to associate it with a kernel function.

Return value is available as ```PT_REGS_RC(ctx)```, given a function declaration of: kretprobe__*kernel_function_name*(struct pt_regs *ctx)

For example:

```C
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    [...]
}
```

This instruments the return of the tcp_v4_connect() kernel function using a kretprobe, and stores the return value in ```ret```.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/tcpv4connect.py#L38) ([output](https://github.com/iovisor/bcc/blob/5bd0eb21fd148927b078deb8ac29fff2fb044b66/examples/tracing/tcpv4connect_example.txt#L8))

### 3. Tracepoints

Syntax: TRACEPOINT_PROBE(*category*, *event*)

This is a macro that instruments the tracepoint defined by *category*:*event*.

The tracepoint name is `<category>:<event>`.
The probe function name is `tracepoint__<category>__<event>`.

Arguments are available in an ```args``` struct, which are the tracepoint arguments. One way to list these is to cat the relevant format file under /sys/kernel/debug/tracing/events/*category*/*event*/format.

The ```args``` struct can be used in place of ``ctx`` in each functions requiring a context as an argument. This includes notably [perf_submit()](#3-perf_submit).

For example:

```C
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
```

This instruments the tracepoint `random:urandom_read tracepoint`, and prints the tracepoint argument ```got_bits```.
When using Python API, this probe is automatically attached to the right tracepoint target.
For C++, this tracepoint probe can be attached by specifying the tracepoint target and function name explicitly:
`BPF::attach_tracepoint("random:urandom_read", "tracepoint__random__urandom_read")`
Note the name of the probe function defined above is `tracepoint__random__urandom_read`.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/a4159da8c4ea8a05a3c6e402451f530d6e5a8b41/examples/tracing/urandomread.py#L19) ([output](https://github.com/iovisor/bcc/commit/e422f5e50ecefb96579b6391a2ada7f6367b83c4#diff-41e5ecfae4a3b38de5f4e0887ed160e5R10)),
[search /examples](https://github.com/iovisor/bcc/search?q=TRACEPOINT_PROBE+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=TRACEPOINT_PROBE+path%3Atools&type=Code)

### 4. uprobes

These are instrumented by declaring a normal function in C, then associating it as a uprobe probe in Python via ```BPF.attach_uprobe()``` (covered later).

Arguments can be examined using ```PT_REGS_PARM``` macros.

For example:

```C
int count(struct pt_regs *ctx) {
    char buf[64];
    bpf_probe_read_user(&buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
    bpf_trace_printk("%s %d", buf, PT_REGS_PARM2(ctx));
    return(0);
}
```

This reads the first argument as a string, and then prints it with the second argument as an integer.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_count.py#L26)

### 5. uretprobes

These are instrumented by declaring a normal function in C, then associating it as a uretprobe probe in Python via ```BPF.attach_uretprobe()``` (covered later).

Return value is available as ```PT_REGS_RC(ctx)```, given a function declaration of: *function_name*(struct pt_regs *ctx)

For example:

```C
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(PT_REGS_RC(ctx));
    return 0;
}
```

This increments the bucket in the ```dist``` histogram that is indexed by the return value.

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_hist.py#L39) ([output](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/examples/tracing/strlen_hist.py#L15)),
[code](https://github.com/iovisor/bcc/blob/4afa96a71c5dbfc4c507c3355e20baa6c184a3a8/tools/bashreadline.py) ([output](https://github.com/iovisor/bcc/commit/aa87997d21e5c1a6a20e2c96dd25eb92adc8e85d#diff-2fd162f9e594206f789246ce97d62cf0R7))

### 6. USDT probes

These are User Statically-Defined Tracing (USDT) probes, which may be placed in some applications or libraries to provide a user-level equivalent of tracepoints. The primary BPF method provided for USDT support method is ```enable_probe()```. USDT probes are instrumented by declaring a normal function in C, then associating it as a USDT probe in Python via ```USDT.enable_probe()```.

Arguments can be read via: bpf_usdt_readarg(*index*, ctx, &addr)

For example:

```C
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128];
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
```

This reads the sixth USDT argument, and then pulls it in as a string to ```path```.

When initializing USDTs via the third argument of ```BPF::init``` in the C API, if any USDT fails to ```init```, entire ```BPF::init``` will fail. If you're OK with some USDTs failing to ```init```, use ```BPF::init_usdt``` before calling ```BPF::init```.

Examples in situ:
[code](https://github.com/iovisor/bcc/commit/4f88a9401357d7b75e917abd994aa6ea97dda4d3#diff-04a7cad583be5646080970344c48c1f4R24),
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Atools&type=Code)

### 7. Raw Tracepoints

Syntax: RAW_TRACEPOINT_PROBE(*event*)

This is a macro that instruments the raw tracepoint defined by *event*.

The argument is a pointer to struct ```bpf_raw_tracepoint_args```, which is defined in [bpf.h](https://github.com/iovisor/bcc/blob/master/src/cc/compat/linux/virtual_bpf.h).  The struct field ```args``` contains all parameters of the raw tracepoint where you can found at linux tree [include/trace/events](https://github.com/torvalds/linux/tree/master/include/trace/events)
directory.

For example:
```C
RAW_TRACEPOINT_PROBE(sched_switch)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next= (struct task_struct *)ctx->args[2];
    s32 prev_tgid, next_tgid;

    bpf_probe_read_kernel(&prev_tgid, sizeof(prev->tgid), &prev->tgid);
    bpf_probe_read_kernel(&next_tgid, sizeof(next->tgid), &next->tgid);
    bpf_trace_printk("%d -> %d\\n", prev_tgid, next_tgid);
}
```

This instruments the sched:sched_switch tracepoint, and prints the prev and next tgid.

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=RAW_TRACEPOINT_PROBE+path%3Atools&type=Code)

### 8. system call tracepoints

Syntax: ```syscall__SYSCALLNAME```

```syscall__``` is a special prefix that creates a kprobe for the system call name provided as the remainder. You can use it by declaring a normal C function, then using the Python ```BPF.get_syscall_fnname(SYSCALLNAME)``` and ```BPF.attach_kprobe()``` to associate it.

Arguments are specified on the function declaration: ```syscall__SYSCALLNAME(struct pt_regs *ctx, [, argument1 ...])```.

For example:
```C
int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    [...]
}
```

This instruments the execve system call.

The first argument is always ```struct pt_regs *```, the remainder are the arguments to the function (they don't need to be specified, if you don't intend to use them).

Corresponding Python code:
```Python
b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
```

Examples in situ:
[code](https://github.com/iovisor/bcc/blob/552658edda09298afdccc8a4b5e17311a2d8a771/tools/execsnoop.py#L101) ([output](https://github.com/iovisor/bcc/blob/552658edda09298afdccc8a4b5e17311a2d8a771/tools/execsnoop_example.txt#L8))

### 9. kfuncs

Syntax: KFUNC_PROBE(*function*, typeof(arg1) arg1, typeof(arg2) arge ...)

This is a macro that instruments the kernel function via trampoline
*before* the function is executed. It's defined by *function* name and
the function arguments defined as *argX*.

For example:
```C
KFUNC_PROBE(do_sys_open, int dfd, const char *filename, int flags, int mode)
{
    ...
```

This instruments the do_sys_open kernel function and make its arguments
accessible as standard argument values.

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=KFUNC_PROBE+path%3Atools&type=Code)

### 10. kretfuncs

Syntax: KRETFUNC_PROBE(*event*, typeof(arg1) arg1, typeof(arg2) arge ..., int ret)

This is a macro that instruments the kernel function via trampoline
*after* the function is executed. It's defined by *function* name and
the function arguments defined as *argX*.

The last argument of the probe is the return value of the instrumented function.

For example:
```C
KRETFUNC_PROBE(do_sys_open, int dfd, const char *filename, int flags, int mode, int ret)
{
    ...
```

This instruments the do_sys_open kernel function and make its arguments
accessible as standard argument values together with its return value.

Examples in situ:
[search /tools](https://github.com/iovisor/bcc/search?q=KRETFUNC_PROBE+path%3Atools&type=Code)


### 11. LSM Probes

Syntax: LSM_PROBE(*hook*, typeof(arg1) arg1, typeof(arg2) arg2 ...)

This is a macro that instruments an LSM hook as a BPF program. It can be
used to audit security events and implement MAC security policies in BPF.
It is defined by specifying the hook name followed by its arguments.

Hook names can be found in
[include/linux/security.h](https://github.com/torvalds/linux/blob/v5.15/include/linux/security.h#L260)
by taking functions like `security_hookname` and taking just the `hookname` part.
For example, `security_bpf` would simply become `bpf`.

Unlike other BPF program types, the return value specified in an LSM probe
matters. A return value of 0 allows the hook to succeed, whereas
any non-zero return value will cause the hook to fail and deny the
security operation.

The following example instruments a hook that denies all future BPF operations:
```C
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    return -EPERM;
}
```

This instruments the `security_bpf` hook and causes it to return `-EPERM`.
Changing `return -EPERM` to `return 0` would cause the BPF program
to allow the operation instead.

LSM probes require at least a 5.7+ kernel with the following configuation options set:
- `CONFIG_BPF_LSM=y`
- `CONFIG_LSM` comma separated string must contain "bpf" (for example,
  `CONFIG_LSM="lockdown,yama,bpf"`)

Examples in situ:
[search /tests](https://github.com/iovisor/bcc/search?q=LSM_PROBE+path%3Atests&type=Code)

### 12. BPF ITERATORS

Syntax: BPF_ITER(target)

This is a macro to define a program signature for a bpf iterator program. The argument *target* specifies what to iterate for the program.

Currently, kernel does not have interface to discover what targets are supported. A good place to find what is supported is in [tools/testing/selftests/bpf/prog_test/bpf_iter.c](https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/prog_tests/bpf_iter.c) and some sample bpf iter programs are in [tools/testing/selftests/bpf/progs](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf/progs) with file name prefix *bpf_iter*.

The following example defines a program for target *task*, which traverses all tasks in the kernel.
```C
BPF_ITER(task)
{
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;

  if (task == (void *)0)
    return 0;

  ... task->pid, task->tgid, task->comm, ...
  return 0;
}
```

BPF iterators are introduced in 5.8 kernel for task, task_file, bpf_map, netlink_sock and ipv6_route . In 5.9, support is added to tcp/udp sockets and bpf map element (hashmap, arraymap and sk_local_storage_map) traversal.

## Data

### 1. bpf_probe_read_kernel()

Syntax: ```int bpf_probe_read_kernel(void *dst, int size, const void *src)```

Return: 0 on success

This copies size bytes from kernel address space to the BPF stack, so that BPF can later operate on it. For safety, all kernel memory reads must pass through bpf_probe_read_kernel(). This happens automatically in some cases, such as dereferencing kernel variables, as bcc will rewrite the BPF program to include the necessary bpf_probe_read_kernel().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel+path%3Atools&type=Code)

### 2. bpf_probe_read_kernel_str()

Syntax: ```int bpf_probe_read_kernel_str(void *dst, int size, const void *src)```

Return:
  - \> 0 length of the string including the trailing NULL on success
  - \< 0 error

This copies a `NULL` terminated string from kernel address space to the BPF stack, so that BPF can later operate on it. In case the string length is smaller than size, the target is not padded with further `NULL` bytes. In case the string length is larger than size, just `size - 1` bytes are copied and the last byte is set to `NULL`.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel_str+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_kernel_str+path%3Atools&type=Code)

### 3. bpf_ktime_get_ns()

Syntax: ```u64 bpf_ktime_get_ns(void)```

Return: u64 number of nanoseconds. Starts at system boot time but stops during suspend.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_ktime_get_ns+path%3Atools&type=Code)

### 4. bpf_get_current_pid_tgid()

Syntax: ```u64 bpf_get_current_pid_tgid(void)```

Return: ```current->tgid << 32 | current->pid```

Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_pid_tgid+path%3Atools&type=Code)

### 5. bpf_get_current_uid_gid()

Syntax: ```u64 bpf_get_current_uid_gid(void)```

Return: ```current_gid << 32 | current_uid```

Returns the user ID and group IDs.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_uid_gid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_uid_gid+path%3Atools&type=Code)

### 6. bpf_get_current_comm()

Syntax: ```bpf_get_current_comm(char *buf, int size_of_buf)```

Return: 0 on success

Populates the first argument address with the current process name. It should be a pointer to a char array of at least size TASK_COMM_LEN, which is defined in linux/sched.h. For example:

```C
#include <linux/sched.h>

int do_trace(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
[...]
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_comm+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_comm+path%3Atools&type=Code)

### 7. bpf_get_current_task()

Syntax: ```bpf_get_current_task()```

Return: current task as a pointer to struct task_struct.

Returns a pointer to the current task's task_struct object. This helper can be used to compute the on-CPU time for a process, identify kernel threads, get the current CPU's run queue, or retrieve many other pieces of information.

With Linux 4.13, due to issues with field randomization, you may need two #define directives before the includes:
```C
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#include <linux/sched.h>

int do_trace(void *ctx) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
[...]
```

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_current_task+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_current_task+path%3Atools&type=Code)

### 8. bpf_log2l()

Syntax: ```unsigned int bpf_log2l(unsigned long v)```

Returns the log-2 of the provided value. This is often used to create indexes for histograms, to construct power-of-2 histograms.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_log2l+path%3Atools&type=Code)

### 9. bpf_get_prandom_u32()

Syntax: ```u32 bpf_get_prandom_u32()```

Returns a pseudo-random u32.

Example in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_prandom_u32+path%3Atools&type=Code)

### 10. bpf_probe_read_user()

Syntax: ```int bpf_probe_read_user(void *dst, int size, const void *src)```

Return: 0 on success

This attempts to safely read size bytes from user address space to the BPF stack, so that BPF can later operate on it. For safety, all user address space memory reads must pass through bpf_probe_read_user().

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user+path%3Atools&type=Code)

### 11. bpf_probe_read_user_str()

Syntax: ```int bpf_probe_read_user_str(void *dst, int size, const void *src)```

Return:
  - \> 0 length of the string including the trailing NULL on success
  - \< 0 error

This copies a `NULL` terminated string from user address space to the BPF stack, so that BPF can later operate on it. In case the string length is smaller than size, the target is not padded with further `NULL` bytes. In case the string length is larger than size, just `size - 1` bytes are copied and the last byte is set to `NULL`.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user_str+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_probe_read_user_str+path%3Atools&type=Code)


### 12. bpf_get_ns_current_pid_tgid()

Syntax: ```u32 bpf_get_ns_current_pid_tgid(u64 dev, u64 ino, struct bpf_pidns_info* nsdata, u32 size)```

Values for *pid* and *tgid* as seen from the current *namespace* will be returned in *nsdata*.

Return 0 on success, or one of the following in case of failure:

- **-EINVAL** if dev and inum supplied don't match dev_t and inode number with nsfs of current task, or if dev conversion to dev_t lost high bits.

- **-ENOENT** if pidns does not exists for the current task.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_get_ns_current_pid_tgid+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_get_ns_current_pid_tgid+path%3Atools&type=Code)


## Debugging

### 1. bpf_override_return()

Syntax: ```int bpf_override_return(struct pt_regs *, unsigned long rc)```

Return: 0 on success

When used in a program attached to a function entry kprobe, causes the
execution of the function to be skipped, immediately returning `rc` instead.
This is used for targeted error injection.

bpf_override_return will only work when the kprobed function is whitelisted to
allow error injections. Whitelisting entails tagging a function with
`ALLOW_ERROR_INJECTION()` in the kernel source tree; see `io_ctl_init` for
an example. If the kprobed function is not whitelisted, the bpf program will
fail to attach with ` ioctl(PERF_EVENT_IOC_SET_BPF): Invalid argument`


```C
int kprobe__io_ctl_init(void *ctx) {
	bpf_override_return(ctx, -ENOMEM);
	return 0;
}
```

## Output

### 1. bpf_trace_printk()

Syntax: ```int bpf_trace_printk(const char *fmt, ...)```

Return: 0 on success

A simple kernel facility for printf() to the common trace_pipe (/sys/kernel/debug/tracing/trace_pipe). This is ok for some quick examples, but has limitations: 3 args max, 1 %s only, and trace_pipe is globally shared, so concurrent programs will have clashing output. A better interface is via BPF_PERF_OUTPUT(). Note that calling this helper is made simpler than the original kernel version, which has ```fmt_size``` as the second parameter.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=bpf_trace_printk+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=bpf_trace_printk+path%3Atools&type=Code)

### 2. BPF_PERF_OUTPUT

Syntax: ```BPF_PERF_OUTPUT(name)```

Creates a BPF table for pushing out custom event data to user space via a perf ring buffer. This is the preferred method for pushing per-event data to user space.

For example:

```C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
```

The output table is named ```events```, and data is pushed to it via ```events.perf_submit()```.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=BPF_PERF_OUTPUT+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=BPF_PERF_OUTPUT+path%3Atools&type=Code)

### 3. perf_submit()

Syntax: ```int perf_submit((void *)ctx, (void *)data, u32 data_size)```

Return: 0 on success

A method of a BPF_PERF_OUTPUT table, for submitting custom event data to user space. See the BPF_PERF_OUTPUT entry. (This ultimately calls bpf_perf_event_output().)

The ```ctx``` parameter is provided in [kprobes](#1-kprobes) or [kretprobes](#2-kretprobes). For ```SCHED_CLS``` or ```SOCKET_FILTER``` programs, the ```struct __sk_buff *skb``` must be used instead.

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=perf_submit+path%3Atools&type=Code)

### 4. perf_submit_skb()

Syntax: ```int perf_submit_skb((void *)ctx, u32 packet_size, (void *)data, u32 data_size)```

Return: 0 on success

A method of a BPF_PERF_OUTPUT table available in networking program types, for submitting custom event data to user space, along with the first ```packet_size``` bytes of the packet buffer. See the BPF_PERF_OUTPUT entry. (This ultimately calls bpf_perf_event_output().)

Examples in situ:
[search /examples](https://github.com/iovisor/bcc/search?q=perf_submit_skb+path%3Aexamples&type=Code),
[search /tools](https://github.com/iovisor/bcc/search?q=perf_submit_skb+path%3Atools&type=Code)

### 5. BPF_RINGBUF_OUTPUT

Syntax: ```BPF_RINGBUF_OUTPUT(name, page_cnt)```

Creates a BPF table for pushing out custom event data to user space via a ringbuf ring buffer.
```BPF_RINGBUF_OUTPUT``` has several advantages over ```BPF_PERF_OUTPUT```, summarized as follows:

- Buffer is shared across all CPUs, meaning no per-CPU allocation
- Supports two APIs for BPF programs
    - ```map.ringbuf_output()``` works like ```map.perf_submit()``` (covered in [ringbuf_output](#6-ringbuf_output))
    - ```map.ringbuf_reserve()```/```map.ringbuf_submit()```/```map.ringbuf_discard()```
      split the process of reserving buffer space and submitting events into two steps
      (covered in [ringbuf_reserve](#7-ringbuf_reserve), [ringbuf_submit](#8-ringbuf_submit), [ringbuf_discard](#9-ringbuf_discard))
- BPF APIs do not require access to a CPU ctx argument
- Superior performance and latency in userspace thanks to a shared ring buffer manager
- Supports two ways of consuming data in userspace

Starting in Linux 5.8, this should be the preferred method for pushing per-event data to user space.

Example of both APIs:

```C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

// Creates a ringbuf called events with 8 pages of space, shared across all CPUs
BPF_RINGBUF_OUTPUT(events, 8);

int first_api_example(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.ringbuf_output(&data, sizeof(data), 0 /* flags */);
