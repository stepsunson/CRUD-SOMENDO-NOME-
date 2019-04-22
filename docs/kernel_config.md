# Kernel Configuration for BPF Features

## BPF Related Kernel Configurations

| Functionalities | Kernel Configuration | Description |
|:----------------|:---------------------|:------------|
| **Basic** | CONFIG_BPF_SYSCALL | Enable the bpf() system call |
|  | CONFIG_BPF_JIT | BPF programs are normally handled by a BPF interpreter. This option allows the kernel to generate native code when a program is loaded into the kernel. This will significantly speed-up processing of BPF programs |
|  | CONFIG_HAVE_BPF_JIT | Enable BPF Just In Time compiler |
|  | CONFIG_HAVE_EBPF_JIT | Extended BPF JIT (eBPF) |
|  | CONFIG_HAVE_CBPF_JIT | Classic BPF JIT (cBPF) |
|  | CONFIG_MODULES | Enable to build loadable kernel modules |
|  | CONFIG_BPF | BPF VM interpreter |
|  | CONFIG_BPF_EVENTS | Allow the user to attach BPF programs to kprobe, uprobe, and tracepoint events |
|  | CONFIG_PERF_EVENTS | Kernel performance events and counters |
|  | CONFIG_HAVE_PERF_EVENTS | Enable perf events |
|  | CONFIG_PROFILING | Enable the extended profiling support mechanisms used by profilers |
| **BTF** | CONFIG_DEBUG_INFO_BTF | Generate deduplicated BTF type information from DWARF debug info |
| | 