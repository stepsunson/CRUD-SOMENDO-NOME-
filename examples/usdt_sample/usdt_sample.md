
# Prerequitites

## Ubuntu 21.10 prerequisites

```bash
$ sudo apt-get install linux-headers-$(uname -r) "llvm-13*" libclang-13-dev luajit luajit-5.1-dev libelf-dev python3-distutils libdebuginfod-dev arping netperf iperf
```

## Building bcc tools

```bash
# Make sure you are in the bcc root folder
$ mkdir -p build && cd build
$ cmake .. -DPYTHON_CMD=python3
$ make -j4
$ sudo make install
```

# Building and executing the usdt_sample (gcc 11.2)

## Build the sample

```bash
$ gcc --version
gcc (Ubuntu 11.2.0-7ubuntu2) 11.2.0
...
# Make sure you are in the bcc root folder
$ mkdir -p examples/usdt_sample/build && cd examples/usdt_sample/build
$ cmake ..
$ make
```

## Create probes using StaticTracepoint.h

bcc comes with a header file, which contains macros to define probes. See tests/python/include/folly/tracing/StaticTracepoint.h

See the usage of FOLLY_SDT macro in examples/usdt_sample/usdt_sample_lib1/src/lib1.cpp.

## Create probes using SystemTap dtrace

As an alternative to using tests/python/include/folly/tracing/StaticTracepoint.h, it's possible to use dtrace, which is installed by systemtap-sdt-dev.
```bash
$ sudo dnf install systemtap-sdt-dev  # For Ubuntu 21.10, other distro's might have differently named packages.
```

If using systemtap-sdt-dev, the following commands can be used to generate the corresponding header and object files:
See examples/usdt_sample/usdt_sample_lib1/CMakeLists.txt file for an example how to do this using cmake.
```bash
$ dtrace -h -s usdt_sample_lib1/src/lib1_sdt.d -o usdt_sample_lib1/include/usdt_sample_lib1/lib1_sdt.h
$ dtrace -G -s usdt_sample_lib1/src/lib1_sdt.d -o lib1_sdt.o
```

## Use tplist.py to list the available probes

Note that the (ope