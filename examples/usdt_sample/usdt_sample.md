
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

Note that the (operation_start, operation_end) probes are created using the macros in the folly headers, the (operation_start_sdt, operation_end_sdt) probes are created using systemtap's dtrace:

```bash
$ python3 tools/tplist.py -l examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_end_sdt
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start
examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so usdt_sample_lib1:operation_start_sdt
$ readelf -n examples/usdt_sample/build/usdt_sample_lib1/libusdt_sample_lib1.so

Displaying notes found in: .note.gnu.property
  Owner                Data size        Description
  GNU                  0x00000010       NT_GNU_PROPERTY_TYPE_0
      Properties: x86 feature: IBT, SHSTK

Displaying notes found in: .note.gnu.build-id
  Owner                Data size        Description
  GNU                  0x00000014       NT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: a483dc6ac17d4983ba748cf65ffd0e398639b61a

Displaying notes found in: .note.stapsdt
  Owner                Data size        Description
  stapsdt              0x00000047       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end
    Location: 0x0000000000011c2f, Base: 0x0000000000000000, Semaphore: 0x0000000000000000
    Arguments: -8@%rbx -8@%rax
  stapsdt              0x0000004f       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_end_sdt
    Location: 0x0000000000011c65, Base: 0x000000000001966f, Semaphore: 0x0000000000020a6a
    Arguments: 8@%rbx 8@%rax
  stapsdt              0x0000004f       NT_STAPSDT (SystemTap probe descriptors)
    Provider: usdt_sample_lib1
    Name: operation_start
    Location: 0x0