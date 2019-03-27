# Contributing bcc/eBPF scripts

If you want to contribute scripts to bcc, or improve your own bcc programs, great! Please read this first.

_(Written by Brendan Gregg.)_

## Type of script

bcc has 2 types of scripts, in different directories:

- **/examples**: intended as short examples of bcc & eBPF code. You should focus on keeping it short, neat, and documented (code comments). A submission can just be the example code.
- **/tools**: intended as production safe performance and troubleshooting tools. You should focus on it being useful, tested, low overhead, documented (incl. all caveats), and easy to use. A submission should involve 4 changes: the tool, a man page, an example file, and an addition to README.md. Follow [my lead](https://github.com/brendangregg/bcc/commit/9fa156273b395cfc5505f0fff5d6b7b1396f7daa), and see the checklist below. These are run in mission critical environments as root (tech companies, financial institutions, government agencies), so if spending hours testing isn't for you, please submit your idea as an issue instead, or chat with us on irc.

More detail for each below.

## Examples

These are grouped into subdirectories (networking, tracing). Your example can either be a Python program with embedded C (eg, tracing/strlen_count.py), or separate Python and C files (eg, tracing/vfsreadlat.*).

As said earlier: keep it short, neat, and documented (code comments).

## Tools

A checklist for bcc tool development:

1. **Research the topic landscape**. Learn the existing tools and metrics (incl. from /proc). Determine what real world problems exist and need solving. We have too many tools and metrics as it is, we don't need more "I guess that's useful" tools, we need more "ah-hah! I couldn't do this before!" tools. Consider asking other developers about your idea. Many of us can be found in IRC, in the #iovisor channel on irc.oftc.net. There's also the mailing list (see the README.md), and github for issues.
1. **Create a known workload for testing**. This might involving writing a 10 line C program, using a micro-benchmark, or just improvising at the shell. If you don't know how to create a workload, learn! Figuring this out will provide invaluable context and details that you may have otherwise overlooked. Sometimes it's easy, and I'm able to just use dd(1) from /dev/urandom or a disk device to /dev/null. It lets me set the I/O size, count, and provides throughput statistics for cross-checking my tool output. But other times I need a micro-benchmark, or some C.
1. **Write the tool to solve the problem and no more**. Unix philosophy: do one thing and do it well. netstat doesn't have an option to dump packets, tcpdump-style. They are two different tools.
1. **Check your tool correctly measures your known workload**. If possible, run a prime number of events (eg, 23) and check that the numbers match. T