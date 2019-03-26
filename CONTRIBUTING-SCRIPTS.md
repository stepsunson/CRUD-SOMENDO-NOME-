# Contributing bcc/eBPF scripts

If you want to contribute scripts to bcc, or improve your own bcc programs, great! Please read this first.

_(Written by Brendan Gregg.)_

## Type of script

bcc has 2 types of scripts, in different directories:

- **/examples**: intended as short examples of bcc & eBPF code. You should focus on keeping it short, neat, and documented (code comments). A submission can just be the example code.
- **/tools**: intended as production safe performance and troubleshooting tools. You should focus on it being useful, tested, low overhead, documented (incl. all caveats), and easy to use. A submission should involve 4 changes: the tool, a man page, an example file, and an 