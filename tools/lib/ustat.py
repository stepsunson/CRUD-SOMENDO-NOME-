#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# ustat  Activity stats from high-level languages, including exceptions,
#        method calls, class loads, garbage collections, and more.
#        For Linux, uses BCC, eBPF.
#
# USAGE: ustat [-l {java,node,perl,php,python,ruby,tcl}] [-C]
#        [-S {cload,excp,gc,method,objnew,thread}] [-r MAXROWS] [-d]
#        [interval [count]]
#
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
# Newly-created processes might only be traced at the next interval, if the
# relevant USDT probe requires enabling through a semaphore.
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 26-Oct-2016   Sasha Goldshtein    Created this.

from __future__ import print_function
import argparse
from bcc import BPF, USDT, USDTException
import os
import sys
from subprocess import call
from time import sleep, strftime

class Category(object):
    THREAD = "THREAD"
    METHOD = "METHOD"
    OBJNEW = "OBJNEW"
    CLOAD = "CLOAD"
    EXCP = "EXCP"
    GC = "GC"

class Probe(object):
    def __init__(self, language, procnames, events):
        """
        Initialize a new probe object with a specific language, set of process
        names to monitor for that language, and a dictionary of events and
        categories. The dictionary is a mapping of USDT probe names (such as
        'gc__start') to event categories supported by this tool -- from the
        Category class.
        """
        self.language = language
        self.procnames = procnames
        self.events = events

    def _find_targets(self):
        """Find pids where the comm is one of the specified list"""
        self.targets = {}
        all_pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
        for pid in all_pids:
            try:
                comm = open('/proc/%d/comm' % pid).read().strip()
                if comm in self.procnames:
                    cmdline = open('/proc/%d/cmdline' % pid).read()
                    self.targets[pid] = cmdline.replace('\0', ' ')
            except IOError:
                continue    # process may already have terminated

    def _enable_probes(self):
        self.usdts = []
        for pid in self.targets:
            try:
                usdt = USDT(pid=pid)
            except USDTException:
                # avoid race condition on pid going away.
                print("failed to instrument %d" % pid, file=sys.stderr)
                continue
            for event in self.events:
                try:
                    usdt.enable_probe(event, "%s_%s" % (self.language, event))
                except Exception:
                    # This process might not have a recent version of the USDT
                    # probes enabled, or might have been compiled without USDT
                    # probes at all. The process could even have been shut down
                    # and the pid been recycled. We have to gracefully handle
                    # the possibility that we can't attach probes to it at all.
                    pass
            self.usdts.append(usdt)

    def _generate_tables(self):
        text = """
BPF_HASH(%s_%s_counts, u32, u64);   // pid to event count
        """
        return str.join('', [text % (self.language, event)
                             for event in self.events])

    def _generate_functions(self):
        text = """
int %s_%s(void *ctx) {
    u64 *valp, zero = 0;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    valp = %s_%s_counts.lookup_or_try_init(&tgid, &zero);
    if (valp) {
        ++(*valp);
    }
    return 0;
}
        """
        lang = self.language
        return str.join('', [text % (lang, event, lang, event)
                             for event in self.events])

    def get_program(self):
        self._find_targets()
        self._enable_probes()
        return self._generate_tables() + self._generate_functions()

    def get_usdts(self):
        return self.usdts

    def get_counts(self, bpf):
        """Return a map of event counts per process"""
        event_dict = dict([(category, 0) for category in self.events.values()])
        result = dict([(pid, event_dict.copy()) for pid in self.targets])
        for event, category in self.events.items():
            counts = bpf["%s_%s_counts" % (self.language, event)]
            for pid, count in counts.items():
                if pid.value not in result:
                    print("result was not found for %d" % pid.value, file=sys.stderr)
                    continue
                result[pid.value][category] = count.value
            counts.clear()
        return result

    def cleanup(self):
        self.usdts = None

class Tool(object):
    def _parse_args(self):
        examples = """examples:
  ./ustat              # stats for all languages, 1 second refresh
  ./ustat -C           # don't clear the screen
  ./ustat -l java      # Java processes only
  ./ustat 5            # 5 second summaries
  ./ustat 5 10         # 5 second summaries, 10 times only
        """
        parser = argparse.ArgumentParser(
            description="Activity stats from high-level languages.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=examples)
        parser.add_argument("-l", "--language",
            choices=["java", "node", "perl", "php", "python", "ruby", "tcl"],
            help="language to trace (default: all languages)")
        parser.add_argument("-C", "--noclear", action="store_true",
            help="don't clear the screen")
        parser.add_argument("-S", "--sort",
            choices=[cat.lower() for cat in dir(Category) if cat.isupper()],
            help="sort by this field (descending order)")
        parser.add_argument("-r", "--maxrows", default=20, type=int,
            help="maximum rows to print, default 20")
        parser.add_argument("-d", "--debug", action="store_true",
            help="Print the resulting BPF program (for debugging purposes)")
        parser.add_argument("interval", nargs="?", default=1, type=int,
            help="output interval, in seconds")
        parser.add_argument("count", nargs="?", default=99999999, type=int,
            help="number of 