import os
import subprocess
import pyroute2
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen

class Simulation(object):
    """
    Helper class for controlling multiple namespaces. Inherit from
    this class and setup your namespaces.
    """

    def __init__(self, ipdb):
        self.ipdb = ipdb
        self.ipdbs = {}
        self.namespaces = []
        self.processes = []
        self.released = False

    # helper function to add additional ifc to namespace
    # if called directly outside Simulation class, "ifc_base_name" should be
    # different from "name", the "ifc_base_name" and "name" are the same for
    # the first ifc created by namespace
    def _ns_add_ifc(self, name, ns_ifc, ifc_base_name=None, in_ifc=None,
                    out_ifc=None, ipaddr=None, macaddr=None, fn=None, cmd=None,
                    action="ok", disable_ipv6=False):
        if name in self.ipdbs:
            ns_ipdb = self.ipdbs[name]
        else:
            try:
                nl=NetNS(name)
                self.namespaces.append(nl)
            except KeyboardInterrupt:
                # remove the namespace if it has been created
                pyroute2.netns.remove(name)
                raise
            ns_ipdb = IPDB(nl)
            self.ipdbs[nl.netns] = ns_ipdb
            if disable_ipv6:
                cmd1 = ["sysctl", "-q", "-w",
                       "net.ipv6.conf.default.disable_ipv6=1"]
                nsp = NSPopen(ns_ipdb.nl.netns, cmd1)
                nsp.wait(); nsp.release()
            try:
                ns_ipdb.interfaces.lo.up().commit()
            except pyroute2.ipdb.exceptions.CommitException:
                print("Warning, commit for lo failed, operstate may be unknown")
        if in_ifc:
            in_ifname = in_ifc.ifname
            with in_ifc as v:
                # move half of veth into namespace
                v.net_ns_fd = ns_ipdb.nl.