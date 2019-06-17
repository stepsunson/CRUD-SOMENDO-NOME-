This example shows a unique way to use a BPF program to demux any ethernet
traffic into a pool of worker veth+namespaces (or any ifindex-based
destination) depending on a configurable mapping of src-mac to ifindex. As
part of the ingress processing, the program will dynamically learn the source
ifindex of the matched source mac.

Simula