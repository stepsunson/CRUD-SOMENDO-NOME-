#!/bin/bash

# This script must be executed by root user
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# add namespaces
ip netns add netns11
ip netns add netns12
ip netns add netns21
ip netns add netns22
ip netns add netns3
ip netns add netns4

# set up veth devices in netns11 to netns21 with connection to netns3  
ip link add veth11 type veth peer name veth13
ip link add veth21 type veth peer name veth23
ip link set veth11 netns netns11
ip link set veth21 netns netns21
ip link set veth13 netns netns3
ip link set veth23 netns netns3

# set up veth devices in netns12 and netns22 with connection to netns4 
ip link add veth12 type veth peer name veth14
ip link add veth22 type veth peer name veth24
ip link set veth12 netns netns12
ip link set veth22 netns netns22
ip link set veth14 netns netns4
ip link set veth24 netns netns4
  
# assign IP addresses and set the devices up 
ip netns exec netns11 ifconfig veth11 192.168.100.11/24 up
ip netns exec netns11 ip link set lo up
ip netns exec netns12 ifconfig veth12 192.168.100.12/24 up
ip netns exec netns12 ip link set lo up
ip netns exec netns21 ifconfig veth21 192.168.200.21/24 up
ip netns exec netns21 ip link set lo up
ip netns exec netns22 ifconfig veth22 192.168.200.22/24 up
ip netns exec netns22 ip link set lo up

# set up bridge brx and its ports 
ip netns exec netns3 brctl addbr brx  
ip netns exec netns3 ip link set brx up
ip netns exec netns3 ip link set veth13 up
ip netns exec netns3 ip link set veth23 up
ip netns exec netns3 brctl addif brx veth13
ip netns exec netns3 brctl addif brx veth23

# set up bridge bry and its ports 
ip netns exec netns4 brctl addbr bry  
ip netns exec netns4 ip link set bry up
ip netns exec netns4 ip link set veth14 up
ip netns exec netns4 ip link set veth24 up
ip netns exec netns4 brctl addif bry veth14
ip netns