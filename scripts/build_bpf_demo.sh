#!/bin/bash

#set -x
set -e

function usage() {
  cat <<DELIM__
usage: $(basename $0) [options]

Options:
  -b, --bridge BRNAME   Which linux bridge to attach to
  -c, --cpu NUM         Number of CPUs to reserve to the instance (default 4)
  -g, --github_token X  HTTP Github oauth token (for buildbots)
  -k, --kickstart KS    Path to kickstart file to use (required)
  -m, --mirror URL      URL at which to reach netinstallable packages
  -M, --mem NUM         Number of MB to reserve to the instance (default 4094)
  -n, --name NAME       Name of the instance (required)
  -p, --password PASS   Password to set in the VM
  -s, --size NUM        Size in GB to reserve for the virtual HDD (default 40GB)
DELIM__
}

TEMP=$(getopt -o b:c:k:m:M:n:p:s: --long bridge:,cpu:,kickstart:,mirror:,mem:,name:,password:size: -- "$@")
if [[ $? -ne 0 ]]; then
  usage
  exit 1
fi

eval set -- "$TEMP"

while true; do
  case "$1" in
    -b|--bridge) BRIDGE="$2"; shift 2 ;;
    -c|--cpu) CPU="$2"; shift 2 ;;
    -k|--kickstart) KICKSTART