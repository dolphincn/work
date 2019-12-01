#!/bin/bash

if [[ $# -ne 3 ]]; then 
   echo "usage: misc_check.sh dns_host_ip dns_port dns_protocol"
   exit 1
fi

if [[ "$2" != "53" ]]; then
   echo "port is not 53"
   echo "usage: misc_check.sh dns_host_ip dns_port dns_protocol"
   exit 1
fi

dns_host_ip=$1
dns_port=$2
dns_protocol=$3

if [[ $dns_protocol=="tcp" ]];then
   host -T {{ lvs.check.hostname }} $dns_host_ip && host -T {{ lvs.check.ip }} $dns_host_ip && exit 0 || exit 1
else
  host {{ lvs.check.hostname }} $dns_host_ip && host {{ lvs.check.ip }} $dns_host_ip && exit 0 || exit 1
fi

