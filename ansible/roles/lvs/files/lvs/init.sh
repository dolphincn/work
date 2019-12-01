#!/bin/bash

set -e
set -o pipefail

config_keepalived() {

  if ! compgen -A variable | grep -q 'KEEPALIVED_VIPS'; then
    echo "[$(date)][KEEPALIVED] No KEEPALIVED_VIPS varibles detected."
    return 1
  fi

  if ! compgen -A variable | grep -q 'KEEPALIVED_INTERFACE'; then
    echo "[$(date)][KEEPALIVED] No KEEPALIVED_INTERFACE varibles detected."
    return 1
  fi



  if [[ ! $KEEPALIVED_UNICAST_SRC_IP ]]; then
    bind_target="$(ip addr show "$KEEPALIVED_INTERFACE" | \
      grep -m 1 -E -o 'inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk '{print $2}')"
    KEEPALIVED_UNICAST_SRC_IP="$bind_target"
  fi

  {
    echo 'global_defs {'
    echo "  router_id KP_LVS_$RANDOM"
    echo '  vrrp_garp_master_refresh 60'
    echo '  vrrp_garp_master_delay 5'
    echo "  vrrp_mcast_group4 224.0.100.${KEEPALIVED_VIRTUAL_ROUTER_ID}"
    echo '}'
    echo 'vrrp_script mantaince_check {'
    echo '  script "[[ -f /etc/keepalived/down ]] && exit 1 || exit 0"'
    echo '  interval 2'
    echo '  weight 20'
    echo '  fall 2'
    echo '  rise 2'
    echo '}'
    echo 'vrrp_script app_check {'
    echo '  script "/bin/bash /etc/keepalived/app_check.sh"'
    echo '  interval 2'
    echo '  weight 20'
    echo '  fall 2'
    echo '  rise 2'
    echo '}'
  } > "$KEEPALIVED_CONF"


#### vrrp_instance start

  {
    echo "vrrp_instance VI_${KEEPALIVED_VIRTUAL_ROUTER_ID} {"
    echo "  state $KEEPALIVED_STATE"
    echo "  interface $KEEPALIVED_INTERFACE"
    echo "  virtual_router_id $KEEPALIVED_VIRTUAL_ROUTER_ID"
    echo "  priority $KEEPALIVED_PRIORITY"
    echo "  advert_int $KEEPALIVED_ADVERT_INT"
  } >> "$KEEPALIVED_CONF"

  ## unicast
  if [[ -n KEEPALIVED_UNICAST_SRC_IP ]] && [[ ${#KEEPALIVED_UNICAST_PEER_ARRAY[@]} -gt 0 ]]; then
    echo "  unicast_src_ip $KEEPALIVED_UNICAST_SRC_IP" >> "$KEEPALIVED_CONF"
    echo '  unicast_peer {' >> "$KEEPALIVED_CONF"
    for peer in "${KEEPALIVED_UNICAST_PEER_ARRAY[@]}"; do
      echo "    ${peer}" >> "$KEEPALIVED_CONF"
    done
    echo '  }' >> "$KEEPALIVED_CONF"
  fi 


  ## authentication
  {
    echo '  authentication {'
    echo '    auth_type PASS'
    echo "    auth_pass $KEEPALIVED_AUTH_PASS"
    echo '  }'
  }  >> "$KEEPALIVED_CONF"

  #keeplived_master_notify=""
  
  ## virtual_ipaddress
  if [[ -n "$KEEPALIVED_VIPS" ]]; then
    echo '  virtual_ipaddress {' >> "$KEEPALIVED_CONF"
    for vip in "${KEEPALIVED_VIPS_ARRAY[@]}"; do
      arrystr=${vip//\// }
      vip_array=($arrystr)
      if [[ ${#vip_array[@]} -eq 3 ]];then
        vip_broadcast="brd ${vip_array[2]}"
      fi
      arrystr=${vip_array[0]//.// }
      vip_num_array=($arrystr)
      vip_last_num=${vip_num_array[3]}

      #if [[ -n KEEPALIVED_GATEWAY ]]; then
      #  keeplived_master_notify="{keeplived_master_notify} /usr/sbin/arping -I ${KEEPALIVED_INTERFACE} -c 3 -s ${vip_array[0]} ${KEEPALIVED_GATEWAY} > /dev/null 2>&1;"
      #fi
      echo "    ${vip_array[0]}/${vip_array[1]}  ${vip_broadcast} label ${KEEPALIVED_INTERFACE}:${vip_last_num} dev ${KEEPALIVED_INTERFACE}" >> "$KEEPALIVED_CONF"
    done
    echo '  }' >> "$KEEPALIVED_CONF"
  fi

  ## virtual_ipaddress_excluded
  if [[ -n "$KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED" ]]; then
    echo '  virtual_ipaddress_excluded {' >> "$KEEPALIVED_CONF"
    for evip in "${KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_ARRAY[@]}"; do
      echo "    ${evip}" >> "$KEEPALIVED_CONF"
    done
    echo '  }' >> "$KEEPALIVED_CONF"
  fi


  ## track_interface
  if [[ -n "$KEEPALIVED_TRACK_INTERFACES" ]]; then
    echo '  track_interface {' >> "$KEEPALIVED_CONF"
    for interface in "${KEEPALIVED_TRACK_INTERFACES_ARRAY[@]}" ; do
      echo "    ${interface}" >> "$KEEPALIVED_CONF"
    done
    echo '  }' >> "$KEEPALIVED_CONF"
  else
    {
      echo '  track_interface {'
      echo "    $KEEPALIVED_INTERFACE"
      echo '  }'
    } >> "$KEEPALIVED_CONF"
 fi


  ## track_script
   {
     echo '  track_script {'
     echo '    mantaince_check'
     echo '    chk_app'
     echo '  }'
   } >> "$KEEPALIVED_CONF"
 
 ## echo "notify_master \"/usr/sbin/arping -I ${KEEPALIVED_INTERFACE} -c 3 -s $VIP $GATEWAY > /dev/null 2>&1 \""
 #if [[ -n KEEPALIVED_GATEWAY ]]; then
 #       echo "notify_master \"${keeplived_master_notify}\""
 #fi 
 echo '}' >> "$KEEPALIVED_CONF"
#### vrrp_instance end



#### lvs virtual server start

## KEEPALIVED_VIP_REAL_SERVERS="192.168.2.60:80/tcp=192.168.2.51:80,192.168.2.52:80;192.168.2.70:53=192.168.2.71:53,192.168.2.72:53"
  if [[ "${KEEPALIVED_USE_LVS,,}" == 'true' ]]; then
    for vip_real_server in "${KEEPALIVED_VIP_REAL_SERVERS_ARRAY[@]}"; do
      if [[ -z "$vip_real_server" ]]; then
        continue
      fi

      ## vip + real_server
      arrystr=${vip_real_server//=/ }
      vip_real_server_array=($arrystr)

      echo "vip_real_server: $vip_real_server"
      echo "========================"

      if [[ ${#vip_real_server_array[@]} -ne 2 ]]; then
        continue
      fi

      
      ## vip(ip:port/protocol)
      vip=${vip_real_server_array[0]}
      arrystr=${vip//:/ }
      vip_array=($arrystr)

      echo "vip: $vip"
      echo "========================"

      if [[ ${#vip_array[@]} -ne 2 ]];then
        continue
      fi
      vip_ip=${vip_array[0]}
      arrystr=${vip_array[1]}
      arrystr=${arrystr//\// }
      vip_port_protocol=($arrystr)
      vip_port=${vip_port_protocol[0]}
      
      if [[ ${#vip_port_protocol[@]} -eq 2 ]]; then
        vip_protocol=${vip_port_protocol[1]}
      fi

      if [[ -z $vip_protocol ]]; then
          vip_protocol="tcp"
      fi
      echo "vip_ip: $vip_ip"
      echo "vip_protocol: $vip_protocol"
      echo "========================"
      if [[ -z "$vip_ip" ]] || [[ -z "$vip_port" ]];then
        continue
      fi


      ## real_servers(ip:port,ip:port)
      real_servers=${vip_real_server_array[1]}
      arrystr=${real_servers//,/ }
      real_server_array=($arrystr)
      if [[ ${#real_server_array[@]} -lt 1 ]];then
        continue
      fi


      ## virtual_server
      {
      echo "virtual_server $vip_ip $vip_port { "
      echo "    delay_loop $KEEPALIVED_DELAY_LOOP"
      echo "    lb_algo $KEEPALIVED_LB_ALGO"
      echo "    lb_kind $KEEPALIVED_LB_KIND"
      echo "    protocol $vip_protocol"
      } >> "$KEEPALIVED_CONF"

      
      ## real_server
      for real_server in "${real_server_array[@]}"; do
          arrystr=${real_server//:/ }
          ip_port_array=($arrystr)
          if [[ ${#ip_port_array[@]} -lt 1 ]];then
            continue
          fi
          host_ip=${ip_port_array[0]}
          host_port=${ip_port_array[1]}
          host_port=${host_port:-$vip_port}
          if [[ -z "$host_ip" ]] || [[ -z "$host_port" ]];then
            continue
          fi

          if [[ "${KEEPALIVED_AUTO_TCP_CHECK,,}" == "true" ]]; then
            if [[ "$vip_port" != "80" ]]; then
              {
              echo "   real_server $host_ip $host_port {"
              echo "         weight 100"
              echo '         TCP_CHECK {'
              echo "            connect_timeout 3"
              echo "            nb_get_retry 3"
              echo "            delay_before_retry 3"
              echo "            connect_port $host_port"
              echo '         }'
              echo '   }'
              } >> "$KEEPALIVED_CONF"
            else
              {
              echo "   real_server $host_ip $host_port {"
              echo "         weight 100"
              echo "         HTTP_GET {"
              echo "           url {"
              echo '             path /'
              echo "             status_code 200"
              echo "           }"
              echo "           connect_timeout 3"
              echo "           nb_get_retry 3"
              echo "           delay_before_retry 3"
              echo "         }"
              echo '   }'
              } >> "$KEEPALIVED_CONF"
            fi 
          else
            {
            echo "    real_server $host_ip $host_port {"
            echo "         weight 100"
            echo '         MISC_CHECK {'
            echo "            misc_path \"/bin/bash /etc/keepalived/misc_check.sh $host_ip $host_port $vip_protocol\" "
            echo "            misc_timeout 3"
            echo "            # delay_before_retry 3"
            echo "            # misc_dynamic"
            echo '         }'
            echo '   }'
            } >> "$KEEPALIVED_CONF"
          fi
      done

      echo "}" >> "$KEEPALIVED_CONF"


      
    done
  fi
  
#### lvs virtual server end



  #### return
  return 0

}



init_vars() {

  ## 下面三段参数 docker run 需要设置
  KEEPALIVED_USE_LVS=${KEEPALIVED_USE_LVS:-"false"}
  KEEPALIVED_AUTOCONF=${KEEPALIVED_AUTOCONF:-"true"}
  KEEPALIVED_CONF_DIR=${KEEPALIVED_CONF_DIR:-"/etc/keepalived"}
  KEEPALIVED_CONF=${KEEPALIVED_CONF:-"$KEEPALIVED_CONF_DIR/keepalived.conf"}

  KEEPALIVED_INTERFACE=${KEEPALIVED_INTERFACE:-"ens33"}
  KEEPALIVED_STATE=${KEEPALIVED_STATE:-"MASTER"}
  KEEPALIVED_STATE=${KEEPALIVED_STATE^^}

  KEEPALIVED_UNICAST_SRC_IP=${KEEPALIVED_UNICAST_SRC_IP:-""}
  KEEPALIVED_UNICAST_PEERS=${KEEPALIVED_UNICAST_PEERS:-""}
  KEEPALIVED_VIPS=${KEEPALIVED_VIPS:-""}
  KEEPALIVED_VIP_REAL_SERVERS=${KEEPALIVED_VIP_REAL_SERVERS:-""}
  #KEEPALIVED_PROTOCOL=${KEEPALIVED_PROTOCOL:-"TCP"}
  KEEPALIVED_AUTO_TCP_CHECK=${KEEPALIVED_AUTO_TCP_CHECK:-true}


  KEEPALIVED_DEBUG=${KEEPALIVED_DEBUG:-true}
  KEEPALIVED_VAR_RUN=${KEEPALIVED_VAR_RUN:-"/var/run/keepalived"}
  #KEEPALIVED_GATEWAY=${KEEPALIVED_GATEWAY:-""}


  KEEPALIVED_PRIORITY=${KEEPALIVED_PRIORITY:-100}
  if [[ "$KEEPALIVED_STATE" != "MASTER" ]];then
     KEEPALIVED_PRIORITY=$(( $KEEPALIVED_PRIORITY - 10))
  fi
  KEEPALIVED_ADVERT_INT=${KEEPALIVED_ADVERT_INT:-1}

  KEEPALIVED_TRACK_INTERFACES=${KEEPALIVED_TRACK_INTERFACES:-""}
  KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED=${KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED:-""}
  KEEPALIVED_DELAY_LOOP=${KEEPALIVED_DELAY_LOOP:-6}
  KEEPALIVED_LB_ALGO=${KEEPALIVED_LB_ALGO:-"wrr"}
  KEEPALIVED_LB_KIND=${KEEPALIVED_LB_KIND:-"DR"}

  OLD_IFS="$IFS"
  IFS=","
  if [[ -n "$KEEPALIVED_UNICAST_PEERS" ]];then
    KEEPALIVED_UNICAST_PEER_ARRAY=($KEEPALIVED_UNICAST_PEERS)
  fi
  if [[ -n "$KEEPALIVED_TRACK_INTERFACES" ]];then
    KEEPALIVED_TRACK_INTERFACES_ARRAY=($KEEPALIVED_TRACK_INTERFACES)
  fi
  if [[ -n "$KEEPALIVED_VIPS" ]] ; then
    KEEPALIVED_VIPS_ARRAY=($KEEPALIVED_VIPS)

  fi
  if [[ -n "$KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED" ]];then
    KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED_ARRAY=($KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED)
  fi
  IFS="$OLD_IFS"

  IFS=";"
  if [[ -n "$KEEPALIVED_VIP_REAL_SERVERS" ]];then
    KEEPALIVED_VIP_REAL_SERVERS_ARRAY=($KEEPALIVED_VIP_REAL_SERVERS)
  fi
  IFS="$OLD_IFS"


  if  [[ -z "$KEEPALIVED_VIRTUAL_ROUTER_ID" ]] && [[ -n "$KEEPALIVED_VIPS" ]]; then
    tmpstr=${KEEPALIVED_VIPS//\// }
    tmparray=($tmpstr)
    tmpstr=${tmparray[0]}

    tmpstr=${tmpstr//,/ }
    tmparray=($tmpstr)
    tmpstr=${tmparray[0]}

    tmpstr=${tmpstr//./ }
    tmparray=($tmpstr)
    if [[ ${#tmparray[@]} -gt 3 ]]; then
      KEEPALIVED_VIRTUAL_ROUTER_ID=${tmparray[3]}
    fi
  fi
  KEEPALIVED_VIRTUAL_ROUTER_ID=${KEEPALIVED_VIRTUAL_ROUTER_ID:-"199"}

  KEEPALIVED_AUTH_PASS=${KEEPALIVED_AUTH_PASS:-"WhatIs$KEEPALIVED_VIRTUAL_ROUTER_ID"}

  if [[ ${KEEPALIVED_DEBUG,,} == 'true' ]]; then
    local kd_cmd="/usr/sbin/keepalived -n -l -D -d -f $KEEPALIVED_CONF"
  else
    local kd_cmd="/usr/sbin/keepalived -n -l -f $KEEPALIVED_CONF"
  fi
  KEEPALIVED_CMD=${KEEPALIVED_CMD:-"$kd_cmd"}
}


main() {

  init_vars

  echo "KEEPALIVED_USE_LVS=${KEEPALIVED_USE_LVS}"
  echo "KEEPALIVED_AUTOCONF=${KEEPALIVED_AUTOCONF}"
  echo "KEEPALIVED_CONF=${KEEPALIVED_CONF}"

  echo "KEEPALIVED_INTERFACE=${KEEPALIVED_INTERFACE}"
  echo "KEEPALIVED_STATE=${KEEPALIVED_STATE}"

  echo "KEEPALIVED_UNICAST_SRC_IP=${KEEPALIVED_UNICAST_SRC_IP}"
  echo "KEEPALIVED_UNICAST_PEERS=${KEEPALIVED_UNICAST_PEERS}"
  echo "KEEPALIVED_VIPS=${KEEPALIVED_VIPS}"
  echo "KEEPALIVED_VIP_REAL_SERVERS=${KEEPALIVED_VIP_REAL_SERVERS}"
  # echo "KEEPALIVED_PROTOCOL=${KEEPALIVED_PROTOCOL}"
  echo "KEEPALIVED_AUTO_TCP_CHECK=${KEEPALIVED_AUTO_TCP_CHECK}"

  echo "KEEPALIVED_DEBUG=${KEEPALIVED_DEBUG}"
  echo "KEEPALIVED_VAR_RUN=${KEEPALIVED_VAR_RUN}"
  #echo "KEEPALIVED_GATEWAY=${KEEPALIVED_GATEWAY}"

  echo "KEEPALIVED_PRIORITY=${KEEPALIVED_PRIORITY}"
  echo "KEEPALIVED_ADVERT_INT=${KEEPALIVED_ADVERT_INT}"
  echo "KEEPALIVED_AUTH_PASS=${KEEPALIVED_AUTH_PASS}"

  echo "KEEPALIVED_TRACK_INTERFACES=${KEEPALIVED_TRACK_INTERFACES}"
  echo "KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED=${KEEPALIVED_VIRTUAL_IPADDRESS_EXCLUDED}"
  echo "KEEPALIVED_DELAY_LOOP=${KEEPALIVED_DELAY_LOOP}"
  echo "KEEPALIVED_LB_ALGO=${KEEPALIVED_LB_ALGO}"
  echo "KEEPALIVED_LB_KIND=${KEEPALIVED_LB_KIND}"
  echo "KEEPALIVED_VIRTUAL_ROUTER_ID=${KEEPALIVED_VIRTUAL_ROUTER_ID}"
  echo "KEEPALIVED_CMD=${KEEPALIVED_CMD}"
  


  if [[ ${KEEPALIVED_AUTOCONF,,} == 'true' ]]; then
    config_keepalived
  fi
  if [[ -n "$KEEPALIVED_VAR_RUN" ]]; then
   rm -fr "$KEEPALIVED_VAR_RUN"
  fi 
  # shellcheck disable=SC2086


  # echo 1 > /proc/sys/net/ipv4/ip_nonlocal_bind
  # echo 1 > /proc/sys/net/ipv4/ip_forward
  # echo "1" > /proc/sys/net/ipv4/vs/nat_icmp_send

  if [[ -n ${LVS_TIME_OUT} ]];then
    ipvsadm --set ${LVS_TIME_OUT}
  fi
  exec $KEEPALIVED_CMD
}


main
