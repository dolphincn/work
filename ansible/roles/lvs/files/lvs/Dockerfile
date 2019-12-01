FROM alpine
RUN apk add --no-cache     bash           curl           ipvsadm        iproute2       keepalived     vim             grep            tcpdump         sed             net-tools       bind-tools  && rm /etc/keepalived/keepalived.conf

COPY /init.sh /
COPY /sysctl.conf /etc/sysctl.conf
COPY /iptables.conf /etc/modprobe.d/iptables.conf
COPY /ip_vs.conf /etc/modprobe.d/ip_vs.conf
COPY /modules /etc/modules

RUN chmod +x init.sh

CMD ["./init.sh"]

