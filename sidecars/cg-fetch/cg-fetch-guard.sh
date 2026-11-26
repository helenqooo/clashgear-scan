#!/bin/sh
# Egress fence for the link fetcher (user cgfetch): no new connections to this box, its LANs, the guests'
# networks or the shop; only the local DNS stub is allowed. Runs as root before every start (idempotent).
set -e
# Extra networks to fence off (your sandbox LAN, your web server), space-separated CIDRs.
CG_FETCH_BLOCKED_SPACE="${CG_FETCH_BLOCKED_SPACE:-}"
U=cgfetch
iptables -N CGFETCH_OUT 2>/dev/null || iptables -F CGFETCH_OUT
iptables -A CGFETCH_OUT -d 127.0.0.53/32 -p udp --dport 53 -j RETURN
iptables -A CGFETCH_OUT -d 127.0.0.53/32 -p tcp --dport 53 -j RETURN
for n in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4 ${CG_FETCH_BLOCKED_SPACE}; do
  iptables -A CGFETCH_OUT -d "$n" -j REJECT
done
iptables -C OUTPUT -m owner --uid-owner "$U" -m conntrack --ctstate NEW -j CGFETCH_OUT 2>/dev/null \
  || iptables -I OUTPUT 1 -m owner --uid-owner "$U" -m conntrack --ctstate NEW -j CGFETCH_OUT
ip6tables -C OUTPUT -m owner --uid-owner "$U" -j REJECT 2>/dev/null \
  || ip6tables -I OUTPUT 1 -m owner --uid-owner "$U" -j REJECT
