#!/usr/bin/env bash
set -e

EXT_IF=$(ip route get 1.1.1.1 | awk '{print $5; exit}')
echo "[*] Detected external interface: $EXT_IF"

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.ip_default_ttl=128
sysctl -w net.ipv4.tcp_timestamps=0
sysctl -w net.ipv4.tcp_window_scaling=1

iptables -t nat -C POSTROUTING -s 10.88.0.0/24 -o "$EXT_IF" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o "$EXT_IF" -j MASQUERADE

iptables -C FORWARD -s 10.88.0.0/24 -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -s 10.88.0.0/24 -j ACCEPT

iptables -C FORWARD -d 10.88.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -d 10.88.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "[+] Windows Server TCP/IP Fingerprint (TTL=128, Timestamps=0) & NAT configured."
