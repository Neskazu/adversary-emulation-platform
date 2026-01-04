#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y iptables-persistent net-tools

# enable ip forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-forward.conf

# allow routing between all interfaces
iptables -P FORWARD ACCEPT

# save
netfilter-persistent save

echo "[OK] Router configured without touching IP addresses."
