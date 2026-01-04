#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y install auditd filebeat osquery curl net-tools

# Настроим базовую телеметрию (filebeat -> SIEM) — укажи корректный адрес siem
echo "filebeat setup TODO: configure with siem ip"
