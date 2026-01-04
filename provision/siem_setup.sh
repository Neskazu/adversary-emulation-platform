#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y install openjdk-11-jre-headless apt-transport-https wget

# Установка Elastic (упрощённо)
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
apt-get update
apt-get -y install elasticsearch kibana logstash

systemctl enable elasticsearch --now || true
systemctl enable kibana --now || true

# Тонкая настройка — делать через Ansible
