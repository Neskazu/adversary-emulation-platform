#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y install docker.io python3-pip git
pip3 install docker-compose

# Создадим папку для caldera
mkdir -p /home/vagrant/caldera
chown vagrant:vagrant /home/vagrant/caldera

# Простейший docker-compose для Caldera (placeholder)
cat > /home/vagrant/caldera/docker-compose.yml <<'EOF'
version: '3.7'
services:
  caldera:
    image: mitre/caldera:4.0.0
    ports:
      - "8888:8888"
    volumes:
      - ./data:/data
EOF

# Запускаем Caldera (может требовать дополнительные настройки)
cd /home/vagrant/caldera
docker-compose up -d || true
