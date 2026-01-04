#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y install samba krb5-user winbind smbclient

# Простейшая подготовка папок (для учебного полигона)
mkdir -p /srv/samba
chown nobody:nogroup /srv/samba

# Настройка Samba AD сильно зависит от задачи; здесь просто placeholder
echo "Samba AD setup placeholder - recommend running full Ansible playbook for samba AD"
