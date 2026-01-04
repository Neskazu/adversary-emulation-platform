#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y install filebeat osquery auditd curl net-tools

# filebeat config will be managed by Ansible later; for now placeholder
mkdir -p /etc/filebeat
echo "# configure filebeat via ansible" > /etc/filebeat/filebeat.yml
