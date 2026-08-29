#!/bin/bash
# Ubuntu 22.04 LTS

sudo apt update
sudo apt install -y git curl wget net-tools python3-pip build-essential
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo apt install -y mininet openvswitch-switch openvswitch-testcontroller
sudo systemctl stop openvswitch-testcontroller
sudo systemctl disable openvswitch-testcontroller

# Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER

# ONOS
docker pull onosproject/onos:latest
docker run -d --name onos \
  -p 8181:8181 -p 8101:8101 -p 6653:6653 -p 6640:6640 \
  onosproject/onos:latest

# ---  ONOS console (ssh -p 8101 karaf@localhost, lozinka: karaf) ---
# app activate org.onosproject.openflow
# app activate org.onosproject.fwd
# app activate org.onosproject.gui2
# cfg set org.onosproject.fwd.ReactiveForwarding matchIpv4Address true
sudo apt install -y iperf3 hping3