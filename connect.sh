#!/bin/bash

sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo ip link set tap0 up
sudo ip addr add fd00:abcd::1/64 dev tap0
sudo ip route add fd00:abcd::/64 dev tap0
while ! ping6 -c 1 -W 1 fd00:abcd::2; do
    echo "Waiting for fd00:abcd::2 - network interface might be down..."
    sleep 1
done
ssh-keygen -R fd00:abcd::2
ssh -o StrictHostKeyChecking=no root@fd00:abcd::2
