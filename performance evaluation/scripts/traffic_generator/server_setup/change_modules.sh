#!/bin/bash
#change modules

ip link set dev enp65s0f0 down
ip link set dev enp65s0f1 down

rmmod i40e
insmod ~/netmap/LINUX/i40e/i40e.ko

ip link set dev enp65s0f0 up
ip link set dev enp65s0f1 up
