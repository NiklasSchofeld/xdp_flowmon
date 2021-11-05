#!/bin/bash
#use ubuntu 16.04 LTS

wkdir=$(pwd)
cd ~


#netmap dependencies
apt-get update
apt -y install build-essential
apt-get install -y git
apt-get install -y linux-headers-$(uname -r)

#tcpreplay dependencies
apt-get install -y build-essential libpcap-dev

#traffic generator script dependency
add-apt-repository ppa:deadsnakes/ppa
apt-get update
apt-get install -y python3.9 python3-pip

#downlaod netmap
git clone https://github.com/luigirizzo/netmap.git
#download tcpreplay
wget https://github.com/appneta/tcpreplay/releases/download/v4.3.4/tcpreplay-4.3.4.tar.xz


#install netmap - needs internet
cd ~/netmap/LINUX
./configure
make
make apps
make install
insmod netmap.ko


#install tcpreplay
cd ~/
tar xf tcpreplay-4.3.4.tar.xz
rm -r tcpreplay-4.3.4.tar.xz
mv tcpreplay-4.3.4/ tcpreplay
cd tcpreplay/
./configure --with-netmap=/root/netmap
make
make install
make test


#reconfigure network interfaces
echo "\n\nEverything may be installed. Network configuration will change now and you lose internet connection.\nChange Network type in Dashboard\nPress ctr + c to stop"
sleep 10
ip link set dev bond0 down
ip link set dev enp65s0f0 down
ip link set dev enp65s0f1 down
cp $wkdir/interfaces /etc/network/interfaces
systemctl restart networking.service

$wkdir/change_modules.sh