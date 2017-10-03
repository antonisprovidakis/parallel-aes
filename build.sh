#!/bin/sh

cd ~/Desktop/parallel-aes/energymon-master/

rm -rf _build && mkdir _build
cd _build
cmake .. -DDEFAULT=odroid-ioctl
make
sudo make install

cd ../../
make clean
make

cd aescrypt
cp aescrypt ./test

