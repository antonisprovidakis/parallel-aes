#!/bin/sh

# build energymon
cd energymon-master

rm -rf _build && mkdir _build
cd _build
cmake .. -DDEFAULT=odroid-ioctl
make
sudo make install
cd ../../

# build everything else (libaes, aescrypt)
make clean
make

# move into "aescypt" folder and create "test" folder
cd aescrypt 
rm -rf test && mkdir test
cp aescrypt ./test
