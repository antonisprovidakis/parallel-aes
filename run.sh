#!/bin/sh

cd ~/Desktop/parallel-aes-mod/aescrypt/test

#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i file200.zip -t 4 -p 2097152
./aescrypt -k 000102030405060708090a0b0c0d0e0f -i file512.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i file2048.zip -t 4 -p 2097152
