#!/bin/sh

cd ~/Desktop/parallel-aes/aescrypt/test

#rm -rf stats
rm  stats.log


####### 20 MB file #######
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 20MB.zip -t 1 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 20MB.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 20MB.zip -t 4 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 20MB.zip -t 8 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 20MB.zip -t 16 -p 2097152


####### 50 MB file #######
./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 50MB.zip -t 1 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 50MB.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 50MB.zip -t 4 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 50MB.zip -t 8 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 50MB.zip -t 16 -p 2097152


####### 100 MB file #######
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 100MB.zip -t 1 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 100MB.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 100MB.zip -t 4 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 100MB.zip -t 8 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 100MB.zip -t 16 -p 2097152


####### 200 MB file #######
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 200MB.zip -t 1 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 200MB.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 200MB.zip -t 4 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 200MB.zip -t 8 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 200MB.zip -t 16 -p 2097152


####### 512 MB file #######
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 512MB.zip -t 1 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 512MB.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 512MB.zip -t 4 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 512MB.zip -t 8 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 512MB.zip -t 16 -p 2097152


####### 1024 MB file #######
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 1024MB.zip -t 1 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 1024MB.zip -t 2 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 1024MB.zip -t 4 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 1024MB.zip -t 8 -p 2097152
#./aescrypt -k 000102030405060708090a0b0c0d0e0f -i 1024MB.zip -t 16 -p 2097152
