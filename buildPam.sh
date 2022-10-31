#!/bin/bash

gcc -fPIC -fno-stack-protector -c src/mypam.c
gcc -fPIC -fno-stack-protector -c src/aes.c
gcc -fPIC -fno-stack-protector -c src/sha3.c

sudo ld -x --shared -o /lib/security/mypam.so mypam.o aes.o sha3.o
# sudo ld -x --shared -o mypam.so mypam.o sha3.o

rm *.o
