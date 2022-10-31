#!/bin/bash

gcc -o mypam src/myapp.c src/aes.c src/sha3.c -lpam -lpam_misc
