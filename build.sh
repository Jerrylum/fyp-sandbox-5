#!/bin/bash

cd build
make
sleep 1
cp libkeyfobpam.so /lib/security
cp keyfob /usr/bin
