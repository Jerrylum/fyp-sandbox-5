#!/bin/bash

# Sandbox
# cd build && make && ./mysandbox

# Deploy 
cd build
make
sleep 1
cp libkeyfobpam.so /lib/security
cp keyfob /usr/bin

# nano /etc/pam.d/common-auth
# auth required libkeyfobpam.so debug
