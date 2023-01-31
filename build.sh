#!/bin/bash

# Sandbox
# cd build && make && ./mysandbox

# Deploy 
cd build && make && sudo cp libmypam.so /lib/security && echo installed

# auth required libmypam.so debug