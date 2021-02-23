#!/bin/bash

# Check if the container name is given
if [[ $# -eq 0 ]] ; then
  echo '[ERROR]: Give as argument the container name.'
  exit 0
fi

# Capturing
for number in {0..1..1}
do
  sudo timeout 100 tcpdump -i $1  src 172.18.0.8 -w ./pcap_test/${number}.pcap 
done

# Feature extraction
python extract_features.py --type test

# Testing
python test.py
