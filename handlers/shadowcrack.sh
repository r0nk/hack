#!/bin/bash

#TODO check if shadow exists
cat shadow | tr ':' ' ' | awk '{print $2}' | grep "\\$" > hashes.txt
hashcat hashes.txt
