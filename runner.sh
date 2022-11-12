#!/bin/sh
cd /home/kali/dev/bash/recon-project/
file='targets.txt'
while read -r line
do
    sh -x recon.sh $line
done < $file
