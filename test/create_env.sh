#!/bin/bash

if [ `id -u` -eq 0 ]
then
echo "execute this script as an unprivileged user"
exit 1
fi

if [ -L /tmp/log ]
then
if [ -d /tmp/log2 ]
then
	unlink /tmp/log
	mv /tmp/log2 /tmp/log
fi	
fi

test -d /tmp/log || mkdir /tmp/log
dd if=/dev/urandom of=pwnme.log bs=1 count=200000
cp pwnme.log /tmp/log/
cp pwnme.log /tmp/log/pwnme.log.13
cp pwnme.log /tmp/log/pwnme.log.12
cp pwnme.log /tmp/log/pwnme.log.11
cp pwnme.log /tmp/log/pwnme.log.10
cp pwnme.log /tmp/log/pwnme.log.9
cp pwnme.log /tmp/log/pwnme.log.8
cp pwnme.log /tmp/log/pwnme.log.7
cp pwnme.log /tmp/log/pwnme.log.6
cp pwnme.log /tmp/log/pwnme.log.5
cp pwnme.log /tmp/log/pwnme.log.4
cp pwnme.log /tmp/log/pwnme.log.3
cp pwnme.log /tmp/log/pwnme.log.2
cp pwnme.log /tmp/log/pwnme.log.1
cp pwnme.log /tmp/log/pwnme.log.0

echo "now execute as root: \"chgrp root /tmp/log\""
