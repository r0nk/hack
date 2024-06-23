#!/bin/bash

function valid_ip()
{
    local  IPA1=$1
    local  stat=1

    if [[ $IPA1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];
    then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS

        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
           && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

if valid_ip $(basename $(pwd)); then
	mkdir -F tcp udp
fi