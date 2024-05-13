#!/bin/bash

countdown(){
	date1=$((`date +%s` + $1));
	message="$2"
	while [ "$date1" -ge `date +%s` ]; do
## Is this more than 24h away?
		hours=$(($(($(( $date1 - $(date +%s))) * 1 ))/3600))
		echo -ne "$hours:$(date -u --date @$(($date1 - `date +%s`)) +%M:%S)	$message              \r";
		sleep 0.1
	done
	echo "$message                           "
	echo -en "\007"
}

countdown $((60*60)) "USER"
countdown $((60*60)) "ROOT"
countdown $((60*60)) "REPORT"
