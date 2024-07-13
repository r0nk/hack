#!/bin/bash

conditions(){
	if [ ! -d searchsploit ];then
		return false
	fi
	if [ ! -f version.txt ];then
		return false
	fi
	return true
}

if ! conditions; then
	exit $(false)
fi

searchsploit $(cat version.txt) -j > searchsploit.json

mkdir searchsploit
cd searchsploit
cat ../searchsploit.json | jq '."RESULTS_EXPLOIT"[].["EDB-ID"]' -r | xargs mkdir
cd -
