#!/bin/bash

conditions(){
	if [ -f spider_urls.txt ];then
		return false
	fi
	return true
}

if ! conditions; then
	exit $(false)
fi

#TODO generate the url from path information
#TODO get_url | katana | anew spider_urls.txt | anew urls.txt
