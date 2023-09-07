#!/bin/bash

title_card(){
	tput setaf 2
	echo "
 ██░ ██  ▄▄▄       ▄████▄   ██ ▄█▀
▓██░ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒
▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░
░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄
░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
 ▒ ░░▒░▒ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
 ▒ ░▒░ ░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░
 ░  ░░ ░  ░   ▒   ░        ░ ░░ ░
 ░  ░  ░      ░  ░░ ░      ░  ░   "
	echo "version 0.1"
	tput sgr0
}

title_card

usage() {
	echo "USAGE (really just all the functions in the file:"
	echo ""
	whereis $0 | awk '{print $2}' | xargs cat | grep "()" | grep "{" | sed "s/()//g" | tr -d '{'
	exit 1;
}

while getopts ":i:d:" opts; do
	case $opts in
		(i)
			echo $OPTARG | anew ip.txt
			;;
		(d)
			echo $OPTARG | anew domains.txt
			;;
		(:)
			echo "Missing value."
			usage
			;;
		(*)
			usage
			;;
		(?)
			echo "Unsupported option."
			usage
			;;
	esac
done
shift $((OPTIND-1))

recon(){
	cat ip.txt domains.txt | naabu | anew naabu.txt | httpx | anew httpx.txt | katana | anew urls.txt
	nmap -sC -sV $(cat ip.txt) > nmap.txt
}

#TODO see if we can FIFO this instead
revs(){
	port=$1

	if [ -z "$port" ]; then
		port="1337"
	fi

	#firefox "https://www.revshells.com" &
	ip addr | grep inet | grep 10 # for ctf vpns
	curl ifconfig.io

	echo "waiting for reverse shell on port $port"
	rlwrap ncat -lvp $port
}

echo "Running $@"
$@

#TODO fuff setup
#cat ffuf.json  | jq -r ".results[].url" | anew urls.txt

#TODO
#inotify daemon that can automatically feed recon pipeline

#TODO
#todo.txt intergration
