#!/bin/bash

hostname="$1"

if [ -z "$1" ] 
then 
#	cat /root/targets/tool_logs/wildcards.txt /root/targets/tool_logs/domains.txt | shuf | head -n 1
	hostname=$(random_target)
	echo Using random target: $hostname
fi

hack_http(){
	echo "hacking http"
	whatweb --color=never $hostname >> whatweb.out
	if cat whatweb.out | grep "RedirectLocation\[https" 
	then 
		return
	else 
		echo "HTTP not redirecting."
	fi
}

hack_https(){
	echo "hacking https"
	whatweb --color=never "https://$hostname" >> whatweb.out

	curl -sv "https://$hostname/" -o curl.out > /dev/null 2> curl_err.out
	echo $hostname | gau > gau.out
	gospider -q -s "https://$hostname" > gospider.out
	cd /root/src/hackerone_reports; gf urls | grep -f $hostname >> h1reports.txt ; cd - > /dev/null
#	dirb "https://$hostname" -o dirbs.out
	gf urls | grep $hostname | sort -u >> urls.txt
	cat urls.txt | sort -u | sponge urls.txt
	rm dirbs.out gau.out gospider.out h1reports.txt ; wc -l urls.txt
	cat urls.txt | sort -u | shuf | head -n 100 | nuclei -l /dev/stdin -t /root/nuclei-templates/vulnerabilities/generic/ -o nuclei_vulns.txt
	cat urls.txt | grep "\.js$" | wget --wait=1 --random-wait -i /dev/stdin -P js/
}

hack_rpcbind(){
	rpcinfo -p $hostname
	echo "look into nmap -Sv stuff to put here."
}

mkdir $hostname
cd $hostname

nmap $hostname | tee nmap.out

if cat nmap.out | grep "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn" > /dev/null;
then 
	echo "Host appears down, so we're just going to exit."
	rm nmap.out
	cd ..; 
	rmdir $hostname
fi

if cat nmap.out | grep "80/tcp" | grep "open" > /dev/null; then hack_http ; fi
if cat nmap.out | grep "443/tcp" | grep "open" > /dev/null; then hack_https ; fi
if cat nmap.out | grep "111/tcp" | grep "open" | grep "rpcbind" > /dev/null; then hack_rpcbind ; fi

