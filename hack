#!/bin/bash

hostname="$1"

if [ -z "$1" ]
then
	echo "No argument specified, exiting..."
	exit
#	cat /root/targets/tool_logs/wildcards.txt /root/targets/tool_logs/domains.txt | shuf | head -n 1
#	hostname=$(random_target)
#	echo Using random target: $hostname
fi

hack_api(){
	echo "TODO hacking api stuff."
#enumerate APIs
#	documentation
#       if /users/1/edit exists, does /orders/1/edit exist?

#rest api endpoint wordlists
#ffuf -w common-methods.txt -u https://$hostname/FUZZ

#introspection for graphql, list all queries types
#echo "{ __schema { types { name } } }" | graphql_url
#for everything it returns, look for sensitive data

#aquire api keys (can we grep the gau output for them?)
#fuzz the endpoint a little, make sure the parser isn't borked.
#while true; do curl endpoint_url -H $(echo $content | radamsa) | anew out ;done

#api version checking
#if echo url | grep -oP "v-?[0-9]+[^\/]*" ; then #test old domain# ;fi

#IDORS
#       for each endpoint
#               remove cookies, does it still work
#               lower permissions cookies, does it still work?
#information disclosure
#juicy

#auth issues, web app requires auth but api doesnt
#       token generation
#buisness logic
#       make numbers large and small, and negative, 0
#       try to skip steps.
#XSS
#       check reflected inputs
#CSRF
#       look for csrf tokens
#sql injections
#race conditions
#memory leaks
}

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
	#@renniepak
	cat js/* | grep -oh "\"\/[a-zA-Z0-9_/?=&]*\"" | sed -e 's/^"//' -e 's/"$//' | sort -u > js_endpoints.out
	cat urls.txt | sort -u | shuf | head -n 100 | wget --wait=1 --random-wait -i /dev/stdin -P url_sample/
	if cat curl.out| jq -e . >/dev/null 2>&1 ; then
		hack_api
	fi
	sha1sum url_sample/* | tee url_sample_hashes.txt | head -n 10
}

hack_rpcbind(){
	rpcinfo -p $hostname
	echo "look into nmap -Sv stuff to put here."
}

hack_executable(){
	#zzuf and radamsa
	#compile with afl-fuzz
	#change input to stdin (preeny)
	#capture relevant inputs/packets
	tcpdump port $PORT_TO_SCAN -w out.pcap
	tcpdump -r out.pcap -x -c 1 2>/dev/null | grep -v "$(hostname)"  | sed "s/0x.*://g" | tr -d '[:space:]' | xxd -r -p > sample.raw
}

google_dorks(){
	echo TODO;
	#site: wikipedia.org
	#allintext:username filetype:log
	#inurl:/proc/self/cwd
	#intitle:index.of id_rsa -id_rsa.pub
	#inurl:top.htm inurl:currenttime
	#inurl:zoom.us/j and intext:scheduled for
	#"index of" "database.sql.zip"
	#intitle:"Index of" wp-admin
	#inurl:Dashboard.jspa intext:"Atlassian Jira Project Management Software"
	# inurl:app/kibana intext:Loading Kibana
	#"google (dorks OR dorking OR hacking)" AND (discussed OR tutorial OR overview).
}

hack_domain(){
	domain="$1"
	mkdir $domain
	cd $domain
	nmap $hostname | tee nmap.out | anew /root/targets/tool_logs/nmap_portlist.out

	if cat nmap.out | grep "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn" > /dev/null;
	then
		echo "Host appears down, so we're just going to exit."
		rm nmap.out
		cd ..;
		rmdir $hostname
	fi

	#certifications
	curl -s "https://crt.sh/?q=$hostname" | sed "s/<\/\?[^>]\+>//g" | grep $hostname > cert_sh.out

	if cat nmap.out | grep "80/tcp" | grep "open" > /dev/null; then hack_http ; fi
	if cat nmap.out | grep "443/tcp" | grep "open" > /dev/null; then hack_https ; fi
	if cat nmap.out | grep "111/tcp" | grep "open" | grep "rpcbind" > /dev/null; then hack_rpcbind ; fi
}

hack_company(){
	cat ~/targets/tool_logs/domains.txt  | grep -o "[^\.]*\.[a-zA-Z]*$" | sort -u | shuf | head -n 1 # get a random company
	echo TODO;
	mkdir $company_name
	cd $company_name
	#get scope
	#if scope has wildcard
	#	get more sub domains
	#check google dorks

	whois $company_name > whois.out
	#for each domain
		#hack_domain $domain

	#for each executable
	#	hack_executable

	#check companies github repo
	#docker run -it abhartiya/tools_gitallsecrets -token="$(cat /root/keys/github_pac.txt)" -org=$hostname

	#check all data for secrets
	juicy
}

while getopts "hc:" arg; do
	case ${arg} in
		h)
			echo "usage: hack <domain>"
			exit
			;;
		c)
			echo "hacking company $OPTARG"
			company_name="$OPTARG"
			;;
		:)
			echo "hacking $1"
			hostname=$1
			;;
		?)
			echo "invalid option $OPTARG"
			;;
		*)
			echo "default $OPTARG"
			;;
	esac
done

shift $(($OPTIND-1))
hostname="$1"
echo hostname $hostname
