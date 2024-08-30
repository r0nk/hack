#!/usr/bin/env -S just --working-directory . --justfile

default:
	@just --list --list-heading '' --list-prefix ''

#update this script
update:
	curl -s https://raw.githubusercontent.com/r0nk/hack/master/hack | sudo tee /usr/bin/hack | wc -l

nmap:
	nmap -v -sV -sC -p- $(pwd | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}") -oA nmap_full
#	nmap -v -sU -p- $(pwd | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}") -oA nmap_udp

#Get the target ip address from the current directory
ip:
	@echo {{invocation_dir()}} | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}"

#Get the domain from the current directory
domain:
	@pwd | tr '/' '\n' | grep "\." | head -n 1

robots:
	curl -L -v $(hack domain)/robots.txt -o robots.txt

hostsfix:
	curl -v $(hack ip) 2>&1 | grep Location: | choose 2 | unfurl domains | anew domains.txt
	echo $(hack ip) $(head -n 1 domains.txt) | sudo tee -a /etc/hosts

http:
	echo $(hack domain) | katana | anew spider_urls | anew urls.txt
	curl -L -s $(hack domain)/robots.txt -o robots.txt
	echo $(hack domain) | dnsx -asn  -a -recon -resp > dnsx.txt
	echo "fuzz 5" | anew todo.txt

wl:
	@find /usr/share/seclists/ -type f | fzf

path_fuzz:
	ffuf -u http://$(hack ip)/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -recursion -od ffufo -ac

path_fuzz_slow:
	ffuf -u http://$(hack domain)/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -recursion -od ffufo -ac -t 1 -p 0.1-0.3

subdomain_fuzz:
	ffuf -u http://$(hack ip) -h "Host: FUZZ.$(head -n 1 domains.txt)" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -od ffufo -ac

rev port:
	ip addr | grep inet | sort
	rlwrap -cAr nc -lvnp {{port}}

#start a http server for the current directory
hs port:
	python3 -m http.server {{port}}

sqliraw:
	sqlmap -r raw.http --risk 3 --level 5

ldap:
	nmap -sV --script "ldap* and not brute" -p 389 $(pwd | gip)
	ldapsearch -H ldap://$(pwd | gip)

smb:
	enum4linux -a $(pwd | gip) | tee enum4linux.txt
	enum4linux -u "guest" -p "" $(pwd | gip) | tee enum4linux.guest.txt
	enum4linux -u "" -p "" $(pwd | gip) | tee enum4linux.empty.txt

hashes:
	echo "check_crackstation	10" | anew todo.txt
	echo "hashcat/rockyou		30" | anew todo.txt
	echo "john/rockyou	30" | anew todo.txt

shadowcrack:
	cat shadow | tr ':' ' ' | awk '{print $2}' | grep "\\$" | anew hashes.txt
	hashcat hashes.txt

dns_scope:
        cat domains.txt | dnsx -a -resp > dnsx.txt
        cat dnsx.txt | awk '{print $2}' | tr -d '[' | tr -d ']' | sort | uniq -c | sort -n  > ip_sus.txt
        cat ip_sus.txt | awk '{print $2}' | anew ips.txt

naabu:
        cat ips.txt | naabu | anew naabu.txt
        cat naabu.txt  | tr ':' ' ' | awk '{print $2}' | sort | uniq -c | sort -rn > naabu_sus.txt

httpx_full:
	httpx -l domains.txt -cdn -sc -cl -location -title -bp -ip -o httpx_full.txt

add_http_todo:
	cat httpx_full.txt | choose 0 | unfurl domains | awk '{print $1,10}' |  anew todo.txt

length_sorted_tasks:
	omira task | choose 1 | awk '{print length(), $0 | "sort -n"}' | choose 1
