#!/usr/bin/env -S just --working-directory . --justfile


default:
	@just --list --list-heading '' --list-prefix ''

#update this script
update:
	curl -s https://raw.githubusercontent.com/r0nk/hack/master/hack | sudo tee /usr/bin/hack | wc -l

#TODO make this also create directories for each port found
nmap:
	nmap -v -sV -sC -p- $(pwd | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}") -oA nmap_full
	nmap -v -su -p- $(pwd | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}") -oA nmap_udp
#	echo "NMAP DONE" | espeak

#Get the target ip address from the current directory
ip:
	@echo {{invocation_dir()}} | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}"

hostsfix:
	curl -v $(pwd | gip) 2>&1 | grep Location: | choose 2 | unfurl domains | anew domains.txt
	echo $(pwd | gip) $(head -n 1 domains.txt) | sudo tee -a /etc/hosts

path_fuzz:
	echo $(pwd | gip) | katana | anew spider_urls | anew urls.txt
	ffuf -u http://$(pwd | gip)/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -recursion -od ffufo -ac

subdomain_fuzz:
	ffuf -u http://$(pwd | gip) -h "Host: FUZZ.$(head -n 1 domains.txt)" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -od ffufo -ac

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