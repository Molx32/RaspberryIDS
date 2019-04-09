#!/bin/sh
echo "ADRESS, PORT, STATUS, SERVICE, VERSION, CVE, IMPACT" > ./data/cve.csv
sudo nmap --script nmap-vulners -sV  $1 | awk '{if($1 ~ /^[0-9]{1}/) {print ","$1","$2","$3","$4",,"} else if($2 ~ /^CVE/) print ",,,,,"$2","$3 ; else if($0 ~ /^Nmap scan report/) print $6}' >> ./data/cve.csv
