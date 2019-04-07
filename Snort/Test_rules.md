- Some of the rules belong to the Snort community rules, that can be found here: https://www.snort.org/downloads/community/community-rules.tar.gz

### Alert1 : TCP SYN Flooding 
##### Overview of the alert
*alert tcp any any -> $HOME_NET any (msg:"TCP SYN FLOODING ATTACK DETECTED"; flags:S; threshold: type threshold, track by_dst, count 10, seconds 30; sid: 5000001; rev:1;)*

##### Testing of the alert
Use hping3 command against the host: (https://securityonline.info/syn-flood-attack-using-hping3/)
Example : *hping3 -i u1 -S -p 80 192.168.56.101*

##### Output of Snort triggering
"TCP SYN FLOODING ATTACK DETECTED",01/05-00:45:58.305844,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,80,1080


### Alert2 : INDICATOR-SCAN UPnP service discover
##### Overview of the alert
*alert udp $EXTERNAL_NET any -> $HOME_NET 1900 (msg:"INDICATOR-SCAN UPnP service discover attempt"; flow:to_server; content:"M-SEARCH "; depth:9; content:"ssdp|3A|discover"; fast_pattern:only; metadata:policy max-detect-ips drop, ruleset community; classtype:network-scan; sid:1917; rev:15;)*

##### Testing of the alert
Use a service discovery utility like nmap (https://snort.org/rule_docs/1-1917)
Example: *Zenmap slow comprehensive scan*

##### Output of Snort triggering
"INDICATOR-SCAN UPnP service discover attempt",01/05-00:55:58.743587,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,1900,51289


### Alert3 : PROTOCOL-ICMP destination unreachable port
##### Overview of the alert
*alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"PROTOCOL-ICMP destination unreachable port unreachable packet detected"; icode:3; itype:3; metadata:policy max-detect-ips drop, ruleset community; reference:cve,2004-0790; reference:cve,2005-0068; classtype:misc-activity; sid:402; rev:16;)*

##### Testing of the alert
Use a service discovery utility like nmap or perform ICMP flood attack using Scapy or hping3 (https://snort.org/rule_docs/1-402)
Example: *Nmap scan OR ICMP flood attack utility*

##### Output of Snort triggering
"PROTOCOL-ICMP destination unreachable port unreachable packet detected",01/05-00:32:48.7455165,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,,


### Alert4 : Detection of Ping
##### Overview of the alert
*alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"PROTOCOL-ICMP PING"; icode:0; itype:8; metadata:ruleset community; classtype:misc-activity; sid:384; rev:8;)*

##### Testing of the alert
Perform ping on the host (https://snort.org/rule_docs/1-384)
Example: *Ping command*

##### Output of Snort triggering
"PROTOCOL-ICMP PING",01/05-00:12:45.486112,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,,


### Alert5 : Attempts to enumerate network interfaces through SNMP.
##### Overview of the alert
*alert tcp $EXTERNAL_NET any -> $HOME_NET 161 (msg:"PROTOCOL-SNMP request tcp"; flow:stateless; metadata:ruleset community, service snmp; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013; classtype:attempted-recon; sid:1418; rev:18;)*

##### Testing of the alert
Use Nmap NSE script snmp-interfaces (https://nmap.org/nsedoc/scripts/snmp-interfaces.html)
Example: *nmap -sU -p 161 --script=snmp-interfaces <target>*

##### Output of Snort triggering
"PROTOCOL-SNMP request tcp",01/05-00:53:12.456218,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,161,53


### Alert6 : PROTOCOL-SNMP AgentX/tcp request
##### Overview of the alert
*alert tcp $EXTERNAL_NET any -> $HOME_NET 705 (msg:"PROTOCOL-SNMP AgentX/tcp request"; flow:stateless; metadata:ruleset community, service snmp; reference:bugtraq,4088; reference:bugtraq,4089; reference:bugtraq,4132; reference:cve,2002-0012; reference:cve,2002-0013;classtype:attempted-recon; sid:1421; rev:18;)*

##### Testing of the alert
Misc: (AgentX: https://www.ietf.org/rfc/rfc2741.txt)
Use Nmap NSE script snmp-interfaces (https://nmap.org/nsedoc/scripts/snmp-interfaces.html)
Example: *nmap -sU -p 161 --script=snmp-interfaces <target>*

##### Output of Snort triggering
"PROTOCOL-SNMP AgentX/tcp request",01/05-00:55:58.743587,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,705,53


### Alert7 : X11 xdmcp info query
##### Overview of the alert
*alert udp $EXTERNAL_NET any -> $HOME_NET 177 (msg:"X11 xdmcp info query"; flow:to_server; content:"|00 01 00 02 00 01 00|"; fast_pattern:only; metadata:ruleset community; reference:nessus,10891; classtype:attempted-recon; sid:1867; rev:6;)*

##### Testing of the alert
Misc: (XDMCP: https://www.x.org/releases/X11R7.6/doc/libXdmcp/xdmcp.html)
Use Nmap NSE script xdmcp-discover (https://nmap.org/nsedoc/scripts/xdmcp-discover.html)
Example: *nmap -sU -p 177 --script xdmcp-discover <ip>*

##### Output of Snort triggering
"X11 xdmcp info query",01/05-00:13:38.122345,192.168.56.101,192.168.56.1,01:02:03:1F:F2:F3,0A:00:23:00:00:00,177,53

