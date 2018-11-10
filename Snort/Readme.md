This file describes the configuration file snort.conf

When installing snort, we don't get rule files, so I commented them, and added two alerts that describe DoS attack and FTP 
anonymous login attempt:

*alert tcp any any -> $HOME_NET any (msg:"TCP SYN FLOODING ATTACK DETECTED"; flags:S; threshold: type threshold, track by_dst, count 10, seconds 30; sid: 5000001; rev:1;)*

*alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"POLICY-OTHER FTP anonymous login attempt"; flow:to_server,established; content:"USER"; fast_pattern:only; pcre:"/^USER\s+(anonymous|ftp)[^\w]*[\r\n]/smi"; metadata:ruleset community, service ftp; classtype:misc-activity; sid:553; rev:13;)*

We also need the result to be in CSV format, and we also want to know the name of the alert, the date, source and destination
IP address, Mac address and port.

To do so, we added the following line:

*output alert_csv:/var/log/alert.csv msg,timestamp,dst,src,ethdst,ethsrc,dstport,srcport*
