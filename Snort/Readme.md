## Snort configuration file
This section describes the configuration file snort.conf

When installing snort, we don't get rule files, so I commented them, and added two alerts that describe DoS attack and FTP 
anonymous login attempt:

*alert tcp any any -> $HOME_NET any (msg:"TCP SYN FLOODING ATTACK DETECTED"; flags:S; threshold: type threshold, track by_dst, count 10, seconds 30; sid: 5000001; rev:1;)*

*alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"POLICY-OTHER FTP anonymous login attempt"; flow:to_server,established; content:"USER"; fast_pattern:only; pcre:"/^USER\s+(anonymous|ftp)[^\w]*[\r\n]/smi"; metadata:ruleset community, service ftp; classtype:misc-activity; sid:553; rev:13;)*

We also need the result to be in CSV format, and we also want to know the name of the alert, the date, source and destination
IP address, Mac address and port.

To do so, we added the following line:

*output alert_csv:/var/log/alert.csv msg,timestamp,dst,src,ethdst,ethsrc,dstport,srcport*

As for the rules, we also included community rules provided by Snort, for that to work, the file community.rules should be placed in the same location as snort.conf

## Integrating Snort to the Web interface
###### Changing the file header.py
This section describes the changes done in the file header.py

We add the following line to add "Alerts" tab:
```
dcc.Link('Alerts   ', href='/RaspberryPiReport/alerts', className="tab")
```

###### Changing the file webServer.py
This section describes the changes done in the file webServer.py

We specify the location of the CSV Snort alerts file, and create a variable that will read the file:
```
INPUT_SCAN_alerts = '/var/log/alert.csv'
DATA_TABLE_alerts = pd.read_csv(INPUT_SCAN_alerts, sep=',')
```

We create the layout for the page that will contain the alerts:
```
page_alerts = html.Div([
	  ...
    ...
    ], className="page"),

```

We add the page Alert in the function display_page(pathname)
```
...
elif pathname == '/alerts' or pathname == '/RaspberryPiReport/alerts':
    	return page_alerts
...
```
We add a callback to refresh the page, and finally we specify in the main() function that we will run the Snort command:
```
subprocess.Popen(["snort", "-dev", "-l", "/home/pi/SNORT_LOG_FILE","-c", "/home/pi/SNORT/snort-2.9.12/etc/snort.conf", "-i", "eth0"])
```
There are things to take into consideration:
- Logging file here is /home/pi/SNORT_LOG_FILE
- Configuration file is located in /home/pi/SNORT/snort-2.9.12/etc/snort.conf
- The interface that we are monitoring is eth0
