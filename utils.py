from scan import Scanner
# Used to handle SIGINT signal

# Imports
import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_table_experiments as dt


import time
import subprocess
import signal
import sys
import re
import pandas as pd

# Function called when SIGINT is received i.e. when Ctrl + C is pressed
# It stops apache2 server
def signal_handler(sig, frame):
    print('\nStopping apache2...')
    subprocess.check_call("systemctl stop apache2".split())
    sys.exit(0)

# Function called to run a scan on a specific IP or IP range
def scan(ip):
    scanner = Scanner()
    scanner.start_scan(ip)

def snif():
	tshark_command = ''
	subprocess.check_call("systemctl stop apache2".split())

# Function to check whether the IP is valid or not
def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False

# thark -i wlan0 -T fields -e eth.src -e eth.dst -e ip.src -e ip.dst -e _ws.col.Protocol -E header=y -E separator=, -E quote=d -E occurrence=f > data/summ.csv
CSV_SUMMARY_PROTO_COL = '_ws.col.Protocol'
protocol_map = {}
def read_protocol_csv(csv):
	proto_col = pd.read_csv(csv, sep=',', usecols=[CSV_SUMMARY_PROTO_COL])
	for line in proto_col['_ws.col.Protocol']:
		# If proto not in list, add it
		if not line in protocol_map:
			protocol_map[line] = 1
		else:
			protocol_map[line] = protocol_map[line] + 1
	return protocol_map


# Renvoie les encadres du SUMMARY
# CSS dans main.css
def indicator(color, text, id_value):
    return html.Div(
        [
            
            html.P(
                text,
                className="twelve columns indicator_text"
            ),
            html.P(
                id = id_value,
                className="indicator_value"
            ),
        ],
        className="four columns indicator",
        
)


def get_bytes(t, iface='wlan0'):
    with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
        data = f.read();
        return int(data)

def tshark():
	command='tshark -i wlan0 -T fields -e eth.src -e eth.dst -e ip.src -e ip.dst -e _ws.col.Protocol -E header=y -E separator=, -E quote=d -E occurrence=f'
	with open('data/summ2.csv', "w") as outfile:
		subprocess.check_call(command.split(), stdout=outfile)