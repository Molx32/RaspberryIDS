from scan import Scanner
# Used to handle SIGINT signal
import subprocess
import signal
import sys
import re

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

# Function to check whether the IP is valid or not
def valid_ip(address):
    try:
        host_bytes = address.split('.')
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if b >= 0 and b<=255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False