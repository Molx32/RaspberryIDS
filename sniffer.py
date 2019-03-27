import sys
import os

import nmap
import time
import threading
from scapy.all import *

# Processes libraries
from multiprocessing import Process
from multiprocessing.managers import BaseManager

import time
import subprocess

class Sniffer(object):
    # in_int:
    #        interface from inside network to external network
    # out_int:
    #        interface from external network to internal network
    def __init__(self, in_int, out_int):
        # Process ID
        self.pid = -1

        # Interfaces which send/rcv packets
        self.in_int = in_int
        self.out_int = out_int

        # Protocols to match
        self.ProtoList = {}
        self.ProtoList[DNS] = "DNS"
        self.ProtoList[SNMP] = "SNMP"
        self.ProtoList[TFTP] = "TFTP"
        self.ProtoList[DHCP] = "DHCP"
        self.ProtoList[RIP] = "RIP"
        self.ProtoList[RTP] = "RTP"
        # Packets per protocol
        self.PROTO_MAP = {}
        
        # Total of received packets
        self.pkt_total = 0

        # Layer 4
        self.pkt_udp = 0
        self.pkt_tcp = 0

    # Analyse packets i.e. produce stats
    def analyzePacket(self, pkt):
        self.incPkt()
        for proto in self.ProtoList.keys():
            if pkt.haslayer(proto):
                sProto = self.ProtoList[proto]
                if not sProto in self.PROTO_MAP:
                    self.PROTO_MAP[sProto] = 1
                else:
                    self.PROTO_MAP[sProto] += 1

    # Sniff packets until process is killed
    def sniff(self):
        sniff(count=0, iface=self.out_int, prn=self.analyzePacket, store=0)



    # Getters for protocols map
    def getProtoMap(self):
        return self.PROTO_MAP
    def getProtoKeys(self):
        return self.PROTO_MAP.keys()
    def getProtoVals(self):
        return self.PROTO_MAP.values()

    # Handle packet number
    def getPkt(self):
        return self.pkt_total
    def incPkt(self):
        self.pkt_total = self.pkt_total + 1

    # Handle reset
    def reset(self):
        self.pkt_total = 0
        self.PROTO_MAP = {}
        self.pkt_udp = 0
        self.pkt_tcp = 0

    # PID
    def getPID(self):
        return self.PID
    def setPID(self, pid):
        self.PID = pid

def runSniffer(obj):
    obj.sniff()