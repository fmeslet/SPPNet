#!/usr/bin/python3.5
#-*-coding:utf-8 -*-
'''
Created on 28 aout 2020

@author: Fabien Meslet-Millet
'''

from scapy.all import sniff, DNS, Ether
from scapy.layers.dns import DNSRR, DNS, DNSQR

from threading import Thread, Lock

import warnings
warnings.filterwarnings("ignore")

class ThreadDnsCapture(Thread):
    """
    Class for capturing DNS packet.
    """

    def __init__(self):
        """
        Constuctor.
        """
        Thread.__init__(self)
        self.dict_dns = {}

    def run(self):
        """
        Start Thread.
        """
        # Get answer DNS
        while(True):
            # For printing packet captured : prn=lambda p: p.summary()
            packet = sniff(count=1,filter="udp src port 53", prn=None)[0]
    
            if(type(packet) != None):
                for i in range(packet['DNS'].qdcount):
                    if(packet['DNS']['DNS Question Record'][i].qtype == 1):
                        dns = packet['DNS']['DNS Question Record'][i].qname.decode("utf-8")
                        
                for i in range(packet['DNS'].ancount):
                    record = packet['DNS']['DNS Resource Record'][i].type
                    if((record == 1) or (record == 28)):
                        addr = packet['DNS']['DNS Resource Record'][i].rdata
                        self.dict_dns[addr] = dns

    def get_nameserver(self, ip_src, ip_dst):
        """Get DNS server name associated with IP source and IP destination.

        Args:
            ip_src (str): IP source.
            ip_dst (str): IP destination.

        Returns:
            str: DNS server name associated with IPs.
        """
        try:
            return self.dict_dns[ip_src]
        except:
            try:
                return self.dict_dns[ip_dst]
            except:
                return None
            
            