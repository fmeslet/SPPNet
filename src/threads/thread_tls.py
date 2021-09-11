#!/usr/bin/python3.5
#-*-coding:utf-8 -*-
'''
Created on 28 aout 2020

@author: Fabien Meslet-Millet
'''

from threading import Thread, Lock
from scapy.all import sniff, TCP, UDP, Raw, Ether, IP, IPv6
from scapy_ssl_tls.ssl_tls import TLSRecord, TLSClientHello
from hashmap import HashMap

import warnings
warnings.filterwarnings("ignore")

class ThreadTlsCapture(Thread):
    """
    Class for capturing TLS handshake packet.
    """
    def __init__(self):
        Thread.__init__(self)
        self.hashmap = HashMap(num_keys=4, num_values=1)
        
        self.ip_src = None
        self.ip_dst = None
        self.port_src = None
        self.port_dst = None

    def run(self):
        """
        Start Thread.
        """
        while(True):
            # For printing packet captured : prn=lambda p: p.summary()
            packet = sniff(count=1,filter="tcp and port 443", prn=None)
            if(type(packet) != None):
                try:
                    server_name = TLSRecord(packet[0].load)[
                        "TLS Extension Servername Indication"]["TLS Servername"].data
                    
                    self.__extract_packet_informations(packet)
                    self.__set_to_hashmap(server_name)
                except:
                    pass 
                    
    def __extract_packet_information(self, packet):
        """Extract packet information.

        Args:
            packet (scapy.packet): Scapy packet.
        """
        if(self.packet.haslayer(IPv6)):
            self.ip_src = self.packet['IPv6'].src
            self.ip_dst = self.packet['IPv6'].dst
        elif(self.packet.haslayer(IP)):
            self.ip_src = self.packet['IP'].src
            self.ip_dst = self.packet['IP'].dst
            
        self.port_src = self.packet['TCP'].sport
        self.port_dst = self.packet['TCP'].dport
        
    def __set_to_hashmap(self, server_name):
        """Set to HashMap the servername associated with a trafic flow.

        Args:
            server_name (str): TLS server name to add to HashMap. 
        """
        keys = [self.ip_src, self.ip_dst, self.port_src, self.port_dst]
        self.hashmap.add_data(keys=keys, values=server_name)
                
    def get_nameserver(self, ip_src, ip_dst, port_src, port_dst):
        """Get TLS server name from flow parameters.

        Args:
            ip_src (str): IP source.
            ip_dst (str): IP destination.
            port_src (str): Port source.
            port_dst (str): Port destination.

        Returns:
            str: TLS server name associated with flow.
        """
        keys = [self.ip_src, self.ip_dst, self.port_src, self.port_dst]
        return self.__get_by_keys_reverse(keys=keys)
    
    def __get_by_keys_reverse(self, keys):
        """Get values from keys.

        Args:
            keys (list): Keys.

        Returns:
            str: TLS server name.
        """
        values_1 = self.hashmap.get_by_keys(keys=keys)
        values_2 = self.hashmap.get_by_keys(
            keys=[keys[1], keys[0], keys[3], keys[2]])
        
        if(values_1 is None):
            return values_2
        else:
            return values_1