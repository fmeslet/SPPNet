#!/usr/bin/python3.5
#-*-coding:utf-8 -*-
'''
Created on 28 aout 2020

@author: Fabien Meslet-Millet
'''

from scapy.all import sniff, TCP, UDP, Raw, load_layer, hex_bytes, IP, IPv6
from scapy.compat import bytes_encode
from threading import Thread, Lock
import numpy as np
import logging

import warnings
warnings.filterwarnings("ignore")

logger = logging.getLogger()

NAMESERVER_LENGTH = 6

class ThreadProcessing(Thread):
    """
    Class for data processing.
    """
    def __init__(self,
                 packet, 
                 thread_dns, 
                 thread_tls,
                 dict_nameserver,
                 dict_embedding_port,
                 dict_index_port,
                 dict_protocol,
                 value='int',
                 representation='1d'):
        """Constructor.

        Args:
            packet (scapy.packet): Packet captured by Scapy.
            thread_dns (threads.ThreadDNSCapture): Thread which capture DNS packets.
            thread_tls (threads.ThreadTLSCapture): Thread which capture TLS Handshake packets.
            dict_nameserver (dict): Dictonnary for nameserver and index mapping.
            dict_embedding_port (dict): Dictonnary for protocol name and index mapping.
            dict_index_port (dict): Dictonnary for port number and protocol name.
            dict_protocol (dict): Dictonnary for udp/tcp and value mapping.
            type (str, optional): [description]. Defaults to 'int'.
            format (str, optional): [description]. Defaults to '1d'.
        """
        Thread.__init__(self)
        self.packet = packet
        
        self.thread_dns = thread_dns
        self.thread_tls = thread_tls
        
        self.dict_nameserver = dict_nameserver
        self.dict_embedding_port = dict_embedding_port
        self.dict_index_port = dict_index_port
        self.dict_protocol = dict_protocol
        
        self.img = None
        self.protocol = None
        self.nameserver = None
        self.nameserver_raw = None
        
        self.port_src = None
        self.port_dst = None
        self.port_id = None
        
        self.ip_src = None
        self.ip_dst = None
        
        self.value = value
        self.representation = representation

    def run(self):
        """
        Start thread.
        """
        if(self.value == 'int'):
            if(self.representation == '1d'):
                self.__transform_img_int_1d()
            else:
                self.__transform_img_int_2d()
        else:
            if(self.representation == '1d'):
                self.__transform_img_bit_1d()
            else:
                self.__transform_img_bit_2d()
            
        self.__transform_protocol()
        self.__transform_port()
        
        # Get nameserver data        
        if(self.packet.haslayer(IPv6)):
            self.ip_src = self.packet['IPv6'].src
            self.ip_dst = self.packet['IPv6'].dst
        elif(self.packet.haslayer(IP)):
            self.ip_src = self.packet['IP'].src
            self.ip_dst = self.packet['IP'].dst

        nameserver = self.thread_dns.get_nameserver(ip_src=self.ip_src, 
                                                    ip_dst=self.ip_dst)
        if(nameserver is None):
            nameserver = self.thread_tls.get_nameserver(ip_src=self.ip_src, 
                                                        ip_dst=self.ip_dst,
                                                        port_src=self.port_src,
                                                        port_dst=self.port_dst)
        
        self.__transform_nameserver(nameserver)
        
    def __remove_header(self, packet, size=0):
        """Remove header from packet in function of size.

        Args:
            packet (np.array): Packet.
            size (int, optional): Header length to remove. Defaults to 0.

        Returns:
            np.array: Packet with header removed.
        """
        new_packet = np.lib.pad(packet.ravel()[size:],
                                (0, size),
                                'constant',
                                constant_values=(0))
        return np.reshape(new_packet, packet.shape)
    
    def __remove_all_header_int(self, data_array):
        """Remove all header from packet in integer (Ethernet, IP, TCP/UDP).

        Args:
            data_array (np.array): Packet with header.

        Returns:
            np.array: Packet without header.
        """
        header_length = 0
        if(self.packet.haslayer(UDP)):
            header_length = 20 + 8 + 14
        elif(self.packet.haslayer(TCP)):
            header_length_value = (data_array.ravel()[14+32]).astype(int)
            header_length_int = int('{0:08b}'.format(header_length_value)[0:4], 2)
            header_length = 14 + 20 + (header_length_int * 4)
        return self.__remove_header(data_array, size=header_length)
    
    def __remove_all_header_bit(self, data_array):
        """Remove all header from packet in bit (Ethernet, IP, TCP/UDP).

        Args:
            data_array (np.array): Packet with header.

        Returns:
            np.array: Packet without header.
        """
        header_length = 0
        if(self.packet.haslayer(UDP)):
            header_length = (20 + 8 + 14) * 8
        elif(self.packet.haslayer(TCP)):
            header_length_bit = (data_array.ravel()[(14+32)*8]).astype(str)
            header_length_int = int("".join(header_length_bit), 2)
            header_length = (14 + 20 + (header_length_int * 4)) * 8
        return self.__remove_header(data_array, size=header_length)
    
    def __transform_img_bit_1d(self):
        """
        Transform packet in vector with value between 0 and 1.
        """
        data = bytes_encode(self.packet)
        data_array = self.__convert_bytes_to_int_array(data)
         # Use a filter to get data less than Ethernet II MTU
        data_array = data_array[0:1536*8]
        
        logger.info("Shape of packet : {}".format(data_array.shape))
        data_array_pad = np.lib.pad(data_array,
                                (0,1536*8-data_array.shape[0]),
                                'constant', constant_values=(0))        
        data_array_pad_reshape = np.reshape(data_array_pad, (1, 1536*8, 1))
        data_array = self.__remove_all_header_int(data_array_pad_reshape)
        self.img = data_array
    
    def __transform_img_int_2d(self):
        """
        Transform packet in matrice with value between 0 and 255.
        """
        data = bytes_encode(self.packet)
        data_array = self.__convert_bytes_to_int_array(data)
        # Use a filter to get data less than Ethernet II MTU
        data_array = data_array[0:1600] 
        
        logger.info("Shape of packet : {}".format(data_array.shape))
        data_array_pad = np.lib.pad(data_array,
                                (0,1600-data_array.shape[0]),
                                'constant', constant_values=(0))        
        data_array_pad_reshape = np.reshape(data_array_pad, (1, 40, 40, 1))
        data_array = self.__remove_all_header_int(data_array_pad_reshape)
        self.img = data_array / 255.
        
    def __transform_img_int_1d(self):
        """
        Transform packet in vector with value between 0 and 255.
        """
        data = bytes_encode(self.packet)
        data_array = self.__convert_bytes_to_int_array(data)
         # Use a filter to get data less than Ethernet II MTU
        data_array = data_array[0:1536]
        
        logger.info("Shape of packet : {}".format(data_array.shape))
        data_array_pad = np.lib.pad(data_array,
                                (0,1536-data_array.shape[0]),
                                'constant', constant_values=(0))        
        data_array_pad_reshape = np.reshape(data_array_pad, (1, 1536, 1))
        data_array = self.__remove_all_header_int(data_array_pad_reshape)
        self.img = data_array  / 255.
        
    def __transform_img_bit_2d(self):
        """
        Transform packet in matrice with value between 0 and 1.
        """
        data = bytes_encode(self.packet)
        data_array_bit = self.__convert_bytes_to_bit_array(data)
        # Use a filter to get data less than Ethernet II MTU
        data_array_bit = data_array_bit[0:111*111]
        
        logger.info("Shape of packet : ", data_array_bit.shape)

        data_array_bit_pad = np.lib.pad(data_array_bit,
                                (0,111*111-data_array_bit.shape[0]),
                                'constant', constant_values=(0))

        data_array_bit_pad = np.reshape(data_array_bit_pad, (1, 111, 111, 1))
        data_array = self.__remove_all_header_bit(data_array_bit_pad)
        self.img = data_array.astype(np.uint8)

    def __transform_nameserver(self, nameserver):
        """
        Transform nameserver for embedding.
        """
        logger.info("Nameserver : {}".format(nameserver))
        self.nameserver_raw = nameserver
        if(nameserver is not None):
            length = len(nameserver.split('.')) - 1
            nameserver_split = nameserver.split('.')[:-1]
            
            # Apply token
            for i in range(length):
                try:
                    nameserver_split[i] = self.dict_nameserver[
                                                nameserver_split[i]]
                except KeyError:
                    nameserver_split[i] = 0
                
            nameserver_split.reverse()
            pad = [self.dict_nameserver["<PAD>"]] * (NAMESERVER_LENGTH - length)
            nameserver_pad = pad + nameserver_split
        else:
            nameserver_pad = [0] * NAMESERVER_LENGTH
            
        nameserver = np.array(nameserver_pad)
    
        self.nameserver = np.reshape(nameserver, (1, NAMESERVER_LENGTH))


    def __transform_protocol(self):
        """
        Transform packet protocol (TCP/UDP).
        """
        if(self.packet.haslayer(UDP)):
            protocol = np.array(self.dict_protocol['UDP'])
        elif(self.packet.haslayer(TCP)):
            protocol = np.array(self.dict_protocol['TCP'])
        else:
            protocol = np.array([0])
            
        self.protocol = np.reshape(protocol, (1, 1))  
    

    def __transform_port(self):
        """
        Transform protocol above TCP/UDP.
        """
        if(self.packet.haslayer(UDP)):
            self.port_src = str(self.packet['UDP'].sport)
            self.port_dst = str(self.packet['UDP'].dport)
        elif(self.packet.haslayer(TCP)):
            self.port_src = str(self.packet['TCP'].sport)
            self.port_dst = str(self.packet['TCP'].dport)
        else:
            self.port_src = None
            self.port_dst = None
        
        port = self.__apply_dict_port(port_src=self.port_src, 
                                      port_dst=self.port_dst)
        self.port_id = np.reshape(port, (1, 1))

    def __apply_dict_port(self, port_src, port_dst):
        """Apply mapping between port and index for embedding.

        Args:
            port_src (str): Port source.
            port_dst (str): Port destination.

        Returns:
            int: Index for embedding.
        """
        try:
            logger.info(
                "Port source : {}".format(self.port_src))
            # Work with particular case where TLS and QUIC are on 443
            if((port_src) == '443' and (self.protocol == 0)):
                port = "TLS"
            else:
                port = self.dict_index_port[int(port_src)].upper()
            logger.info("Index port : {}".format(port))
            return self.dict_embedding_port[port]
        except KeyError:
            try:
                logger.info(
                    "Port destination : {}, Protocol : {}".format(
                        port_dst, self.protocol))
                # Work with particular case where TLS and QUIC are on 443
                if((port_dst) == '443' and (self.protocol == 0)):
                    port = "TLS"
                else:
                    port = self.dict_index_port[int(port_dst)].upper()
                logger.info("Index port : {}".format(port))
                return self.dict_embedding_port[port]
            except KeyError:
                return 0
                
        
    def __convert_bytes_to_int_array(self, data):
        """Convert bytes array to int array.

        Args:
            data (np.array): Array in bytes.

        Returns:
            np.array: Array in bytes convert to int.
        """
        data_int = [int(byte) for byte in data]
        data_int_array = np.array(data_int)
        return data_int_array
    
    def __convert_bytes_to_bit_array(self, data):
        """Convert bytes array to bit array.

        Args:
            data (np.array): Array in bytes.

        Returns:
            np.array: Array in bytes convert to bit.
        """
        data_bit = ''.join(format(byte, '08b') for byte in data)

        def split(bits):
            return [bit for bit in bits]
        
        data_bit = [int(byte) for byte in data_bit]
        data_bit_array = np.array(data_bit)
        return data_bit_array
    
    def get_img(self):
        """Get transformed packet.

        Returns:
            np.array: Transformed packet.
        """
        return self.img
    
    def get_port_src(self):
        """Get port source value.

        Returns:
            str: Get port source.
        """
        return self.port_src
    
    def get_port_dst(self):
        """Get port destination.

        Returns:
            str: Get port destination.
        """
        return self.port_dst
    
    def get_port_id(self):
        """Get port index.

        Returns:
            np.array: Array with port index.
        """
        return self.port_id
    
    def get_ip_src(self):
        """Get port source.

        Returns:
            str: Port source.
        """
        return self.ip_src
    
    def get_ip_dst(self):
        """Get port destination.

        Returns:
            str: Port destination.
        """
        return self.ip_dst
    
    def get_protocol(self):
        """Get protocol value.

        Returns:
            int: Protocol value. 
        """
        return self.protocol
    
    def get_nameserver(self):
        """Get transformed nameserver.

        Returns:
            np.array: Get transformed nameserver.
        """
        return self.nameserver
    
    def get_nameserver_raw(self):
        """Get raw nameserver.

        Returns:
            str: Raw nameserver.
        """
        return self.nameserver_raw
    
    def get_packet_length(self):
        """Get packet length.

        Returns:
            int: Packet length.
        """
        return len(self.packet)