#!/usr/bin/python3.5
#-*-coding:utf-8 -*-
'''
Created on 28 aout 2020

@author: Fabien Meslet-Millet
'''

from scapy.all import sniff
from threading import Thread, Lock
import numpy as np
from socketIO_client import SocketIO, LoggingNamespace

from .thread_processing import ThreadProcessing
from hashmap import HashMap
import logging

import warnings
warnings.filterwarnings("ignore")

logger = logging.getLogger()

class ThreadInference(Thread):
    """
    Class for inference and lauch thread for processing data.
    """

    def __init__(self,
                 thread_lock,
                 hashmap,
                 session,
                 packet,
                 model,
                 thread_dns, 
                 thread_tls,
                 dict_nameserver,
                 dict_embedding_port,
                 dict_index_port,
                 dict_protocol,
                 value,
                 representation):
        """Constructor.

        Args:
            thread_lock (thread.Lock): Lock to manage thread safe access.
            hashmap (HashMap): Hashamp which save proba associated to traffic flow.
            session (Tensorflow.session): Session Tensorflow.
            packet (Scapy.packet): Packet captured by Scapy.
            model (Keras model): Model Keras.
            thread_dns (threads.ThreadCaptureDNS): Thread which capture DNS packets.
            thread_tls (threads.ThreadCaptureTLS): Thread which capture TLS Handshake packets.
            dict_nameserver (dict): Dictonnary for nameserver and index mapping.
            dict_embedding_port (dict): Dictonnary for protocol name and index mapping.
            dict_index_port (dict): Dictonnary for port number and protocol name.
            dict_protocol (dict): Dictonnary for udp/tcp and value mapping.
            value (str): Packet value range (0-255 or 0-1).
            representation (str): Packet representation (Vector or matrice).
        """
        Thread.__init__(self)
        self.dict_label = {0 : 'Chat',
                           1 : 'Email',
                           2 : 'File_Transfer',
                           3 : 'P2P',
                           4 : 'Streaming',
                           5 : 'VoIP',
                           6 : 'Web_Browsing'}
        self.session = session
        
        self.packet = packet
        self.model = model
        
        self.thread_dns = thread_dns
        self.thread_tls = thread_tls
        
        self.dict_nameserver = dict_nameserver
        self.dict_index_port = dict_index_port
        self.dict_embedding_port = dict_embedding_port
        self.dict_protocol = dict_protocol
        
        self.hashmap = hashmap
        self.thread_lock = thread_lock
        
        self.processing = None
        
        self.value = value
        self.representation = representation

    def run(self): 
        """
        Start Thread.
        """
        self.processing = ThreadProcessing(packet=self.packet, 
                                    thread_dns=self.thread_dns, 
                                    thread_tls=self.thread_tls,
                                    dict_nameserver=self.dict_nameserver,
                                    dict_embedding_port=self.dict_embedding_port,
                                    dict_index_port=self.dict_index_port,
                                    dict_protocol=self.dict_protocol,
                                    value=self.value,
                                    representation=self.representation)

        self.processing.start()
        self.processing.join()
        
        condition_length = self.processing.get_packet_length() \
            in [52, 54, 64, 66, 72, 74, 78, 80, 82, 86, 90, 93,
                94, 97, 98, 105, 146]
        condition_tcp = (self.processing.get_protocol() == 0)
        condition_nameserver = (self.processing.get_nameserver_raw() is None)
        
        if(condition_length and
           (condition_tcp) and
           (condition_nameserver)):
            pred_proba = self.__extract_proba_hashmap()
        else:
            pred_proba = self.__predict_proba()
            self.__set_hashmap(pred_proba)
        
        # Print hashmap
        print(self.hashmap.get_hashmap())
        self.__send_data(pred_proba)
    
    def __extract_proba_hashmap(self):
        """Get proba associated with traffic flowcfrom HashMap.

        Returns:
            np.array: Array of proba associated for each class.
        """
        key_0 = self.processing.get_ip_src()
        key_1 = self.processing.get_ip_dst()
        key_2 = self.processing.get_port_src()
        key_3 = self.processing.get_port_dst()
        
        keys = [key_0, key_1, key_2, key_3]

        pred_proba, keys = self.__get_by_keys_reverse(keys=keys)
        
        if(pred_proba is None):
            pred_proba = np.array([[0]*7], dtype=np.float32)[0]
        else:
            pred_proba = np.array(pred_proba[0:-1]) / pred_proba[-1]
    
        return pred_proba
    
    def __predict_proba(self):
        """Get model prediction.

        Returns:
            np.array: Array of proba associated for each class.
        """
        X = [self.processing.get_img(),
             self.processing.get_port_id(),
             self.processing.get_protocol(),
             self.processing.get_nameserver()]
        
        logger.info("Port : {}".format(self.processing.get_port_id()))
        logger.info("Protocol : {}".format(self.processing.get_protocol()))
        logger.info("Nameserver : {}".format(self.processing.get_nameserver()))
        
        with self.session.as_default():
            with self.session.graph.as_default():
                # To avoid JSON Serializable error
                pred_proba = self.model.predict(X).astype(np.float64)[0]

        return pred_proba
        
        
    def __set_hashmap(self, pred_proba):
        """Update traffic flow prediction in HashMap.

        Args:
            pred_proba (np.array): Class probabilities get by model prediction or HashMap.
        """
        key_0 = self.processing.get_ip_src()
        key_1 = self.processing.get_ip_dst()
        key_2 = self.processing.get_port_src()
        key_3 = self.processing.get_port_dst()
        
        keys = [key_0, key_1, key_2, key_3]
        
        values, keys = self.__get_by_keys_reverse(keys=keys)
        
        if(values is not None):
            pred_proba_old = np.array(values[0:-1])
            pred_proba_tmp = np.array(pred_proba)
            quantity = np.array(values[-1])
            
            # Update proba values
            pred_proba_new = (pred_proba_old + pred_proba_tmp)
            
            self.thread_lock.acquire()
            self.hashmap.set_by_keys(keys=keys, values=pred_proba_new)
            self.thread_lock.release()
        else:
            self.thread_lock.acquire()
            self.hashmap.add_data(keys=keys, values=pred_proba)
            self.thread_lock.release()
            
    def __get_by_keys_reverse(self, keys):
        """Extract values from HashMap with the keys reversed.

        Args:
            keys (list): Keys to extract values.

        Returns:
            tuple: Values and keys order where values are extracted.
        """
        values_1 = self.hashmap.get_by_keys(keys=keys)
        values_2 = self.hashmap.get_by_keys(
            keys=[keys[1], keys[0], keys[3], keys[2]])
        
        if(values_1 is None):
            return values_2, [keys[1], keys[0], keys[3], keys[2]]
        else:
            return values_1, keys
        
    def __send_data(self, pred_proba):
        """Send data to Flask server.

        Args:
            pred_proba (np.array): Class probabilities get by model prediction or HashMap.
        """
        send_data = {}
        print("Packet length : {}".format(self.processing.get_packet_length()))
        
        for label, pred in zip(range(0, 7), pred_proba):
            print(self.dict_label[label], int(pred* 100))
            send_data[self.dict_label[label]] = int(pred * 100)
           
        send_data["packet_length"] = self.processing.get_packet_length()
        
        with SocketIO('localhost', 5000, LoggingNamespace) as socketIO:
            socketIO.emit('my event', send_data)
            