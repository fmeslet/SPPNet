#!/usr/bin/python3.5
#-*-coding:utf-8 -*-
'''
Created on 28 aout 2020

@author: Fabien Meslet-Millet
'''

from scapy.all import sniff, IP

import random
import sys
from threading import Thread, Lock
import time
import socket
import numpy as np
import pandas as pd
import pickle
import gc
from pathlib import Path

import logging
import traceback
from logging import config

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import warnings
with warnings.catch_warnings():
    warnings.filterwarnings("ignore")
    import keras

import threads

import keras_resnet

from hashmap import HashMap

DIR_PATH = str(Path(__file__).parent.resolve())
NAME = str(time.strftime("%Y%m%d_%H%M%S", time.localtime()))
PATH_LOG = "{}/logs/{}.log".format(DIR_PATH, NAME)
IP = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] 
      if not ip.startswith("127.")][0]
CUSTOM_OBJECTS = keras_resnet.custom_objects.copy()
VALUE = 'int'
REPRESENTATION = '1d'

import tensorflow as tf
import numpy as np

# Set up config session
config = tf.ConfigProto(
    device_count={'GPU': 1},
    intra_op_parallelism_threads=1,
    allow_soft_placement=True
)
config.gpu_options.allow_growth = True
config.gpu_options.per_process_gpu_memory_fraction = 0.6

# Init Tensorflow session
session = tf.Session(config=config)
keras.backend.set_session(session)

logging.basicConfig(
    filename=PATH_LOG,
    level=logging.DEBUG,
    format='%(asctime)s - %(filename)s - %(levelname)s - %(message)s'
)

# Set up logging to console
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter('%(message)s'))

# Add the handler to the root logger
logging.getLogger().addHandler(console)
logger = logging.getLogger(__name__)

def eprint(*args, **kwargs):
    # print(*args, file=sys.stderr, **kwargs)
    logger.info(str(args))

def load_model(path, name, custom_objects=None):
    """Load Keras model.

    Args:
        path (str): Folder path of model.
        name (str): Name of model.
        custom_objects (Keras objects, optional): Custom objects need for loading. Defaults to None.

    Returns:
        Keras model: Keras model loaded.
    """
    model = keras.models.load_model('{}/{}.h5'.format(path, name),
                                    custom_objects=custom_objects)
    return model

def load_object(path, name):
    """Load a Python object.

    Args:
        path (str): Folder path of Python object.
        name (str): Name of Python object.

    Returns:
        Python object: Python object loaded.
    """
    with open("{}/{}".format(path, name), "rb") as f:
        dictionnary = pickle.load(f)
    return dictionnary


def main():
    try:
        eprint("---------------- BEGIN ----------------")    
    
        eprint("********Loading model********")
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")#,category=FutureWarning)
            model = load_model(path='./data',
                            name="model_1d_cnn_int_embedding_ports_protocols_dns_NON_TOR_VPN_L3_768_15_FULL",
                            custom_objects=CUSTOM_OBJECTS)
        eprint("********Model loaded********")
        
        # Compile predict function in order to allow
        # multi threading
        model._make_predict_function()
        
        eprint("********Loading dictionnaries********") #/home/fmeslet/Documents/CNES/PFE/RealTime
        dict_nameserver = load_object(path='./data',
                                    name='dict_nameserver')
        
        dict_embedding_port = load_object(path='./data',
                                    name='dict_ports')
        
        # Give correspondance between number of port and protocol name
        dict_index_port = load_object(path='./data',
                                    name='dict_index_port')

        dict_protocol = {"UDP" : 1, 
                        "TCP" : 0}
        eprint("********Dictionnaries loaded********")

        eprint("********Start threads********")

        # Start thread DNS
        thread_dns = threads.ThreadDnsCapture()
        thread_dns.start()
        
        # Start thread TLS
        thread_tls = threads.ThreadTlsCapture()
        thread_tls.start()
        
        # Start thread QUIC
        # To Do
        
        eprint("********Threads started********")
        
        # Create HashMap
        hashmap = HashMap(num_keys=4, num_values=7)
        
        # Create threadLock to thread safe access to HashMap
        thread_lock = Lock()
        
        filter_protocol = "((udp) or (tcp))"
        # DNS and MDNS and SSDP and Nbns and others useless protocol
        filter_port = "(not (port 53)) and (not (port 5353)) and \
            (not (port 1900)) and (not (port 135)) and \
            (not (port 137)) and (not (port 138)) and \
            (not (port 139)) and (not (port 8009))"  
        
        filter = filter_protocol + " and " + filter_port
        
        eprint("********Start capture********")
        
        while(True):
            packet = sniff(count=1, filter=filter, prn=lambda p: p.summary())[0]

            # Check if packet captured is interpretable by Scapy
            if((type(packet) != None) and (packet != None)):
                print("\n")
                thread_inference = threads.ThreadInference(
                                            thread_lock=thread_lock,
                                            hashmap=hashmap,
                                            session=session,
                                            packet=packet, 
                                            model=model,
                                            thread_dns=thread_dns,
                                            thread_tls=thread_tls,
                                            dict_nameserver=dict_nameserver,
                                            dict_embedding_port=dict_embedding_port,
                                            dict_index_port=dict_index_port,
                                            dict_protocol=dict_protocol,
                                            value=VALUE,
                                            representation=REPRESENTATION)
                thread_inference.start()
                gc.collect()
                
        eprint("----------------- END -----------------")
    
    except Exception:
        # Display the *original* exception
        traceback.print_exception(*sys.exc_info())
        return
        
if __name__ == "__main__":
    main()
    
