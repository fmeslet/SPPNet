#!/usr/bin/python3.5
#-*-coding:utf-8 -*-

import sys
import json
import requests

import numpy as np
import time

# Create fake data en send it
while(True):
    y_pred = np.random.random(7)
    print(y_pred)
    # Create dict
    dict_pred = {}
    labels = ["packet_length", "Chat", "Email", "File_Transfer", 
              "P2P", "Streaming", "VoIP", "Web_Browsing"]
    for y, label in zip(y_pred, labels):
        dict_pred[label] = y

    s = json.dumps(dict_pred)

    res = requests.post("http://127.0.0.1:5000/chart", json=s)#.json()
    time.sleep(1)
