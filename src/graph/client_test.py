import time
from random import randrange
from socketIO_client import SocketIO, LoggingNamespace

import sys
import json
import requests

import numpy as np

if __name__ == '__main__':
    with SocketIO('localhost', 5000, LoggingNamespace) as socketIO:
        while True:

            y_pred = np.random.random(7)
            print(y_pred)
            # Create dict
            send_data = {}
            labels = ["Chat", "Email", "File_Transfer", 
                      "P2P", "Streaming", "VoIP", "Web_Browsing"]
            for y, label in zip(y_pred, labels):
                send_data[label] = y

            # Send
            socketIO.emit('my event', send_data)
            time.sleep(0.5)
