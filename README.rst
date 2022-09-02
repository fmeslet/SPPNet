======================================================================================
SPPNet: An Appoach For Real-Time Encrypted Traffic Classification Using Deep Learning
======================================================================================

Presentation
------------

SPPNet (ServerName Protocol Packet Network) is the Deep Learning architecture used 
to classify encrypted network traffic. The model works in packet level and classify 
packet in real time. This work is being published in IEEE GLOBECOM 2021 : 
`link: <https://ieeexplore.ieee.org/document/9686037>`

Usage
-----

Lauch all programs and configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The inference program can only classify IPv4 packets. In Linux, you can desactivate 
IPv6 by adding this line in ``/etc/sysctl.conf`` :

* ``net.ipv6.conf.lo.disable_ipv6 = 1``  
* ``net.ipv6.conf.all.disable_ipv6 = 1``   
* ``net.ipv6.conf.all.autoconf = 0`` 
* ``net.ipv6.conf.default.disable_ipv6 = 1``    
* ``net.ipv6.conf.default.autoconf = 0`` 


To apply the change run : ``sysctl -p``.

The package ``scapy_ssl_tls`` is not adapted for working in Python 3. The package 
adapted for Python 3 is available in the ``scapy_ssl_tls`` folder.

Lauch all programs
^^^^^^^^^^^^^^^^^^

``cd src/``
``sudo ./start_sppnet``


Lauch inference program
^^^^^^^^^^^^^^^^^^^^^^^^

``sudo python3.5 src/main.py``

Lauch visualization program
^^^^^^^^^^^^^^^^^^^^^^^^^^^

``sudo python3.5 src/graph/server.py``

.. image:: https://github.com/fmeslet/SPPNet/blob/master/others/dashboard_sppnet.png?raw=true
  :width: 400
  :alt: Visualization of SPPNet classification in realtime.

Informations
------------

You can get a video demonstration inside the ``others`` folder. The model is available in ``src/data``.  

Requirements
------------

* Python 3.6.0
* Keras  2.0.5
* TensorFlow 1.3.1
* Numpy 1.14.3
* Pandas 0.22.0
* Scapy 2.4.3
* Scapy_ssl_tls 2.0.0

Updates
-------

* Version 1.0.0

Authors
-------

* **Fabien Meslet**

Contributors
------------

*

LICENSE
-------

See the file "LICENSE" for information.
