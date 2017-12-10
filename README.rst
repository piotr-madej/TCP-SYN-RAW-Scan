Requirements

.. code-block:: bash

    import socket, argparse, sys, logging
    from time import sleep
    from struct import pack, unpack
    from scapy.all import *
    from multiprocessing import Process

Usage: syn_scan.py [-h] -s SOURCE -d DESTINATION -w WAIT
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        Source IP | x.x.x.x
  -d DESTINATION, --destination DESTINATION
                        Destination IP | x.x.x.x
  -w WAIT, --wait WAIT  Time interval in milisecond | x
