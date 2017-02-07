#!/usr/bin/env python 

import os
import pyshark

sipcallid = 'SDc20m701-0f3f372bc955d5f0aa0a05ea4a244132-cl7qg13'

currentDir = os.path.dirname(os.path.realpath(__file__))
pcaps = []

for x in os.listdir(currentDir):
    if ".pcap" in x:
        pcaps.append(currentDir + '/' + x)

for x in pcaps:
    print(x)


def find_call(callid):
    for pkt in cap:
        try:
            if pkt.sip.call_id == callid:
                if pkt.sip.method == 'OPTION':
                    pass
                else:
                    print("Found call-id: " + callid)
                    return 1
        except AttributeError as e:
            pass

for pcap in pcaps:
    if find_call(sipcallid):
        print("Call found in " + pcap)
