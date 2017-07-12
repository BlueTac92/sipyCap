#!/usr/bin/python

import pyshark

input_callid = '191f6237850fd0f51352749e35e496cd4750ee'
cap = pyshark.FileCapture('example1.pcap')
sdp = {}
cseq = []

def find_call(callid):
    for pkt in cap:
        try:
            if callid in pkt.sip.call_id:
                if pkt.sip.method == 'OPTION':
                    pass
                else:
                    return 1
        except AttributeError as e:
            pass

def find_cseq(callid):
    a = ''
    for pkt in cap:
        try:
            if (pkt.sip.call_id == callid and pkt.sip.sdp_media_port):
                a = pkt.sip.cseq
                a = a.split(' ')
                if a[0] in cseq:
                    pass
                else:
                    cseq.append(a[0])
            else:
                pass
        except AttributeError as e:
            pass



# extract_media will return a list containing all the sets of media information
# m = extract_media(callid)
# print(m)
# [ {ip: 172.168.0.1, port: 7941},
#   {ip: 172.168.0.2, port: 8461}]


def extract_media(callid):
    media = []
    for pkt in cap:
        try:
            if callid in pkt.sip.call_id:
                media.append({
                    "ip": pkt.sip.sdp_connection_info_address,
                    "port": pkt.sip.sdp_media_port,
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    }
                    )
        except AttributeError as e:
            pass

    return(media)


def groups_channels_by_legs(ungrouped_media):
    for x in len(ungrouped_media):
        print(x)


    

if find_call(input_callid):
    print('call found')
else:
    print('call not found')
    exit

call_media = extract_media(input_callid)
for media in call_media:
    print(media)





"""
    find_cseq(input_callid)
    find_pkt_media(input_callid)
    for x in cseq:
        print(x)
        """
