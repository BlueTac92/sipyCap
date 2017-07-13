#!/usr/bin/python
# test

import pyshark

input_callid = '191f6237850fd0f51352749e35e496cd4750ee'
cap = pyshark.FileCapture('./test/example1.pcap')
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
    print(media["ip"] + ":" + media["port"] + " [pkt source: " + media["src_ip"] + " pkt destination: " + media["dst_ip"] + "]")


