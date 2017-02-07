#!/usr/bin/python

import pyshark

input_callid = '191f6237850fd0f51352749e35e496cd4750ee@212.165.21.6'
cap = pyshark.FileCapture('example1.pcap', display_filter='sip')
sdp = {}
cseq = []

def find_call(callid):
    for pkt in cap:
        try:
            if pkt.sip.call_id == callid:
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

def find_pkt_media(leg,cseq):

    for pkt in cap:
        try:
            if (pkt.sip.cseq_seq = cseq and pkt.sip.sdp_media_port):
                port = pkt.sip.sdp_media_port
                ip = pkt.sip.sdp_media_ip
                

            pkt.sip.sdp_media_port
#            a['port'] = pkt.sip.sdp_media_port
#            a['ip'] = pkt.sip.sdp_connection_info_address
            srce = pkt.ip.src
            dest = pkt.ip.dst
            cseq = pkt.sip.cseq
            print(dest + ' -> ' + srce + ':' + cseq)
#            print('IP: ' + a['ip'])
#            print('Port: ' + a['port'])
        except AttributeError as e:
            pass

if find_call(input_callid):
    print('call found')
    find_cseq(input_callid)
    find_leg_media(input_callid)
    for x in cseq:
        print(x)
else:
    print('call not found')

#for pkt in cap:
#    print(pkt.sip.cseq)

