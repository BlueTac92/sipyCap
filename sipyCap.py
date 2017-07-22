#!/usr/bin/python

import pyshark
import sys
import os

input_callid = '191f6237850fd0f51352749e35e496cd4750ee'
cap = './test/example1.pcap'
sdp = {}
cseq = []
directory = ""
multiple_files = "n"
location = ""
sip_only = "y"

# check for arguements
if len(sys.argv) <= 1:
    # If no arguments were passed when started, then we need to ask for some information before anything can happen
    print("--> No arguments were passed when you ran sipPycap...")
    print("--> ")
    # Check if we will be searching multiple pcaps
    multiple_files = input("--> Are you searching multiple pcaps? (y/n): ")
    if multiple_files.lower() == "y":
        print("+++ multiple_files = true")
        multiple_files = True
    elif multiple_files.lower() == "n":
        print("+++ multiple_files = false")
        multiple_files = False
    else:
        print("??? Invalid option. Using default (false)")
        print("+++ multiple_files = false")
    # Check if only searching for SIP 
    sip_only = input("--> Are you searching SIP only? (y/n): ")
    if sip_only.lower() == "y":
        print("+++ sip_only = true")
        sip_only = True
    elif sip_only.lower() == "n":
        print("+++ sip_only = false")
        sip_only = False
    else:
        print("??? Invalid option. Using default (false)")
        print("+++ sip_only = false")
    print("--> ")
    print("--> ")
    if multiple_files == False:
        location = input("--> Please provide path to file ( /tmp/example_call.pcap ): ")
        # Create a use currect directory option for both this section and multiple_files == True section
        if os.path.isfile(location):
            print("+++ Path appears to be valid " + location)
            cap = location
        else:
            print("ERR Path appears to be invalid, please make sure that file exists and you have permissions to read it")
            exit(404)
    elif multiple_files == True:
        location = input("--> Please provide path to directory containing pcaps ( /tmp/pcaps/ ): ")
        if os.path.isdir(location):
            print("+++ Path appears to be valid " + location)
        else:
            print("ERR Path appears to be invalid, please make sure that directory exists, you have read permissions, and it is not a file")
            exit(404)
else:
#    for arg in sys.args:
#        if arg == 
    print("Yay arguemnets")
    print("I've not configured this yet, please try again without arguments")


# function to find different types of files that pyshark can work with
def find_multi_pcaps(directory):
    pcaps = []

    for files in os.listdir(directory):
        if '.pcap' in files:
            pcaps.append(files)
        elif  '.pcapng' in files:
            pcaps.append(files)
        elif  '.cap' in files:
            pcaps.append(files)
        elif  '.dmp' in files:
            pcaps.append(files)
        else:
            pass

    return(pcaps)


# try to load pcap file
try:
    cap = pyshark.FileCapture(cap)
except FileNotFoundError as e:
    print("Error opening file. Check file exists and you have correct permissions on the file")
    exit()



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


if multiple_files:
    pcaps = find_multi_pcaps(location)
else:
    print("--> Not creating list of PCAPs because only 1 file is being used. (This is not an error)")
    

if find_call(input_callid):
    print('call found')
else:
    print('call not found')
    exit

call_media = extract_media(input_callid)
for media in call_media:
    print(media["ip"] + ":" + media["port"] + " [pkt source: " + media["src_ip"] + " pkt destination: " + media["dst_ip"] + "]")


