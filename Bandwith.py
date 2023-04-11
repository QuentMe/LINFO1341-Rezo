from math import floor
import pyshark
import os
import matplotlib.pyplot as plt


bin_size = .1 # in seconds

folder = "WireShark_Records/bandwith/"


for file in os.listdir(folder):
    if file[0] == "." or file == "Hidden":
        continue
    
    
    print(file[0:-7])
        
    capture = pyshark.FileCapture(folder + file, display_filter= "udp && !(eth.addr == 8c:dc:d4:38:2a:a2) &&  !(eth.addr == b8:27:eb:6b:b6:aa) &&  !(eth.addr == 4e:60:5f:38:96:97) && !(ipv6.addr == fe80::aa6a:bbff:fe81:1883) && !(ip.addr == 239.255.255.250)")
    #capture.load_packets()
    time_start = float(capture[0].sniff_timestamp)
    time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
    #get file size
    size = os.path.getsize(folder + file)
    #change to kB
    size = size/1000
    print("File Size: " + str(size)[0:5] + " kilobytes")
    print('Bandwidth: ' + str(size/(time_end-time_start))[0:5] + ' kilobytes/s\n')
