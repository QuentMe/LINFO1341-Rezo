from math import floor
import pyshark
import os
import matplotlib.pyplot as plt


bin_size = .1 # in s

for file in os.listdir("WireShark_Records/"):
    
    capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter="(udp || tcp) && !(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883) ")
    capture.load_packets()
    print("")

    # check if file is in ./Graphs


    if (capture.__len__() > 0):
        time_start = float(capture[0].sniff_timestamp)
        time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
        nBins = floor((time_end-time_start)/bin_size)
        print("Analysing file: " + str(file) + "\n" + str(len(capture)) + " unfilteredd packets and " + str(nBins) + " bins with a filterd duration of: " + str(time_end-time_start)[0:5]+ "s")

        n_quic = 0
        for packet in capture:
            if packet.transport_layer == "quic":
                n_quic += 1
        print("quic packets: " + str(n_quic))
