from math import floor
import pyshark
import os
import matplotlib.pyplot as plt


bin_size = .1 # in seconds

layers = ["udp", "tcp", "mdns", "dns", "tls", "quic", "stun", "icmp"]
header = ""
for i in range(len(layers)):
    header += f"{layers[i]:>6}"
print(header)

for file in os.listdir("WireShark_Records/"):
    if file[0] == "." or file == "Hidden" or file == "bandwith":
        continue
    if os.path.isfile("Graphs/" + file[0:-7] + ".png"):
        print("skipping : " + file[0:-7])
        continue
    
    
    print(file[0:-7])
        
    capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter= "!(eth.addr == 8c:dc:d4:38:2a:a2) &&  !(eth.addr == b8:27:eb:6b:b6:aa) &&  !(eth.addr == 4e:60:5f:38:96:97) && !(ipv6.addr == fe80::aa6a:bbff:fe81:1883) && !(ip.addr == 239.255.255.250)")
    capture.load_packets()
    time_start = float(capture[0].sniff_timestamp)
    time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
    size = len(capture)
    nBins = floor((time_end-time_start)/bin_size)
    
    
    layer_times = [[] for i in range(len(layers))]
    for i in range(len(layers)):
        capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter = layers[i] + " && !(eth.addr == 8c:dc:d4:38:2a:a2) &&  !(eth.addr == b8:27:eb:6b:b6:aa) &&  !(eth.addr == 4e:60:5f:38:96:97) && !(ipv6.addr == fe80::aa6a:bbff:fe81:1883) && !(ip.addr == 239.255.255.250)")
        capture.load_packets()
        for packet in capture:
            layer_times[i].append(float(packet.sniff_timestamp)- time_start)

    PrintBuff_layer_times = ""
    for i in range(len(layers)):
        PrintBuff_layer_times += f"{str(len(layer_times[i])):>6}"

    print(PrintBuff_layer_times +
            "       for a total of " + 
            f"{str(size):>5}" + 
            " unfiltered packets in " + 
            str(time_end-time_start)[0:5] + " s")

    for i in range(len(layers)):
        # graph packets per second
        plt.hist(layer_times[i], bins=nBins, label= layers[i] + " Packets", alpha=.5)


    plt.xlabel('Time (s)')
    plt.ylabel('Number of Packets')
    plt.title(file + "\nbin size: " + str(bin_size) + "s")

    plt.legend(loc='upper right')

    # save graph
    plt.savefig("Graphs/" + file[0:-7] + ".png")
    plt.clf()
