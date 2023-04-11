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
    capture.load_packets()
    time_start = float(capture[0].sniff_timestamp)
    time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
    #get file size
    size = os.path.getsize(folder + file)
    #change to kB
    size = size/1000
    print("File Size: " + str(size)[0:5] + " kilobytes")
    print('Bandwidth: ' + str(size/(time_end-time_start))[0:5] + ' kilobytes/s\n')

    #make a graph of the bandwith
    #make a list of the time stamps
    time_stamps = []
    for packet in capture:
        time_stamps.append(float(packet.sniff_timestamp))
    #make a list of the bandwith
    bandwith = []
    for i in range(0, floor((time_end-time_start)/bin_size)):
        bandwith.append(0)
        for time in time_stamps:
            if time > time_start + i*bin_size and time < time_start + (i+1)*bin_size:
                bandwith[i] += capture[0].size
    
    plt.plot(bandwith, label= "Bandwith",
             x = [i*bin_size for i in range(0, floor((time_end-time_start)/bin_size))],
             y = bandwith,
             )


    plt.xlabel('Time (s)')
    plt.ylabel('Bandwith (kB/s)')
    plt.title(file + "\nbin size: " + str(bin_size) + "s")

    plt.legend(loc='upper right')

    # save graph
    plt.savefig("Graphs/" + file[0:-7] + ".png")
    plt.clf()
