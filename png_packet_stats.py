from math import floor
import pyshark
import os
import matplotlib.pyplot as plt


bin_size = .1 # in s

for file in os.listdir("WireShark_Records/"):
    if os.path.exists("Graphs/" + file[0:-7] + ".png"):
        print("skipping file: " + file + " (already graphed)")
        continue

    capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter="(udp || tcp) && !(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883) ")
    capture.load_packets()
    print("")

    # check if file is in ./Graphs


    if (capture.__len__() > 0):
        time_start = float(capture[0].sniff_timestamp)
        time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
        nBins = floor((time_end-time_start)/bin_size)
        print("Analysing file: " + str(file) + "\n" + str(len(capture)) + " unfilteredd packets and " + str(nBins) + " bins with a filterd duration of: " + str(time_end-time_start)[0:5]+ "s")
        print("")

        udp_times = []
        tcp_times = []
        dns_times = []
        mdns_times = []
        tls_times = []
        quic_times = []
        for packet in capture:
            if packet.transport_layer == "UDP":
                udp_times.append(float(packet.sniff_timestamp) - time_start)
            elif packet.transport_layer == "TCP":
                tcp_times.append(float(packet.sniff_timestamp) - time_start)
            elif packet.transport_layer == "DNS":
                dns_times.append(float(packet.sniff_timestamp) - time_start)
            elif packet.transport_layer == "MDNS":
                mdns_times.append(float(packet.sniff_timestamp) - time_start)
            elif packet.transport_layer == "TLS":
                tls_times.append(float(packet.sniff_timestamp) - time_start)
            elif packet.transport_layer == "QUIC":
                quic_times.append(float(packet.sniff_timestamp) - time_start)
                
        

        # graph dns packets per second
        plt.hist(dns_times, bins=nBins, label="DNS Packets", alpha=1)

        # graph mdns packets per second
        plt.hist(mdns_times, bins=nBins, label="MDNS Packets", alpha=1)

        # graph tcp packets per second
        plt.hist(tcp_times, bins=nBins, label="TCP Packets", alpha=0.5)

        # graph udp packets per second
        plt.hist(udp_times, bins=nBins, label="UDP Packets", alpha=0.5)

        # graph tls packets per second
        plt.hist(tls_times, bins=nBins, label="TLS Packets", alpha=1)

        # graph quic packets per second
        plt.hist(quic_times, bins=nBins, label="QUIC Packets", alpha=1)



        plt.xlabel('Time (s)')
        plt.ylabel('Number of Packets')
        plt.title(file + "\nbin size: " + str(bin_size) + "s")

        plt.legend(loc='upper right')

        # save graph
        plt.savefig("Graphs/" + file[0:-7] + ".png")
        plt.clf()
