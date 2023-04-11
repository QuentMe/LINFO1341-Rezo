from math import floor
import pyshark
import os
import matplotlib.pyplot as plt


bin_size = .1 # in s

print("   UDP   TCP   DNS   MDNS   TLS   QUIC")

for file in os.listdir("WireShark_Records/"):
    if file[0] == "." or os.path.exists("Graphs/" + file[0:-7] + ".png"):
        print("skipping file: " + file[0:-7])
        continue
    else:
        print(file[0:-7])

    capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter="udp && !(eth.addr == 8c:dc:d4:38:2a:a2) &&  !(eth.addr == b8:27:eb:6b:b6:aa) &&  !(eth.addr == 4e:60:5f:38:96:97) && !(ipv6.addr == fe80::aa6a:bbff:fe81:1883) && !(ip.addr == 239.255.255.250)")
    udp_times = []
    #get list of times for udp packets
    for packet in capture:
        udp_times.append(float(packet.sniff_timestamp))

    capture.load_packets()

    # check if file is in ./Graphs


    print("capture length: " + str(len(capture)))
    if (len(capture) > 0):
        time_start = float(capture[0].sniff_timestamp)
        time_end = float(capture[capture.__len__() - 1].sniff_timestamp)
        nBins = floor((time_end-time_start)/bin_size)

        #dns workaroud
        #DNS_capture = pyshark.FileCapture("WireShark_Records/" + file, display_filter = "dns && !(ip.src == 192.168.1.38) && !(eth.src == 8c:dc:d4:38:2a:a2) && !(ip.src == 192.168.1.29) && !(ipv6.src == fe80::ba27:ebff:fe6b:b6aa) && !(ip.dst == 239.255.255.250) && !(ipv6.src == fe80::aa6a:bbff:fe81:1883) ")
        #dns_times = []
        #for packet in DNS_capture:
        #    dns_times.append(float(packet.sniff_timestamp) - time_start)f
        

        udp_times = []
        tcp_times = []
        dns_times = []
        mdns_times = []
        tls_times = []
        quic_times = []
        for packet in capture:
            match str(packet.application_layer):
                case "DNS":
                    dns_times.append(float(packet.sniff_timestamp) - time_start)
                case "MDNS":
                    mdns_times.append(float(packet.sniff_timestamp) - time_start)
                case "TLS":
                    tls_times.append(float(packet.sniff_timestamp) - time_start)
                case _:
                    match packet.transport_layer:
                        case "UDP":
                            #check that the packet is quic
                            n_quic = 0
                            for layer in packet.layers:
                                if layer.layer_name == "quic":
                                    n_quic += 1
                                    break
                            if n_quic != 0:
                                quic_times.append(float(packet.sniff_timestamp) - time_start)
                            else:
                                udp_times.append(float(packet.sniff_timestamp) - time_start)
                        case "TCP":
                            tcp_times.append(float(packet.sniff_timestamp) - time_start)
                        #case "DNS":
                            #dns_times.append(float(packet.sniff_timestamp) - time_start)
                        case _: 
                            print(packet.transport_layer+ " " + packet.application_layer)


            ##print(str(packet.transport_layer))
            #if packet.transport_layer == "UDP":
            #    
            #elif packet.transport_layer == "TCP":
            #    
            #elif packet.transport_layer == "DNS":
            #    dns_times.append(float(packet.sniff_timestamp) - time_start)
            #elif packet.transport_layer == "MDNS":
            #    mdns_times.append(float(packet.sniff_timestamp) - time_start)
            #elif packet.transport_layer == "TLS":
            #    tls_times.append(float(packet.sniff_timestamp) - time_start)

                

                
        print(f"{len(udp_times):>6}" + 
              f"{len(tcp_times):>6}" + 
              #f"{len(dns_times):>6}" + 
              f"{len(mdns_times):>6}" + 
              f"{len(tls_times):>6}" + 
              f"{len(quic_times):>6}" +
              "       for a total of " + 
              f"{str(len(capture)):>5}" + " unfiltered packets in " + str(time_end-time_start)[0:5] + " s")

        # graph dns packets per second
        #plt.hist(dns_times, bins=nBins, label="DNS Packets", alpha=1)

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
