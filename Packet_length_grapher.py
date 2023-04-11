from matplotlib import pyplot as plt
import numpy as np

Packet_lengths = ["0-19","20-39","40-79","80-159","160-319","320-639","640-1279","1280-2559","2560-5119","5120 and greater"]

#* Normal Call
percentages_normal = [0.00, 0.00, 0.08, 8.00, 8.34, 1.90, 81.67, 0.00, 0.00, 0.00]

#* Audio Only Call
percentages_audioOnly = [0.00, 0.00, 0.74, 28.08, 67.98, 0.00, 3.20, 0.00, 0.00, 0.00]


# set width of bar
barWidth = 0.25
fig = plt.subplots(figsize =(12, 8))

# Set position of bar on X axis
br1 = np.arange(10)-barWidth/2
br2 = [x + barWidth for x in br1]


#graph packet lengths
plt.bar(br1, percentages_audioOnly, width=barWidth, label='audio call')
plt.bar(br2, percentages_normal, width=barWidth, label='video call')

plt.xlabel('Packet Lengths (bytes)', fontweight ='bold', fontsize=15)
plt.xticks([r for r in range(len(Packet_lengths))],
        Packet_lengths, rotation=10, size=8)


plt.ylabel('Percentage of Packets',fontweight ='bold', fontsize=15)
plt.legend(loc='upper right')
plt.savefig("Graphs/" + "Packet_distribution" + ".png")
#plt.show()