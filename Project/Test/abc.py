import pcapkit
import os
from prettytable import PrettyTable

os.getcwd()
relativePath = 'Project\\resources\\ipp.pcap' # Relative directory something like '../test.pcap'
fullPath = os.path.join(os.getcwd(),relativePath) # Produces something like '/home/hallandspur/Documents/test.pcap'
extraction = pcapkit.extract(fin=fullPath, nofile=True) 
totalFrames = len(extraction.frame) 
print(totalFrames)

out = PrettyTable()
out.field_names = ["Source IP", "Destination IP", "Protocol"]

# check if IP in this frame, otherwise don't print
for x in range(totalFrames):
    flag = pcapkit.IP in extraction.frame[x]
    frameInfo = extraction.frame[x][pcapkit.IP] if flag else None
    frameTime = extraction.frame[x].info.time  #frame_info
    if x >= 1:
        previousTime = extraction.frame[x - 1].info.time
        time = frameTime - previousTime
        print(time)
    if frameInfo != None:
        sourceIP = frameInfo.src
        destinationIP = frameInfo.dst
        protocolUsed = frameInfo.protocol
        out.add_row([sourceIP,destinationIP, protocolUsed])
        
        
print(out)   