import pcapkit
import os
import csv
from pcapkit.utilities.validations import pkt_check 
from collections import Counter, defaultdict
from prettytable import PrettyTable

relativePath = 'Project\\resources\\Training Data\\http-flood.pcap' # Relative directory something like '../test.pcap'
fullPath = os.path.join(os.getcwd(),relativePath) # gets the fullpath of the file by con current working directory to 
extraction = pcapkit.extract(fin=fullPath, nofile=True) 
totalFrames = len(extraction.frame) 

results = PrettyTable()
results.field_names = ["IP", "Count", "Total_Bytes_Sent", "SYN Flood", "HTTP_GET_Req", "Pings_Sent", "Malicious"] #, "Pings per Second", "Slowloris"]

#creating lists for all the source IP's
srcIP = []


countDict = defaultdict(lambda: defaultdict(lambda: 0))
finalTime = 0
# check if IP in this frame, otherwise don't print
for x in range(totalFrames):
    flag = pcapkit.IP in extraction.frame[x]
    frameInfo = extraction.frame[x][pcapkit.IP] if flag else None
    frameTime = extraction.frame[x].info.time
    length = extraction.frame[x].info.cap_len
    if x == 0:
            firstTime = frameTime
            time = 0.00
    if x >= 1:
        time = frameTime - firstTime
        if x == totalFrames -1:
            finalTime = time.total_seconds() 
    if frameInfo != None:
        sourceIP = frameInfo.src
        destinationIP = frameInfo.dst
        protocolUsed = frameInfo.protocol
        headerinfo = frameInfo.info.packet.header
        print (headerinfo)
        countDict[sourceIP]["Total_Bytes_Sent"] += length
        #adding various items to their respective lists
        srcIP.append(sourceIP) 
        if protocolUsed == 1: #1 --> ICMP protocol
                countDict[sourceIP]["ICMP"] += 1
        if protocolUsed == 6: #6 --> TCP protocol
            #get flags for HTTP GET flood
            getFlag = frameInfo.info.packet.payload
            getFlag = str(getFlag)
            #get flags for SYN flood condition
            synFlag = frameInfo.info.tcp.flags.syn
            ackFlag = frameInfo.info.tcp.flags.ack
            ackNo = frameInfo.info.tcp.ack
            #SYN Flood CONDITIONS
            if synFlag == True and ackFlag == False and ackNo != 0:
                countDict[sourceIP]["TCP"] += 1 
            #HTTP GET Flood CONDITIONS    
            if "GET / HTTP" in getFlag:
                countDict[sourceIP]["HTTP_GET"] += 1     

#Getting the no. of occurrences of each individual source IP
cntIP = Counter()
for ip in srcIP:
    cntIP[ip] += 1          
for ip, count in cntIP.most_common():
    results.add_row([ip, count, countDict[ip]["Total_Bytes_Sent"], countDict[ip]["TCP"], countDict[ip]["HTTP_GET"], countDict[ip]["ICMP"], 0]) #, countDict[ip]["ICMP"], countDict[ip]["Slowloris"]])        
print(results)  

result = []

for line in str(results).splitlines():
    splitdata = line.split("|")
    if len(splitdata) == 1:
        continue  # skip lines with no separators
    linedata = []
    for field in splitdata:
        field = field.strip()
        if field:
            linedata.append(field)
    result.append(linedata)

with open('training_data.csv', 'a', newline='') as outcsv:
    writer = csv.writer(outcsv)
    writer.writerows(result)