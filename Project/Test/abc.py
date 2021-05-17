import pcapkit
import os 
import plotly 
import tkinter as tk
import tkinter.scrolledtext as st
from collections import Counter
from scapy.all import *
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, r2_score
from prettytable import PrettyTable

relativePath = 'Project\\resources\\http-syn-fllod-25-20.pcap' # Relative directory something like '../test.pcap'
fullPath = os.path.join(os.getcwd(),relativePath) # gets the fullpath of the file by con current working directory to 
extraction = pcapkit.extract(fin=fullPath, nofile=True) 
totalFrames = len(extraction.frame) 


out = PrettyTable()
out.field_names = ["No","Time","Source IP", "Destination IP", "Protocol"]

sIP = PrettyTable()
sIP.field_names = ["IP", "Count", "TCP Flag Issue"]

#creating lists for all the source IP's, timestamps, and number of bytes
srcIP = []
pktTimes = []
pktBytes = []

cntbadSYN = Counter()
countDict = defaultdict(lambda: defaultdict(lambda: 0)) #ask alex to check that this is ok?
#countDict = defaultdict(lambda: 0)

# check if IP in this frame, otherwise don't print
for x in range(totalFrames):
    flag = pcapkit.IP in extraction.frame[x]
    frameInfo = extraction.frame[x][pcapkit.IP] if flag else None
    frameTime = extraction.frame[x].info.time  #frame_info
    ###I DON'T KNOW#######length = frameInfo.len
    if x == 0:
        firstTime = frameTime
        time = 0.0000
    if x >= 1:
        previousTime = extraction.frame[x - 1].info.time
        time = frameTime - firstTime
    if frameInfo != None:
        sourceIP = frameInfo.src
        destinationIP = frameInfo.dst
        protocolUsed = frameInfo.protocol
        #########SEND HELP########bytesUsed = frameInfo.
        out.add_row([x+1,time,sourceIP,destinationIP,protocolUsed])
        srcIP.append(sourceIP)
        pktTimes.append(time)
        #SYN Flood CONDITIONS 
        if protocolUsed == 6: #6 --> TCP protocol
            synFlag = frameInfo.info.tcp.flags.syn
            ackFlag = frameInfo.info.tcp.flags.ack
            ackNo = frameInfo.info.tcp.ack
            if synFlag == True and ackFlag == False and ackNo != 0:
                countDict[sourceIP]["TCP"] += 1      
            
print(countDict)



#Getting the no. of occurrences of each individual source IP
cntIP = Counter()
for ip in srcIP:
    cntIP[ip] += 1          
for ip, count in cntIP.most_common():
   sIP.add_row([ip, count, countDict[ip]["TCP"]])        
print(sIP)  

###################  GUI  ######################


window=tk.Tk()

window.title('Results')
window.geometry("990x600+300+100")

text_area = st.ScrolledText(window,
                            width = 80, 
                            height = 24, 
                            font = ("Courier",
                                    15))
  
text_area.grid(column = 0, pady = 10, padx = 10)
  
# Inserting Text which is read only
text_area.insert(tk.INSERT,out)
  
# Making the text read only
text_area.configure(state ='disabled')

window.mainloop()
