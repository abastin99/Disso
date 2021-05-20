from ipaddress import IPv4Address
import pcapkit
import os
import pickle
from pcapkit.utilities.validations import pkt_check 
import plotly.graph_objects as go
import tkinter as tk
import tkinter.scrolledtext as st
import pandas as pd
from PIL import Image, ImageTk
from collections import Counter
from tkinter import *
import prettytable
from scapy.all import *
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, r2_score
from prettytable import PrettyTable

def on_closing():
    if os.path.exists("temp/test.png"):
        os.remove("temp/test.png") 

def main():
    while True:
        try:
            user_input = input("Enter PCAP filename or Q to quit: ") #get filename e.g.http-syn-fllod-25-20
            if user_input == "Q" or user_input == "q":
                exit()
            if user_input == "":
                print("This input invaild, please re-enter")
                continue  
            if not os.path.exists("Project\\resources\\Testing Data\\" + user_input + ".pcap"):
                print("invaild input or file doesn't exist, please try again")
                continue    
        except ValueError:
            print("This input invaild, please re-enter")
            continue
        else:
            break
    
    relativePath = 'Project\\resources\\Testing Data\\' + user_input + '.pcap' # Relative directory something like '../test.pcap'
    fullPath = os.path.join(os.getcwd(),relativePath) # gets the fullpath of the file by con current working directory to 
    extraction = pcapkit.extract(fin=fullPath, nofile=True) 
    totalFrames = len(extraction.frame) 

    out = PrettyTable()
    out.field_names = ["No","Time","Source IP", "Destination IP", "Protocol"]
    
    tempTraffic = []
    
    results = PrettyTable()
    results.field_names = ["IP", "Count", "Total_Bytes_Sent", "SYN Flood", "HTTP_GET_Req", "Pings_Sent"]
    #creating lists for all the source IP's, timestamps, and number of bytes
    srcIP = []
    pktTimes = []
    pktBytes = []

    countDict = defaultdict(lambda: defaultdict(lambda: 0)) 
    
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
            #previousTime = extraction.frame[x - 1].info.time
            time = frameTime - firstTime
        if frameInfo != None:
            sourceIP = frameInfo.src
            destinationIP = frameInfo.dst
            protocolUsed = frameInfo.protocol
            out.add_row([x+1,time,sourceIP,destinationIP,protocolUsed])
            tempTraffic.append([x+1,time,sourceIP,destinationIP,protocolUsed])
            #adding the source IP, frame time and frame length to their respective lists
            srcIP.append(sourceIP)
            pktTimes.append(time)
            pktBytes.append(length)
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
    i = 0
    pass_data = pd.DataFrame(columns=["IP", "Count", "Total_Bytes_Sent", "SYN Flood", "HTTP_GET_Req", "Pings_Sent"])
    for ip in srcIP:
        cntIP[ip] += 1          
    for ip, count in cntIP.most_common():
        results.add_row([ip, count, countDict[ip]["Total_Bytes_Sent"], countDict[ip]["TCP"], countDict[ip]["HTTP_GET"], countDict[ip]["ICMP"]]) #countDict[ip]["Slowloris"]])        
        pass_data.loc[i] = [str(ip), count, countDict[ip]["Total_Bytes_Sent"], countDict[ip]["TCP"], countDict[ip]["HTTP_GET"], countDict[ip]["ICMP"]]
        i +=1
    print(results)  

    result = [] 
    limited_data = pass_data[['Count', 'Total_Bytes_Sent','SYN Flood', 'HTTP_GET_Req', 'Pings_Sent']]
    loaded_model = pickle.load(open('RandomForestClassifier.sav', 'rb'))
    result = loaded_model.predict(limited_data)

    #Loop to get Malicious traffic
    malicious_ips = []
    diagnosis = "no attack detected"
    for x in range(len(result)):
        if result[x] == 1:
            malicious_ips.append(pass_data["IP"][x])
    if len(malicious_ips) == 1:  
        diagnosis = "DoS attack detected from " + str(malicious_ips[0])      
    elif len(malicious_ips) > 1:
        diagnosis = "DDoS attack detected from " + str(malicious_ips)
    
    print(diagnosis)  
    
    bad_traffic = PrettyTable()
    bad_traffic.field_names =["No","Time","Source IP", "Destination IP", "Protocol"]
    if len(malicious_ips) > 0:
        for x in range(len(tempTraffic)):
            sIP = str(tempTraffic[x][2])
            dIP = str(tempTraffic[x][3])
            if sIP in malicious_ips or dIP in malicious_ips:
                bad_traffic.add_row(tempTraffic[x])
    else:
        bad_traffic = out        
        
      
    #printing out graph containing number of bytes over time
    bytes = pd.Series(pktBytes).astype(int)
    #Converting the list to a series and the timestamp list to a pd date_time
    times = pd.to_datetime(pd.Series(pktTimes).astype(str), errors='coerce')
    #Create the dataframe
    df  = pd.DataFrame({"Bytes": bytes, "Times":times})
    #set the date from a range to an timestamp
    df = df.set_index('Times')
    #Create a new dataframe of 2 second sums to pass to plotly
    df2=df.resample('2S').sum()
    #Create the graph
    graphData = go.Scatter(x=df2.index, y=df2['Bytes'])
    graphLayout = go.Layout(title="Bytes over Time ",xaxis=dict(title="Time"),yaxis=dict(title="Bytes"))                                       
    fig = go.Figure(data = graphData, layout = graphLayout)
    if not os.path.exists("temp"):
        os.mkdir("temp")
    fig.write_image("temp/test.png")


    ###################  GUI  ######################


    window=tk.Tk()

    window.title('Results')
    window.geometry("1550x600+0+0")

    img = PhotoImage(file="temp/test.png")

    text_area = st.ScrolledText(window,
                                width = 79, 
                                height = 30, 
                                font = ("Courier",
                                        11))
    
    text_area.grid(column = 0, pady = 10, padx = 10)
    
    # Inserting Text which is read only
    text_area.insert(tk.INSERT,bad_traffic)
    
    # Making the text read only
    text_area.configure(state ='disabled')

    label = tk.Label(window,image= img)
    label.place(x= 750, y= 10)
    expTable = tk.Button(window,text="Export Table") #button to export table contents
    expTable.place(x=350, y=550)
    
    def export_graph():
        #downloadTo = ""
        print("Button clicked")
        if os.path.exists("temp/test.png"):
            os.rename("temp/test.png", "C:/Users/andre/Downloads/exportedGraph.png")
    
    expGraph = tk.Button(window,text="Export Graph", command=export_graph)#button to export graph showing bytes over time, command=export_graph())
    expGraph.place(x=1050, y=550)
 
    window.protocol("WM_DELETE_WINDOWS", on_closing)
    window.mainloop()
   
main()        

