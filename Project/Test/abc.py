import pcapkit
import os


os.getcwd()
relativePath = 'Project\\resources\\test.pcap' # Relative directory something like '../test.pcap'
fullPath = os.path.join(os.getcwd(),relativePath) # Produces something like '/home/hallandspur/Documents/test.pcap'
extraction = pcapkit.extract(fin=fullPath, nofile=False, fout='out.plist', format='plist')  
frame0 = extraction.frame[0]
# check if IP in this frame, otherwise ProtocolNotFound will be raised
flag = pcapkit.IP in frame0
tcp = frame0[pcapkit.IP] if flag else None
#print(tcp)
