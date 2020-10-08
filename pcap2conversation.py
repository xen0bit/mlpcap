from scapy.all import *
import base64
from tqdm import tqdm
pkts = rdpcap("./pcaps/http.pcap")
with open('./data/test.txt', 'a') as f:
    for pkt in tqdm(pkts):
        #print(base64.standard_b64encode(pkt['Raw'].load))
        f.write(base64.standard_b64encode(pkt['Raw'].load).decode("utf-8").replace('=','') + '\n')