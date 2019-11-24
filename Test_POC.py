from scapy.all import *

asset_addr = "10.0.0.1"
send(IP(src = '10.0.0.8', dst = asset_addr)/ICMP()/'LALALALALALA')
pkt = sniff(filter="icmp", count=1)[0]

pkt.show()
