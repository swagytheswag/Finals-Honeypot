from scapy.all import *

asset_addr = "10.0.0.1"
honeypot_addr = "10.0.0.13"

def handle_packets(pkt):
    pkt = IP(src=honeypot_addr, dst=asset_addr)/ICMP()/"response to "+str(pkt.summary())
    send(pkt)


# Capture Every incoming traffic from the asset.

sniff(prn=handle_packets, filter="icmp", store=0, count=1)