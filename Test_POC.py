"""
from scapy.all import *
import socket

asset_addr = "10.0.0.5"

send(IP(src = '10.0.0.6', dst = asset_addr)/TCP())#/'LALALALALALA')

pkt = sniff(filter="ip.addr == 10.0.0.5 and tcp", count=1)


print str(pkt.show())
"""
import socket
import sys

TCP_IP = '10.0.0.5'
TCP_PORT = 5005
BUFFER_SIZE = 1024
MESSAGE = "Hello, World!"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)
s.close()

print "received data:", data
