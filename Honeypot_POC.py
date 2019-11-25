from scapy.all import *

asset_addr = "10.0.0.5"
honeypot_addr = "10.0.0.13"

def handle_packets(pkt):
    response = "response to " + str(pkt[TCP].payload)
    packet = IP(src=honeypot_addr, dst=asset_addr)\
             /TCP(sport=pkt[TCP].dport,dport=pkt[TCP].sport,seq=pkt[TCP].ack,ack=pkt[TCP].seq + len(str(pkt[TCP].payload)), flags='A')\
             /Raw(load=response)
    send(packet)


# Capture Every incoming traffic from the asset.
#while True:
for _ in range(10):
    sniff(prn=handle_packets, filter="tcp", store=0, count=1)

"""
import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
] = ('10.0.0.13', 5005)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for connection
    connection, client_address = sock.accept()
    print >>sys.stderr, 'new connection from ' % client_address
    data = connection.recv(1024)
    print >>sys.stderr, 'received "%s"' % data
    print >>sys.stderr, 'sending data back to the client'
    connection.sendall(data)
    print >>sys.stderr, 'end session with ' % client_address
    connection.close()
"""
