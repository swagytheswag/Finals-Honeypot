
import pydivert
import scapy.all as scapy


asset_addr = "10.0.0.5"
honeypot_addr = "10.0.0.13"
incoming_addr = []
# Capture Every incoming traffic.
w = pydivert.WinDivert("tcp and (ip.SrcAddr == 10.0.0.6 or ip.SrcAddr == %s)"%(honeypot_addr))


w.open()  # Packets will be captured from now on
while True:
    packet = w.recv()  # Read a single packet

    # If the packet came from the honeypot
    if packet.ipv4.src_addr == honeypot_addr:
        # rout the packet back to the original sender
        packet.ipv4.src_addr = asset_addr
        packet.ipv4.dst_addr = str(incoming_addr.pop(0))
        packet.direction = 0 # outbounding
        w.send(packet)
        # if it's TCP, send also a FIN
        if packet.tcp:
            # using scapy
            scapy.send(scapy.IP(src=asset_addr,dst=packet.ipv4.dst_addr)\
                /scapy.TCP(sport=packet.src_port,dport=packet.dst_port,flags='FA',\
                    seq=packet.tcp.seq_num, ack=packet.tcp.ack_num))

      
    # Else it's an outside traffic
    else:
        # if it's TCP SYN, Send back SYN-ACK (to the same port)
        if packet.tcp.syn:
            # using scapy
            scapy.send(scapy.IP(src=asset_addr,dst=packet.ipv4.src_addr)\
                /scapy.TCP(sport=packet.dst_port,dport=packet.src_port,flags='SA',\
                    seq=packet.tcp.ack_num, ack=packet.tcp.seq_num+1))
        # if it's TCP ACK, it's alright ;)
        elif packet.tcp.ack and not packet.tcp.psh:
            pass
        
        else:
            # save the incoming 
            incoming_addr.append(str(packet.ipv4.src_addr))
            # rout the packet to the honeypot
            packet.ipv4.dst_addr = honeypot_addr
            packet.direction = 0 # outbounding
            w.send(packet)

w.close()  # stop capturing packets