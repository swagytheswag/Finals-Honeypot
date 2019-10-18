import pydivert

asset_addr = "10.0.0.1"
honeypot_addr = "10.0.0.13"
incoming_addr = []
# Capture Every incoming traffic.
w = pydivert.WinDivert("icmp and ip.DstAddr == %s"%(asset_addr))


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
        
    # Else it's an outside traffic
    else:
        # save the incoming 
        incoming_addr.append(str(packet.ipv4.src_addr))
        # rout the packet to the honeypot
        packet.ipv4.dst_addr = honeypot_addr
        packet.direction = 0 # outbounding
        w.send(packet)

w.close()  # stop capturing packets