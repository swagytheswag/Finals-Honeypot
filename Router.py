import pydivert
import scapy.all as scapy


class Router(object):
    def __init__(self, asset_addr, honeypot_addr):
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr
        self.w = pydivert.WinDivert("tcp and (ip.SrcAddr == 10.0.0.6 or ip.SrcAddr == %s)"%(honeypot_addr))
        self.incoming_addr = []
    
    def start_router(self):
        self.w.open()   # Packets will be captured from now on

    def stop_router(self):
        self.w.close()  # stop capturing packets

    def from_honeypot(self, packet):
        return packet.ipv4.src_addr == self.honeypot_addr
    
    def handle_packet_from_honeypot(self, packet):
        # rout the packet back to the original sender
        packet.ipv4.src_addr = asset_addr
        packet.ipv4.dst_addr = str(incoming_addr.pop(0))
        packet.direction = 0 # outbounding
        self.w.send(packet)
        # if it's TCP, send also a FIN
        if packet.tcp:
            # using scapy
            scapy.send(scapy.IP(src=asset_addr,dst=packet.ipv4.dst_addr)\
                /scapy.TCP(sport=packet.src_port,dport=packet.dst_port,flags='FA',\
                    seq=packet.tcp.seq_num, ack=packet.tcp.ack_num))
    
    def handle_packet_from_outside(self, packet):
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
            self.incoming_addr.append(str(packet.ipv4.src_addr))
            # rout the packet to the honeypot
            packet.ipv4.dst_addr = self.honeypot_addr
            packet.direction = 0 # outbounding
            self.w.send(packet)

    def router_mainloop(self):
        packet = self.w.recv()  # Read a single packet

        # If the packet came from the honeypot
        if router.from_honeypot(packet):
            router.handle_packet_from_honeypot(packet)
        
        # Else it's an outside traffic
        else:
            router.handle_packet_from_outside(packet)



router = Router("10.0.0.5", "10.0.0.13")    # Initialize the router opbject 
router.start_router()  # Packets will be captured from now on
while True:
    router.router_mainloop()

router.stop_router()    # stop capturing packets