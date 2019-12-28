import pydivert
import scapy.all as scapy
import urllib


class Router(object):
    def __init__(self, asset_addr, honeypot_addr):
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr
        self.w = pydivert.WinDivert("(tcp.SrcPort == 5000 or tcp.DstPort == 5000) and ip.SrcAddr == %s"%(self.honeypot_addr))
    
    def start_router(self):
        print 'Starting The Router'
        self.w.open()   # Packets will be captured from now on

    def stop_router(self):
        print 'Stopping The Router'
        self.w.close()  # stop capturing packets

    def router_mainloop(self):
        packet = self.w.recv()  # Read a single packet
        # If the packet fired from the honeypot, outbound
        if packet.direction == 0:
            packet.ipv4.dst_addr = self.asset_addr
            #self.send_packet_with_original_destination(packet)
            print 'Sending a packet for %s to the Asset' % (packet.ipv4.dst_addr)

    def send_packet_with_original_destination(self, packet):
        print packet.payload
        srcaddr = self.honeypot_addr
        dstaddr = self.asset_addr
        srcport = packet.src_port
        dstport = packet.dst_port
        seqnum = packet.tcp.seq_num
        acknum = packet.tcp.ack_num+len(self.asset_addr)+len('origin')
        flg = ""
        if packet.tcp.fin:
            flg += "F"
        if packet.tcp.syn:
            flg += "S"
        if packet.tcp.ack:
            flg += "A"
        if packet.tcp.psh:
            flg += "P"
        if packet.tcp.urg:
            flg += "U"
        if packet.tcp.rst:
            flg += "R"

        html = scapy.Raw(load = packet.payload + 'origin' + packet.ipv4.dst_addr)
        ip = scapy.IP(src = srcaddr, dst = dstaddr)
        tcp = scapy.TCP(sport=srcport, dport=dstport, flags=flg, seq=seqnum, ack=acknum)
        pkt = ip/tcp/html
        scapy.send(pkt)

router = Router("10.0.0.7", "10.0.0.17")    # Initialize the router opbject
router.start_router()  # Packets will be captured from now on
while True:
    router.router_mainloop()

router.stop_router()    # stop capturing packets