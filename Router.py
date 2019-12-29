import pydivert
import scapy.all as scapy
import re
import urllib
import logging


class Router(object):
    def __init__(self, asset_addr, honeypot_addr):
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr
        self.blacklist = []
        self.w = pydivert.WinDivert("(tcp.SrcPort == 5000 or tcp.DstPort == 5000) and ip.SrcAddr != %s"%(self.asset_addr))

        open('logger.log', 'w').close()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')

        self.file_handler = logging.FileHandler('logger.log')
        self.file_handler.setLevel(logging.INFO)
        self.file_handler.setFormatter(self.formatter)

        self.stream_handler = logging.StreamHandler()
        self.stream_handler.setLevel(logging.DEBUG)
        self.stream_handler.setFormatter(self.formatter)

        self.logger.addHandler(self.file_handler)
        self.logger.addHandler(self.stream_handler)
    
    def start_router(self):
        self.logger.info('Starting The Router')
        self.w.open()   # Packets will be captured from now on

    def stop_router(self):
        self.logger.info('Stopping The Router')
        self.w.close()  # stop capturing packets

    def from_honeypot(self, packet):
        return packet.ipv4.src_addr == self.honeypot_addr
    
    def handle_packet_from_honeypot(self, packet):
        # rout the packet back to the original sender
        # self.send_packet_with_original_destination(packet)
        packet.ipv4.src_addr = self.asset_addr
        packet.ipv4.dst_addr = '10.0.0.2'
        packet.direction = 0  # outbounding
        self.w.send(packet)
        self.logger.debug('Redirecting a packet from the Honeypot to the Hacker at %s' % (packet.ipv4.dst_addr))

    def handle_packet_from_outside(self, packet):
        if packet.ipv4.src_addr == self.asset_addr:
            self.w.send(packet)
        else:
            if packet.ipv4.src_addr in self.blacklist:
                self.send_to_honeypot(packet)
                self.logger.debug('Redirecting a blacklisted packet to the Honeypot from %s'%(packet.ipv4.src_addr))

            # if the packet includes malicious data
            elif self.is_malicious(packet):
                self.blacklist.append(packet.ipv4.src_addr)
                self.send_to_honeypot(packet)
                self.logger.debug('Redirecting a malicious packet to the Honeypot from %s'%(packet.ipv4.src_addr))

            # if the packet is safe, let it go
            else:
                self.w.send(packet)
                self.logger.debug('Let in a non-malicious, non-blacklisted packet from %s'%(packet.ipv4.src_addr))

    def send_to_honeypot(self, packet):
        '''
        # rout the packet to the honeypot
        if packet.payload:
            srcaddr = packet.ipv4.src_addr
            dstaddr = self.honeypot_addr
            srcport = packet.src_port
            dstport = packet.dst_port
            seqnum = packet.tcp.seq_num
            acknum = packet.tcp.ack_num + (packet.payload.count(self.asset_addr)+1)*(len(self.asset_addr)-len(self.honeypot_addr))
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

            html = scapy.Raw(load=packet.payload.replace(self.asset_addr, self.honeypot_addr))
            ip = scapy.IP(src=srcaddr, dst=dstaddr)
            tcp = scapy.TCP(sport=srcport, dport=dstport, flags=flg, seq=seqnum, ack=acknum)
            pkt = ip / tcp / html
            scapy.send(pkt)

        else:
        '''
        packet.ipv4.src_addr = self.asset_addr
        packet.ipv4.dst_addr = self.honeypot_addr
        #packet.payload = packet.payload.replace(self.asset_addr, self.honeypot_addr)
        packet.direction = 0  # outbounding
        self.w.send(packet)

    def router_mainloop(self):
        packet = self.w.recv()  # Read a single packet
        # If the packet came from the honeypot
        if self.from_honeypot(packet):
            self.handle_packet_from_honeypot(packet)
        
        # Else it's an outside traffic
        else:
            self.handle_packet_from_outside(packet)

    def is_malicious(self, packet):
        # for SQLI
        pattern = re.compile(r"&email=(?P<email>.*)&password=(?P<password>.*)&submit=Login")
        m = re.search(pattern, packet.payload)

        if packet.payload[0:4] == 'POST' and m:
            credentials = (urllib.unquote(m.group('email')), urllib.unquote(m.group('password')))
            for cred in credentials:
                if '"' in cred or "'" in cred:
                    self.logger.warning('SQLInjection attempt caught from %s'%(packet.ipv4.src_addr))
                    return True
        return False




router = Router("10.0.0.7", "10.0.0.17")    # Initialize the router opbject
router.start_router()  # Packets will be captured from now on
while True:
    router.router_mainloop()

router.stop_router()    # stop capturing packets