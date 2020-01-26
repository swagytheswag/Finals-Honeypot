import pydivert
import scapy.all as scapy
import re
import urllib
import logging
from SessionManager import SessionManager, Client, Session


class Router(object):
    def __init__(self, asset_addr, honeypot_addr):
        """
        Creating a Router instance which handles incoming packets, defends against attacks and logs everything.
        :param asset_addr:
        :param honeypot_addr:
        """
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr
        self.session_manager = SessionManager()
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
        return packet.ipv4.src_addr == self.honeypot_addr # checks if the packet from the honeypot
    
    def handle_packet_from_honeypot(self, packet):
        # rout the packet back to the original sender
        self.session_manager.update_honeypot_sessions(packet)
        if self.session_manager.is_client_blacklisted(packet):
            self.send_from_honeypot_to_client(packet)
            self.logger.debug('Redirecting a packet from the Honeypot to the Hacker at %s' % (packet.ipv4.dst_addr))

    def handle_packet_from_outside(self, packet):
        """
        Handles packets from outside clients.
        :param packet:
        """
        if packet.ipv4.src_addr == self.asset_addr:
            self.w.send(packet)
        else:
            self.session_manager.update_incoming_sessions(packet)
            if self.session_manager.is_client_blacklisted(packet):
                pass
                #self.logger.debug('Redirecting a blacklisted packet to the Honeypot from %s' % (packet.ipv4.src_addr))

            # if the packet includes malicious data
            elif self.is_malicious(packet):
                self.session_manager.blacklist_client(packet)
                self.logger.debug('Redirecting a malicious packet to the Honeypot from %s' % (packet.ipv4.src_addr))
                #self.start_tcp_session_with_honeypot(packet)

            # if the packet is safe, let it go
            else:
                self.logger.debug('Let in a non-malicious, non-blacklisted packet from %s' % (packet.ipv4.src_addr))
                self.w.send(packet)

            self.send_to_honeypot(packet)

    def send_to_honeypot(self, packet):
        """
        Redirect the packet to the honeypot.
        :param packet:
        :return:
        """
        sess = self.session_manager.get_honeypot_session(packet)

        packet.direction = 0  # outbounding
        pkt = scapy.IP(packet.ipv4.raw.tobytes())
        # Correct the IP/TCP fields
        if isinstance(sess, int):
            del pkt[scapy.IP].id
            pkt[scapy.IP].id = sess
            print pkt[scapy.IP].id
            del pkt[scapy.IP].chksum
            pkt[scapy.IP].src = self.asset_addr
            pkt[scapy.IP].dst = self.honeypot_addr
            pkt[scapy.TCP].seq = packet.tcp.ack_num
            pkt[scapy.TCP].ack = packet.tcp.seq_num + packet.tcp.header_len
        else:
            del pkt[scapy.IP].id
            pkt[scapy.IP].id = sess.ipv4_id
            del pkt[scapy.IP].chksum
            pkt[scapy.IP].src = self.asset_addr
            pkt[scapy.IP].dst = self.honeypot_addr
            pkt[scapy.TCP].seq = sess.tcp_ack
            pkt[scapy.TCP].ack = sess.tcp_seq + sess.tcp_header_len - 40

            # Change the payload to fit the Honeypot's IP
        payload_before = len(pkt[scapy.TCP].payload)
        pkt[scapy.TCP].payload = scapy.Raw(str(pkt[scapy.TCP].payload).replace(self.asset_addr, self.honeypot_addr))
        payload_after = len(pkt[scapy.TCP].payload)
        payload_dif = payload_after - payload_before
        pkt[scapy.IP].len = pkt[scapy.IP].len + payload_dif

        # calculate the correct TCP fields
        del pkt[scapy.TCP].chksum
        del pkt[scapy.TCP].window
        pkt[scapy.TCP] = pkt[scapy.TCP].__class__(str(pkt[scapy.TCP]))

        scapy.send(pkt)

    def send_from_honeypot_to_client(self, packet):
        sess = self.session_manager.get_asset_session(packet)

        packet.direction = 0  # outbounding
        pkt = scapy.IP(packet.ipv4.raw.tobytes())
        # Correct the IP/TCP fields
        pkt[scapy.IP].id = sess['ipv4_id']
        del pkt[scapy.IP].chksum
        pkt[scapy.IP].src = self.asset_addr
        pkt[scapy.IP].dst = sess['tcp_src_port']
        pkt[scapy.TCP].seq = sess['tcp_ack']
        pkt[scapy.TCP].ack = sess['tcp_seq'] + sess['tcp_header_len']

        # Change the payload to fit the Honeypot's IP
        payload_before = len(pkt[scapy.TCP].payload)
        pkt[scapy.TCP].payload = scapy.Raw(str(pkt[scapy.TCP].payload).replace(self.asset_addr, self.honeypot_addr))
        payload_after = len(pkt[scapy.TCP].payload)
        payload_dif = payload_after - payload_before
        pkt[scapy.IP].len = pkt[scapy.IP].len + payload_dif

        # calculate the correct TCP fields
        del pkt[scapy.TCP].chksum
        del pkt[scapy.TCP].window
        pkt[scapy.TCP] = pkt[scapy.TCP].__class__(str(pkt[scapy.TCP]))

        scapy.send(pkt)

    def router_mainloop(self):
        '''
        The mainloop of the Router
        '''
        packet = self.w.recv()  # Read a single packet
        # If the packet came from the honeypot
        if self.from_honeypot(packet):
            self.handle_packet_from_honeypot(packet)
        
        # Else it's an outside traffic
        else:
            self.handle_packet_from_outside(packet)

    def is_malicious(self, packet):
        """
        Checks if a packet is malicious
        :param packet:
        :return:
        """
        # for SQLI
        pattern = re.compile(r"email=(?P<email>.*)&password=(?P<password>.*)&submit=Login")
        m = re.search(pattern, packet.payload)

        if packet.payload[0:4] == 'POST' and m:
            credentials = (urllib.unquote(m.group('email')), urllib.unquote(m.group('password')))
            for cred in credentials:
                if '"' in cred or "'" in cred:
                    self.logger.warning('SQLInjection attempt caught from %s'%(packet.ipv4.src_addr))
                    return True
        return False

    def start_tcp_session_with_honeypot(self, packet):
        synack = scapy.sr1(scapy.IP(src=self.asset_addr, dst=self.honeypot_addr) \
                   / scapy.TCP(sport=packet.src_port, dport=packet.dst_port, flags='S', \
                               seq=packet.tcp.seq_num-1, ack=packet.tcp.ack_num))

        scapy.send(scapy.IP(src=self.asset_addr, dst=self.honeypot_addr) \
                   / scapy.TCP(sport=packet.src_port, dport=packet.dst_port, flags='A', \
                               seq=packet.tcp.seq_num, ack=synack[scapy.TCP].seq+1))

        packet.direction = 0  # outbounding
        pkt = scapy.IP(packet.ipv4.raw.tobytes())
        # Correct the IP/TCP fields
        del pkt[scapy.IP].id
        del pkt[scapy.IP].chksum
        pkt[scapy.IP].src = self.asset_addr
        pkt[scapy.IP].dst = self.honeypot_addr
        pkt[scapy.TCP].seq = synack[scapy.TCP].ack
        pkt[scapy.TCP].ack = synack[scapy.TCP].seq + 1

        # Change the payload to fit the Honeypot's IP
        payload_before = len(pkt[scapy.TCP].payload)
        pkt[scapy.TCP].payload = scapy.Raw(str(pkt[scapy.TCP].payload).replace(self.asset_addr, self.honeypot_addr))
        payload_after = len(pkt[scapy.TCP].payload)
        payload_dif = payload_after - payload_before
        pkt[scapy.IP].len = pkt[scapy.IP].len + payload_dif

        # calculate the correct TCP fields
        del pkt[scapy.TCP].chksum
        del pkt[scapy.TCP].window
        pkt[scapy.TCP] = pkt[scapy.TCP].__class__(str(pkt[scapy.TCP]))

        scapy.send(pkt)




router = Router("10.0.0.7", "10.0.0.17")    # Initialize the router opbject
router.start_router()  # Packets will be captured from now on
while True:
    router.router_mainloop()

router.stop_router()    # stop capturing packets