import pydivert
import scapy.all as scapy
import re
import urllib
import logging
#from SessionManager import SessionManager, Client, Session
import socket
import threading


class Router(object):
    def __init__(self, asset_addr, honeypot_addr):
        """
        Creating a Router instance which handles incoming packets, defends against attacks and logs everything.
        :param asset_addr:
        :param honeypot_addr:
        """
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr
        #self.session_manager = SessionManager()
        self.w = pydivert.WinDivert("(tcp.SrcPort == 50000 or tcp.DstPort == 50000) and ip.SrcAddr != %s and ip.SrcAddr != %s"%(self.asset_addr, self.honeypot_addr))

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
        threading.Thread(target = send_to_asset_handler, args = (self.asset_addr, )).start()
        threading.Thread(target = send_to_honeypot_handler, args = (self.honeypot_addr, )).start()

    def stop_router(self):
        self.logger.info('Stopping The Router')
        self.w.close()  # stop capturing packets

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
                    self.logger.warning('SQLInjection attempt caught from %s' % (packet.ipv4.src_addr))
                    return True
        return False

    def router_mainloop(self):
        '''
        The mainloop of the Router
        '''

        global send_to_asset
        global send_to_honeypot

        packet = self.w.recv()  # Read a single packet

        # if it's TCP SYN, Send back SYN-ACK (to the same port)
        if packet.tcp.syn:
            # using scapy
            scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                       / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='SA', \
                                   seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + 1))
        # if it's TCP ACK, it's alright ;)
        elif packet.tcp.ack and not packet.tcp.psh:
            pass

        elif packet.tcp.ack and packet.tcp.psh:
            elif self.is_malicious(packet):
                send_to_honeypot.append(packet)
            else:
                send_to_asset.append(packet)


def get_packet_payload(packet):
    pkt = scapy.IP(packet.ipv4.raw.tobytes())
    return str(pkt[scapy.TCP].payload)

def send_to_asset_handler(asset_addr):
    global send_to_asset
    while True:
        if send_to_asset:
            packet = send_to_asset.pop(0)
            payload = get_packet_payload(packet)

            HOST = asset_addr
            PORT = 55555
            BUFFSIZ = 4096
            ADDR = (HOST, PORT)

            tcpClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcpClientSock.connect(ADDR)
            tcpClientSock.send(payload)

            payload_to_send = ""
            while True:
                data = tcpClientSock.recv(BUFFSIZ)
                if not data: break
                payload_to_send += data
            tcpClientSock.close()

            ack_back = scapy.IP(packet.ipv4.raw.tobytes())
            ack_back[scapy.TCP].seq = ack_back[scapy.TCP].seq + len(ack_back[scapy.TCP].payload)

            scapy.send(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                       / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='A', \
                                   seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq), \
                       verbose=False)
            n = int(len(payload_to_send)/5)
            payloads_to_send = [payload_to_send[0:n], payload_to_send[n:2*n], payload_to_send[2*n:3*n], payload_to_send[3*n:4*n], payload_to_send[4*n:]]
            for pay in payloads_to_send:
                ack_back = scapy.sr1(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                               / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='PA', \
                                           seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                                / scapy.Raw(pay) \
                                , verbose=False)

            scapy.send(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                       / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='F', \
                                   seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                       , verbose=False)


def send_to_honeypot_handler(honeypot_addr):
    global send_to_honeypot
    while True:
        if send_to_honeypot:
            packet = send_to_honeypot.pop(0)
            payload = get_packet_payload(packet)

            HOST = honeypot_addr
            PORT = 55555
            BUFFSIZ = 4096
            ADDR = (HOST, PORT)

            tcpClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcpClientSock.connect(ADDR)
            tcpClientSock.send(payload)

            payload_to_send = ""
            while True:
                data = tcpClientSock.recv(BUFFSIZ)
                if not data: break
                payload_to_send += data
            tcpClientSock.close()

            ack_back = scapy.IP(packet.ipv4.raw.tobytes())
            ack_back[scapy.TCP].seq = ack_back[scapy.TCP].seq + len(ack_back[scapy.TCP].payload)

            scapy.send(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                       / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='A', \
                                   seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq), \
                       verbose=False)
            n = int(len(payload_to_send) / 5)
            payloads_to_send = [payload_to_send[0:n], payload_to_send[n:2 * n], payload_to_send[2 * n:3 * n],
                                payload_to_send[3 * n:4 * n], payload_to_send[4 * n:]]
            for pay in payloads_to_send:
                ack_back = scapy.sr1(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                                     / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport,
                                                 flags='PA', \
                                                 seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                                     / scapy.Raw(pay) \
                                     , verbose=False)

            scapy.send(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                       / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='F', \
                                   seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                       , verbose=False)


global send_to_asset
send_to_asset = []
global send_to_honeypot
send_to_honeypot = []

router = Router("10.0.0.7", "10.0.0.17")    # Initialize the router object
router.start_router()  # Packets will be captured from now on
while True:
    router.router_mainloop()

router.stop_router()    # stop capturing packets