import pydivert
import scapy.all as scapy
import urllib
import socket
import threading
from logGui import *
import re
from father_router import BaseWrapper

class Router50000(BaseWrapper):
    def __init__(self, father_router):
        super(Router50000, self).__init__(father_router)
        """
        Creating a Router instance which handles incoming packets to port 50000 (HTTP), defends against attacks and logs everything.
        :param father_router: the main router which this one encapsulate
        """
        self.syn_counter = 0
        self.w = pydivert.WinDivert("(tcp.SrcPort == 50000 or tcp.DstPort == 50000) and ip.SrcAddr != %s and ip.SrcAddr != %s"%(self.asset_addr, self.honeypot_addr))

        self.all_packets = []
        self.send_to_asset = []
        self.send_to_honeypot = []

    def start_router(self):
        # for the Tkinter GUI
        threading.Thread(target=self.my_gui.gui_worker).start()

        self.logger.info('Starting The HTTP Router')
        threading.Thread(target=self.all_packets_handler, args=()).start()
        threading.Thread(target=self.send_to_asset_handler, args=()).start()
        threading.Thread(target=self.send_to_honeypot_handler, args=()).start()
        self.w.open()   # Packets will be captured from now on

        threading.Thread(target=self.router_mainloop, args=()).start() # start the mainloop action

    def stop_router(self):
        self.logger.info('Stopping The HTTP Router')
        self.w.close()  # stop capturing packets

    def is_malicious(self, packet, payload):
        """
        Checks if a packet is malicious
        :param payload:
        :return:
        """
        # for SQLI
        pattern = re.compile(r"email=(?P<email>.*)&password=(?P<password>.*)&submit=Login")
        m = re.search(pattern, payload)

        if payload[0:4] == 'POST' and m:
            credentials = (urllib.unquote(m.group('email')), urllib.unquote(m.group('password')))
            for cred in credentials:
                if '"' in cred or "'" in cred:
                    self.logger.warning('SQLInjection attempt caught from %s' % (packet.ipv4.src_addr))
                    threading.Thread(target=self.fingerprinting, args=(packet,)).start()
                    return True
        return False

    def router_mainloop(self):
        '''
        The mainloop of the Router
        '''
        while True:
            packet = self.w.recv()  # Read a single packet

            # if it's TCP SYN, Send back SYN-ACK (to the same port)
            if packet.tcp.syn:
                self.syn_counter += 1
                # using scapy
                scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                           / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='SA', \
                                       seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + 1), \
                           verbose=False)
            elif packet.tcp.fin:
                scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                           / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='FA', \
                                       seq=packet.tcp.ack_num, ack=packet.tcp.seq_num), \
                           verbose=False)
                scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                           / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='A', \
                                       seq=packet.tcp.ack_num, ack=packet.tcp.seq_num+1), \
                           verbose=False)
            # if packet has payload over TCP, deal with it
            elif packet.tcp.ack and len(self.get_packet_payload(packet)) > 1:
                scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                           / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='A', \
                                       seq=packet.tcp.ack_num, ack=packet.tcp.seq_num+len(self.get_packet_payload(packet))), \
                           verbose=False)
                payload = self.get_packet_payload(packet)
                self.all_packets.append((packet, payload))
            # if it's TCP ACK, it's alright ;)
            else:
                if self.syn_counter > 0:
                    self.syn_counter -= 1
                pass

            # syn flood:
            if self.syn_counter >= 5:
                self.syn_counter = 0
                self.logger.warning('SYN Flood - DOS caught. Router paused for 50000 seconds')
                time.sleep(60)

    def all_packets_handler(self):
        '''
        Goes through all the incoming packets and decides what to do with them.
        :return:
        '''
        while True:
            if self.all_packets: # if there's a packet to read
                packet, payload = self.all_packets.pop(0)
                # check if the full payload has arrived
                pattern = re.compile(r"Content-Length: (?P<content_length>\d*)")
                m = re.search(pattern, payload)
                content_length = m.group('content_length') if m else 0

                pattern = re.compile(r"\r\n\r\n(?P<content>(.|\s)*)")
                m = re.search(pattern, payload)
                # if not, search for the full payload in the next packets
                while not m or int(len(m.group('content'))) != int(content_length):
                    while True:
                        if self.all_packets: break
                    packet, xpayload = self.all_packets.pop(0)
                    payload += xpayload
                    m = re.search(pattern, payload)

                if packet.ipv4.src_addr in self.blacklist or self.is_malicious(packet, payload):
                    if packet.ipv4.src_addr not in self.blacklist:
                        self.add_to_blacklist(packet.ipv4.src_addr)
                        self.logger.info('%s is now blacklisted' % (packet.ipv4.src_addr))
                    self.send_to_honeypot.append((packet, payload))
                else:
                    self.send_to_asset.append((packet, payload))

    def send_to_asset_handler(self):
        '''
        Goes through all the packets directed to the asset.
        Talks with the asset and redirects the answer to the original sender.
        '''
        while True:
            if self.send_to_asset: # if there's a packet to read
                packet, payload = self.send_to_asset.pop(0)

                HOST = self.asset_addr
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
                '''
                scapy.send(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                           / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='A', \
                                       seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq), \
                           verbose=False)
                '''
                n = int(len(payload_to_send)/5)
                payloads_to_send = [payload_to_send[0:n], payload_to_send[n:2*n], payload_to_send[2*n:3*n], payload_to_send[3*n:4*n], payload_to_send[4*n:]]
                for pay in payloads_to_send:
                    ack_back = scapy.sr1(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                                   / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport, flags='PA', \
                                               seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                                    / scapy.Raw(pay), \
                                    verbose=False)

    def send_to_honeypot_handler(self):
        '''
        Goes through all the packets directed to the honeypot.
        Talks with the honeypot and redirects the answer to the original sender.
        '''
        while True:
            if self.send_to_honeypot: # if there's a packet to read
                packet, payload = self.send_to_honeypot.pop(0)

                HOST = self.honeypot_addr
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
                                         / scapy.Raw(pay), \
                                         verbose=False)