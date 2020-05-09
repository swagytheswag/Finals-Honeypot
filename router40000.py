import pydivert
import scapy.all as scapy
import socket
import threading
from logGui import *
from father_router import BaseWrapper

class Disconnected(Exception):
    pass
class Blacklisted(Exception):
    pass

class Router40000(BaseWrapper):
    def __init__(self, father_router):
        super(Router40000, self).__init__(father_router)
        """
        Creating a Router instance which handles incoming packets to port 40000 (Telnet), defends against attacks and logs everything.
        :param father_router: the main router which this one encapsulate
        """
        self.syn_counter = 0
        self.filter = "(tcp.SrcPort == 40000 or tcp.DstPort == 40000) and ip.SrcAddr != %s and ip.SrcAddr != %s"%(self.asset_addr, self.honeypot_addr)
        self.w = pydivert.WinDivert(self.filter)

        self.allowed_commands = []
        # get all allowed commands from the file
        with open("allowed_commands.txt", 'rb') as commands_file:
            for line in commands_file:
                self.allowed_commands.append(line.replace("\n", ""))

        self.active_clients = []

    def start_router(self):
        # for the Tkinter GUI
        threading.Thread(target=self.my_gui.gui_worker).start()

        self.logger.info('Starting The Telnet Router')
        self.w.open()   # Packets will be captured from now on

        threading.Thread(target=self.router_mainloop, args=()).start()  # start the mainloop action
        threading.Thread(target=self.catch_unwanted_resets, args=()).start()  # catch unwanted resets made by the kernel

    def stop_router(self):
        self.logger.info('Stopping The Telnet Router')
        self.w.close()  # stop capturing packets

    def catch_unwanted_resets(self):
        z = pydivert.WinDivert("tcp.SrcPort == 40000 and tcp.Rst and ip.SrcAddr == %s" % (self.asset_addr))
        z.open()
        while True:
            z.recv()

    def is_malicious(self, packet, payload):
        """
        Checks if a packet is malicious
        :param payload:
        :return:
        """
        if payload.startswith('execute '):
            if payload.replace('execute ', '') not in self.allowed_commands:
                self.logger.warning('Disallowed command execution attempted by %s' % (packet.ipv4.src_addr))
                threading.Thread(target=self.fingerprinting, args=(packet,)).start()
                return True
        return False

    def router_mainloop(self):
        '''
        The mainloop of the Router
        '''
        while True:
            packet = self.w.recv()  # Read a single packet

            # if it's from an active client it should be handled by the correct thread
            if packet.ipv4.src_addr in self.active_clients:
                self.w.send(packet)

            # if it's TCP SYN, Send back SYN-ACK (to the same port)
            elif packet.tcp.syn:
                self.syn_counter += 1
                # using scapy
                scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                           / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='SA', \
                                       seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + 1), \
                           verbose=False)
            # if it's TCP ACK, the client is invested in a connection.
            else:
                if packet.src_addr not in self.blacklist:
                    threading.Thread(target=self.handle_client_with_asset, args=(packet,)).start()
                else:
                    threading.Thread(target=self.handle_client_with_honeypot, args=(packet,)).start()
                time.sleep(1)
                if self.syn_counter > 0:
                    self.syn_counter -= 1
                pass

            # syn flood:
            if self.syn_counter >= 5:
                self.syn_counter = 0
                self.logger.warning('SYN Flood - DOS caught. Router40000 paused for 60 seconds')
                time.sleep(60)

    def handle_client_with_asset(self, packet):
        self.active_clients.append(
            packet.ipv4.src_addr)  # don't pick anymore of this client's packet, let this thread handle it
        overall = ""  # gather the full command
        # connect to the asset
        HOST = self.asset_addr
        PORT = 44444
        BUFFSIZ = 4096
        ADDR = (HOST, PORT)
        tcpClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpClientSock.connect(ADDR)
        try:
            # show the first prompt of the session
            ack_back = scapy.IP(packet.ipv4.raw.tobytes())
            ack_back[scapy.TCP].seq = ack_back[scapy.TCP].seq + len(ack_back[scapy.TCP].payload)
            prompt = tcpClientSock.recv(BUFFSIZ)
            symbol = tcpClientSock.recv(BUFFSIZ)
            for data in (prompt, symbol):
                ack_back = scapy.sr1(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                                     / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport,
                                                 flags='PA', \
                                                 seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                                     / scapy.Raw(data), \
                                     verbose=False)

            # capture data from client and send to the asset
            z = pydivert.WinDivert("tcp.DstPort == 40000 and ip.SrcAddr == %s" % (packet.ipv4.src_addr))
            z.open()
            while True:
                packet = z.recv()  # get packet from client
                payload = self.get_packet_payload(packet)  # get character from packet

                if payload == '\b':  # if client backspaced
                    overall = overall[:-1]  # delete the last character of the gathered command
                    tcpClientSock.send(payload)  # send the character to the asset
                    data = tcpClientSock.recv(
                        BUFFSIZ)  # recieve the prompt change from the asset, and send to the client
                    ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                         / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                     flags='PA', \
                                                     seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                         / scapy.Raw(data), \
                                         verbose=False)
                elif payload == '\r\n':  # client pressed Enter - the command is executed and an answer is incoming
                    if self.is_malicious(packet, overall):
                        raise Blacklisted
                    if overall == 'quit':
                        raise Disconnected
                    overall = ""  # re-gather the next command
                    tcpClientSock.send(payload)  # send the character to the asset
                    data1 = tcpClientSock.recv(BUFFSIZ)  # gather answer
                    data2 = tcpClientSock.recv(BUFFSIZ)  # gather '/>'
                    data = data1 + data2
                    # send to the client
                    if len(data) > 100:
                        n = int(len(data) / 2)
                        payloads_to_send = [data[0:n], data[n:]]
                        scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                     / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                 flags='A', \
                                                 seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                     / scapy.Raw(payloads_to_send[0]), \
                                     verbose=False)
                        ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                             / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                         flags='PA', \
                                                         seq=packet.tcp.ack_num+len(payloads_to_send[0]), ack=packet.tcp.seq_num + len(payload)) \
                                             / scapy.Raw(payloads_to_send[1]), \
                                             verbose=False)
                    else:
                        ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                             / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                         flags='PA', \
                                                         seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                             / scapy.Raw(data), \
                                             verbose=False)
                else:
                    if payload:
                        # send acknowledgment to the client
                        scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                   / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                               flags='A', \
                                               seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                   / scapy.Raw(""), \
                                   verbose=False)
                        overall += payload  # append data to the full command
                    tcpClientSock.send(payload)  # send the character to the asset
        except Disconnected:
            # end connection
            ack_back = scapy.sr1(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                                 / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='FA', \
                                             seq=packet.tcp.ack_num, ack=packet.tcp.seq_num), \
                                 verbose=False)
            packet = z.recv()
            packet = z.recv()
            scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                       / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='A', \
                                   seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + 1), \
                       verbose=False)
            self.active_clients.remove(packet.ipv4.src_addr)
        except Blacklisted:
            # add IP to blacklist
            self.add_to_blacklist(packet.ipv4.src_addr)
            self.logger.info('%s is now blacklisted' % (packet.ipv4.src_addr))
            # kill this thread, and start a new one to connect with the honeypot
            threading.Thread(target=self.convert_client_to_honeypot, args=(packet,overall)).start()
        finally:
            z.close()

    def handle_client_with_honeypot(self, packet):
        self.active_clients.append(
            packet.ipv4.src_addr)  # don't pick anymore of this client's packet, let this thread handle it
        overall = ""  # gather the full command
        # connect to the asset
        HOST = self.honeypot_addr
        PORT = 44444
        BUFFSIZ = 4096
        ADDR = (HOST, PORT)
        tcpClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpClientSock.connect(ADDR)
        try:
            # show the first prompt of the session
            ack_back = scapy.IP(packet.ipv4.raw.tobytes())
            ack_back[scapy.TCP].seq = ack_back[scapy.TCP].seq + len(ack_back[scapy.TCP].payload)
            prompt = tcpClientSock.recv(BUFFSIZ)
            symbol = tcpClientSock.recv(BUFFSIZ)
            for data in (prompt, symbol):
                ack_back = scapy.sr1(scapy.IP(src=ack_back[scapy.IP].dst, dst=ack_back[scapy.IP].src) \
                                     / scapy.TCP(sport=ack_back[scapy.TCP].dport, dport=ack_back[scapy.TCP].sport,
                                                 flags='PA', \
                                                 seq=ack_back[scapy.TCP].ack, ack=ack_back[scapy.TCP].seq) \
                                     / scapy.Raw(data), \
                                     verbose=False)

            # capture data from client and send to the asset
            z = pydivert.WinDivert("tcp.DstPort == 40000 and ip.SrcAddr == %s" % (packet.ipv4.src_addr))
            z.open()
            while True:
                packet = z.recv()  # get packet from client
                payload = self.get_packet_payload(packet)  # get character from packet

                if payload == '\b':  # if client backspaced
                    overall = overall[:-1]  # delete the last character of the gathered command
                    tcpClientSock.send(payload)  # send the character to the asset
                    data = tcpClientSock.recv(
                        BUFFSIZ)  # recieve the prompt change from the asset, and send to the client
                    ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                         / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                     flags='PA', \
                                                     seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                         / scapy.Raw(data), \
                                         verbose=False)
                elif payload == '\r\n':  # client pressed Enter - the command is executed and an answer is incoming
                    if overall == 'quit':
                        raise Disconnected
                    overall = ""  # re-gather the next command
                    tcpClientSock.send(payload)  # send the character to the asset
                    data1 = tcpClientSock.recv(BUFFSIZ)  # gather answer
                    data2 = tcpClientSock.recv(BUFFSIZ)  # gather '/>'
                    data = data1 + data2
                    # send to the client
                    if len(data) > 100:
                        n = int(len(data) / 2)
                        payloads_to_send = [data[0:n], data[n:]]
                        scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                   / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                               flags='A', \
                                               seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                   / scapy.Raw(payloads_to_send[0]), \
                                   verbose=False)
                        ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                             / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                         flags='PA', \
                                                         seq=packet.tcp.ack_num + len(payloads_to_send[0]),
                                                         ack=packet.tcp.seq_num + len(payload)) \
                                             / scapy.Raw(payloads_to_send[1]), \
                                             verbose=False)
                    else:
                        ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                             / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                         flags='PA', \
                                                         seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                             / scapy.Raw(data), \
                                             verbose=False)
                else:
                    if payload:
                        # send acknowledgment to the client
                        scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                   / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                               flags='A', \
                                               seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                   / scapy.Raw(""), \
                                   verbose=False)
                        overall += payload  # append data to the full command
                    tcpClientSock.send(payload)  # send the character to the asset
        except Disconnected:
            # end connection
            ack_back = scapy.sr1(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                                 / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='FA', \
                                             seq=packet.tcp.ack_num, ack=packet.tcp.seq_num), \
                                 verbose=False)
            packet = z.recv()
            packet = z.recv()
            scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                       / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='A', \
                                   seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + 1), \
                       verbose=False)
            self.active_clients.remove(packet.ipv4.src_addr)
        finally:
            z.close()

    def convert_client_to_honeypot(self, packet, cmd_to_start_with):
        overall = cmd_to_start_with  # start with executing this command
        # connect to the honeypot
        HOST = self.honeypot_addr
        PORT = 44444
        BUFFSIZ = 4096
        ADDR = (HOST, PORT)
        tcpClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpClientSock.connect(ADDR)
        try:
            # get the first prompt of the session, no need to send it to client
            payload = self.get_packet_payload(packet)
            prompt = tcpClientSock.recv(BUFFSIZ)
            symbol = tcpClientSock.recv(BUFFSIZ)

            # send the command to start with to the honeypot:
            tcpClientSock.send(overall+'\r\n')  # send the character to the asset
            data1 = tcpClientSock.recv(BUFFSIZ)  # gather answer
            data2 = tcpClientSock.recv(BUFFSIZ)  # gather '/>'
            data = data1 + data2
            # send to the client
            # send to the client
            if len(data) > 100:
                n = int(len(data) / 2)
                payloads_to_send = [data[0:n], data[n:]]
                scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                           / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                       flags='A', \
                                       seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                           / scapy.Raw(payloads_to_send[0]), \
                           verbose=False)
                ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                     / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                 flags='PA', \
                                                 seq=packet.tcp.ack_num + len(payloads_to_send[0]),
                                                 ack=packet.tcp.seq_num + len(payload)) \
                                     / scapy.Raw(payloads_to_send[1]), \
                                     verbose=False)
            else:
                ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                     / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                 flags='PA', \
                                                 seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                     / scapy.Raw(data), \
                                     verbose=False)

            overall = ""  # re-gather the next command
            # capture data from client and send to the asset
            z = pydivert.WinDivert("tcp.DstPort == 40000 and ip.SrcAddr == %s" % (packet.ipv4.src_addr))
            z.open()
            while True:
                packet = z.recv()  # get packet from client
                payload = self.get_packet_payload(packet)  # get character from packet

                if payload == '\b':  # if client backspaced
                    overall = overall[:-1]  # delete the last character of the gathered command
                    tcpClientSock.send(payload)  # send the character to the asset
                    data = tcpClientSock.recv(
                        BUFFSIZ)  # recieve the prompt change from the asset, and send to the client
                    ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                         / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                     flags='PA', \
                                                     seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                         / scapy.Raw(data), \
                                         verbose=False)
                elif payload == '\r\n':  # client pressed Enter - the command is executed and an answer is incoming
                    if overall == 'quit':
                        raise Disconnected
                    overall = ""  # re-gather the next command
                    tcpClientSock.send(payload)  # send the character to the asset
                    data1 = tcpClientSock.recv(BUFFSIZ)  # gather answer
                    data2 = tcpClientSock.recv(BUFFSIZ)  # gather '/>'
                    data = data1 + data2
                    # send to the client
                    if len(data) > 100:
                        n = int(len(data) / 2)
                        payloads_to_send = [data[0:n], data[n:]]
                        scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                   / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                               flags='A', \
                                               seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                   / scapy.Raw(payloads_to_send[0]), \
                                   verbose=False)
                        ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                             / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                         flags='PA', \
                                                         seq=packet.tcp.ack_num + len(payloads_to_send[0]),
                                                         ack=packet.tcp.seq_num + len(payload)) \
                                             / scapy.Raw(payloads_to_send[1]), \
                                             verbose=False)
                    else:
                        ack_back = scapy.sr1(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                             / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                                         flags='PA', \
                                                         seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                             / scapy.Raw(data), \
                                             verbose=False)
                else:
                    if payload:
                        # send acknowledgment to the client
                        scapy.send(scapy.IP(src=packet.ipv4.dst_addr, dst=packet.ipv4.src_addr) \
                                   / scapy.TCP(sport=packet.tcp.dst_port, dport=packet.tcp.src_port,
                                               flags='A', \
                                               seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + len(payload)) \
                                   / scapy.Raw(""), \
                                   verbose=False)
                        overall += payload  # append data to the full command
                    tcpClientSock.send(payload)  # send the character to the asset
        except Disconnected:
            # end connection
            ack_back = scapy.sr1(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                                 / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='FA', \
                                             seq=packet.tcp.ack_num, ack=packet.tcp.seq_num), \
                                 verbose=False)
            packet = z.recv()
            packet = z.recv()
            scapy.send(scapy.IP(src=self.asset_addr, dst=packet.ipv4.src_addr) \
                       / scapy.TCP(sport=packet.dst_port, dport=packet.src_port, flags='A', \
                                   seq=packet.tcp.ack_num, ack=packet.tcp.seq_num + 1), \
                       verbose=False)
            self.active_clients.remove(packet.ipv4.src_addr)
        finally:
            z.close()