class SessionManager(object):
    def __init__(self):
        self.all_clients = []
        self.all_ipv4_addrs = []

    def update_incoming_sessions(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        if session_info['ipv4_src'] not in self.all_ipv4_addrs:
            self.all_ipv4_addrs.append(session_info['ipv4_src'])
            self.all_clients.append(Client(**session_info))
        else:
            for i in range(len(self.all_clients)):
                if self.all_clients[i].ipv4_addr == session_info['ipv4_src']:
                    self.all_clients[i].update_asset_session(**session_info)
                    break

    def update_honeypot_sessions(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        if packet.tcp.fin or packet.tcp.rst:
            for i in range(len(self.all_clients)):
                if self.all_clients[i].id == session_info['ipv4_id']:
                    self.all_clients[i].reset_honeypot_session()
                    break
        else:
            for i in range(len(self.all_clients)):
                if self.all_clients[i].id == session_info['ipv4_id']:
                    self.all_clients[i].update_honeypot_session(**session_info)
                    break

    def is_client_blacklisted(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        for i in range(len(self.all_clients)):
            if self.all_clients[i].ipv4_addr == session_info['ipv4_src']:
                return self.all_clients[i].blacklisted

    def blacklist_client(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        for i in range(len(self.all_clients)):
            if self.all_clients[i].ipv4_addr == session_info['ipv4_src']:
                self.all_clients[i].blacklisted = True
                break

    def get_asset_session(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        for i in range(len(self.all_clients)):
            if self.all_clients[i].asset_session['ipv4_id'] == session_info['ipv4_id']:
                return self.all_clients[i].asset_session

    def get_honeypot_session(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        for i in range(len(self.all_clients)):
            if self.all_clients[i].ipv4_addr == session_info['ipv4_src']:
                return self.all_clients[i].honeypot_session

    def get_session_info_from_packet(self, packet):
        session_info = {}
        session_info['ipv4_src'] = packet.ipv4.src_addr
        session_info['ipv4_dst'] = packet.ipv4.dst_addr
        session_info['ipv4_id'] = packet.ipv4.ident
        session_info['tcp_header_len'] = packet.tcp.header_len
        session_info['tcp_src_port'] = packet.src_port
        session_info['tcp_dst_port'] = packet.dst_port
        session_info['tcp_seq'] = packet.tcp.seq_num
        session_info['tcp_ack'] = packet.tcp.ack_num
        return session_info

class Client(object):
    counter = 1
    def __init__(self, **kwargs):
        self.id = Client.counter
        Client.counter += 1
        self.ipv4_addr = kwargs['ipv4_src']
        self.blacklisted = False
        self.asset_session = Session(**kwargs)
        self.honeypot_session = self.id

    def update_asset_session(self, **kwargs):
        self.asset_session = Session(**kwargs)

    def update_honeypot_session(self, **kwargs):
        self.self.honeypot_session = Session(**kwargs)

    def reset_honeypot_session(self, **kwargs):
        self.self.honeypot_session = self.id

class Session(object):
    def __init__(self, **kwargs):
        self.ipv4_src = kwargs['ipv4_src']
        self.ipv4_dst = kwargs['ipv4_dst']
        self.ipv4_id = kwargs['ipv4_id']
        self.tcp_header_len = kwargs['tcp_header_len']
        self.tcp_src_port = kwargs['tcp_src_port']
        self.tcp_dst_port = kwargs['tcp_dst_port']
        self.tcp_seq = kwargs['tcp_seq']
        self.tcp_ack = kwargs['tcp_ack']