class SessionManager(object):
    def __init__(self):
        self.all_clients = []

    def already_known_client(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        for client in self.all_clients:
            if session_info['ipv4_src'] == client.ipv4_addr or client.honeypot_session(**session_info):
                return client
        return None

    def update_asset_sessions(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        client = self.already_known_client(packet)
        if client:
            client.update_asset_sessions(**session_info)
        else:
            self.all_clients.append(Client(**session_info))

    def update_honeypot_sessions(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        #if packet.tcp.fin or packet.tcp.rst:
        client = self.already_known_client(packet)
        if client:
            client.update_honeypot_sessions(**session_info)

    def is_client_blacklisted(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        client = self.already_known_client(packet)
        if client:
            return client.blacklisted

    def blacklist_client(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        client = self.already_known_client(packet)
        if client:
            client.blacklisted = True

    def get_asset_session(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        client = self.already_known_client(packet)
        if client:
            return client.asset_session(**session_info)

    def get_honeypot_session(self, packet):
        session_info = self.get_session_info_from_packet(packet)
        client = self.already_known_client(packet)
        if client:
            return client.honeypot_session(**session_info)

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
        self.asset_sessions = []
        self.honeypot_sessions = []
        self.update_asset_sessions(**kwargs)

    def asset_session(self, **kwargs):
        for sess in self.asset_sessions:
            l = [x for x in [sess.tcp_src_port, sess.tcp_dst_port, kwargs['tcp_src_port'], kwargs['tcp_dst_port']] if x != 5000]
            if len(l) != len(set(l)):
                return sess
        return None

    def honeypot_session(self, **kwargs):
        for sess in self.honeypot_sessions:
            l = [x for x in [sess.tcp_src_port, sess.tcp_dst_port, kwargs['tcp_src_port'], kwargs['tcp_dst_port']] if x != 5000]
            if len(l) != len(set(l)):
                return sess
        return None

    def update_asset_sessions(self, **kwargs):
        '''
        Updates the matched session by id / creates new session if doesn't match.
        :param kwargs: session info
        :return:
        '''
        sess = self.asset_session(**kwargs)
        if sess:
            sess.update(**kwargs)
        else:
            self.asset_sessions.append(Session(**kwargs))
            temp = Session.temporary_honeypot_session(**kwargs)
            self.honeypot_sessions.append(temp)

    def update_honeypot_sessions(self, **kwargs):
        '''
        Updates the matched session by id / creates new session if doesn't match.
        :param kwargs: session info
        :return:
        '''
        sess = self.asset_session(**kwargs)
        if sess:
            sess.update(**kwargs)
        else:
            self.honeypot_sessions.append(Session(**kwargs))

class Session(object):
    counter = 1
    def __init__(self, **kwargs):
        self.ipv4_src = kwargs['ipv4_src']
        self.ipv4_dst = kwargs['ipv4_dst']
        self.ipv4_id = kwargs['ipv4_id']
        self.tcp_header_len = kwargs['tcp_header_len']
        self.tcp_src_port = kwargs['tcp_src_port']
        self.tcp_dst_port = kwargs['tcp_dst_port']
        self.tcp_seq = kwargs['tcp_seq']
        self.tcp_ack = kwargs['tcp_ack']
        Session.counter += 1

    @classmethod
    def temporary_honeypot_session(cls, **kwargs):
        session_info = {}
        session_info['ipv4_src'] = ""
        session_info['ipv4_dst'] = ""
        session_info['ipv4_id'] = Session.counter
        session_info['tcp_header_len'] = kwargs['tcp_header_len']
        session_info['tcp_src_port'] = kwargs['tcp_src_port']
        session_info['tcp_dst_port'] = kwargs['tcp_dst_port']
        session_info['tcp_seq'] = kwargs['tcp_seq']
        session_info['tcp_ack'] = kwargs['tcp_ack']
        return cls(**session_info)

    def update(self, **kwargs):
        self.ipv4_src = kwargs['ipv4_src']
        self.ipv4_dst = kwargs['ipv4_dst']
        self.ipv4_id = kwargs['ipv4_id']
        self.tcp_header_len = kwargs['tcp_header_len']
        self.tcp_src_port = kwargs['tcp_src_port']
        self.tcp_dst_port = kwargs['tcp_dst_port']
        self.tcp_seq = kwargs['tcp_seq']
        self.tcp_ack = kwargs['tcp_ack']
