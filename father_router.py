import pydivert
import scapy.all as scapy
from logGui import *

class BaseWrapper(object):
    """
    An object to inherit from in order to wrap (encapsulate) a given object.
    Inherits all attributes of wrapped object immediately.
    """
    def __init__(self, obj):
        super(BaseWrapper, self).__init__()
        self._obj = obj
        self._base_methods = list(set(dir(obj)) - set(dir(object)) - {'aa'})

    def __getattr__(self, key):
        if key in self._base_methods:
            return getattr(self._obj, key)
        return None

class FatherRouter(object):
    def __init__(self, asset_addr, honeypot_addr):
        """
        Creating a Father Router instance which is encapsulated by other routers instances for specific jobs.
        :param asset_addr:
        :param honeypot_addr:
        :param my_gui: the gui to write to
        """
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr

        self.blacklist = []
        # Update initial blacklist from a file
        with open("blacklist.txt", 'rb') as black_file:
            for line in black_file:
                self.blacklist.append(line)

        # GUI
        self.root = tk.Tk()
        self.my_gui = myGUI(self.root)

        open('logger.log', 'w').close()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

        # logger.log File
        self.file_handler = logging.FileHandler('logger.log')
        self.file_handler.setLevel(logging.INFO)
        self.file_handler.setFormatter(self.formatter)

        # in console
        self.stream_handler = logging.StreamHandler()
        self.stream_handler.setLevel(logging.DEBUG)
        self.stream_handler.setFormatter(self.formatter)

        # for the Tkinter GUI
        self.text_handler = self.my_gui.text_handler
        self.text_handler.setLevel(logging.INFO)
        self.text_handler.setFormatter(self.formatter)

        self.logger.addHandler(self.file_handler)
        self.logger.addHandler(self.stream_handler)
        self.logger.addHandler(self.text_handler)

    def add_to_blacklist(self, ip_addr):
        """
        add the given ip to the blacklist
        :param ip_addr:
        :return:
        """
        self.blacklist.append(ip_addr)
        with open("blacklist.txt", 'ab') as black_file:
            black_file.write("\n" + ip_addr)

    def fingerprinting(self, packet):
        """
        Checks for the OS and device of the packet source, and logs the information.
        Analysis based on window size and ttl.
        :param pydivert packet:
        :return:
        """
        ttl = packet.ipv4.ttl
        win_siz = packet.tcp.window_size
        os = ""
        if ttl == 64 and win_siz == 5840:
            os = "Linux (kernel 2.4 and 2.6)"
        elif ttl == 64 and win_siz == 5720:
            os = "Google's customized Linux"
        elif ttl == 64 and win_siz == 65535:
            os = "FreeBSD"
        elif ttl == 128 and win_siz == 65535:
            os = "Windows XP"
        elif ttl == 128 and win_siz == 65535:
            os = "Windows 7, Vista and Server 2008"
        elif ttl == 255 and win_siz == 4128:
            os = "Cisco Router (IOS 12.4)"
        else:
            os = "Unknown"
        self.logger.info("The OS of the machine at %s is probably: %s" % (packet.ipv4.src_addr, os))

    def get_packet_payload(self, packet):
        """
        :param pydivert packet:
        :return the TCP payload:
        """
        pkt = scapy.IP(packet.ipv4.raw.tobytes())
        return str(pkt[scapy.TCP].payload)