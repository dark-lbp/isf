from icssploit import (
    exploits,
    validators,
    print_table
)
from icssploit.protocols.enip import *
from icssploit.utils import export_table
import threading
from scapy.layers.inet import Ether, IP, UDP
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.sendrecv import sendp, sniff


TABLE_HEADER = ["Product Name", "Device Type", "Vendor ", "Revision", "Serial Number", "IP Address"]
ENIP_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'Ethernet/IP device scan',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>'  # icssploit module
        ],
        'description': 'Scan all device which support Ethernet/IP protocol with broadcast discovery packet.',
        'references': [
            'https://github.com/nmap/nmap/blob/master/scripts/enip-info.nse'
        ],
    }

    nic = exploits.Option('eth0', 'Interface Name e.g eth0, en0')
    timeout = exploits.Option(5, 'Timeout for response', validators=validators.integer)
    verbose = exploits.Option(0, 'Scapy verbose level, 0 to 2', validators=validators.integer)
    sniff_mac_address = None
    sniff_finished = threading.Event()
    result = []

    def sniff_answer(self):
        self.sniff_finished.clear()
        response = sniff(iface=self.nic, filter="ether dst host %s" % self.sniff_mac_address, timeout=self.timeout)
        self.result = []
        for i in range(len(response)):
            pkt = response[i]
            if pkt.haslayer(ENIPHeader):
                product_name = ''
                device_type = ''
                vendor = ''
                revision = ''
                serial_number = ''
                ip_address = ''
                if pkt.haslayer(ListIdentityResponse):
                    product_name = pkt[ListIdentityResponse].ProductName
                    device_type = pkt[ListIdentityResponse].DeviceType
                    if device_type in DEVICE_TYPES.keys():
                        device_type = DEVICE_TYPES[device_type]
                    ip_address = pkt[SocketAddress].SinAddress
                    vendor = pkt[ListIdentityResponse].VendorID
                    if vendor in VENDOR_IDS.keys():
                        vendor = VENDOR_IDS[vendor]
                    revision = pkt[ListIdentityResponse].Revision
                    revision = struct.pack("!H", revision)
                    revision = "{0:d}.{1:d}".format(ord(revision[0]), ord(revision[1]))
                    serial_number = pkt[ListIdentityResponse].SerialNumber
                    serial_number = struct.pack("!I", serial_number).encode('hex')
                self.result.append([product_name, device_type, vendor, revision, serial_number, ip_address])
        self.sniff_finished.set()

    def exploit(self):
        self.discover_local_device()

    def discover_local_device(self):
        self.sniff_mac_address = get_if_hwaddr(self.nic)
        p = threading.Thread(target=self.sniff_answer)
        p.setDaemon(True)
        p.start()
        # wait sniff start
        time.sleep(0.2)
        packet = Ether(src=self.sniff_mac_address, dst="ff:ff:ff:ff:ff:ff")/IP(src=get_if_addr(self.nic), dst="255.255.255.255")/UDP(sport=44818, dport=44818)/ENIPHeader(Command=0x0063)
        sendp(packet, iface=self.nic)
        self.sniff_finished.wait(self.timeout + 1)

    def run(self):
        conf.verb = self.verbose
        self.exploit()
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        print_table(TABLE_HEADER, *unique_device)

    def command_export(self, file_path, *args, **kwargs):
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_device = sorted(unique_device)
        export_table(file_path, TABLE_HEADER, unique_device)
