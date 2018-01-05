from icssploit import (
    exploits,
    print_table,
    validators,
)
import threading
from icssploit.protocols.pn_dcp import *
from icssploit.utils import export_table
from scapy.arch import get_if_hwaddr
from scapy.sendrecv import sendp, sniff


TABLE_HEADER = ['Device Name', 'Device Type', "MAC Address", "IP Address", "Netmask", "GateWay"]
PROFINET_BROADCAST_ADDRESS_1 = '01:0e:cf:00:00:00'
PROFINET_BROADCAST_ADDRESS_2 = "28:63:36:5a:18:f1"
PROFINET_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'profinet device scan',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>'  # icssploit module
        ],
        'description': 'Scan all device which support PROFINET-DCP protocol.',
        'references': [
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
            if pkt[Ether].dst == self.sniff_mac_address:
                Device_Name = ''
                Device_Type = ''
                MAC_Address = pkt[Ether].src
                IP_Address = ''
                Netmask = ''
                GateWay = ''
                if pkt.haslayer(PNDCPIdentDeviceNameOfStationResponseBlock):
                    Device_Name = pkt[PNDCPIdentDeviceNameOfStationResponseBlock].NameOfStation
                if pkt.haslayer(PNDCPIdentDeviceManufacturerSpecificResponseBlock):
                    Device_Type = pkt[PNDCPIdentDeviceManufacturerSpecificResponseBlock].DeviceVendorValue
                if pkt.haslayer(PNDCPIdentIPParameterResponseBlock):
                    IP_Address = pkt[PNDCPIdentIPParameterResponseBlock].IPaddress
                    Netmask = pkt[PNDCPIdentIPParameterResponseBlock].Subnetmask
                    GateWay = pkt[PNDCPIdentIPParameterResponseBlock].StandardGateway
                self.result.append([Device_Name, Device_Type, MAC_Address, IP_Address, Netmask, GateWay])
        self.sniff_finished.set()

    def exploit(self, target_mac):
        packet = Ether(src=self.sniff_mac_address, dst=target_mac, type=0x8892) / ProfinetIO(frameID=0xFEFE) / \
                 PNDCPHeader(ServiceID=5, ServiceType=0, DCPBlocks=[PNDCPIdentRequest()])
        sendp(packet, iface=self.nic)

    def run(self):
        conf.verb = self.verbose
        self.sniff_mac_address = get_if_hwaddr(self.nic)
        p = threading.Thread(target=self.sniff_answer)
        p.setDaemon(True)
        p.start()
        self.exploit(target_mac=PROFINET_BROADCAST_ADDRESS_1)
        self.exploit(target_mac=PROFINET_BROADCAST_ADDRESS_2)
        self.sniff_finished.wait(self.timeout + 1)
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        print_table(TABLE_HEADER, *unique_device)

    def command_export(self, file_path, *args, **kwargs):
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_device = sorted(unique_device)
        export_table(file_path, TABLE_HEADER, unique_device)
