from icssploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from icssploit.clients.s7plus_client import S7PlusClient
from scapy.all import conf
from icssploit.utils import port_scan, export_table

TABLE_HEADER = ['Order Code', 'Serial Number', 'Hardware Version', "Firmware Version", "IP Address"]
S7_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'S7Plus PLC Scan',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>'  # icssploit module
        ],
        'description': 'Scan all S7 1200/1500 PLC with s7comm plus version 1 protocol.',
        'references': [
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(102, 'S7comm port, default is 102/TCP', validators=validators.integer)
    verbose = exploits.Option(0, 'Scapy verbose level, 0 to 2', validators=validators.integer)
    result = []

    def get_target_info(self, host, port):
            ip_address = host
            try:
                target = S7PlusClient(name='S7Scanner', ip=host, port=port)
                target.connect()
                order_code, serial_number, hardware_version, firmware_version = target.get_target_info()
                if order_code != '':
                    self.result.append([order_code, serial_number, hardware_version, firmware_version, ip_address])
            except Exception as err:
                print_error(err)
                return False

    def run(self):
        self.result = []
        conf.verb = self.verbose
        nm = port_scan(protocol='TCP', target=self.target, port=self.port)
        for host in nm.all_hosts():
            if nm[host]['tcp'][self.port]['state'] == "open":
                print_success("Host: %s, port:%s is open" % (host, self.port))
                self.get_target_info(host=host, port=self.port)
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        if len(self.result) > 0:
            print_success("Find %s targets" % len(self.result))
            print_table(TABLE_HEADER, *unique_device)
            print('\r')
        else:
            print_error("Didn't find any target on network %s" % self.target)

    def command_export(self, file_path, *args, **kwargs):
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_device = sorted(unique_device)
        export_table(file_path, TABLE_HEADER, unique_device)
