from icssploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_table,
    validators,
)
from icssploit.clients.s7_client import S7Client
from scapy.all import conf
from icssploit.utils import port_scan, export_table

TABLE_HEADER = ['Order Code', 'Module Type Name', "Firmware Version", "Module Name", "Serial Number", "Rack/Slot", "IP Address"]
S7_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'S7comm PLC Scan',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>'  # icssploit module
        ],
        'description': 'Scan all S7 300/400 PLC with s7comm protocol.',
        'references': [
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(102, 'S7comm port, default is 102/TCP', validators=validators.integer)
    verbose = exploits.Option(0, 'Scapy verbose level, 0 to 2', validators=validators.integer)
    min_rack = exploits.Option(0, 'Minimum PLC Rack number for scan, default is 0, set to 1 '
                                  'if you want start with rack 1', validators=validators.integer)
    max_rack = exploits.Option(0, 'Maximum PLC Rack number for scan, default is 0, set to 1 '
                                  'if you want scan up to rack 1', validators=validators.integer)
    min_slot = exploits.Option(2, 'Minimum PLC Slot number for scan, default is 2, set to 4 '
                                  'if you want start with slot 4', validators=validators.integer)
    max_slot = exploits.Option(5, 'Maximum PLC Slot number for scan, default is 5, set to 10 '
                                  'if you want scan up to slot 5', validators=validators.integer)
    result = []

    def get_target_info(self, host, port):
        for rack_num in range(self.min_rack, self.max_rack + 1):
            for slot_num in range(self.min_slot, self.max_slot + 1):
                print_status("Tring to scan %s with Rack%s/Slot%s" % (host, rack_num, slot_num))
                order_code = ''
                firmware_version = ''
                module_type_name = ''
                module_name = ''
                serial_number = ''
                ip_address = host
                try:
                    target = S7Client(name='S7Scanner', ip=host, port=port, rack=rack_num, slot=slot_num)
                    target.connect()
                    order_code, firmware_version, module_type_name, \
                        as_name, module_name, serial_number = target.get_target_info()
                    ip_address = host
                    if order_code != '':
                        self.result.append([order_code, module_type_name, firmware_version, module_name, serial_number,
                                            str(rack_num) + '/' + str(slot_num), ip_address])
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
