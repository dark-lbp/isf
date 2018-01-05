from icssploit import (
    exploits,
    print_success,
    print_error,
    print_table,
    validators,
)
from icssploit.clients.wdb2_client import *
from icssploit.utils import port_scan, export_table


TABLE_HEADER = ['Target Type', 'VxWorks Version', "CPU Type", "CPU Model", "Memory Size", "IP Address"]
VXWORKS_DEVICES = []


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'vxworks 6.x device scan',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>'  # icssploit module
        ],
        'description': 'Scan all vxworks 6.x device with wdbrpc version 2 protocol.',
        'references': [
        ],
    }

    target = exploits.Option('', "string for hosts as nmap use it 'scanme.nmap.org'"
                                 " or '198.116.0-255.1-127' or '216.163.128.20/20'")
    port = exploits.Option(17185, 'WdbRPC port, default is 17185/UDP', validators=validators.integer)
    verbose = exploits.Option(0, 'Scapy verbose level, 0 to 2', validators=validators.integer)
    result = []

    @staticmethod
    def sizeof_fmt(num, suffix='B'):
        for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
            if abs(num) < 1024.0:
                return "%3.1f%s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f%s%s" % (num, 'Yi', suffix)

    def get_target_info(self, host, port):
        target_type = ''
        vxworks_version = ''
        cpu_type = ''
        cpu_model = ''
        memory_size = ''
        ip_address = host
        try:
            target = Wdb2Client(name='Vxworks_6.6', ip=host, port=self.port)
            target.connect()
            target.get_target_info()
            target_type = target.target_info['Target_Type']
            vxworks_version = target.target_info['Vx_Version']
            cpu_type = target.target_info['CPU_Type']
            cpu_model = target.target_info['CPU_Model']
            memory_size = self.sizeof_fmt(target.target_info['Memory_Size'])
            ip_address = host
            self.result.append([target_type, vxworks_version, cpu_type, cpu_model, memory_size, ip_address])
        except Exception as err:
            print_error(err)
            return False

    def run(self):
        conf.verb = self.verbose
        nm = port_scan(protocol='UDP', target=self.target, port=self.port)
        for host in nm.all_hosts():
            if nm[host]['udp'][self.port]['state'] == "open":
                print_success("Host: %s, port:%s is open" % (host, self.port))
                self.get_target_info(host=host, port=self.port)
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        print_table(TABLE_HEADER, *unique_device)

    def command_export(self, file_path, *args, **kwargs):
        unique_device = [list(x) for x in set(tuple(x) for x in self.result)]
        unique_device = sorted(unique_device)
        export_table(file_path, TABLE_HEADER, unique_device)
