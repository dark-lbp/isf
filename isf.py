#!/usr/bin/env python2

from __future__ import print_function

import argparse
import logging.handlers
import os

from icssploit.interpreter import IcssploitInterpreter
from icssploit.utils import create_exploit

log_handler = logging.handlers.RotatingFileHandler(filename='icssploit.log', maxBytes=500000)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)

parser = argparse.ArgumentParser(description='ICSSploit - ICS Exploitation Framework')
parser.add_argument('-e',
                    '--extra-package-path',
                    metavar='extra_package_path',
                    help='Add extra packet(clients, modules, protocols) to isf.')


def icssploit(extra_package_path=None):
    isf = IcssploitInterpreter(extra_package_path)
    isf.start()

if __name__ == "__main__":
    args = parser.parse_args()
    if args.extra_package_path:
        if os.path.isdir(args.extra_package_path):
            icssploit(extra_package_path=args.extra_package_path)
    else:
        icssploit()
