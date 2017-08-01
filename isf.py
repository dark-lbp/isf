#!/usr/bin/env python2

from __future__ import print_function

import argparse
import logging.handlers

from icssploit.interpreter import IcssploitInterpreter
from icssploit.utils import create_exploit

log_handler = logging.handlers.RotatingFileHandler(filename='icssploit.log', maxBytes=500000)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)

parser = argparse.ArgumentParser(description='ICSSploit - ICS Exploitation Framework')
parser.add_argument('-a',
                    '--add-exploit',
                    metavar='exploit_path',
                    help='Add exploit using default template.')


def icssploit():
    isf = IcssploitInterpreter()
    isf.start()

if __name__ == "__main__":
    args = parser.parse_args()

    if args.add_exploit:
        create_exploit(args.add_exploit)
    else:
        icssploit()
