#!/usr/bin/env python3
# See LICENSE file for copyright and license details.
"""
Retrieves and prints a hidden service's public key to stdout.

Usage: dirauth.py <foo.onion>
"""

from sys import argv, stdout
from stem.control import Controller


with Controller.from_port() as ctl:
    ctl.authenticate(password='topkek')
    stdout.write(ctl.get_hidden_service_descriptor(argv[1]).permanent_key)
    stdout.flush()
