#!/usr/bin/env python3
# See LICENSE file for copyright and license details.
"""
Controller daemon running the ephemeral hidden service.
"""

from sys import argv, stdout
from time import sleep
from stem.control import Controller


# PORTMAP holds the port mapping of our ports. The key is the port that
# is accessible through Tor, and the value is the port opened locally for
# Tor to use.
PORTMAP = {
    80: 49371
}


def start_hs(ctl=None, ktype=None, kcont=None):
    """
    Function starting our ephemeral hidden service
    """
    if not ktype or not kcont:
        assert False, 'No key data passed.'
    if not ctl:
        assert False, 'No controller passed.'

    return ctl.create_ephemeral_hidden_service(PORTMAP, key_type=ktype,
                                               key_content=kcont,
                                               await_publication=True)


def main():
    """
    Main loop
    """
    controller = Controller.from_port()
    controller.authenticate(password='topkek')

    keyfile = argv[1]
    ktype = 'RSA1024'
    kcont = open(keyfile).read()
    kcont = kcont.replace('\n', '')
    kcont = kcont.replace('-----BEGIN RSA PRIVATE KEY-----', '')
    kcont = kcont.replace('-----END RSA PRIVATE KEY-----', '')

    service = start_hs(ctl=controller, ktype=ktype, kcont=kcont)

    stdout.write('Started HS at %.onion\n' % service.service_id)
    while True:
        stdout.write('OK\n')
        sleep(10)

if __name__ == '__main__':
    main()
