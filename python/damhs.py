#!/usr/bin/env python3
# Copyright (c) 2017-2018 Dyne.org Foundation
# tor-dam is written and maintained by Ivan Jelincic <parazyd@dyne.org>
#
# This file is part of tor-dam
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Controller daemon running the ephemeral hidden service.

Usage: damhs.py <path_to_private.key> <portmap>

<portmap> is a comma-separated string of at least one of the
following element: 80:49371 (80 is the remote, 49371 is local)
"""

from argparse import ArgumentParser
from sys import stdout
from time import sleep

from stem.control import Controller


def start_hs(ctl=None, ktype=None, kcont=None, portmap=None):
    """
    Function starting our ephemeral hidden service
    """
    return ctl.create_ephemeral_hidden_service(portmap, key_type=ktype,
                                               key_content=kcont,
                                               await_publication=True)


def main():
    """
    Main loop
    """
    parser = ArgumentParser()
    parser.add_argument('-k', '--private-key',
                        help='Path to the ed25519 private key',
                        default='/home/decode/.dam/private.key')
    parser.add_argument('-p', '--port-map',
                        help='Comma-separated string of local:remote ports',
                        default='80:49731,5000:5000')
    args = parser.parse_args()

    ctl = Controller.from_port()
    ctl.authenticate(password='topkek')

    portmap = {}
    ports = args.port_map.split(',')
    for i in ports:
        tup = i.split(':')
        portmap[int(tup[0])] = int(tup[1])

    keyfile = args.private_key
    ktype = 'ED25519-V3'
    kcont = open(keyfile).read()

    service = start_hs(ctl=ctl, ktype=ktype, kcont=kcont, portmap=portmap)

    stdout.write('Started HS at %s.onion\n' % service.service_id)
    stdout.write('OK\n')
    stdout.flush()
    while True:
        sleep(60)


if __name__ == '__main__':
    main()
