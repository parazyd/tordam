#!/usr/bin/env python3
# Copyright (c) 2017-2018 Dyne.org Foundation
# tor-dam is writen and maintained by Ivan J. <parazyd@dyne.org>
#
# This file is part of tor-dam
#
# This source code is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this source code. If not, see <http://www.gnu.org/licenses/>.

"""
Controller daemon running the ephemeral hidden service.

Usage: damhs.py <path_to_private.key> <portmap>

<portmap> is a comma-separated string of at least one of the
following element: 80:49371 (80 is the remote, 49371 is local)
"""

from sys import argv, stdout
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
    ctl = Controller.from_port()
    ctl.authenticate(password='topkek')

    portmap = {}
    ports = argv[2].split(',')
    for i in ports:
        tup = i.split(':')
        portmap[int(tup[0])] = int(tup[1])

    keyfile = argv[1]
    ktype = 'RSA1024'
    kcont = open(keyfile).read()
    kcont = kcont.replace('\n', '')
    kcont = kcont.replace('-----BEGIN RSA PRIVATE KEY-----', '')
    kcont = kcont.replace('-----END RSA PRIVATE KEY-----', '')

    service = start_hs(ctl=ctl, ktype=ktype, kcont=kcont, portmap=portmap)

    stdout.write('Started HS at %s.onion\n' % service.service_id)
    stdout.write('OK\n')
    stdout.flush()
    while True:
            sleep(60)


if __name__ == '__main__':
    main()
