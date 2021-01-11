#!/usr/bin/env python3
# Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
#
# This file is part of tor-dam
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_STREAM

import socks

parser = ArgumentParser()
parser.add_argument('-a', '--address', default='some.onion')
parser.add_argument('-p', '--port', default=5000)
parser.add_argument('-t', '--tor', default='127.0.0.1:9050')
args = parser.parse_args()

if '.onion' in args.address:
	s = socks.socksocket(AF_INET, SOCK_STREAM)
	s.set_proxy(socks.SOCKS5, args.tor.split()[0], int(args.tor.split()[1]))
else:
	s = socket(AF_INET, SOCK_STREAM)

s.connect((args.address, args.port))
s.send(b'HELLO')
data = s.recv(1024)
s.close()

print(data)
