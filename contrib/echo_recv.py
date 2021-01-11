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

parser = ArgumentParser()
parser.add_argument('-l', '--listen', default='127.0.0.1')
parser.add_argument('-p', '--port', default=5000)
args = parser.parse_args()

s = socket(AF_INET, SOCK_STREAM)
s.bind((args.listen, args.port))
s.listen(1)

conn, ddr = s.accept()
while 1:
    data = conn.recv(1024)
    if not data:
        break
    print(data)
    conn.send(data)
conn.close()
