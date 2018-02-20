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
Retrieves and prints a hidden service's public key to stdout.

Usage: damauth.py <foo.onion>
"""

from sys import argv, stdout
from stem.control import Controller


with Controller.from_port() as ctl:
    ctl.authenticate(password='topkek')
    stdout.write(ctl.get_hidden_service_descriptor(argv[1]).permanent_key)
    stdout.flush()
