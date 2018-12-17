package damlib

/*
 * Copyright (c) 2017-2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan Jelincic <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import "os"

// Workdir holds the path to the directory where we will Chdir on startup.
var Workdir = os.Getenv("HOME") + "/.dam"

// PrivKeyPath holds the name of where our private key is.
const PrivKeyPath = "dam-private.key"

// SeedPath holds the name of where our private key seed is.
const SeedPath = "dam-private.seed"

// PubSubChan is the name of the pub/sub channel we're publishing to in Redis.
const PubSubChan = "tordam"

// PostMsg holds the message we are signing with our private key.
const PostMsg = "I am a DAM node!"

// WelcomeMsg holds the message we return when welcoming a node.
const WelcomeMsg = "Welcome to the DAM network!"

// ProxyAddr is the address of our Tor SOCKS port.
const ProxyAddr = "127.0.0.1:9050"

// TorPortMap is a comma-separated string holding the mapping of ports
// to be opened by the Tor Hidden Service. Format is "remote:local".
const TorPortMap = "80:49371,13010:13010,13011:13011,5000:5000"

// DirPort is the port where dam-dir will be listening.
const DirPort = 49371

// Testnet is flipped with a flag in dam-dir and represents if all new
// nodes are initially marked valid or not.
var Testnet = false
