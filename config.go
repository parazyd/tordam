// Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
//
// This file is part of tordam
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package tordam

import (
	"crypto/ed25519"
	"net"
)

// Config is the configuration structure, to be filled by library user.
type Config struct {
	Listen   *net.TCPAddr // Local listen address for the JSON-RPC server
	TorAddr  *net.TCPAddr // Tor SOCKS5 proxy address, filled by SpawnTor()
	Datadir  string       // Path to data directory
	Portmap  []string     // The peer's portmap, to be mapped in the Tor HS
	Seeds    []string     // Initial peer(s)
	Announce bool         // Announce or not
}

// SignKey is an ed25519 private key, to be assigned by library user.
var SignKey ed25519.PrivateKey

// Onion is the library user's something.onion:port identifier. It can be read
// from the datadir once Tor is spawned.
var Onion string

// Cfg is the global config structure, to be filled by library user.
var Cfg = Config{}

// Peers is the global map of peers
var Peers = map[string]Peer{}
