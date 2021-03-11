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
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"path/filepath"
	"strings"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"golang.org/x/net/proxy"
)

// Announce is a function that announces to a certain onion address. Upon
// success, it appends the peers received from the endpoint to the global
// Peers map, which in turn also writes it to the peers db file.
func Announce(onionaddr string) error {
	log.Println("Announcing to", onionaddr)

	if err := ValidateOnionInternal(onionaddr); err != nil {
		return err
	}

	socks, err := proxy.SOCKS5("tcp", Cfg.TorAddr.String(), nil, proxy.Direct)
	if err != nil {
		return err
	}

	// conn, err := net.Dial(jrpc2.Network(Cfg.Listen), Cfg.Listen)
	conn, err := socks.Dial("tcp", onionaddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	cli := jrpc2.NewClient(channel.RawJSON(conn, conn), nil)
	defer cli.Close()
	ctx := context.Background()

	b64pk := base64.StdEncoding.EncodeToString(
		SignKey.Public().(ed25519.PublicKey))

	var resp [2]string
	data := []string{Onion, b64pk, strings.Join(Cfg.Portmap, ",")}

	if peer, ok := Peers[onionaddr]; ok {
		// Here the implication is that it's not our first announce, so we
		// should have received a revoke key to use for a subsequent announce.
		data = append(data, peer.SelfRevoke)
	}

	if err := cli.CallResult(ctx, "ann.Init", data, &resp); err != nil {
		return err
	}
	nonce := resp[0]

	// TODO: Think about this >
	var peer Peer
	if _, ok := Peers[onionaddr]; ok {
		peer = Peers[onionaddr]
	}
	peer.SelfRevoke = resp[1]
	Peers[onionaddr] = peer

	sig := base64.StdEncoding.EncodeToString(
		ed25519.Sign(SignKey, []byte(nonce)))

	var newPeers []string
	if err := cli.CallResult(ctx, "ann.Validate",
		[]string{Onion, sig}, &newPeers); err != nil {
		return err
	}

	return AppendPeers(newPeers)
}

// AppendPeers appends given []string peers to the global Peers map. Usually
// received by validating ourself to a peer and them replying with a list of
// their valid peers. If a peer is not in format of "unlikelyname.onion:port",
// they will not be appended. When done, the function also writes the Peers
// struct as a JSON file in the Datadir.
// As a placeholder, this function can return an error, but it has no reason
// to do so right now.
func AppendPeers(p []string) error {
	for _, i := range p {
		if _, ok := Peers[i]; ok {
			continue
		}
		if err := ValidateOnionInternal(i); err != nil {
			log.Printf("warning: received garbage peer (%v)", err)
			continue
		}
		Peers[i] = Peer{}
	}

	writePeersDBWithSem(filepath.Join(Cfg.Datadir, dbFile))
	return nil
}
