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
	"errors"
	"strings"
	"time"
)

type ann struct{}

// Init takes three parameters:
// - onion: onionaddress:port where the peer and tordam can be reached
// - pubkey: ed25519 public signing key in base64
// - portmap: List of ports available for communication
// - (optional) revoke: Revocation key for updating peer info
//  {"jsonrpc":"2.0",
//   "id": 1,
//   "method": "ann.Init",
//   "params": ["unlikelynameforan.onion:49371", "214=", "69:420,323:2354"]
//  }
// Returns:
// - nonce: A random nonce which is to be signed by the client
// - revoke: A key which can be used to revoke key and portman and reannounce the peer
//  {"jsonrpc":"2.0",
//   "id":1,
//   "result": ["somenonce", "somerevokekey"]
//  }
// On any kind of failure returns an error and the reason.
func (ann) Init(ctx context.Context, vals []string) ([]string, error) {
	if len(vals) != 3 && len(vals) != 4 {
		return nil, errors.New("invalid parameters")
	}

	onion := vals[0]
	pubkey := vals[1]
	portmap := strings.Split(vals[2], ",")

	if err := ValidateOnionInternal(onion); err != nil {
		rpcWarn("ann.Init", err.Error())
		return nil, err
	}

	rpcInfo("ann.Init", "got request for", onion)

	var peer Peer
	reallySeen := false
	peer, ok := Peers[onion]
	if ok {
		// We have seen this peer
		if peer.Pubkey != nil || peer.PeerRevoke != "" {
			reallySeen = true
		}
	}

	if reallySeen {
		// Peer announced to us before
		if len(vals) != 4 {
			rpcWarn("ann.Init", "no revocation key provided")
			return nil, errors.New("no revocation key provided")
		}
		revoke := vals[3]
		if strings.Compare(revoke, peer.PeerRevoke) != 0 {
			rpcWarn("ann.Init", "revocation key doesn't match")
			return nil, errors.New("revocation key doesn't match")
		}
	}

	pk, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		rpcWarn("ann.Init", "got invalid base64 public key")
		return nil, errors.New("invalid base64 public key")
	} else if len(pk) != 32 {
		rpcWarn("ann.Init", "got invalid pubkey (len != 32)")
		return nil, errors.New("invalid public key")
	}

	if err := ValidatePortmap(portmap); err != nil {
		rpcWarn("ann.Init", err.Error())
		return nil, err
	}

	nonce, err := RandomGarbage(32)
	if err != nil {
		rpcInternalErr("ann.Init", err.Error())
		return nil, errors.New("internal error")
	}

	newrevoke, err := RandomGarbage(128)
	if err != nil {
		rpcInternalErr("ann.Init", err.Error())
		return nil, errors.New("internal error")
	}

	peer.Pubkey = pk
	peer.Portmap = portmap
	peer.Nonce = nonce
	peer.PeerRevoke = newrevoke
	peer.LastSeen = time.Now().Unix()
	peer.Trusted = 0
	Peers[onion] = peer

	return []string{nonce, newrevoke}, nil
}

// Validate takes two parameters:
// - onion: onionaddress:port where the peer and tordam can be reached
// - signature: base64 signature of the previously obtained nonce
//  {"jsonrpc":"2.0",
//   "id":2,
//   "method": "ann.Announce",
//   "params": ["unlikelynameforan.onion:49371", "deadbeef=="]
//  }
// Returns:
// - peers: A list of known validated peers (max. 50)
//  {"jsonrpc":"2.0",
//   "id":2,
//   "result": ["unlikelynameforan.onion:69", "yetanother.onion:420"]
//  }
// On any kind of failure returns an error and the reason.
func (ann) Validate(ctx context.Context, vals []string) ([]string, error) {
	if len(vals) != 2 {
		return nil, errors.New("invalid parameters")
	}

	onion := vals[0]
	signature := vals[1]

	if err := ValidateOnionInternal(onion); err != nil {
		rpcWarn("ann.Validate", err.Error())
		return nil, err
	}

	rpcInfo("ann.Validate", "got request for", onion)

	peer, ok := Peers[onion]
	if !ok {
		rpcWarn("ann.Validate", onion, "not in peer map")
		return nil, errors.New("this onion was not seen before")
	}

	if peer.Pubkey == nil || peer.Nonce == "" {
		rpcWarn("ann.Validate", onion, "tried to validate before init")
		return nil, errors.New("tried to validate before init")
	}

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		rpcWarn("ann.Validate", "invalid base64 signature string")
		return nil, errors.New("invalid base64 signature string")
	}

	if !ed25519.Verify(peer.Pubkey, []byte(peer.Nonce), sig) {
		rpcWarn("ann.Validate", "signature verification failed")
		// delete(Peers, onion)
		return nil, errors.New("signature verification failed")
	}

	rpcInfo("ann.Validate", "validation success for", onion)

	var ret []string
	for addr, data := range Peers {
		if data.Trusted > 0 {
			ret = append(ret, addr)
		}
	}

	peer.Nonce = ""
	peer.Trusted = 1
	peer.LastSeen = time.Now().Unix()
	Peers[onion] = peer

	rpcInfo("ann.Validate", "sending back list of peers to", onion)
	return ret, nil
}
