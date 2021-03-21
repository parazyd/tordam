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
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"
)

func TestAnnounce(t *testing.T) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	Cfg.Datadir = os.TempDir()

	vals := []string{
		"p7qaewjgnvnaeihhyybmoofd5avh665kr3awoxlh5rt6ox743kjdr6qd.onion:666",
		base64.StdEncoding.EncodeToString(pk),
		"12345:54321,666:3521",
	}

	ret, err := Ann.Init(Ann{}, context.Background(), vals)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ret {
		if _, err := base64.StdEncoding.DecodeString(i); err != nil {
			t.Fatal(err)
		}
	}

	vals = []string{
		"p7qaewjgnvnaeihhyybmoofd5avh665kr3awoxlh5rt6ox743kjdr6qd.onion:666",
		base64.StdEncoding.EncodeToString(ed25519.Sign(sk, []byte(ret[0]))),
	}

	ret, err = Ann.Validate(Ann{}, context.Background(), vals)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ret {
		if err := ValidateOnionInternal(i); err != nil {
			t.Fatal(err)
		}
	}
}
