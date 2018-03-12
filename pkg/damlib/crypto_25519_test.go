package damlib

/*
 * Copyright (c) 2017-2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan J. <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This source code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code. If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"os"
	"testing"
)

func TestGenEd25519(t *testing.T) {
	_, _, err := GenEd25519()
	if err != nil {
		t.Fatal("Failed generating ed25519 key:", err.Error())
	}

	t.Log("Successfully generated ed25519 keypair.")
}

func TestSavePubEd25519(t *testing.T) {
	pk, _, err := GenEd25519()
	if err != nil {
		t.Fatal("Failed generating ed25519 key:", err.Error())
	}

	err = SavePubEd25519("/tmp/ed25519pub.test", pk)
	if err != nil {
		t.Fatal("Failed saving pubkey:", err.Error())
	}

	os.Remove("/tmp/ed25519pub.test")
	t.Log("Success saving ed25519 pubkey")
}

func TestSavePrivEd25519(t *testing.T) {
	_, sk, err := GenEd25519()
	if err != nil {
		t.Fatal("Failed generating ed25519 key:", err.Error())
	}

	err = SavePrivEd25519("/tmp/ed25519priv.test", sk)
	if err != nil {
		t.Fatal("Failed saving privkey:", err.Error())
	}

	os.Remove("/tmp/ed25519priv.test")
	t.Log("Success saving ed25519 privkey")
}

func TestOnionFromPubkeyEd25519(t *testing.T) {
	pk, _, err := GenEd25519()
	if err != nil {
		t.Fatal("Failed generating ed25519 key:", err.Error())
	}

	res := OnionFromPubkeyEd25519(pk)
	valid := ValidateOnionAddress(string(res))

	t.Log("Got:", string(res))

	if !valid {
		t.Fatal("Address is invalid.")
	}
	t.Log("Address is valid")
}
