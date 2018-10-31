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
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// GenEd25519 generates an ed25519 keypair. Returns error on failure.
func GenEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	log.Println("Generating ed25519 keypair...")

	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// SavePrivEd25519 writes a ed25519.PrivateKey type to a given string filename.
// Expands ed25519.PrivateKey to (a || RH) form, writing base64. Returns error
// upon failure.
func SavePrivEd25519(filename string, key ed25519.PrivateKey) error {
	log.Println("Writing ed25519 private key to", filename)

	h := sha512.Sum512(key[:32])
	// Set bits so that h[:32] is a private scalar "a".
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	// Since h[32:] is RH, h is now (a || RH)
	encoded := base64.StdEncoding.EncodeToString(h[:])
	return ioutil.WriteFile(filename, []byte(encoded), 0600)
}

// SaveSeedEd25519 saves the ed25519 private key seed to a given string filename
// for later reuse. Returns error upon failure.
func SaveSeedEd25519(filename string, key ed25519.PrivateKey) error {
	log.Println("Writing ed25519 private key seed to", filename)

	encoded := base64.StdEncoding.EncodeToString(key.Seed())
	return ioutil.WriteFile(filename, []byte(encoded), 0600)
}

// LoadEd25519KeyFromSeed loads a key from a given seed file and returns
// ed25519.PrivateKey. Otherwise, on failure, it returns error.
func LoadEd25519KeyFromSeed(filename string) (ed25519.PrivateKey, error) {
	log.Println("Loading ed25519 private key from seed in", filename)

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(decoded), nil
}

// SignMsgEd25519 signs a message using ed25519. Returns the signature in the
// form of []byte, or returns an error if it fails.
func SignMsgEd25519(message []byte, key ed25519.PrivateKey) ([]byte, error) {
	log.Println("Signing message...")

	sig, err := key.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// OnionFromPubkeyEd25519 generates a valid onion address from a given ed25519
// public key. Returns the onion address as a slice of bytes.
//
// Tor Spec excerpt from https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt
// ---
// 6. Encoding onion addresses [ONIONADDRESS]
// The onion address of a hidden service includes its identity public key, a
// version field and a basic checksum. All this information is then base32
// encoded as shown below:
//
//		onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
//		CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
//
//		where:
//			- PUBKEY is the 32 bytes ed25519 master pubkey of the hidden service.
//			- VERSION is an one byte version field (default value '\x03')
//			- ".onion checksum" is a constant string
//			- CHECKSUM is truncated to two bytes before inserting it in onion_address
func OnionFromPubkeyEd25519(pubkey ed25519.PublicKey) []byte {
	const hashConst = ".onion checksum"
	const versConst = '\x03'

	var h []byte
	h = append(h, []byte(hashConst)...)
	h = append(h, []byte(pubkey)...)
	h = append(h, byte(versConst))

	csum := sha3.Sum256(h)
	checksum := csum[:2]

	var enc []byte
	enc = append(enc, []byte(pubkey)...)
	enc = append(enc, checksum...)
	enc = append(enc, byte(versConst))

	encoded := base32.StdEncoding.EncodeToString(enc)
	return []byte(strings.ToLower(encoded) + ".onion")
}
