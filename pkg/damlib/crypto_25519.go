package damlib

// See LICENSE file for copyright and license details.

import (
	"crypto/rand"
	"encoding/base32"
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// GenEd25519 generates an ed25519 keypair. Returns error on failure.
func GenEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	log.Println("Generating ed25519 keypair...")
	rng := rand.Reader
	pk, sk, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// SavePubEd25519 writes a ed25519.PublicKey type to a given string filename.
// Returns error upon failure.
func SavePubEd25519(filename string, key ed25519.PublicKey) error {
	log.Println("Writing ed25519 public key to", filename)
	const pkprefix = "== ed25519v1-public: type0 =="
	var pub []byte
	for _, i := range []byte(pkprefix) {
		pub = append(pub, i)
	}
	for _, i := range []byte(key) {
		pub = append(pub, i)
	}
	if err := ioutil.WriteFile(filename, pub, 0600); err != nil {
		return err
	}
	return nil
}

// SavePrivEd25519 writes a ed25519.PrivateKey type to a given string filename.
// Returns error upon failure.
func SavePrivEd25519(filename string, key ed25519.PrivateKey) error {
	log.Println("Writing ed25519 private key to", filename)
	const skprefix = "== ed25519v1-secret: type0 =="
	var sec []byte
	for _, i := range []byte(skprefix) {
		sec = append(sec, i)
	}
	for _, i := range []byte(key) {
		sec = append(sec, i)
	}
	if err := ioutil.WriteFile(filename, sec, 0600); err != nil {
		return err
	}
	return nil
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
	for _, i := range []byte(hashConst) {
		h = append(h, i)
	}
	for _, i := range []byte(pubkey) {
		h = append(h, i)
	}
	h = append(h, byte(versConst))

	csum := sha3.Sum256(h)
	checksum := csum[:2]

	var enc []byte
	for _, i := range []byte(pubkey) {
		enc = append(enc, i)
	}
	for _, i := range checksum {
		enc = append(enc, i)
	}
	enc = append(enc, byte(versConst))

	encoded := base32.StdEncoding.EncodeToString(enc)
	return []byte(strings.ToLower(encoded) + ".onion")
}
