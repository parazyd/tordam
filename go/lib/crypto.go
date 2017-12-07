package lib

// See LICENSE file for copyright and license details.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// GenRsa generates a private RSA keypair of a given bitSize int.
func GenRsa(bitSize int) *rsa.PrivateKey {
	log.Printf("Generating %d-bit RSA keypair...\n", bitSize)
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, bitSize)
	CheckError(err)

	return key
}

// SavePub saves a given RSA public key to a given filename.
func SavePub(filename string, pubkey rsa.PublicKey) {
	log.Printf("Writing pubkey to %s\n", filename)
	outfile, err := os.Create(filename)
	CheckError(err)
	defer outfile.Close()

	asn1Bytes, err := asn1.Marshal(pubkey)
	CheckError(err)

	var pemkey = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	err = pem.Encode(outfile, pemkey)
	CheckError(err)
}

// SavePriv saves a given RSA private key to a given filename.
func SavePriv(filename string, privkey *rsa.PrivateKey) {
	log.Printf("Writing private key to %s\n", filename)
	outfile, err := os.Create(filename)
	CheckError(err)
	defer outfile.Close()

	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	err = pem.Encode(outfile, pemkey)
	CheckError(err)
}

// LoadKeyFromFile loads a RSA private key from a given filename.
func LoadKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	log.Println("Loading RSA private key from", filename)
	dat, err := ioutil.ReadFile(filename)
	CheckError(err)

	block, _ := pem.Decode(dat)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	CheckError(err)

	return priv, nil
}

// SignMsg signs a given []byte message using a given RSA private key.
func SignMsg(message []byte, privkey *rsa.PrivateKey) []byte {
	log.Println("Signing message...")
	rng := rand.Reader

	hashed := sha512.Sum512(message)
	sig, err := rsa.SignPKCS1v15(rng, privkey, crypto.SHA512, hashed[:])
	CheckError(err)

	return sig
}

// EncryptMsg encrypts a given []byte message using a given RSA public key.
func EncryptMsg(message []byte, pubkey *rsa.PublicKey) ([]byte, error) {
	log.Println("Encrypting message...")
	rng := rand.Reader

	msg, err := rsa.EncryptPKCS1v15(rng, pubkey, message)
	CheckError(err)

	return msg, nil
}

// VerifyMsg verifies a []byte message and []byte signature against a given
// RSA pubkey.
func VerifyMsg(message []byte, signature []byte, pubkey *rsa.PublicKey) (bool, error) {
	log.Println("Verifying message signature")

	hashed := sha512.Sum512(message)
	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA512, hashed[:], signature)
	if err != nil {
		log.Println("Error:", err)
		return false, nil
	}

	log.Println("Signature valid")
	return true, nil
}

// OnionFromPubkey generates a valid onion address from a given RSA pubkey.
func OnionFromPubkey(pubkey rsa.PublicKey) string {
	asn1Bytes, err := asn1.Marshal(pubkey)
	CheckError(err)

	hashed := sha1.New()
	_, err = hashed.Write(asn1Bytes)
	CheckError(err)

	encoded := strings.ToLower(base32.StdEncoding.EncodeToString(hashed.Sum(nil)))[:16]

	return encoded + ".onion"
}

// ParsePubkey parses a []byte form of a RSA public key and returns the proper
// type.
func ParsePubkey(pubkey []byte) (*rsa.PublicKey, error) {
	var pub rsa.PublicKey
	var ret *rsa.PublicKey

	block, _ := pem.Decode(pubkey)
	_, err := asn1.Unmarshal(block.Bytes, &pub)
	CheckError(err)

	ret = &pub
	return ret, nil
}
