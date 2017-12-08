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
func GenRsa(bitSize int) (*rsa.PrivateKey, error) {
	log.Printf("Generating %d-bit RSA keypair...\n", bitSize)
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, bitSize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SavePub saves a given RSA public key to a given filename.
func SavePub(filename string, pubkey rsa.PublicKey) (bool, error) {
	log.Printf("Writing pubkey to %s\n", filename)
	outfile, err := os.Create(filename)
	defer outfile.Close()
	if err != nil {
		return false, err
	}

	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return false, err
	}

	var pemkey = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	err = pem.Encode(outfile, pemkey)
	if err != nil {
		return false, err
	}
	return true, nil
}

// SavePriv saves a given RSA private key to a given filename.
func SavePriv(filename string, privkey *rsa.PrivateKey) (bool, error) {
	log.Printf("Writing private key to %s\n", filename)
	outfile, err := os.Create(filename)
	defer outfile.Close()
	if err != nil {
		return false, err
	}

	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}

	err = pem.Encode(outfile, pemkey)
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadKeyFromFile loads a RSA private key from a given filename.
func LoadKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	log.Println("Loading RSA private key from", filename)
	dat, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(dat)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// SignMsg signs a given []byte message using a given RSA private key.
func SignMsg(message []byte, privkey *rsa.PrivateKey) ([]byte, error) {
	log.Println("Signing message...")
	rng := rand.Reader

	hashed := sha512.Sum512(message)
	sig, err := rsa.SignPKCS1v15(rng, privkey, crypto.SHA512, hashed[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// EncryptMsg encrypts a given []byte message using a given RSA public key.
// Returns the encrypted message in []byte form.
func EncryptMsg(message []byte, pubkey *rsa.PublicKey) ([]byte, error) {
	log.Println("Encrypting message...")
	rng := rand.Reader

	msg, err := rsa.EncryptPKCS1v15(rng, pubkey, message)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// DecryptMsg decrypts a given []byte message using a given RSA private key.
// Returns the decrypted message in []byte form.
func DecryptMsg(message []byte, privkey *rsa.PrivateKey) ([]byte, error) {
	log.Println("Decrypting message...")
	rng := rand.Reader

	msg, err := rsa.DecryptPKCS1v15(rng, privkey, message)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// VerifyMsg verifies a []byte message and []byte signature against a given
// RSA pubkey.
func VerifyMsg(message []byte, signature []byte, pubkey *rsa.PublicKey) (bool, error) {
	log.Println("Verifying message signature")

	hashed := sha512.Sum512(message)
	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA512, hashed[:], signature)
	if err != nil {
		return false, err
	}

	log.Println("Signature valid")
	return true, nil
}

// OnionFromPubkey generates a valid onion address from a given RSA pubkey.
func OnionFromPubkey(pubkey rsa.PublicKey) ([]byte, error) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return nil, err
	}

	hashed := sha1.New()
	_, err = hashed.Write(asn1Bytes)
	if err != nil {
		return nil, err
	}

	encoded := strings.ToLower(base32.StdEncoding.EncodeToString(hashed.Sum(nil)))[:16]
	encoded += ".onion"

	return []byte(encoded), nil
}

// ParsePubkey parses a []byte form of a RSA public key and returns the proper
// type.
func ParsePubkey(pubkey []byte) (*rsa.PublicKey, error) {
	var pub rsa.PublicKey
	var ret *rsa.PublicKey

	block, _ := pem.Decode(pubkey)
	_, err := asn1.Unmarshal(block.Bytes, &pub)
	if err != nil {
		return nil, err
	}

	ret = &pub
	return ret, nil
}
