package damlib

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

// GenRsa generates a private RSA keypair of a given bitSize int and returns it
// as rsa.PrivateKey.
func GenRsa(bitSize int) (*rsa.PrivateKey, error) {
	log.Printf("Generating %d-bit RSA keypair...\n", bitSize)
	rng := rand.Reader
	key, err := rsa.GenerateKey(rng, bitSize)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SavePubRsa saves a given RSA public key to a given filename.
// SavePubRsa takes the filename to write as a string, and the key as
// rsa.PublicKey. It returns an error on failure, otherwise: nil
func SavePubRsa(filename string, pubkey rsa.PublicKey) error {
	log.Println("Writing RSA pubkey to", filename)
	outfile, err := os.Create(filename)
	defer outfile.Close()
	if err != nil {
		return err
	}
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return err
	}
	var pemkey = &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	if err = pem.Encode(outfile, pemkey); err != nil {
		return err
	}
	if err = outfile.Chmod(0400); err != nil {
		return err
	}
	return nil
}

// SavePrivRsa saves a given RSA private key to a given filename.
// SavePrivRsa takes the filename to write as a string, and the key as
// *rsa.PrivateKey. It returns an error on failure, otherwise: nil
func SavePrivRsa(filename string, privkey *rsa.PrivateKey) error {
	log.Printf("Writing private key to %s\n", filename)
	outfile, err := os.Create(filename)
	defer outfile.Close()
	if err != nil {
		return err
	}
	var pemkey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	}
	if err = pem.Encode(outfile, pemkey); err != nil {
		return err
	}
	if err = outfile.Chmod(0400); err != nil {
		return err
	}
	return nil
}

// LoadRsaKeyFromFile loads a RSA private key from a given filename.
// LoadRsaKeyFromFile takes a string filename and tries to read from it, parsing
// the private RSA key. It will return a *rsa.PrivateKey on success, and error
// on fail.
func LoadRsaKeyFromFile(filename string) (*rsa.PrivateKey, error) {
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

// SignMsgRsa signs a given []byte message using a given RSA private key.
// It will return the signature as a slice of bytes on success, and error on
// failure.
func SignMsgRsa(message []byte, privkey *rsa.PrivateKey) ([]byte, error) {
	log.Println("Signing message...")
	rng := rand.Reader
	hashed := sha512.Sum512(message)
	sig, err := rsa.SignPKCS1v15(rng, privkey, crypto.SHA512, hashed[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// EncryptMsgRsa encrypts a given []byte message using a given RSA public key.
// Returns the encrypted message as a slice of bytes on success, and error on
// failure.
func EncryptMsgRsa(message []byte, pubkey *rsa.PublicKey) ([]byte, error) {
	log.Println("Encrypting message...")
	rng := rand.Reader
	msg, err := rsa.EncryptPKCS1v15(rng, pubkey, message)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// DecryptMsgRsa decrypts a given []byte message using a given RSA private key.
// Returns the decrypted message as a slice of bytes on success, and error on
// failure.
func DecryptMsgRsa(message []byte, privkey *rsa.PrivateKey) ([]byte, error) {
	log.Println("Decrypting message...")
	rng := rand.Reader
	msg, err := rsa.DecryptPKCS1v15(rng, privkey, message)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// VerifyMsgRsa verifies a message and signature against a given RSA pubkey.
// Returns a boolean value and error depending on whether it has failed or not.
func VerifyMsgRsa(message []byte, signature []byte, pubkey *rsa.PublicKey) (bool, error) {
	log.Println("Verifying message signature")
	hashed := sha512.Sum512(message)
	if err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA512, hashed[:], signature); err != nil {
		return false, err
	}
	return true, nil
}

// OnionFromPubkeyRsa generates a valid onion address from a given RSA pubkey.
// Returns the onion address as a slice of bytes on success and error on
// failure.
func OnionFromPubkeyRsa(pubkey rsa.PublicKey) ([]byte, error) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return nil, err
	}
	hashed := sha1.New()
	if _, err = hashed.Write(asn1Bytes); err != nil {
		return nil, err
	}
	encoded := strings.ToLower(base32.StdEncoding.EncodeToString(hashed.Sum(nil)))[:16]
	encoded += ".onion"

	return []byte(encoded), nil
}

// ParsePubkeyRsa parses a []byte form of a RSA public key and returns it as
// *rsa.PublicKey on success. Otherwise, error.
func ParsePubkeyRsa(pubkey []byte) (*rsa.PublicKey, error) {
	var pub rsa.PublicKey
	var ret *rsa.PublicKey
	block, _ := pem.Decode(pubkey)
	if _, err := asn1.Unmarshal(block.Bytes, &pub); err != nil {
		return nil, err
	}
	ret = &pub
	return ret, nil
}
