package damlib

// See LICENSE file for copyright and license details.

import (
	"log"
	"regexp"
	"strings"
	"time"
)

// ValidateReq validates our given request against the logic we are checking.
// The function takes a request data map, and a public key in the form of a
// string. If the public key is an empty string, the function will run an
// external program to fetch the node's public key from a Tor HSDir.
//
// ValidateReq  will first validate "nodetype", looking whether the announcer
// is a node or a directory.
// Then, it will validate the onion address using a regular expression.
// Now, if pubkey is empty, it will run the external program to fetch it. If a
// descriptor can't be retrieved, it will retry for 10 times, and fail if those
// are not successful.
//
// Continuing, ValidateReq will verify the RSA signature posted by the
// announcer.
// If any of the above are invalid, the function will return nil and false.
// Otherwise, it will return the pubkey as a slice of bytes, and true.
func ValidateReq(req map[string]string, pubkey string) ([]byte, bool) {
	// Validate nodetype.
	if req["nodetype"] != "node" {
		return nil, false
	}
	// Validate address.
	re, err := regexp.Compile("^[a-z2-7]{16}\\.onion$")
	CheckError(err)
	if len(re.FindString(req["address"])) != 22 {
		return nil, false
	}
	log.Println(req["address"], "seems valid")

	if len(pubkey) == 0 {
		// Address is valid, we try to fetch its pubkey from a HSDir
		cnt := 0
		for { // We try until we have it.
			cnt++
			if cnt > 10 {
				// We probably can't get a good HSDir. The client shall retry
				// later on.
				return []byte("Couldn't get a descriptor. Try later."), false
			}
			pubkey = FetchHSPubkey(req["address"])
			if strings.HasPrefix(pubkey, "-----BEGIN RSA PUBLIC KEY-----") &&
				strings.HasSuffix(pubkey, "-----END RSA PUBLIC KEY-----") {
				log.Println("Got descriptor!")
				break
			}
			time.Sleep(2000 * time.Millisecond)
		}
	}
	// Validate signature.
	msg := []byte(req["message"])
	sig := []byte(req["signature"])
	pub, err := ParsePubkeyRsa([]byte(pubkey))
	CheckError(err)

	val, _ := VerifyMsgRsa(msg, sig, pub)
	if val != true {
		log.Println("crypto/rsa: verification failure")
		return nil, false
	}

	return []byte(pubkey), true
}
