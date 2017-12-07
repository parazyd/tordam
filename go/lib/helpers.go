package lib

import (
	"bytes"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// CheckError is a handler for errors.
func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

// FetchHSPubkey fetches a hidden service's RSA pubkey by running an external
// program, giving it an onion address.
func FetchHSPubkey(addr string) string {
	var outb, errb bytes.Buffer

	log.Println("Fetching pubkey for:", addr)

	cmd := exec.Command("./dirauth.py", addr)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Start()
	CheckError(err)

	err = cmd.Wait()
	CheckError(err)

	return outb.String()
}

// ValidateReq validates our given request against some checks.
func ValidateReq(req map[string]string) bool {
	// Validate nodetype.
	if req["nodetype"] != "node" {
		return false
	}

	// Validate address.
	re, err := regexp.Compile("^[a-z2-7]{16}\\.onion$")
	CheckError(err)
	if len(re.FindString(req["address"])) != 22 {
		return false
	}

	// Address is valid, we try to fetch its pubkey from a HSDir
	var pubkey string
	log.Println("Onion seems valid")
	for { // We try until we have it.
		if strings.HasPrefix(pubkey, "-----BEGIN RSA PUBLIC KEY-----") &&
			strings.HasSuffix(pubkey, "-----END RSA PUBLIC KEY-----") {
			log.Println("Got descriptor!")
			break
		}
		time.Sleep(2000 * time.Millisecond)
		pubkey = FetchHSPubkey(req["address"])
		//log.Println(pubkey)
	}

	// Validate signature.
	msg := []byte(req["message"])
	sig := []byte(req["signature"])
	pub := []byte(pubkey)
	val, err := VerifyMsg(msg, sig, pub)
	CheckError(err)
	if val != true {
		return false
	}

	return true
}
