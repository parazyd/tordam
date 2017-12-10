package damlib

// See LICENSE file for copyright and license details.

import (
	"bytes"
	"log"
	"os/exec"
)

// FetchHSPubkey fetches a hidden service's RSA pubkey by running an external
// program, giving it an onion address. It returns the retrieved public key as a
// string.
func FetchHSPubkey(addr string) string {
	var outb, errb bytes.Buffer

	log.Println("Fetching pubkey for:", addr)

	cmd := exec.Command("damauth.py", addr)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()
	CheckError(err)

	err = cmd.Wait()
	if err != nil {
		log.Println("Could not fetch descriptor:", err)
		return ""
	}

	return outb.String()
}
