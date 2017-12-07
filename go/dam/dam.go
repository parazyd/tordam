package main

// See LICENSE file for copyright and license details.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	"../lib"
)

// Bits hold the size of our RSA private key. Tor standard is 1024.
const Bits = 1024

// Privpath holds the path of where our private key is.
const Privpath = "private.key"

// Pubpath holds the path of where our public key is.
const Pubpath = "public.key"

func main() {
	if _, err := os.Stat("private.key"); os.IsNotExist(err) {
		key := lib.GenRsa(Bits)
		lib.SavePriv(Privpath, key)
		lib.SavePub(Pubpath, key.PublicKey)
	}

	key, err := lib.LoadKeyFromFile(Privpath)
	lib.CheckError(err)

	sig := lib.SignMsg([]byte("I am a DECODE node!"), key)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	vals := map[string]string{
		"nodetype":  "node",
		"address":   lib.OnionFromPubkey(key.PublicKey),
		"message":   "I'm a DECODE node!",
		"signature": encodedSig,
	}

	log.Println("Announcing keypair for:", vals["address"])

	jsonVal, err := json.Marshal(vals)
	lib.CheckError(err)

	log.Println("Sending request")
	resp := lib.HTTPPost("http://localhost:8080/announce", jsonVal)

	log.Println(resp)
}
