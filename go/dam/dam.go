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
//const Pubpath = "public.key"

// Postmsg holds the message we are signing with our private key.
const Postmsg = "I am a DECODE node!"

type msgStruct struct {
	Secret string
}

func main() {
	if _, err := os.Stat("private.key"); os.IsNotExist(err) {
		key := lib.GenRsa(Bits)
		lib.SavePriv(Privpath, key)
		//lib.SavePub(Pubpath, key.PublicKey)
	}

	key, err := lib.LoadKeyFromFile(Privpath)
	lib.CheckError(err)

	sig := lib.SignMsg([]byte(Postmsg), key)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	vals := map[string]string{
		"nodetype":  "node",
		"address":   lib.OnionFromPubkey(key.PublicKey),
		"message":   Postmsg,
		"signature": encodedSig,
		"secret":    "",
	}

	log.Println("Announcing keypair for:", vals["address"])

	jsonVal, err := json.Marshal(vals)
	lib.CheckError(err)

	log.Println("Sending request")
	resp := lib.HTTPPost("http://localhost:8080/announce", jsonVal)

	// TODO: Handle the secret decryption and returning it back decrypted to the
	// directory. Note to self: start saving state on ddir's side.

	// Parse server's reply
	var m msgStruct
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&m)
	lib.CheckError(err)

	if resp.StatusCode == 500 {
		log.Println("Unsuccessful reply from directory.")
		log.Fatalln("Server replied:", m.Secret)
	}

	if resp.StatusCode == 200 {
		log.Println("Successful reply from directory.")
		decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
		lib.CheckError(err)

		decrypted, err := lib.DecryptMsg([]byte(decodedSecret), key)
		lib.CheckError(err)

		decryptedEncode := base64.StdEncoding.EncodeToString(decrypted)

		vals["secret"] = decryptedEncode
		jsonVal, err := json.Marshal(vals)
		lib.CheckError(err)

		log.Println("Sending back decrypted secret.")
		resp = lib.HTTPPost("http://localhost:8080/announce", jsonVal)
		decoder = json.NewDecoder(resp.Body)
		err = decoder.Decode(&m)
		lib.CheckError(err)

		if resp.StatusCode == 200 {
			log.Println("Successfully authenticated!")
			log.Println("Server replied:", m.Secret)
		} else {
			log.Println("Unsuccessful reply from directory.")
			log.Fatalln("Server replied:", m.Secret)
		}
	}
}
