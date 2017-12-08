package main

// See LICENSE file for copyright and license details.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/parazyd/tor-dam/pkg/lib"
)

// Bits hold the size of our RSA private key. Tor standard is 1024.
const Bits = 1024

// Privpath holds the path of where our private key is.
const Privpath = "/tmp/decode-private.key"

// Pubpath holds the path of where our public key is.
//const Pubpath = "/tmp/decode-public.pub"

// Postmsg holds the message we are signing with our private key.
const Postmsg = "I am a DECODE node!"

type msgStruct struct {
	Secret string
}

func main() {
	if _, err := os.Stat(Privpath); os.IsNotExist(err) {
		key, err := lib.GenRsa(Bits)
		lib.CheckError(err)
		_, err = lib.SavePriv(Privpath, key)
		lib.CheckError(err)
	}

	// Start up the hidden service
	log.Println("Starting up the hidden service...")
	cmd := exec.Command("decodehs.py", Privpath)
	stdout, err := cmd.StdoutPipe()
	lib.CheckError(err)

	err = cmd.Start()
	lib.CheckError(err)

	scanner := bufio.NewScanner(stdout)
	ok := false
	go func() {
		// If we do not manage to publish our descriptor, we will exit.
		t1 := time.Now().Unix()
		for !(ok) {
			t2 := time.Now().Unix()
			if t2-t1 > 90 {
				cmd.Process.Kill()
				log.Fatalln("Too much time passed. Exiting.")
			}
			time.Sleep(1000 * time.Millisecond)
		}
	}()
	for !(ok) {
		scanner.Scan()
		status := scanner.Text()
		if status == "OK" {
			log.Println("Hidden service is now running")
			ok = true
		}
	}

	key, err := lib.LoadKeyFromFile(Privpath)
	lib.CheckError(err)

	sig, err := lib.SignMsg([]byte(Postmsg), key)
	lib.CheckError(err)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	onionAddr, err := lib.OnionFromPubkey(key.PublicKey)
	lib.CheckError(err)

	vals := map[string]string{
		"nodetype":  "node",
		"address":   string(onionAddr),
		"message":   Postmsg,
		"signature": encodedSig,
		"secret":    "",
	}

	log.Println("Announcing keypair for:", vals["address"])

	jsonVal, err := json.Marshal(vals)
	lib.CheckError(err)

	log.Println("Sending request")
	resp, err := lib.HTTPPost("http://localhost:8080/announce", jsonVal)
	lib.CheckError(err)

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
		resp, err := lib.HTTPPost("http://localhost:8080/announce", jsonVal)
		lib.CheckError(err)
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

	err = cmd.Wait() // Hidden service Python daemon
	lib.CheckError(err)
}
