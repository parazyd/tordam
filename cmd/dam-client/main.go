package main

// See LICENSE file for copyright and license details.

import (
	"bufio"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/parazyd/tor-dam/pkg/lib"
)

// Cwd holds the path to the directory where we will Chdir on startup.
var Cwd = os.Getenv("HOME") + "/.dam"

// RsaBits holds the size of our RSA private key. Tor standard is 1024.
const RsaBits = 1024

// Privpath holds the name of where our private key is.
const Privpath = "dam-private.key"

// Postmsg holds the message we are signing with our private key.
const Postmsg = "I am a DAM node!"

type msgStruct struct {
	Secret string
}

func announce(dir string, vals map[string]string, privkey *rsa.PrivateKey) (bool, error) {
	msg, err := json.Marshal(vals)
	if err != nil {
		return false, err
	}

	if dir == "localhost" {
		// Modify the string if we are authenticating to ourself.
		dir = "localhost:49371"
	}

	log.Println("Announcing keypair to:", dir)
	resp, err := lib.HTTPPost("http://"+dir+"/announce", msg)
	if err != nil {
		return false, err
	}

	// Parse server's reply
	var m msgStruct
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&m)
	if err != nil {
		return false, err
	}

	if resp.StatusCode == 500 {
		log.Printf("%s: Fail. Reply: %s\n", dir, m.Secret)
		return false, nil
	}

	if resp.StatusCode == 200 {
		log.Printf("%s: Success. 1/2 handshake valid.\n", dir)
		decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
		if err != nil {
			return false, err
		}

		decrypted, err := lib.DecryptMsgRsa([]byte(decodedSecret), privkey)
		if err != nil {
			return false, err
		}

		decryptedEncode := base64.StdEncoding.EncodeToString(decrypted)

		vals["secret"] = decryptedEncode
		msg, err := json.Marshal(vals)
		if err != nil {
			return false, err
		}

		log.Printf("%s: Success. Sending back decrypted secret\n", dir)
		resp, err := lib.HTTPPost("http://"+dir+"/announce", msg)
		if err != nil {
			return false, err
		}
		decoder = json.NewDecoder(resp.Body)
		err = decoder.Decode(&m)
		if err != nil {
			return false, err
		}

		if resp.StatusCode == 200 {
			log.Printf("%s: Success. 2/2 handshake valid.\n", dir)
			log.Printf("%s: Reply: %s\n", dir, m.Secret)
			return true, nil
		} else {
			log.Printf("%s: Fail. Reply: %s\n", dir, m.Secret)
			return false, nil
		}
	}

	return false, nil
}

func main() {
	if _, err := os.Stat(Cwd); os.IsNotExist(err) {
		err := os.Mkdir(Cwd, 0700)
		lib.CheckError(err)
	}
	log.Println("Chdir to", Cwd)
	err := os.Chdir(Cwd)
	lib.CheckError(err)

	if _, err := os.Stat(Privpath); os.IsNotExist(err) {
		key, err := lib.GenRsa(RsaBits)
		lib.CheckError(err)
		_, err = lib.SavePrivRsa(Privpath, key)
		lib.CheckError(err)
	}

	// Start up the hidden service
	log.Println("Starting up the hidden service...")
	cmd := exec.Command("damhs.py", Privpath)
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

	key, err := lib.LoadRsaKeyFromFile(Privpath)
	lib.CheckError(err)

	sig, err := lib.SignMsgRsa([]byte(Postmsg), key)
	lib.CheckError(err)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	onionAddr, err := lib.OnionFromPubkeyRsa(key.PublicKey)
	lib.CheckError(err)

	nodevals := map[string]string{
		"nodetype":  "node",
		"address":   string(onionAddr),
		"message":   Postmsg,
		"signature": encodedSig,
		"secret":    "",
	}

	var ann = 0 // Track of how many successful authentications

	dirs := []string{"qvhgzxjkdchj2jl5.onion", "localhost"}

	var wg sync.WaitGroup
	for _, i := range dirs {
		wg.Add(1)
		go func(x string) {
			valid, err := announce(x, nodevals, key)
			lib.CheckError(err)
			if valid {
				ann++
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	if ann > 0 {
		log.Printf("Successfully authenticated with %d nodes.\n", ann)
	} else {
		cmd.Process.Kill()
		log.Fatalln("No successful authentications. Exiting.")
	}

	err = cmd.Wait() // Hidden service Python daemon
	lib.CheckError(err)
}
