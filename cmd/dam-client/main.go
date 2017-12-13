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
	"strconv"
	"sync"
	"time"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

type msgStruct struct {
	Secret string
}

func announce(dir string, vals map[string]string, privkey *rsa.PrivateKey) (bool, error) {
	msg, err := json.Marshal(vals)
	if err != nil {
		return false, err
	}

	if dir == "localhost" || dir == "127.0.0.1" {
		// Modify the string if we are authenticating to ourself.
		dir += ":" + strconv.Itoa(lib.DirPort)
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

	if resp.StatusCode == 400 {
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

		sig, err := lib.SignMsgRsa([]byte(decryptedEncode), privkey)
		lib.CheckError(err)
		encodedSig := base64.StdEncoding.EncodeToString(sig)

		vals["secret"] = decryptedEncode
		vals["message"] = decryptedEncode
		vals["signature"] = encodedSig
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
		}
		log.Printf("%s: Fail. Reply: %s\n", dir, m.Secret)
		return false, nil
	}

	return false, nil
}

func main() {
	if _, err := os.Stat(lib.Cwd); os.IsNotExist(err) {
		err := os.Mkdir(lib.Cwd, 0700)
		lib.CheckError(err)
	}
	err := os.Chdir(lib.Cwd)
	lib.CheckError(err)

	if _, err := os.Stat(lib.PrivKeyPath); os.IsNotExist(err) {
		key, err := lib.GenRsa(lib.RsaBits)
		lib.CheckError(err)
		err = lib.SavePrivRsa(lib.PrivKeyPath, key)
		lib.CheckError(err)
	}

	// Start up the hidden service
	log.Println("Starting up the hidden service...")
	cmd := exec.Command("damhs.py", lib.PrivKeyPath, lib.TorPortMap)
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

	key, err := lib.LoadRsaKeyFromFile(lib.PrivKeyPath)
	lib.CheckError(err)

	sig, err := lib.SignMsgRsa([]byte(lib.PostMsg), key)
	lib.CheckError(err)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	onionAddr, err := lib.OnionFromPubkeyRsa(key.PublicKey)
	lib.CheckError(err)

	nodevals := map[string]string{
		"nodetype":  "node",
		"address":   string(onionAddr),
		"message":   lib.PostMsg,
		"signature": encodedSig,
		"secret":    "",
	}

	var ann = 0 // Track of how many successful authentications

	dirs := []string{"3mb6b3exknytbqdg.onion", "localhost"}

	var wg sync.WaitGroup
	for _, i := range dirs {
		wg.Add(1)
		go func(x string) {
			valid, err := announce(x, nodevals, key)
			if err != nil {
				log.Printf("%s: %s\n", x, err.Error())
			}
			if valid {
				ann++
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	if ann < 1 {
		cmd.Process.Kill()
		log.Fatalln("No successful authentications. Exiting.")
	}
	log.Printf("Successfully authenticated with %d nodes.\n", ann)

	err = cmd.Wait() // Hidden service Python daemon
	lib.CheckError(err)
}
