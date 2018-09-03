package main

/*
 * Copyright (c) 2017-2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan J. <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This source code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code. If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
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

// Network entry points. These files hold the lists of directories we can
// announce to. Format is "DIR:22mobp7vrb7a4gt2.onion", other lines are ignored.
var dirHosts = []string{
	"https://dam.decodeproject.eu/dirs.txt",
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

		decrypted, err := lib.DecryptMsgRsa(decodedSecret, privkey)
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
		if err = decoder.Decode(&m); err != nil {
			return false, err
		}

		if resp.StatusCode == 200 {
			log.Printf("%s: Success. 2/2 handshake valid.\n", dir)
			// TODO: To TOFU or not to TOFU?
			data, err := base64.StdEncoding.DecodeString(m.Secret)
			if err != nil {
				// Not a list of nodes.
				log.Printf("%s: Reply: %s\n", dir, m.Secret)
				return true, nil
			}
			log.Println("Got node data. Processing...")
			b := bytes.NewReader(data)
			r, _ := gzip.NewReader(b)
			nodes := make(map[string]map[string]interface{})
			decoder = json.NewDecoder(r)
			if err = decoder.Decode(&nodes); err != nil {
				return false, err
			}
			for k, v := range nodes {
				log.Printf("Adding %s to redis\n", k)
				redRet, err := lib.RedisCli.HMSet(k, v).Result()
				lib.CheckError(err)
				if redRet != "OK" {
					log.Println("Redis returned:", redRet)
				}
			}
			return true, nil
		}
		log.Printf("%s: Fail. Reply: %s\n", dir, m.Secret)
		return false, nil
	}

	return false, nil
}

func fetchDirlist(locations []string) ([]string, error) {
	var dirSlice, dirlist []string
	log.Println("Grabbing a list of directories.")

	// Remote network entry points
	if !(lib.Noremote) {
		for _, i := range locations {
			log.Println("Fetching", i)
			dirs, err := lib.HTTPDownload(i)
			if err != nil {
				return nil, err
			}
			dirSlice = lib.ParseDirs(dirSlice, dirs)
		}
	}

	// Local ~/.dam/directories.txt
	if _, err := os.Stat("directories.txt"); err == nil {
		dirs, err := ioutil.ReadFile("directories.txt")
		lib.CheckError(err)
		dirSlice = lib.ParseDirs(dirSlice, dirs)
	}

	// Local nodes known to redis
	nodes, err := lib.RedisCli.Keys("*.onion").Result()
	lib.CheckError(err)
	for _, i := range nodes {
		valid, err := lib.RedisCli.HGet(i, "valid").Result()
		lib.CheckError(err)
		if valid == "1" {
			dirSlice = append(dirSlice, i)
		}
	}

	if len(dirSlice) < 1 {
		log.Fatalln("Couldn't get any directories. Exiting.")
	} else if len(dirSlice) <= 6 {
		log.Printf("Found only %d directories.\n", len(dirSlice))
		dirlist = dirSlice
	} else {
		log.Println("Found enough directories. Picking out 6 random ones.")
		// Pick out 6 random directories from the retrieved list.
		for k := 0; k <= 5; k++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(dirSlice))))
			dirlist = append(dirlist, dirSlice[n.Int64()])
			dirSlice[n.Int64()] = dirSlice[len(dirSlice)-1]
			dirSlice = dirSlice[:len(dirSlice)-1]
		}
	}
	dirlist = append(dirlist, "localhost")
	return dirlist, nil
}

func main() {
	var d bool
	var ai int

	flag.BoolVar(&d, "d", false, "Don't fetch remote entry points")
	flag.IntVar(&ai, "ai", 10, "Announce interval in minutes")
	flag.Parse()

	if d {
		lib.Noremote = true
	}

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
		onionaddr, err := lib.OnionFromPubkeyRsa(key.PublicKey)
		lib.CheckError(err)
		err = ioutil.WriteFile("hostname", onionaddr, 0644)
		lib.CheckError(err)
		log.Println("Our hostname is:", string(onionaddr))
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

	for {
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

		log.Println("Announcing to directories...")
		var ann = 0 // Track of how many successful authentications
		var wg sync.WaitGroup
		dirlist, err := fetchDirlist(dirHosts)
		if err != nil {
			// No route to host, or failed dl. Try later.
			log.Println("Failed to fetch directory list. Retrying in a minute.")
			time.Sleep(60 * time.Second)
			continue
		}
		for _, i := range dirlist {
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
		} else {
			log.Printf("Successfully authenticated with %d nodes.\n", ann)
		}
		log.Printf("Waiting %d min. before next announce.\n", ai)
		time.Sleep(time.Duration(ai) * time.Minute)
	}

	//err = cmd.Wait() // Hidden service Python daemon
	//lib.CheckError(err)
}
