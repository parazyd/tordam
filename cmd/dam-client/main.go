package main

/*
 * Copyright (c) 2017-2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan Jelincic <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

type msgStruct struct {
	Secret string
}

func clientInit(gen bool) error {
	pub, priv, err := lib.GenEd25519()
	if err != nil {
		return err
	}
	if err := lib.SavePrivEd25519(lib.PrivKeyPath, priv); err != nil {
		return err
	}
	if err := lib.SaveSeedEd25519(lib.SeedPath, priv.Seed()); err != nil {
		return err
	}
	if err := os.Chmod(lib.PrivKeyPath, 0600); err != nil {
		return err
	}
	if err := os.Chmod(lib.SeedPath, 0600); err != nil {
		return err
	}
	onionaddr := lib.OnionFromPubkeyEd25519(pub)
	if err := ioutil.WriteFile("hostname", onionaddr, 0600); err != nil {
		return err
	}
	if gen {
		log.Println("Our hostname is:", string(onionaddr))
		os.Exit(0)
	}
	return nil
}

func fetchNodeList(epLists []string, noremote bool) ([]string, error) {
	var nodeslice, nodelist []string

	log.Println("Fetching a list of nodes.")

	// Remote network entrypoints
	if !(noremote) {
		for _, i := range epLists {
			log.Println("Fetching", i)
			n, err := lib.HTTPDownload(i)
			if err != nil {
				return nil, err
			}
			nodeslice = lib.ParseDirs(nodeslice, n)
		}
	}

	// Local ~/.dam/directories.txt
	if _, err := os.Stat("directories.txt"); err == nil {
		ln, err := ioutil.ReadFile("directories.txt")
		if err != nil {
			return nil, err
		}
		nodeslice = lib.ParseDirs(nodeslice, ln)
	}

	// Local nodes known to Redis
	nodes, _ := lib.RedisCli.Keys("*.onion").Result()
	for _, i := range nodes {
		valid, err := lib.RedisCli.HGet(i, "valid").Result()
		if err != nil {
			// Possible RedisCli bug, possible Redis bug. To be investigated.
			// Sometimes it returns err, but it's nil and does not say what's
			// happening exactly.
			continue
		}
		if valid == "1" {
			nodeslice = append(nodeslice, i)
		}
	}

	// Remove possible duplicates. Duplicates can cause race conditions and are
	// redundant to the entire logic.
	encounter := map[string]bool{}
	for i := range nodeslice {
		encounter[nodeslice[i]] = true
	}
	nodeslice = []string{}
	for key := range encounter {
		nodeslice = append(nodeslice, key)
	}

	if len(nodeslice) < 1 {
		log.Fatalln("Couldn't fetch any nodes to announce to. Exiting.")
	} else if len(nodeslice) <= 6 {
		log.Printf("Found only %d nodes.\n", len(nodeslice))
		nodelist = nodeslice
	} else {
		log.Println("Found enough directories. Picking out 6 random ones.")
		for i := 0; i <= 5; i++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nodeslice))))
			nodelist = append(nodelist, nodeslice[n.Int64()])
			nodeslice[n.Int64()] = nodeslice[len(nodeslice)-1]
			nodeslice = nodeslice[:len(nodeslice)-1]
		}
	}
	return nodelist, nil
}

func announce(node string, vals map[string]string, privkey ed25519.PrivateKey) (bool, error) {
	msg, _ := json.Marshal(vals)

	log.Println("Announcing keypair to:", node)
	resp, err := lib.HTTPPost("http://"+node+"/announce", msg)
	if err != nil {
		return false, err
	}

	// Parse server's reply
	var m msgStruct
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&m); err != nil {
		return false, err
	}

	if resp.StatusCode == 400 {
		log.Printf("%s fail. Reply: %s\n", node, m.Secret)
		return false, nil
	}

	if resp.StatusCode == 200 {
		log.Printf("%s success. 1/2 handshake valid.", node)

		sig, err := lib.SignMsgEd25519([]byte(m.Secret), privkey)
		if err != nil {
			return false, err
		}
		encodedSig := base64.StdEncoding.EncodeToString(sig)

		vals["secret"] = m.Secret
		vals["message"] = m.Secret
		vals["signature"] = encodedSig

		msg, _ := json.Marshal(vals)

		log.Printf("%s: success. Sending back signed secret.\n", node)
		resp, err := lib.HTTPPost("http://"+node+"/announce", msg)
		if err != nil {
			return false, err
		}
		decoder = json.NewDecoder(resp.Body)
		if err := decoder.Decode(&m); err != nil {
			return false, err
		}

		if resp.StatusCode == 200 {
			log.Printf("%s success. 2/2 handshake valid.\n", node)
			data, err := base64.StdEncoding.DecodeString(m.Secret)
			if err != nil {
				// Not a list of nodes.
				log.Printf("%s replied: %s\n", node, m.Secret)
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
				log.Printf("Adding %s to Redis.\n", k)
				redRet, err := lib.RedisCli.HMSet(k, v).Result()
				lib.CheckError(err)
				if redRet != "OK" {
					log.Println("Redis returned:", redRet)
				}
			}
			return true, nil
		}
		log.Printf("%s fail. Reply: %s\n", node, m.Secret)
		return false, nil
	}

	return false, nil
}

func main() {
	var noremote, gen bool
	var ai int
	var dh string

	flag.BoolVar(&noremote, "d", false, "Don't fetch remote entrypoints.")
	flag.BoolVar(&gen, "gen", false, "Only (re)generate keypairs and exit cleanly.")
	flag.IntVar(&ai, "ai", 5, "Announce interval in minutes.")
	flag.StringVar(&dh, "dh", "https://dam.decodeproject.eu/dirs.txt",
		"Remote lists of entrypoints. (comma-separated)")
	flag.Parse()

	// Network entrypoints. These files hold the lists of nodes we can announce
	// to initially. Format is "DIR:unlikelynamefora.onion", other lines are
	// ignored and can be used as comments or similar.
	epLists := strings.Split(dh, ",")

	if _, err := os.Stat(lib.Workdir); os.IsNotExist(err) {
		err := os.Mkdir(lib.Workdir, 0700)
		lib.CheckError(err)
	}
	err := os.Chdir(lib.Workdir)
	lib.CheckError(err)

	if _, err = os.Stat(lib.PrivKeyPath); os.IsNotExist(err) || gen {
		err = clientInit(gen)
		lib.CheckError(err)
	}

	log.Println("Starting up the hidden service.")
	cmd := exec.Command("damhs.py", "-k", lib.PrivKeyPath, "-p", lib.TorPortMap)
	defer cmd.Process.Kill()
	stdout, err := cmd.StdoutPipe()
	lib.CheckError(err)

	err = cmd.Start()
	lib.CheckError(err)

	scanner := bufio.NewScanner(stdout)
	ok := false
	go func() {
		// If we do not manage to publish our descriptor, we shall exit.
		t1 := time.Now().Unix()
		for !(ok) {
			t2 := time.Now().Unix()
			if t2-t1 > 90 {
				log.Fatalln("Too much time has passed for publishing descriptor.")
			}
			time.Sleep(1000 * time.Millisecond)
		}
	}()
	for !(ok) {
		scanner.Scan()
		status := scanner.Text()
		if status == "OK" {
			log.Println("Hidden service is now running.")
			ok = true
		}
	}

	onionaddr, err := ioutil.ReadFile("hostname")
	lib.CheckError(err)
	log.Println("Our hostname is:", string(onionaddr))

	for {
		log.Println("Announcing to nodes...")
		var ann = 0 // Track of successful authentications.
		var wg sync.WaitGroup
		nodes, err := fetchNodeList(epLists, noremote)
		if err != nil {
			// No route to host, or failed download. Try later.
			log.Println("Failed to fetch any nodes. Retrying in a minute.")
			time.Sleep(60 * time.Second)
			continue
		}

		privkey, err := lib.LoadEd25519KeyFromSeed(lib.SeedPath)
		lib.CheckError(err)

		pubkey := privkey.Public().(ed25519.PublicKey)
		onionaddr := lib.OnionFromPubkeyEd25519(pubkey)
		encodedPub := base64.StdEncoding.EncodeToString([]byte(pubkey))

		sig, err := lib.SignMsgEd25519([]byte(lib.PostMsg), privkey)
		lib.CheckError(err)
		encodedSig := base64.StdEncoding.EncodeToString(sig)

		nodevals := map[string]string{
			"address":   string(onionaddr),
			"pubkey":    encodedPub,
			"message":   lib.PostMsg,
			"signature": encodedSig,
			"secret":    "",
		}

		for _, i := range nodes {
			wg.Add(1)
			go func(x string) {
				valid, err := announce(x, nodevals, privkey)
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

		log.Printf("%d successful authentications.\n", ann)
		log.Printf("Waiting %d min before next announce.\n", ai)
		time.Sleep(time.Duration(ai) * time.Minute)
	}
}
