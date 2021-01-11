package main

/*
 * Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
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
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
)

func fetchNodeList(epLists []string, remote bool) ([]string, error) {
	var ns, nl []string

	log.Println("Building a list of nodes")

	// Remote network entrypoints
	if !remote {
		for _, i := range epLists {
			log.Println("Fetching", i)
			n, err := httpGet(i)
			if err != nil {
				return nil, err
			}
			ns = parseDirs(ns, n)
		}
	}

	// Local workdir/dirs.txt
	ld := strings.Join([]string{*workdir, "dirs.txt"}, "/")
	if _, err := os.Stat(ld); err == nil {
		ln, err := ioutil.ReadFile(ld)
		if err != nil {
			return nil, err
		}
		ns = parseDirs(ns, ln)
	}

	// Local nodes from redis
	nodes, _ := rcli.Keys(rctx, "*.onion").Result()
	for _, i := range nodes {
		valid, err := rcli.HGet(rctx, i, "valid").Result()
		if err != nil {
			// Possible RedisCli bug, possible Redis bug. To be investigated.
			// Sometimes it returns err, but it's empty and does not say what's
			// happening exactly.
			continue
		}
		if valid == "1" {
			ns = append(ns, i)
		}
	}

	// Remove possible dupes. Duplicates can cause race conditions and are
	// redundant to the entire logic.
	// TODO: Work this in above automatically (by changing the var type)
	encounter := map[string]bool{}
	for i := range ns {
		encounter[ns[i]] = true
	}
	ns = []string{}
	for key := range encounter {
		ns = append(ns, key)
	}

	if len(ns) < 1 {
		log.Fatal("Couldn't find any nodes to announce to. Exiting...")
	} else if len(ns) <= 6 {
		log.Printf("Found %d nodes\n", len(ns))
		nl = ns
	} else {
		log.Printf("Found %d nodes. Picking out 6 at random\n", len(ns))
		for i := 0; i <= 5; i++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ns))))
			nl = append(nl, ns[n.Int64()])
			ns[n.Int64()] = ns[len(ns)-1]
			ns = ns[:len(ns)-1]
		}
	}

	return nl, nil
}

func announce(addr string, vals map[string]string) (bool, error) {
	msg, _ := json.Marshal(vals)

	log.Println("Announcing keypair to", addr)
	resp, err := httpPost("http://"+addr+":49371"+"/announce", msg)
	if err != nil {
		return false, err
	}

	// Parse server's reply
	var m Message
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&m); err != nil {
		return false, err
	}

	if resp.StatusCode != 200 {
		log.Printf("%s returned error: %s\n", addr, m.Secret)
		return false, nil
	}

	log.Println("Got nonce from", addr)

	sig := ed25519.Sign(signingKey, []byte(m.Secret))

	vals["secret"] = m.Secret
	vals["message"] = m.Secret
	vals["signature"] = base64.StdEncoding.EncodeToString(sig)
	msg, _ = json.Marshal(vals)

	log.Println("Sending back signed secret to", addr)
	resp, err = httpPost("http://"+addr+":49371"+"/announce", msg)
	if err != nil {
		return false, err
	}

	dec = json.NewDecoder(resp.Body)
	if err := dec.Decode(&m); err != nil {
		return false, err
	}

	if resp.StatusCode != 200 {
		log.Printf("%s returned error: %s\n", addr, m.Secret)
		return false, nil
	}

	log.Printf("%s handshake valid\n", addr)
	data, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		// Not a list of nodes
		log.Printf("%s replied: %s\n", addr, m.Secret)
		return true, nil
	}

	log.Println("Got node data, processing...")
	b := bytes.NewReader(data)
	r, _ := gzip.NewReader(b)
	nodes := make(map[string]map[string]interface{})
	dec = json.NewDecoder(r)
	if err = dec.Decode(&nodes); err != nil {
		return false, err
	}

	for k, v := range nodes {
		log.Printf("Adding %s to redis\n", k)
		if _, err := rcli.HSet(rctx, k, v).Result(); err != nil {
			log.Fatal(err)
		}
	}

	return true, nil
}
