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
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

// ListenAddress controls where our HTTP API daemon is listening.
const ListenAddress = "127.0.0.1:49371"

type nodeStruct struct {
	Address   string
	Message   string
	Signature string
	Secret    string
	Pubkey    string
	Firstseen int64
	Lastseen  int64
	Valid     int64
}

func postback(rw http.ResponseWriter, data map[string]string, retCode int) error {
	jsonVal, err := json.Marshal(data)
	if err != nil {
		return err
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(retCode)
	rw.Write(jsonVal)
	return nil
}

func handlePost(rw http.ResponseWriter, request *http.Request) {
	var ret map[string]string
	var n nodeStruct

	if request.Method != "POST" || request.Header["Content-Type"][0] != "application/json" {
		ret = map[string]string{"secret": "Invalid request format."}
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}

	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(&n); err != nil {
		log.Println("Failed decoding request:", err)
		return
	}

	// Bail out as soon as possible.
	if len(n.Address) == 0 || len(n.Message) == 0 || len(n.Signature) == 0 {
		ret = map[string]string{"secret": "Invalid request format."}
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}
	if !(lib.ValidateOnionAddress(n.Address)) {
		log.Println("Invalid onion address. Got:", n.Address)
		ret = map[string]string{"secret": "Invalid onion address."}
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}

	req := map[string]string{
		"address":   n.Address,
		"message":   n.Message,
		"pubkey":    n.Pubkey,
		"signature": n.Signature,
		"secret":    n.Secret,
	}

	// First handshake
	if len(n.Message) != 88 && len(n.Secret) != 88 {
		valid, msg := lib.ValidateFirstHandshake(req)
		ret = map[string]string{"secret": msg}
		if valid {
			log.Printf("%s: 1/2 handshake valid.\n", n.Address)
			log.Println("Sending nonce.")
			if err := postback(rw, ret, 200); err != nil {
				lib.CheckError(err)
			}
			return
		}
		log.Printf("%s: 1/2 handshake invalid: %s\n", n.Address, msg)
		// Delete it all from redis.
		_, err := lib.RedisCli.Del(n.Address).Result()
		lib.CheckError(err)
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}

	// Second handshake
	if len(req["secret"]) == 88 && len(req["message"]) == 88 {
		valid, msg := lib.ValidateSecondHandshake(req)
		ret = map[string]string{"secret": msg}

		if valid {
			log.Printf("%s: 2/2 handshake valid.\n", n.Address)
			hasConsensus, err := lib.RedisCli.HGet(n.Address, "valid").Result()
			lib.CheckError(err)

			us := request.Host // Assume our name is what was requested as the URL.
			nodemap := make(map[string]map[string]string)

			if hasConsensus == "1" {
				// The node does have consensus, we'll teach it about the valid
				// nodes we know.
				log.Printf("%s has consensus. Propagating our nodes to it...\n", n.Address)
				nodes, err := lib.RedisCli.Keys("*.onion").Result()
				lib.CheckError(err)
				for _, i := range nodes {
					if i == n.Address {
						continue
					}
					nodedata, err := lib.RedisCli.HGetAll(i).Result()
					lib.CheckError(err)
					if nodedata["valid"] == "1" {
						nodemap[i] = nodedata
						delete(nodemap[i], "secret")
					}
				}
			} else {
				log.Printf("%s does not have consensus. Propagating ourself to it...\n", n.Address)
				// The node doesn't have consensus in the network. We will only
				// teach it about ourself.
				nodedata, err := lib.RedisCli.HGetAll(us).Result()
				lib.CheckError(err)
				nodemap[us] = nodedata
				delete(nodemap[us], "secret")
			}

			nodestr, err := json.Marshal(nodemap)
			lib.CheckError(err)
			comp, err := lib.GzipEncode(nodestr)
			lib.CheckError(err)
			ret = map[string]string{"secret": comp}
			if err := postback(rw, ret, 200); err != nil {
				lib.CheckError(err)
			}

			lib.PublishToRedis("am", n.Address)

			return
		}

		// If we have't returned so far, the handshake is invalid.
		log.Printf("%s: 2/2 handshake invalid.\n", n.Address)
		// Delete it all from redis.
		lib.PublishToRedis("d", n.Address)
		_, err := lib.RedisCli.Del(n.Address).Result()
		lib.CheckError(err)
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}
}

func pollNodeTTL(interval int64) {
	for {
		log.Println("Polling redis for expired nodes")
		nodes, err := lib.RedisCli.Keys("*.onion").Result()
		lib.CheckError(err)
		now := time.Now().Unix()

		for _, i := range nodes {
			res, err := lib.RedisCli.HGet(i, "lastseen").Result()
			lib.CheckError(err)
			lastseen, err := strconv.Atoi(res)
			lib.CheckError(err)

			diff := (now - int64(lastseen)) / 60
			if diff > interval {
				log.Printf("Deleting %s from redis because of expiration\n", i)
				lib.PublishToRedis("d", i)
				lib.RedisCli.Del(i)
			}
		}
		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

// handleElse is a noop for anything that isn't /announce. We don't care about
// other requests (yet).
func handleElse(rw http.ResponseWriter, request *http.Request) {}

func main() {
	var wg sync.WaitGroup
	var ttl int64
	var redconf string

	flag.BoolVar(&lib.Testnet, "t", false, "Mark all new nodes valid initially")
	flag.Int64Var(&ttl, "ttl", 0, "Set expiry time in minutes (TTL) for nodes")
	flag.StringVar(&redconf, "redconf", "/usr/local/share/tor-dam/redis.conf",
		"Path to redis' redis.conf.")
	flag.Parse()

	// Chdir to our working directory.
	if _, err := os.Stat(lib.Workdir); os.IsNotExist(err) {
		err := os.Mkdir(lib.Workdir, 0700)
		lib.CheckError(err)
	}
	err := os.Chdir(lib.Workdir)
	lib.CheckError(err)

	if _, err := lib.RedisCli.Ping().Result(); err != nil {
		// We assume redis is not running. Start it up.
		cmd, err := lib.StartRedis(redconf)
		defer cmd.Process.Kill()
		lib.CheckError(err)
	}

	if lib.Testnet {
		log.Println("Will mark all nodes valid by default.")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/announce", handlePost)
	mux.HandleFunc("/", handleElse)
	srv := &http.Server{
		Addr:         ListenAddress,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	wg.Add(1)
	go srv.ListenAndServe()
	log.Println("Listening on", ListenAddress)

	if ttl > 0 {
		log.Printf("Enabling TTL polling (%d minute expire time).\n", ttl)
		go pollNodeTTL(ttl)
	}

	wg.Wait()
}
