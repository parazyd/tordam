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
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func postback(rw http.ResponseWriter, data map[string]string, ret int) error {
	val, err := json.Marshal(data)
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(ret)
	if _, err := rw.Write(val); err != nil {
		return err
	}
	return nil
}

func handleAnnounce(rw http.ResponseWriter, req *http.Request) {
	var r map[string]string
	var n Node

	if req.Method != "POST" || req.Header["Content-Type"][0] != "application/json" {
		r = map[string]string{"secret": "Invalid request format"}
		if err := postback(rw, r, 400); err != nil {
			log.Fatal(err)
		}
		return
	}

	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&n); err != nil {
		log.Println("Failed decoding request:", err)
		return
	}

	// Bail out as soon as possible
	if len(n.Address) == 0 || len(n.Message) == 0 || len(n.Signature) == 0 {
		r = map[string]string{"secret": "Invalid request format"}
		if err := postback(rw, r, 400); err != nil {
			log.Fatal(err)
		}
		return
	}

	if !validateOnionAddress(n.Address) {
		log.Println("Invalid onion address:", n.Address)
		r = map[string]string{"secret": "Invalid onion address"}
		if err := postback(rw, r, 400); err != nil {
			log.Fatal(err)
		}
		return
	}

	rq := map[string]string{
		"address":   n.Address,
		"message":   n.Message,
		"pubkey":    n.Pubkey,
		"signature": n.Signature,
		"secret":    n.Secret,
	}

	// First handshake
	if len(n.Message) != 88 || len(n.Secret) != 88 {
		valid, msg := firstHandshake(rq)
		r = map[string]string{"secret": msg}
		if valid {
			log.Printf("%s: 1/2 handskake valid\n", n.Address)
			log.Println("Sending nonce to", n.Address)
			if err := postback(rw, r, 200); err != nil {
				log.Fatal(err)
			}
			return
		}
		log.Printf("%s: 1/2 handshake invalid: %s\n", n.Address, msg)
		// Delete it all from redis
		// TODO: Can this be abused?
		if _, err := rcli.Del(rctx, n.Address).Result(); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Second handshake
	if len(rq["secret"]) == 88 && len(rq["message"]) == 88 {
		valid, msg := secondHandshake(rq)
		r = map[string]string{"secret": msg}

		if valid {
			log.Printf("%s: 2/2 handshake valid\n", n.Address)
			isTrusted, err := rcli.HGet(rctx, n.Address, "trusted").Result()
			if err != nil {
				log.Fatal(err)
			}

			// Assume our name is what was requested
			us := strings.TrimSuffix(req.Host, ":49371")
			nodemap := make(map[string]map[string]string)

			if isTrusted == "1" {
				// The node is marked as trusted so we'll teack it about other
				// trusted nodes we know about.
				log.Printf("%s is trusted. Propagating knowledge...\n", n.Address)
				nodes, err := rcli.Keys(rctx, "*.onion").Result()
				if err != nil {
					log.Fatal(err)
				}
				for _, i := range nodes {
					if i == n.Address {
						continue
					}
					nodedata, err := rcli.HGetAll(rctx, i).Result()
					if err != nil {
						log.Fatal(err)
					}
					if nodedata["trusted"] == "1" {
						nodemap[i] = nodedata
						delete(nodemap[i], "secret")
					}
				}
			} else {
				log.Printf("%s is not trusted. Propagating self...", n.Address)
				// The node doesn't have trust in the network. We will only
				// teach it about ourself.
				nodedata, err := rcli.HGetAll(rctx, us).Result()
				if err != nil {
					log.Fatal(err)
				}
				nodemap[us] = nodedata
				delete(nodemap[us], "secret")
			}

			nodestr, err := json.Marshal(nodemap)
			if err != nil {
				log.Fatal(err)
			}
			comp, err := gzipEncode(nodestr)
			if err != nil {
				log.Fatal(err)
			}
			r = map[string]string{"secret": comp}
			if err := postback(rw, r, 200); err != nil {
				log.Fatal(err)
			}

			publishToRedis('M', n.Address)
			return
		}

		// If we haven't returned so far, the handshake is invalid
		log.Printf("%s: 2/2 handshake invalid\n", n.Address)
		// Delete it all from redis
		// TODO: Can this be abused?
		publishToRedis('D', n.Address)
		if _, err := rcli.Del(rctx, n.Address).Result(); err != nil {
			log.Fatal(err)
		}
		if err := postback(rw, r, 400); err != nil {
			log.Fatal(err)
		}
		return
	}
}

func handleElse(rw http.ResponseWriter, req *http.Request) {
	log.Println("Got handleElse")
}
