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
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"regexp"
	"time"
)

func validateOnionAddress(addr string) bool {
	re, _ := regexp.Compile(`^[a-z2-7](?:.{55})\.onion`)
	return len(re.FindString(addr)) == 62
}

// firstHandshake will take the incoming public key either from the request
// or, if found, from redis. This key is stored, and a nonce is generated.
// This nonce is returned back to the client to sign with the key. In the
// second handshake, we verify this nonce signature against the retrieved
// public key.
func firstHandshake(req map[string]string) (bool, string) {
	var pubstr string

	// Check if we have seen this node already
	ex, err := rcli.Exists(rctx, req["address"]).Result()
	if err != nil {
		log.Fatal(err)
	}

	if ex == 1 {
		// We saw it so we should hae the public key stored in redis.
		// If we do not, that is an internal error.
		pubstr, err = rcli.HGet(rctx, req["address"], "pubkey").Result()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// We take it from the request
		pubstr = req["pubkey"]
	}

	randString, err := genRandomASCII(64)
	if err != nil {
		log.Fatal(err)
	}

	enc := base64.StdEncoding.EncodeToString([]byte(randString))

	var info = map[string]interface{}{
		"address":   req["address"],
		"message":   enc,
		"signature": req["signature"],
		"secret":    enc,
		"lastseen":  time.Now().Unix(),
	} // Can not cast, need this for HSet

	if ex != 1 {
		// We did not have this node in redis
		info["pubkey"] = pubstr
		info["firstseen"] = time.Now().Unix()
		if *trustall {
			info["trusted"] = 1
		} else {
			info["trusted"] = 0
		}
	}

	log.Printf("%s: Writing to redis\n", req["address"])
	if _, err := rcli.HSet(rctx, req["address"], info).Result(); err != nil {
		log.Fatal(err)
	}

	return true, enc
}

func secondHandshake(req map[string]string) (bool, string) {
	// Check if we have seen this node already
	ex, err := rcli.Exists(rctx, req["address"]).Result()
	if err != nil {
		log.Fatal(err)
	}
	if ex != 1 {
		log.Printf("%s tried to jump in 2/2 handshake before getting a nonce\n",
			req["address"])
		return false, "We have not seen you before. Authenticate properly."
	}

	// We saw it so we should have the public key in redis. If we do not,
	// then it's an internal error.
	pubstr, err := rcli.HGet(rctx, req["address"], "pubkey").Result()
	if err != nil {
		log.Fatal(err)
	}

	lSec, err := rcli.HGet(rctx, req["address"], "secret").Result()
	if err != nil {
		log.Fatal(err)
	}

	if lSec != req["secret"] || lSec != req["message"] {
		log.Printf("%s: Secrets didn't match\n", req["address"])
		return false, "Secrets didn't match."
	}

	// Validate signature.
	msg := []byte(lSec)
	sig, _ := base64.StdEncoding.DecodeString(req["signature"])
	deckey, err := base64.StdEncoding.DecodeString(pubstr)
	if err != nil {
		log.Fatal(err)
	}
	pubkey := ed25519.PublicKey(deckey)

	if !ed25519.Verify(pubkey, msg, sig) {
		log.Println("crypto/ed25519: Signature verification failure")
		return false, "Signature verification failure"
	}

	// The request is valid at this point

	// Make a new random secret to prevent reuse.
	randString, _ := genRandomASCII(64)
	encSecret := base64.StdEncoding.EncodeToString([]byte(randString))

	var info = map[string]interface{}{
		"address":   req["address"],
		"message":   encSecret,
		"signature": req["signature"],
		"secret":    encSecret,
		"lastseen":  time.Now().Unix(),
	} // TODO: Use struct

	log.Printf("Adding %s to redis\n", req["address"])
	if _, err := rcli.HSet(rctx, req["address"], info).Result(); err != nil {
		log.Fatal(err)
	}

	return true, "Welcome to tor-dam"
}
