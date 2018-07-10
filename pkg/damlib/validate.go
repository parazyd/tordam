package damlib

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
	"encoding/base64"
	"errors"
	"log"
	"regexp"
	"strings"
	"time"
)

// ValidateOnionAddress matches a string against a regular expression matching
// a Tor hidden service address. Returns true on success and false on failure.
func ValidateOnionAddress(addr string) bool {
	re, _ := regexp.Compile(`^[a-z2-7](?:.{55}|.{15})\.onion`)
	if len(re.FindString(addr)) == 22 || len(re.FindString(addr)) == 62 {
		return true
	}
	return false
}

// sanityCheck performs basic sanity checks against the incoming request.
// Returns a boolean value according to the validity, and a string with an
// according message.
func sanityCheck(req map[string]string, handshake int) (bool, string) {
	if !(ValidateOnionAddress(req["address"])) {
		return false, "Invalid onion address"
	}
	if _, err := base64.StdEncoding.DecodeString(req["signature"]); err != nil {
		return false, err.Error()
	}

	// TODO: When a node wants to promote itself from something it already was,
	// what to do?
	switch req["nodetype"] {
	case "node":
		log.Printf("%s is a node.", req["address"])
	case "directory":
		log.Printf("%s is a directory.", req["address"])
	default:
		return false, "Invalid nodetype."
	}

	if handshake == 2 {
		if _, err := base64.StdEncoding.DecodeString(req["message"]); err != nil {
			return false, err.Error()
		}
		if _, err := base64.StdEncoding.DecodeString(req["secret"]); err != nil {
			return false, err.Error()
		}
	}
	return true, ""
}

// ValidateFirstHandshake validates the first incoming handshake.
// It first calls sanityCheck to validate it's actually working with proper
// data.
// Next, it will look if the node is already found in redis. If so, it will
// fetch its public hey from redis, otherwise it will run an external program to
// fetch the node's public key from a Tor HSDir. If that program fails, so will
// the function.
// Once the public key is retrieved, it will validate the received message
// signature against that key. If all is well, we consider the request valid.
// Continuing, a random ASCII string will be generated and encrypted with the
// retrieved public key. All this data will be written into redis, and finally
// the encrypted (and base64 encoded) secret will be returned along with a true
// boolean value.
// On any failure, the function will return false, and produce an according
// string which is to be considered as an error message.
func ValidateFirstHandshake(req map[string]string) (bool, string) {
	if sane, what := sanityCheck(req, 1); !(sane) {
		return false, what
	}

	// Get the public key.
	var pub string
	// Check if we have seen this node already.
	ex, err := RedisCli.Exists(req["address"]).Result()
	CheckError(err)
	if ex == 1 {
		// We saw it so we should have the public key in redis.
		// If we do not, that is an internal error.
		pub, err = RedisCli.HGet(req["address"], "pubkey").Result()
		CheckError(err)
		// FIXME: Do a smarter check
		if len(pub) < 20 {
			CheckError(errors.New("Invalid data fetched from redis when requesting pubkey"))
		}
	} else {
		// We fetch it from a HSDir
		cnt := 0
		for { // We try until we have it.
			cnt++
			if cnt > 10 {
				// We probably can't get a good HSDir. The client shall retry
				// later on.
				return false, "Could not get a descriptor. Try later."
			}
			pub = FetchHSPubkey(req["address"])
			if strings.HasPrefix(pub, "-----BEGIN RSA PUBLIC KEY-----") &&
				strings.HasSuffix(pub, "-----END RSA PUBLIC KEY-----") {
				log.Println("Got descriptor!")
				break
			}
			time.Sleep(2000 * time.Millisecond)
		}
	}

	// Validate signature.
	msg := []byte(req["message"])
	decSig, _ := base64.StdEncoding.DecodeString(req["signature"])
	sig := decSig
	pubkey, err := ParsePubkeyRsa([]byte(pub)) // pubkey is their public key in *rsa.PublicKey type
	CheckError(err)
	if val, _ := VerifyMsgRsa(msg, sig, pubkey); !(val) {
		log.Println("crypto/rsa: verification failure")
		return false, "Signature verification failure."
	}

	// The request is valid at this point.

	// Make a random secret for them, and save our node info to redis.
	randString, err := GenRandomASCII(64)
	CheckError(err)
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(randString))

	var info = map[string]interface{}{
		"nodetype":  req["nodetype"],
		"address":   req["address"],
		"message":   encodedSecret,
		"signature": req["signature"],
		"secret":    encodedSecret,
		"lastseen":  time.Now().Unix(),
	} // Can not cast, need this for HMSet
	if ex != 1 { // We did not have this node in redis.
		info["pubkey"] = pub
		info["firstseen"] = time.Now().Unix()
		info["valid"] = 1
	}

	log.Printf("%s: writing to redis\n", req["address"])
	redRet, err := RedisCli.HMSet(req["address"], info).Result()
	CheckError(err)

	if redRet != "OK" {
		return false, "Internal server error"
	}

	encryptedSecret, err := EncryptMsgRsa([]byte(randString), pubkey)
	CheckError(err)

	encryptedEncodedSecret := base64.StdEncoding.EncodeToString(encryptedSecret)
	return true, encryptedEncodedSecret
}

// ValidateSecondHandshake validates the second part of the handshake.
// First basic sanity checks are performed to ensure we are working with valid
// data.
// Next, the according public key will be retrieved from redis. If no key is
// found, we will consider the handshake invalid.
// Now the decrypted secret that was sent to us will be compared with what we
// have saved before. Upon proving they are the same, the RSA signature will now
// be validated. If all is well, we consider the request valid.
// Further on, we will generate a new random ASCII string and save it in redis
// to prevent further reuse of the already known string. Upon success, the
// function will return true, and a welcome message. Upon failure, the function
// will return false, and an according string which is to be considered an error
// message.
func ValidateSecondHandshake(req map[string]string) (bool, string) {
	if sane, what := sanityCheck(req, 2); !(sane) {
		return false, what
	}

	// Get the public key.
	var pub string
	// Check if we have seen this node already.
	ex, err := RedisCli.Exists(req["address"]).Result()
	CheckError(err)
	if ex == 1 {
		// We saw it so we should have the public key in redis.
		// If we do not, that is an internal error.
		pub, err = RedisCli.HGet(req["address"], "pubkey").Result()
		CheckError(err)
		// FIXME: Do a smarter check
		if len(pub) < 20 {
			CheckError(errors.New("Invalid data fetched from redis when requesting pubkey"))
		}
	} else {
		log.Printf("%s tried to jump in 2/2 handshake before doing the first.\n", req["address"])
		return false, "We have not seen you before. Please authenticate properly."
	}

	localSec, err := RedisCli.HGet(req["address"], "secret").Result()
	CheckError(err)

	if !(localSec == req["secret"] && localSec == req["message"]) {
		log.Printf("%s: Secrets don't match.\n", req["address"])
		return false, "Secrets don't match."
	}

	// Validate signature.
	msg := []byte(req["message"])
	decSig, _ := base64.StdEncoding.DecodeString(req["signature"])
	sig := decSig
	pubkey, err := ParsePubkeyRsa([]byte(pub)) // pubkey is their public key in *rsa.PublicKey type
	CheckError(err)
	if val, _ := VerifyMsgRsa(msg, sig, pubkey); !(val) {
		log.Printf("%s: Signature verification failure\n", req["address"])
		return false, "Signature verification failure."
	}

	// The request is valid at this point.

	// Make a new random secret to prevent reuse.
	randString, err := GenRandomASCII(64)
	CheckError(err)
	encodedSecret := base64.StdEncoding.EncodeToString([]byte(randString))

	var info = map[string]interface{}{
		"nodetype":  req["nodetype"],
		"address":   req["address"],
		"message":   encodedSecret,
		"signature": req["signature"],
		"secret":    encodedSecret,
		"lastseen":  time.Now().Unix(),
	} // Can not cast, need this for HMSet

	log.Printf("%s: writing to redis\n", req["address"])
	redRet, err := RedisCli.HMSet(req["address"], info).Result()
	CheckError(err)

	if redRet != "OK" {
		return false, "Internal server error"
	}

	return true, WelcomeMsg
}
