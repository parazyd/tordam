package damlib

// See LICENSE file for copyright and license details.

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
	re, _ := regexp.Compile("^[a-z2-7]{16}\\.onion$")
	if len(re.FindString(addr)) != 22 {
		return false
	}
	return true
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

// ValidateFirst validates the first incoming handshake.
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
func ValidateFirst(req map[string]string) (bool, string) {
	sane, what := sanityCheck(req, 1)
	if !(sane) {
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
	sig := []byte(decSig)
	pubkey, err := ParsePubkeyRsa([]byte(pub)) // pubkey is their public key in *rsa.PublicKey type
	CheckError(err)
	val, _ := VerifyMsgRsa(msg, sig, pubkey)
	if val != true {
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
		info["valid"] = 0
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

// ValidateSecond validates the second part of the handshake.
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
func ValidateSecond(req map[string]string) (bool, string) {
	sane, what := sanityCheck(req, 2)
	if !(sane) {
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
		log.Println("Secrets don't match.")
		return false, "Secrets don't match."
	}

	// Validate signature.
	msg := []byte(req["message"])
	decSig, _ := base64.StdEncoding.DecodeString(req["signature"])
	sig := []byte(decSig)
	pubkey, err := ParsePubkeyRsa([]byte(pub)) // pubkey is their public key in *rsa.PublicKey type
	CheckError(err)
	val, _ := VerifyMsgRsa(msg, sig, pubkey)
	if val != true {
		log.Println("crypto/rsa: verification failure")
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
