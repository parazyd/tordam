package main

// See LICENSE file for copyright and license details.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis"

	"../lib"
)

// ListenAddress controls where our HTTP API daemon is listening.
const ListenAddress = "127.0.0.1:8080"

// RedisAddress points us to our Redis instance.
const RedisAddress = "127.0.0.1:6379"

// RedisCli is our global Redis client
var RedisCli = redis.NewClient(&redis.Options{
	Addr:     RedisAddress,
	Password: "",
	DB:       0,
})

type nodeStruct struct {
	Nodetype  string
	Address   string
	Message   string
	Signature string
	Secret    string
	Pubkey    string
	Firstseen int64
	Lastseen  int64
	Valid     int64
}

func handlePost(rw http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)

	var n nodeStruct
	err := decoder.Decode(&n)
	lib.CheckError(err)

	decSig, err := base64.StdEncoding.DecodeString(n.Signature)
	lib.CheckError(err)

	req := map[string]string{
		"nodetype":  n.Nodetype,
		"address":   n.Address,
		"message":   n.Message,
		"signature": string(decSig),
		"secret":    n.Secret,
	}

	pkey, valid := lib.ValidateReq(req)
	if !(valid) && pkey == nil {
		log.Fatalln("Request is not valid.")
	} else if !(valid) && pkey != nil {
		// We couldn't get a descriptor.
		ret := map[string]string{
			"secret": string(pkey),
		}
		jsonVal, err := json.Marshal(ret)
		lib.CheckError(err)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(500)
		rw.Write(jsonVal)
		return
	}

	pubkey, err := lib.ParsePubkey(pkey)
	lib.CheckError(err)

	n.Pubkey = string(pkey)
	now := time.Now()
	n.Firstseen = now.Unix()
	n.Lastseen = now.Unix()

	if len(req["secret"]) != 88 {
		// Client did not send a decrypted secret.
		randString, err := lib.GenRandomASCII(64)
		lib.CheckError(err)

		// FIXME: delete this line after debug mode
		log.Println("Secret:", randString)

		secret, err := lib.EncryptMsg([]byte(randString), pubkey)
		lib.CheckError(err)

		encodedSecret := base64.StdEncoding.EncodeToString(secret)
		ret := map[string]string{
			"secret": encodedSecret,
		}
		jsonVal, err := json.Marshal(ret)
		lib.CheckError(err)

		// TODO: We probably _do_ want to allow the keyholder to
		// reannounce itself, so let's not handle this yet.
		//ex := RedisCli.Exists(n.Address)

		// Save the node into redis
		info := map[string]interface{}{
			"nodetype":  n.Nodetype,
			"address":   n.Address,
			"message":   n.Message,
			"signature": n.Signature,
			"secret":    base64.StdEncoding.EncodeToString([]byte(randString)),
			"pubkey":    n.Pubkey,
			"firstseen": n.Firstseen,
			"lastseen":  n.Lastseen,
			"valid":     0, // This should be 1 after the node is not considered malicious
		}
		log.Println("Writing into Redis")
		redRet, err := RedisCli.HMSet(n.Address, info).Result()
		lib.CheckError(err)

		if redRet == "OK" {
			log.Println("Returning encrypted secret to caller.")
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			rw.Write(jsonVal)
			return
		}
	}

	if len(req["secret"]) == 88 {
		// Client sent a decrypted secret.
		//decodedSec, err := base64.StdEncoding.DecodeString(req["secret"])
		//lib.CheckError(err)

		var correct = false
		localSec, err := RedisCli.HGet(n.Address, "secret").Result()
		lib.CheckError(err)

		if localSec == req["secret"] {
			log.Println("Secrets match!")
			correct = true
		}

		if correct {
			log.Printf("Welcoming %s to the network\n", n.Address)
			ret := map[string]string{
				"secret": "Welcome to the DECODE network!",
			}
			n.Valid = 0

			jsonVal, err := json.Marshal(ret)
			lib.CheckError(err)

			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			rw.Write(jsonVal)
			return
		}
	}
}

func main() {
	var wg sync.WaitGroup

	_, err := RedisCli.Ping().Result()
	lib.CheckError(err)

	http.HandleFunc("/announce", handlePost)

	wg.Add(1)
	go http.ListenAndServe(ListenAddress, nil)
	log.Println("Listening on", ListenAddress)

	wg.Wait()
}
