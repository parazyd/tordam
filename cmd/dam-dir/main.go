package main

// See LICENSE file for copyright and license details.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/go-redis/redis"
	"github.com/parazyd/tor-dam/pkg/lib"
)

// Cwd holds the path to the directory where we will Chdir on startup.
var Cwd = os.Getenv("HOME") + "/.dam"

// ListenAddress controls where our HTTP API daemon is listening.
const ListenAddress = "127.0.0.1:49371"

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

func startRedis() {
	log.Println("Staring up redis-server...")
	cmd := exec.Command("redis-server", "/usr/local/share/tor-dam/redis.conf")
	err := cmd.Start()
	lib.CheckError(err)

	time.Sleep(500 * time.Millisecond)

	_, err = RedisCli.Ping().Result()
	lib.CheckError(err)
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

	// Check if we have seen this node already.
	ex, err := RedisCli.Exists(n.Address).Result()
	lib.CheckError(err)
	var pub = ""
	if ex == 1 {
		res, err := RedisCli.HGet(n.Address, "pubkey").Result()
		pub = string(res)
		lib.CheckError(err)
	}

	pkey, valid := lib.ValidateReq(req, pub)
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

	pubkey, err := lib.ParsePubkeyRsa(pkey)
	lib.CheckError(err)

	n.Pubkey = string(pkey)
	now := time.Now()
	n.Firstseen = now.Unix()
	n.Lastseen = now.Unix()

	if len(req["secret"]) != 88 {
		// Client did not send a decrypted secret.
		randString, err := lib.GenRandomASCII(64)
		lib.CheckError(err)

		secret, err := lib.EncryptMsgRsa([]byte(randString), pubkey)
		lib.CheckError(err)

		encodedSecret := base64.StdEncoding.EncodeToString(secret)
		ret := map[string]string{
			"secret": encodedSecret,
		}
		jsonVal, err := json.Marshal(ret)
		lib.CheckError(err)

		// Check if we have seen this node already.
		ex, err := RedisCli.Exists(n.Address).Result()
		lib.CheckError(err)

		// Save the node into redis
		info := map[string]interface{}{
			"nodetype":  n.Nodetype,
			"address":   n.Address,
			"message":   n.Message,
			"signature": n.Signature,
			"secret":    base64.StdEncoding.EncodeToString([]byte(randString)),
			"pubkey":    n.Pubkey,
			"lastseen":  n.Lastseen,
		}

		if ex != 1 {
			info["firstseen"] = n.Firstseen
			info["valid"] = 0 // This should be 1 after the node is not considered malicious
		}
		log.Println("Writing to Redis")
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
				"secret": "Welcome to the DAM network!",
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

	if _, err := os.Stat(Cwd); os.IsNotExist(err) {
		err := os.Mkdir(Cwd, 0700)
		lib.CheckError(err)
	}
	log.Println("Chdir to", Cwd)
	err := os.Chdir(Cwd)
	lib.CheckError(err)

	if _, err := RedisCli.Ping().Result(); err != nil {
		// We assume redis is not running. Start it up.
		startRedis()
	}

	http.HandleFunc("/announce", handlePost)

	wg.Add(1)
	go http.ListenAndServe(ListenAddress, nil)
	log.Println("Listening on", ListenAddress)

	wg.Wait()
}
