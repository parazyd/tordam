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
	lib "github.com/parazyd/tor-dam/pkg/damlib"
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
	log.Println("Starting up redis-server...")
	cmd := exec.Command("redis-server", "/usr/local/share/tor-dam/redis.conf")
	err := cmd.Start()
	lib.CheckError(err)

	time.Sleep(500 * time.Millisecond)

	_, err = RedisCli.Ping().Result()
	lib.CheckError(err)
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
	if request.Method != "POST" || request.Header["Content-Type"][0] != "application/json" {
		return
	}

	var ret map[string]string
	var n nodeStruct
	decoder := json.NewDecoder(request.Body)
	err := decoder.Decode(&n)
	if err != nil {
		log.Println("Failed decoding request:", err)
		return
	}

	// Drop out ASAP.
	if len(n.Nodetype) == 0 || len(n.Address) == 0 ||
		len(n.Message) == 0 || len(n.Signature) == 0 {
		return
	}

	decSig, err := base64.StdEncoding.DecodeString(n.Signature)
	if err != nil {
		log.Println("Failed decoding signature:", err)
		ret = map[string]string{"secret": err.Error()}
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}

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
		ret := map[string]string{"secret": "Request is not valid."}
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	} else if !(valid) && pkey != nil {
		// We couldn't get a descriptor.
		ret := map[string]string{"secret": string(pkey)}
		if err := postback(rw, ret, 500); err != nil {
			lib.CheckError(err)
		}
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
		ret := map[string]string{"secret": encodedSecret}

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
			if err := postback(rw, ret, 200); err != nil {
				lib.CheckError(err)
			}
			return
		}
	}

	if len(req["secret"]) == 88 && len(req["message"]) == 88 {
		// Client sent a decrypted secret.
		var correct = false
		localSec, err := RedisCli.HGet(n.Address, "secret").Result()
		lib.CheckError(err)

		if localSec == req["secret"] && localSec == req["message"] {
			log.Println("Secrets match!")
			correct = true
		} else {
			log.Println("Secrets don't match!")
			correct = false
		}

		if correct {
			msg := []byte(req["message"])
			sig := []byte(req["signature"])
			pub, err := lib.ParsePubkeyRsa([]byte(n.Pubkey))
			lib.CheckError(err)
			val, err := lib.VerifyMsgRsa(msg, sig, pub)
			lib.CheckError(err)
			if val {
				log.Println("Signature valid!")
				correct = true
			} else {
				log.Println("Signature invalid!")
				correct = false
			}
		}

		if correct {
			// Replace the secret in redis to prevent reuse.
			randString, err := lib.GenRandomASCII(64)
			lib.CheckError(err)
			encoded := base64.StdEncoding.EncodeToString([]byte(randString))
			_, err = RedisCli.HSet(n.Address, "secret", encoded).Result()
			lib.CheckError(err)
			log.Printf("Welcoming %s to the network\n", n.Address)
			ret := map[string]string{"secret": "Welcome to the DAM network!"}
			if err := postback(rw, ret, 200); err != nil {
				lib.CheckError(err)
			}
			return
		} else {
			// Delete it all from redis.
			_, err := RedisCli.Del(n.Address).Result()
			lib.CheckError(err)
			log.Printf("Verifying %s failed.\n", n.Address)
			ret := map[string]string{"secret": "Verification failed. Bye."}
			if err := postback(rw, ret, 400); err != nil {
				lib.CheckError(err)
			}
			return
		}
	}
}

func handleElse(rw http.ResponseWriter, request *http.Request) {
	// noop for anything that isn't /announce.
	return
}

func main() {
	var wg sync.WaitGroup

	if _, err := os.Stat(Cwd); os.IsNotExist(err) {
		err := os.Mkdir(Cwd, 0700)
		lib.CheckError(err)
	}
	err := os.Chdir(Cwd)
	lib.CheckError(err)

	if _, err := RedisCli.Ping().Result(); err != nil {
		// We assume redis is not running. Start it up.
		startRedis()
	}

	http.HandleFunc("/announce", handlePost)
	http.HandleFunc("/", handleElse)

	wg.Add(1)
	go http.ListenAndServe(ListenAddress, nil)
	log.Println("Listening on", ListenAddress)

	wg.Wait()
}
