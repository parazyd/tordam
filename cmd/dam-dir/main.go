package main

// See LICENSE file for copyright and license details.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

// ListenAddress controls where our HTTP API daemon is listening.
const ListenAddress = "127.0.0.1:49371"

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

	_, err = lib.RedisCli.Ping().Result()
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
	err := decoder.Decode(&n)
	if err != nil {
		log.Println("Failed decoding request:", err)
		return
	}

	// Bail out as soon as possible.
	if len(n.Nodetype) == 0 || len(n.Address) == 0 ||
		len(n.Message) == 0 || len(n.Signature) == 0 {
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
		"nodetype":  n.Nodetype,
		"address":   n.Address,
		"message":   n.Message,
		"signature": n.Signature,
		"secret":    n.Secret,
	}

	// First handshake
	if len(n.Message) != 88 && len(n.Secret) != 88 {
		valid, msg := lib.ValidateFirst(req)
		ret = map[string]string{"secret": msg}
		if valid {
			log.Printf("%s: 1/2 handshake valid.\n", n.Address)
			log.Println("Sending back encrypted secret.")
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
		valid, msg := lib.ValidateSecond(req)
		ret = map[string]string{"secret": msg}
		if valid {
			log.Printf("%s: 2/2 handshake valid.\n", n.Address)
			log.Println("Sending back welcome message.")
			if err := postback(rw, ret, 200); err != nil {
				lib.CheckError(err)
			}
			return
		}
		log.Printf("%s: 2/2 handshake invalid.\n", n.Address)
		// Delete it all from redis.
		_, err := lib.RedisCli.Del(n.Address).Result()
		lib.CheckError(err)
		if err := postback(rw, ret, 400); err != nil {
			lib.CheckError(err)
		}
		return
	}
}

func handleElse(rw http.ResponseWriter, request *http.Request) {
	// noop for anything that isn't /announce.
	return
}

func main() {
	var wg sync.WaitGroup

	// Chdir to our working directory.
	if _, err := os.Stat(lib.Cwd); os.IsNotExist(err) {
		err := os.Mkdir(lib.Cwd, 0700)
		lib.CheckError(err)
	}
	err := os.Chdir(lib.Cwd)
	lib.CheckError(err)

	if _, err := lib.RedisCli.Ping().Result(); err != nil {
		// We assume redis is not running. Start it up.
		startRedis()
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
	wg.Wait()
	os.Exit(1)
}
