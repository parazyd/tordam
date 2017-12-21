package main

// See LICENSE file for copyright and license details.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
	if err := decoder.Decode(&n); err != nil {
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
		valid, msg := lib.ValidateFirstHandshake(req)
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
		valid, msg := lib.ValidateSecondHandshake(req)
		ret = map[string]string{"secret": msg}

		if valid {
			log.Printf("%s: 2/2 handshake valid.\n", n.Address)
			hasConsensus, err := lib.RedisCli.HGet(n.Address, "valid").Result()
			lib.CheckError(err)

			us := request.Host // Assume our name is what was requested as the URL.
			if strings.HasPrefix(us, "localhost") {
				// No need to propagate to ourself.
				ret = map[string]string{"secret": lib.WelcomeMsg}
				if err := postback(rw, ret, 200); err != nil {
					lib.CheckError(err)
				}
				return
			}

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
					}
				}
			} else {
				log.Printf("%s does not have consensus. Propagating ourself to it...\n", n.Address)
				// The node doesn't have consensus in the network. We will only
				// teach it about ourself.
				nodedata, err := lib.RedisCli.HGetAll(us).Result()
				lib.CheckError(err)
				nodemap[us] = nodedata
			}

			nodestr, err := json.Marshal(nodemap)
			lib.CheckError(err)
			comp, err := lib.GzipEncode(nodestr)
			lib.CheckError(err)
			ret = map[string]string{"secret": comp}
			if err := postback(rw, ret, 200); err != nil {
				lib.CheckError(err)
			}
			return
		}

		// If we have't returned so far, the handshake is invalid.
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

// handleElse is a noop for anything that isn't /announce. We don't care about
// other requests (yet).
func handleElse(rw http.ResponseWriter, request *http.Request) {
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
