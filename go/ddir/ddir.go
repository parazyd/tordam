package main

// See LICENSE file for copyright and license details.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"../lib"
)

const ListenAddress = "127.0.0.1:8080"

type nodeStruct struct {
	Nodetype  string
	Address   string
	Message   string
	Signature string
	Secret    string
	Pubkey    string
	Firstseen int64
	Lastseen  int64
	Valid     bool
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

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		rw.Write(jsonVal)
		return
	}

	if len(req["secret"]) == 88 {
		// Client sent a decrypted secret.
		decodedSec, err := base64.StdEncoding.DecodeString(req["secret"])
		lib.CheckError(err)

		// TODO: validate against state
		var correct = true

		log.Println(string(decodedSec))

		if correct {
			ret := map[string]string{
				"secret": "Welcome to the DECODE network!",
			}
			n.Valid = false

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

	http.HandleFunc("/announce", handlePost)

	wg.Add(1)
	go http.ListenAndServe(ListenAddress, nil)
	log.Println("Listening on", ListenAddress)

	wg.Wait()
}
