package main

// See LICENSE file for copyright and license details.

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"../lib"
)

const ListenAddress = "127.0.0.1:8080"

type nodeStruct struct {
	Nodetype  string
	Address   string
	Message   string
	Signature string
	Secret    string
}

func handlePost(rw http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)

	var n nodeStruct
	err := decoder.Decode(&n)
	lib.CheckError(err)

	req := map[string]string{
		"nodetype":  n.Nodetype,
		"address":   n.Address,
		"message":   n.Message,
		"signature": n.Signature,
		"secret":    n.Secret,
	}

	pkey, valid := lib.ValidateReq(req)
	if !(valid) {
		log.Fatalln("Request is not valid.")
	}

	pubkey, err := lib.ParsePubkey(pkey)
	lib.CheckError(err)

	if len(req["secret"]) != 64 {
		randString, err := lib.GenRandomASCII(64)
		lib.CheckError(err)

		secret, err := lib.EncryptMsg([]byte(randString), pubkey)
		lib.CheckError(err)

		ret := map[string]string{
			"secret": string(secret),
		}
		jsonVal, err := json.Marshal(ret)
		lib.CheckError(err)

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		rw.Write(jsonVal)
		return
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
