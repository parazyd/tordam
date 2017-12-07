package main

// See LICENSE file for copyright and license details.

import (
	"encoding/json"
	"log"
	"net/http"

	"../lib"
)

const ListenAddress = "127.0.0.1:8080"

type nodeStruct struct {
	Nodetype  string
	Address   string
	Message   string
	Signature string
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
	}

	if lib.ValidateReq(req) != true {
		log.Fatalln("Request is not valid.")
	}

}

func main() {
	http.HandleFunc("/announce", handlePost)
	http.ListenAndServe(ListenAddress, nil)
	log.Println("Listening on", ListenAddress)
}
