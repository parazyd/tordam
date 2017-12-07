package main

// See LICENSE file for copyright and license details.

import (
	"encoding/json"
	"log"
	"net/http"

	"../lib"
)

type nodeStruct struct {
	Nodetype  string
	Address   string
	Message   string
	Signature string
}

func parsePost(rw http.ResponseWriter, request *http.Request) {
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
		log.Fatal("Request is not valid.")
	}
}

func main() {
	http.HandleFunc("/announce", parsePost)
	http.ListenAndServe(":8080", nil)
}
