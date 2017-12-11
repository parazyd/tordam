package main

// See LICENSE file for copyright and license details.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	//"os/exec"
	//"strings"
	//"syscall"
	"testing"
	//"time"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

type msgStruct struct {
	Secret string
}

var ValidFirst = map[string]string{
	"nodetype":  "node",
	"address":   "22mobp7vrb7a4gt2.onion",
	"message":   "I am a DAM node!",
	"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
	"secret":    "",
}

func postReq(data map[string]string) (*http.Response, error) {
	msg, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	resp, err := lib.HTTPPost("http://localhost:49371/announce", msg)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func getRespText(resp *http.Response) (msgStruct, error) {
	var m msgStruct

	decoder := json.NewDecoder(resp.Body)
	err := decoder.Decode(&m)
	if err != nil {
		return m, err
	}

	return m, nil
}

func firstAnnValid() (*http.Response, error) {
	resp, err := postReq(ValidFirst)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func TestValidFirstHandshake(t *testing.T) {
	resp, err := firstAnnValid()
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Server did not respond with HTTP 200")
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Error(err)
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		t.Error(err)
	}
	if len(decodedSecret) != 128 {
		t.Error("decodedSecret is not of correct length.")
	}
	t.Log("Server replied:", m.Secret)
}

func TestValidSecondHandshake(t *testing.T) {
	resp, err := firstAnnValid()
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Server did not respond with HTTP 200")
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Error(err)
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		t.Error(err)
	}
	if len(decodedSecret) != 128 {
		t.Error("decodedSecret is not of correct length.")
	}

	// Second handshake starts here.
	privkey, err := lib.LoadRsaKeyFromFile("./dam-private.key")
	if err != nil {
		t.Error(err)
	}
	decrypted, err := lib.DecryptMsgRsa([]byte(decodedSecret), privkey)
	if err != nil {
		t.Error(err)
	}
	decryptedEncode := base64.StdEncoding.EncodeToString(decrypted)
	sig, err := lib.SignMsgRsa([]byte(decryptedEncode), privkey)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	vals := ValidFirst
	vals["secret"] = decryptedEncode
	vals["message"] = decryptedEncode
	vals["signature"] = encodedSig

	resp, err = postReq(vals)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	}
	if m.Secret == "Welcome to the DAM network!" {
		t.Log("Server replied:", m.Secret)
	} else {
		t.Error(m.Secret)
	}
}

func TestMain(m *testing.M) {
	//cmd := exec.Command("./dam-dir")
	//cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	//cmd.Start()
	//time.Sleep(1000 * time.Millisecond)

	ex := m.Run()
	//syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	os.Exit(ex)
}
