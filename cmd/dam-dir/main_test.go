package main

// See LICENSE file for copyright and license details.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

type msgStruct struct {
	Secret string
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

func TestValidFirstHandshake(t *testing.T) {
	// Valid 1/2 handshake request
	req := map[string]string{
		"nodetype":  "node",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	resp, err := postReq(req)
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
	// Valid 2/2 handshake request
	req := map[string]string{
		"nodetype":  "node",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	resp, err := postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Error(err)
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		t.Error(err)
	}

	privkey, err := lib.LoadRsaKeyFromFile("dam-private.key")
	if err != nil {
		t.Error(err)
	}

	decrypted, err := lib.DecryptMsgRsa([]byte(decodedSecret), privkey)
	if err != nil {
		t.Error(err)
	}

	decryptedEncode := base64.StdEncoding.EncodeToString(decrypted)
	sig, err := lib.SignMsgRsa([]byte(decryptedEncode), privkey)
	if err != nil {
		t.Error(err)
	}
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	req["message"] = decryptedEncode
	req["secret"] = decryptedEncode
	req["signature"] = encodedSig
	resp, err = postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	} else if m.Secret == "Welcome to the DAM network!" {
		t.Log("Server replied:", m.Secret)
	} else {
		t.Error("Server replied:", m.Secret)
	}
}

func TestInvalidFirstHandshake(t *testing.T) {
	// Invalid 1/2 handshake request
	var req map[string]string

	// We don't actually care about the validity. We are rather trying to crash
	// the directory daemon.

	// Invalid: nodetype
	req = map[string]string{
		"nodetype":  "foobar",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	t.Log("Testing Invalid: nodetype")
	resp, err := postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("Server replied:", m.Secret)
	}

	// Invalid: address
	req = map[string]string{
		"nodetype":  "node",
		"address":   "11moup7v3b7a4gt20onion",
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	t.Log("Testing Invalid: address")
	resp, err = postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("Server replied:", m.Secret)
	}

	// Invalid: message vs. signature
	req = map[string]string{
		"nodetype":  "node",
		"address":   "11moup7v3b7a4gt20onion",
		"message":   "I am a weird DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	t.Log("Testing Invalid: message vs. signature")
	resp, err = postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("Server replied:", m.Secret)
	}

	// Invalid: signature format
	req = map[string]string{
		"nodetype":  "node",
		"address":   "11moup7v3b7a4gt20onion",
		"message":   "I am a DAM node!",
		"signature": "this is not base64",
		"secret":    "",
	}
	t.Log("Testing Invalid: signature format")
	resp, err = postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	} else {
		t.Log("Server replied:", m.Secret)
	}
}

func TestInvalidSecondHandshake(t *testing.T) {
	// Valid 2/2 handshake request
	req := map[string]string{
		"nodetype":  "node",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	resp, err := postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Error(err)
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		t.Error(err)
	}

	privkey, err := lib.LoadRsaKeyFromFile("dam-private.key")
	if err != nil {
		t.Error(err)
	}

	decrypted, err := lib.DecryptMsgRsa([]byte(decodedSecret), privkey)
	if err != nil {
		t.Error(err)
	}

	decryptedEncode := base64.StdEncoding.EncodeToString(decrypted)
	sig, err := lib.SignMsgRsa([]byte(decryptedEncode), privkey)
	if err != nil {
		t.Error(err)
	}
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	// The initial valid request.
	oldreq := req

	// Message and secret are different
	req["message"] = decryptedEncode
	req["secret"] = strings.ToLower(decryptedEncode)
	req["signature"] = encodedSig
	resp, err = postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	} else if m.Secret == "Verification failed. Bye." {
		t.Log("Server replied:", m.Secret)
	} else {
		t.Error("Server replied:", m.Secret)
	}

	// Signature is an invalid format
	req["message"] = oldreq["message"]
	req["secret"] = oldreq["secret"]
	req["signature"] = "Thisisnotbase64"
	resp, err = postReq(req)
	if err != nil {
		t.Error(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Error(err)
	} else if strings.HasPrefix(m.Secret, "illegal base64 data at input byte") {
		t.Log("Server replied:", m.Secret)
	} else {
		t.Error("Server replied:", m.Secret)
	}

	/*
		// Secret is not the one we should be sending.
		req["message"] = "a2V1Mzg3NTY0N0BAMTM0NTZ5Z2huZmJndXNpPz8/Ly8vcztwZlsndF1bb2U4NTg3Xnloc25tZ2V5ZGtsZTExCg=="
		req["secret"] = "a2V1Mzg3NTY0N0BAMTM0NTZ5Z2huZmJndXNpPz8/Ly8vcztwZlsndF1bb2U4NTg3Xnloc25tZ2V5ZGtsZTExCg=="
		sig, err = lib.SignMsgRsa([]byte(req["secret"]), privkey)
		if err != nil {
			t.Error(err)
		}
		encodedSig = base64.StdEncoding.EncodeToString(sig)
		req["signature"] = encodedSig
		resp, err = postReq(req)
		if err != nil {
			t.Error(err)
		}
		m, err = getRespText(resp)
		if err != nil {
			t.Error(err)
		} else if strings.HasPrefix(m.Secret, "illegal base64 data at input byte") {
			t.Log("Server replied:", m.Secret)
		} else {
			t.Error("Server replied:", m.Secret)
		}
	*/
}

func TestMain(m *testing.M) {
	cmd := exec.Command("./dam-dir")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Start()
	time.Sleep(1000 * time.Millisecond)

	ex := m.Run()
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	os.Exit(ex)
}
