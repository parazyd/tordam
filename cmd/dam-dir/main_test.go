package main

/*
 * Copyright (c) 2017-2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan J. <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This source code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code. If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	//"os/exec"
	"strings"
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
	return m, err
}

func firstAnnValid() (*http.Response, error) {
	resp, err := postReq(ValidFirst)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func TestValidFirstHandshake(t *testing.T) {
	//t.SkipNow()
	resp, err := firstAnnValid()
	if err != nil {
		t.Fatal(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret == "Could not get a descriptor. Try later." {
		t.Skipf("Server replied: %s\n", m.Secret)
	}

	decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedSecret) != 128 {
		t.Fatal("decodedSecret is not of correct length.")
	}
	if resp.StatusCode != 200 {
		t.Log(resp.StatusCode)
		t.Fatal("Server did not respond with HTTP 200")
	}
	t.Log("Server replied:", m.Secret)
}

func TestValidSecondHandshake(t *testing.T) {
	//t.SkipNow()
	resp, err := firstAnnValid()
	if err != nil {
		t.Fatal(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret == "Could not get a descriptor. Try later." {
		t.Skipf("Server replied: %s\n", m.Secret)
	}
	if resp.StatusCode != 200 {
		t.Log(resp.StatusCode)
		t.Fatal("Server did not respond with HTTP 200")
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(m.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedSecret) != 128 {
		t.Fatal("decodedSecret is not of correct length.")
	}

	// Second handshake starts here.
	privkey, err := lib.LoadRsaKeyFromFile("./dam-private.key")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := lib.DecryptMsgRsa([]byte(decodedSecret), privkey)
	if err != nil {
		t.Fatal(err)
	}
	decryptedEncode := base64.StdEncoding.EncodeToString(decrypted)
	sig, _ := lib.SignMsgRsa([]byte(decryptedEncode), privkey)
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	vals := ValidFirst
	vals["secret"] = decryptedEncode
	vals["message"] = decryptedEncode
	vals["signature"] = encodedSig

	resp, err = postReq(vals)
	if err != nil {
		t.Fatal(err)
	}
	m, err = getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret != lib.WelcomeMsg {
		t.Fatal(m.Secret)
	}
	t.Log("Server replied:", m.Secret)
}

func TestInvalidNodetypeFirst(t *testing.T) {
	//t.SkipNow()
	var vals = map[string]string{
		"nodetype":  "foobar", // Invalid.
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	resp, err := postReq(vals)
	if err != nil {
		t.Fatal(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret != "Invalid nodetype." {
		t.Fatal("Server replied:", m.Secret)
	}
	if resp.StatusCode != 400 {
		t.Fatal("Server did not respond with HTTP 400")
	}
	t.Log("Server replied:", m.Secret)
}

func TestInvalidAddressFirst(t *testing.T) {
	//t.SkipNow()
	var vals = map[string]string{
		"nodetype":  "node",
		"address":   "foobar.onion", // Invalid.
		"message":   "I am a DAM node!",
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	resp, err := postReq(vals)
	if err != nil {
		t.Fatal(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret != "Invalid onion address." {
		t.Fatal("Server replied:", m.Secret)
	}
	if resp.StatusCode != 400 {
		t.Fatal("Server did not respond with HTTP 400")
	}
	t.Log("Server replied:", m.Secret)
}

func TestInvalidMessageFirst(t *testing.T) {
	//t.SkipNow()
	// Valid message and signature, but the signature did not sign this message.
	var vals = map[string]string{
		"nodetype":  "node",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a MAD node!", // Not matching the below signature.
		"signature": "BuB/Dv8E44CLzUX88K2Ab0lUNS9A0GSkHPtrFNNWZMihPMWN0ORhwMZBRnMJ8woPO3wSONBvEvaCXA2hvsVrUJTa+hnevQNyQXCRhdTVVuVXEpjyFzkMamxb6InrGqbsGGkEUqGMSr9aaQ85N02MMrM6T6JuyqSSssFg2xuO+P4=",
		"secret":    "",
	}
	resp, err := postReq(vals)
	if err != nil {
		t.Fatal(err)
	}

	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret == "Could not get a descriptor. Try later." {
		t.Skipf("Server replied: %s\n", m.Secret)
	}
	if m.Secret != "Signature verification failure." {
		t.Fatal("Server replied:", m.Secret)
	}
	if resp.StatusCode != 400 {
		t.Fatal("Server did not respond with HTTP 400")
	}
	t.Log("Server replied:", m.Secret)
}

func TestInvalidSignatureFirst(t *testing.T) {
	//t.SkipNow()
	// Invalid signature format.
	var vals = map[string]string{
		"nodetype":  "node",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "I am a DAM node!",
		"signature": "ThisIsnotbasE64==", // Invalid.
		"secret":    "",
	}
	resp, err := postReq(vals)
	if err != nil {
		t.Fatal(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !(strings.HasPrefix(m.Secret, "illegal base64 data at input byte ")) {
		t.Fatal("Server replied:", m.Secret)
	}
	if resp.StatusCode != 400 {
		t.Fatal("Server did not respond with HTTP 400")
	}
	t.Log("Server replied:", m.Secret)
}

func TestInvalidSecond(t *testing.T) {
	//t.SkipNow()
	// Try to jump in the second handshake without doing the first.
	// The values below are a valid second handshake, but here we test it
	// without doing the first one..
	var vals = map[string]string{
		"nodetype":  "node",
		"address":   "22mobp7vrb7a4gt2.onion",
		"message":   "ZShhYHYsRGNLOTZ6YUwwP3ZXPnxhQiR9UFVWfmk5TG56TEtLb04vMms+OTIrLlQ7aS4rflR3V041RG5Je0tnYw==",
		"signature": "L1N+VEi3T3aZaYksAy1+0UMoYn7B3Gapfk0dJzOUxUtUYVhj84TgfYeDnADNYrt5UK9hN/lCTIhsM6zPO7mSjQI43l3dKvMIikqQDwNey/XaokyPI4/oKrMoGQnu8E8UmHmI1pFvwdO5EQQaKbi90qWNj93KB/NlTwqD9Ir4blY=",
		"secret":    "ZShhYHYsRGNLOTZ6YUwwP3ZXPnxhQiR9UFVWfmk5TG56TEtLb04vMms+OTIrLlQ7aS4rflR3V041RG5Je0tnYw==",
	}
	resp, err := postReq(vals)
	if err != nil {
		t.Fatal(err)
	}
	m, err := getRespText(resp)
	if err != nil {
		t.Fatal(err)
	}
	if m.Secret != "We have not seen you before. Please authenticate properly." {
		t.Fatal("Server replied:", m.Secret)
	}
	if resp.StatusCode != 400 {
		t.Fatal("Server did not respond with HTTP 400")
	}
	t.Log("Server replied:", m.Secret)
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
