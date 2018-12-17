package damlib

/*
 * Copyright (c) 2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan Jelincic <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"encoding/base64"
	"testing"
)

func makeReq() map[string]string {
	return map[string]string{
		"address":   "gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion",
		"pubkey":    "M86S9NsfcWIe0R/FXYs4ZMYvHB74YPXewZPv+aHXn80=",
		"message":   "I am a DAM node!",
		"signature": "CWqptO9ZRIvYMIHd3XHXaVny+W23P8FGkfbn5lvUqeJbDcY3G8+B4G8iCCIQiZkxkMofe6RbstHn3L1x88c3AA==",
		"secret":    "",
	}
}

func TestValidateOnionAddress(t *testing.T) {
	if !(ValidateOnionAddress("gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion")) {
		t.Fatal("Validating a valid address failed.")
	}
	if ValidateOnionAddress("gphjf5g3d5ywe1wd.onion") {
		t.Fatal("Validating an invalid address succeeded.")
	}
}

func TestValidValidateFirstHandshake(t *testing.T) {
	cmd, _ := StartRedis("../../contrib/redis.conf")
	defer cmd.Process.Kill()

	if valid, _ := ValidateFirstHandshake(makeReq()); !(valid) {
		t.Fatal("Failed to validate first handshake.")
	}
}

func TestInvalidValidateFirstHandshake(t *testing.T) {
	cmd, _ := StartRedis("../../contrib/redis.conf")
	defer cmd.Process.Kill()

	// Invalid message for this signature.
	req := makeReq()
	req["message"] = "I am a bad DAM node!"

	if valid, _ := ValidateFirstHandshake(req); valid {
		t.Fatal("Invalid request passed as valid.")
	}
}

func TestValidValidateSecondHandshake(t *testing.T) {
	cmd, _ := StartRedis("../../contrib/redis.conf")
	defer cmd.Process.Kill()

	pk, sk, _ := GenEd25519()
	onionaddr := OnionFromPubkeyEd25519(pk)

	sig, err := SignMsgEd25519([]byte("I am a DAM node!"), sk)
	if err != nil {
		t.Fatal(err)
	}
	encodedSig := base64.StdEncoding.EncodeToString(sig)
	encodedPub := base64.StdEncoding.EncodeToString([]byte(pk))

	req := map[string]string{
		"address":   string(onionaddr),
		"pubkey":    encodedPub,
		"message":   "I am a DAM node!",
		"signature": encodedSig,
		"secret":    "",
	}

	valid, secret := ValidateFirstHandshake(req)
	if !(valid) {
		t.Fatal("Failed on first handshake.")
	}

	sig, err = SignMsgEd25519([]byte(secret), sk)
	if err != nil {
		t.Fatal(err)
	}
	encodedSig = base64.StdEncoding.EncodeToString(sig)

	req = map[string]string{
		"address":   string(onionaddr),
		"pubkey":    encodedPub,
		"message":   secret,
		"signature": encodedSig,
		"secret":    secret,
	}

	if valid, _ = ValidateSecondHandshake(req); !(valid) {
		t.Fatal("Failed to validate second handshake.")
	}
}

func TestInValidValidateSecondHandshake(t *testing.T) {
	cmd, _ := StartRedis("../../contrib/redis.conf")
	defer cmd.Process.Kill()

	pk, sk, _ := GenEd25519()
	onionaddr := OnionFromPubkeyEd25519(pk)

	sig, err := SignMsgEd25519([]byte("I am a DAM node!"), sk)
	if err != nil {
		t.Fatal(err)
	}
	encodedSig := base64.StdEncoding.EncodeToString(sig)
	encodedPub := base64.StdEncoding.EncodeToString([]byte(pk))

	req := map[string]string{
		"address":   string(onionaddr),
		"pubkey":    encodedPub,
		"message":   "I am a DAM node!",
		"signature": encodedSig,
		"secret":    "",
	}

	valid, secret := ValidateFirstHandshake(req)
	if !(valid) {
		t.Fatal("Failed on first handshake.")
	}

	sig, err = SignMsgEd25519([]byte(secret), sk)
	if err != nil {
		t.Fatal(err)
	}
	encodedSig = base64.StdEncoding.EncodeToString(sig)

	secret = "We're malicious!"

	req = map[string]string{
		"address":   string(onionaddr),
		"pubkey":    encodedPub,
		"message":   secret,
		"signature": encodedSig,
		"secret":    secret,
	}

	if valid, _ = ValidateSecondHandshake(req); valid {
		t.Fatal("Invalid second handshake passed as valid.")
	}
}
