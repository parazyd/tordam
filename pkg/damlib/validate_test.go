package damlib

/*
 * Copyright (c) 2018 Dyne.org Foundation
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
	"testing"
)

func TestValidateOnionAddress(t *testing.T) {
	if !(ValidateOnionAddress("gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion")) {
		t.Fatal("Validating a valid address failed.")
	}
	if ValidateOnionAddress("gphjf5g3d5ywe1wd.onion") {
		t.Fatal("Validating an invalid address succeeded.")
	}
}

func TestValidValidateFirstHandshake(t *testing.T) {
	req := map[string]string{
		"address":   "gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion",
		"pubkey":    "M86S9NsfcWIe0R/FXYs4ZMYvHB74YPXewZPv+aHXn80=",
		"message":   "I am a DAM node!",
		"signature": "CWqptO9ZRIvYMIHd3XHXaVny+W23P8FGkfbn5lvUqeJbDcY3G8+B4G8iCCIQiZkxkMofe6RbstHn3L1x88c3AA==",
		"secret":    "",
	}

	cmd, _ := StartRedis("../../contrib/redis.conf")
	valid, _ := ValidateFirstHandshake(req)
	if !(valid) {
		t.Fatal("Failed to validate first handshake.")
	}
	cmd.Process.Kill()
}

func TestInvalidValidateFirstHandshake(t *testing.T) {
	// Invalid message for this signature.
	req := map[string]string{
		"address":   "gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion",
		"pubkey":    "M86S9NsfcWIe0R/FXYs4ZMYvHB74YPXewZPv+aHXn80=",
		"message":   "I am a bad DAM node!",
		"signature": "CWqptO9ZRIvYMIHd3XHXaVny+W23P8FGkfbn5lvUqeJbDcY3G8+B4G8iCCIQiZkxkMofe6RbstHn3L1x88c3AA==",
		"secret":    "",
	}

	cmd, _ := StartRedis("../../contrib/redis.conf")
	valid, _ := ValidateFirstHandshake(req)
	if valid {
		t.Fatal("Invalid request passed as valid.")
	}
	cmd.Process.Kill()
}

func TestValidValidateSecondHandshake(t *testing.T) {
	cmd, _ := StartRedis("../../contrib/redis.conf")

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

	valid, _ = ValidateSecondHandshake(req)
	if !(valid) {
		t.Fatal("Failed to validate second handshake.")
	}
	cmd.Process.Kill()
}

func TestInValidValidateSecondHandshake(t *testing.T) {
	cmd, _ := StartRedis("../../contrib/redis.conf")

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

	valid, _ = ValidateSecondHandshake(req)
	if !(valid) {
		t.Fatal("Failed to validate second handshake.")
	}
	cmd.Process.Kill()
}
