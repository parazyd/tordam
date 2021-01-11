package main

/*
 * Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func generateED25519Keypair(dir string) error {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	seedpath := strings.Join([]string{dir, seedName}, "/")

	log.Println("Writing ed25519 key seed to", seedpath)
	return ioutil.WriteFile(seedpath,
		[]byte(base64.StdEncoding.EncodeToString(sk.Seed())), 0600)
}

func loadED25519Seed(file string) (ed25519.PrivateKey, error) {
	log.Println("Reading ed25519 seed from", file)

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	dec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	return ed25519.NewKeyFromSeed(dec), nil
}
