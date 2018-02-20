package damlib

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
	"bytes"
	"log"
	"os/exec"
)

// FetchHSPubkey fetches a hidden service's RSA pubkey by running an external
// program, giving it an onion address. It returns the retrieved public key as a
// string.
func FetchHSPubkey(addr string) string {
	var outb, errb bytes.Buffer

	log.Println("Fetching pubkey for:", addr)

	cmd := exec.Command("damauth.py", addr)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()
	CheckError(err)

	if err = cmd.Wait(); err != nil {
		log.Println("Could not fetch descriptor:", err)
		return ""
	}

	return outb.String()
}
