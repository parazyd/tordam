// Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
//
// This file is part of tordam
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package tordam

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ValidateOnionAddresses checks if the given string is a valid Tor v3 Hidden
// service address. Returns error if not.
func ValidateOnionAddress(addr string) error {
	aupp := strings.ToUpper(strings.TrimSuffix(addr, ".onion"))
	if len(aupp) != 56 {
		return fmt.Errorf("invalid v3 onion address (len != 56)")
	}

	if _, err := base32.StdEncoding.DecodeString(aupp); err != nil {
		return fmt.Errorf("invalid v3 onion address: %s", err)
	}

	return nil
}

// ValidateOnionInternal takes someunlikelyname.onion:port as a parameter
// and validates its format.
func ValidateOnionInternal(onionaddr string) error {
	splitOnion := strings.Split(onionaddr, ":")
	if len(splitOnion) != 2 {
		return errors.New("onion address doesn't contain a port")
	}

	p, err := strconv.Atoi(splitOnion[1])
	if err != nil {
		return errors.New("onion port is invalid (not a number)")
	}
	if p < 1 || p > 65535 {
		return errors.New("onion port is invalid (!= 0 < port < 65536)")
	}

	return ValidateOnionAddress(splitOnion[0])
}

// ValidatePortmap checks if the given []string holds valid portmaps in the
// form of port:port (e.g. 1234:48372). Returns error if any of the found
// portmaps are invalid.
func ValidatePortmap(pm []string) error {
	for _, pmap := range pm {
		ports := strings.Split(pmap, ":")

		if len(ports) != 2 {
			return fmt.Errorf("invalid portmap: %s (len != 2)", pmap)
		}

		for i := 0; i < 2; i++ {
			p, err := strconv.Atoi(ports[i])
			if err != nil {
				return fmt.Errorf("invalid port: %s (%s)", ports[i], err)
			}
			if p < 1 || p > 65535 {
				return fmt.Errorf("invalid port: %d (!= 0 < %d < 65536)", p, p)
			}
		}
	}
	return nil
}
