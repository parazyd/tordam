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

import "testing"

func TestValidateOnionAddress(t *testing.T) {
	const val0 = "p7qaewjgnvnaeihhyybmoofd5avh665kr3awoxlh5rt6ox743kjdr6qd.onion"
	const inv0 = "p7qaewjg1vnaeihhyybmoofd5avh665kr3awoxlh5rt6ox743kjdr6qd.onion"
	const inv1 = "p7qaewjgvybmoofd5avh665kr3awoxlh5rt6ox743kjdr6qd.onion"
	const inv2 = "p7qaewjgvybmoofd5avh665kr3awoxl1jdr6qd.onion"

	if err := ValidateOnionAddress(val0); err != nil {
		t.Fatalf("valid onion address reported invalid: %s", val0)
	}

	for _, i := range []string{inv0, inv1, inv2} {
		if err := ValidateOnionAddress(i); err == nil {
			t.Fatalf("invalid onion address reported valid: %s", i)
		}
	}
}

func TestValidatePortmap(t *testing.T) {
	val0 := []string{"1234:3215"}
	val1 := []string{}
	val2 := []string{"31983:35155", "31587:11"}
	inv0 := []string{"1515:315foo"}
	inv1 := []string{"101667:8130", "1305:3191"}

	for _, i := range [][]string{val0, val1, val2} {
		if err := ValidatePortmap(i); err != nil {
			t.Fatalf("valid portmap reported invalid: %v", i)
		}
	}

	for _, i := range [][]string{inv0, inv1} {
		if err := ValidatePortmap(i); err == nil {
			t.Fatalf("invalid portmap reported valid: %v", i)
		}
	}
}
