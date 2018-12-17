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
	"testing"
)

func TestStringInSlice(t *testing.T) {
	sl := []string{"foo", "bar", "baz"}
	if !(StringInSlice("bar", sl)) {
		t.Fatal("\"bar\" should be in the slice.")
	}
	if StringInSlice("kek", sl) {
		t.Fatal("\"kek\" should not be in the slice.")
	}
}

func TestGzipEncode(t *testing.T) {
	data := "Compress this string"
	if _, err := GzipEncode([]byte(data)); err != nil {
		t.Fatal(err)
	}
}

func TestParseDirs(t *testing.T) {
	var sl []string
	data := `DIR:gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion
# Some random data
DIR:vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion`

	sl = ParseDirs(sl, []byte(data))

	if len(sl) != 2 {
		t.Fatal("Length of slice is not 2.")
	}
}

func TestGenRandomASCII(t *testing.T) {
	res, err := GenRandomASCII(64)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 64 {
		t.Fatal("Length of ASCII string is not 64.")
	}
}
