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
	"compress/gzip"
	"encoding/base64"
	"log"
	"strings"
)

// CheckError is a handler for errors. It takes an error type as an argument,
// and issues a log.Fatalln, printing the error and exiting with os.Exit(1).
func CheckError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

// StringInSlice loops over a slice of strings and checks if a given string is
// already an existing element. Returns true if so, and false if not.
func StringInSlice(str string, slice []string) bool {
	for _, i := range slice {
		if str == i {
			return true
		}
	}
	return false
}

// GzipEncode compresses a given slice of bytes using gzip, and returns it as
// a base64 encoded string. Returns error upon failure.
func GzipEncode(data []byte) (string, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		return "", err
	}
	if err := gz.Flush(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// ParseDirs parses and appends a given slice of bytes and returns an appended
// slice of strings with new contents.
func ParseDirs(sl []string, data []byte) []string {
	dirStr := string(data)
	_dirs := strings.Split(dirStr, "\n")
	for _, j := range _dirs {
		if strings.HasPrefix(j, "DIR:") {
			t := strings.Split(j, "DIR:")
			if !(StringInSlice(t[1], sl)) {
				sl = append(sl, t[1])
			}
		}
	}
	return sl
}
