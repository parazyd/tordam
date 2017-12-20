package damlib

// See LICENSE file for copyright and license details.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"log"
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

// GzipEncode compresses a given string using gzip, and returns it as a base64
// encoded string. Returns error upon failure.
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
