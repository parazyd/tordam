package damlib

// See LICENSE file for copyright and license details.

import (
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
