package damlib

import (
	"crypto/rand"
	"math/big"
)

// GenRandomASCII generates a random ASCII string of a given length.
// Takes length int as argument, and returns a string of that length on success
// and error on failure.
func GenRandomASCII(length int) (string, error) {
	var res string
	for {
		if len(res) >= length {
			return res, nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}
		n := num.Int64()
		if n > 32 && n < 127 {
			res += string(n)
		}
	}
}
