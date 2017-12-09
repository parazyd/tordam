package lib

// See LICENSE file for copyright and license details.

import (
	"bytes"
	"crypto/rand"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyAddr is the address of our Tor SOCKS port.
const ProxyAddr = "127.0.0.1:9050"

// CheckError is a handler for errors. It takes an error type as an argument,
// and issues a log.Fatalln, printing the error and exiting with os.Exit(1).
func CheckError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

// FetchHSPubkey fetches a hidden service's RSA pubkey by running an external
// program, giving it an onion address. It returns the retrieved public key as a
// string.
func FetchHSPubkey(addr string) string {
	var outb, errb bytes.Buffer

	log.Println("Fetching pubkey for:", addr)

	cmd := exec.Command("dirauth.py", addr)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Start()
	CheckError(err)

	err = cmd.Wait()
	if err != nil {
		log.Println("Could not fetch descriptor:", err)
		return ""
	}

	return outb.String()
}

// ValidateReq validates our given request against the logic we are checking.
// The function takes a request data map, and a public key in the form of a
// string. If the public key is an empty string, the function will run an
// external program to fetch the node's public key from a Tor HSDir.
//
// ValidateReq  will first validate "nodetype", looking whether the announcer
// is a node or a directory.
// Then, it will validate the onion address using a regular expression.
// Now, if pubkey is empty, it will run the external program to fetch it. If a
// descriptor can't be retrieved, it will retry for 10 times, and fail if those
// are not successful.
//
// Continuing, ValidateReq will verify the RSA signature posted by the
// announcer.
// If any of the above are invalid, the function will return nil and false.
// Otherwise, it will return the pubkey as a slice of bytes, and true.
func ValidateReq(req map[string]string, pubkey string) ([]byte, bool) {
	// Validate nodetype.
	if req["nodetype"] != "node" {
		return nil, false
	}
	// Validate address.
	re, err := regexp.Compile("^[a-z2-7]{16}\\.onion$")
	CheckError(err)
	if len(re.FindString(req["address"])) != 22 {
		return nil, false
	}
	log.Println(req["address"], "seems valid")

	if len(pubkey) == 0 {
		// Address is valid, we try to fetch its pubkey from a HSDir
		cnt := 0
		for { // We try until we have it.
			cnt++
			if cnt > 10 {
				// We probably can't get a good HSDir. The client shall retry
				// later on.
				return []byte("Couldn't get a descriptor. Try later."), false
			}
			pubkey = FetchHSPubkey(req["address"])
			if strings.HasPrefix(pubkey, "-----BEGIN RSA PUBLIC KEY-----") &&
				strings.HasSuffix(pubkey, "-----END RSA PUBLIC KEY-----") {
				log.Println("Got descriptor!")
				break
			}
			time.Sleep(2000 * time.Millisecond)
		}
	}
	// Validate signature.
	msg := []byte(req["message"])
	sig := []byte(req["signature"])
	pub, err := ParsePubkeyRsa([]byte(pubkey))
	CheckError(err)

	val, err := VerifyMsgRsa(msg, sig, pub)
	CheckError(err)
	if val != true {
		return nil, false
	}

	return []byte(pubkey), true
}

// HTTPPost sends an HTTP POST request to the given host.
// Takes the host to request and the data to post as arguments.
// If the host ends with ".onion", it will enable the request to be performed
// over a SOCKS proxy, defined in ProxyAddr.
// On success, it will return the http.Response. Otherwise, it returns an error.
func HTTPPost(host string, data []byte) (*http.Response, error) {
	socksify := false
	parsedHost, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	hostname := parsedHost.Hostname()
	if strings.HasSuffix(hostname, ".onion") {
		socksify = true
	}
	httpTransp := &http.Transport{}
	httpClient := &http.Client{Transport: httpTransp}
	if socksify {
		log.Println("Detected a .onion request. Using SOCKS proxy.")
		dialer, err := proxy.SOCKS5("tcp", ProxyAddr, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		httpTransp.Dial = dialer.Dial
	}
	request, err := http.NewRequest("POST", host, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GenRandomASCII returns a random ASCII string of a given length.
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
