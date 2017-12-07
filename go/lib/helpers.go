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

// CheckError is a handler for errors.
func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

// FetchHSPubkey fetches a hidden service's RSA pubkey by running an external
// program, giving it an onion address.
func FetchHSPubkey(addr string) string {
	var outb, errb bytes.Buffer

	log.Println("Fetching pubkey for:", addr)

	cmd := exec.Command("./dirauth.py", addr)
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err := cmd.Start()
	CheckError(err)

	err = cmd.Wait()
	if err != nil {
		log.Println("Could not fetch descriptor. Retrying...")
		return ""
	}

	return outb.String()
}

// ValidateReq validates our given request against some checks.
func ValidateReq(req map[string]string) ([]byte, bool) {
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

	// Address is valid, we try to fetch its pubkey from a HSDir
	var pubkey string
	log.Println(req["address"], "seems valid")
	for { // We try until we have it.
		if strings.HasPrefix(pubkey, "-----BEGIN RSA PUBLIC KEY-----") &&
			strings.HasSuffix(pubkey, "-----END RSA PUBLIC KEY-----") {
			log.Println("Got descriptor!")
			break
		}
		time.Sleep(2000 * time.Millisecond)
		pubkey = FetchHSPubkey(req["address"])
		//log.Println(pubkey)
	}

	// FIXME: commented until bug 23032 is resolved.
	// https://github.com/golang/go/issues/23032
	// Validate signature.
	/*
		msg := []byte(req["message"])
		sig := []byte(req["signature"])
		pub := []byte(pubkey)
			val, err := VerifyMsg(msg, sig, pub)
			CheckError(err)
			if val != true {
				return false
			}
	*/

	return []byte(pubkey), true
}

// HTTPPost sends an HTTP POST request to the given host. It sends data as
// application/json.
func HTTPPost(host string, data []byte) *http.Response {
	socksify := false

	parsedHost, err := url.Parse(host)
	CheckError(err)
	hostname := parsedHost.Hostname()
	if strings.HasSuffix(hostname, ".onion") {
		socksify = true
	}

	httpTransp := &http.Transport{}
	httpClient := &http.Client{Transport: httpTransp}
	if socksify {
		log.Println("Detected a .onion request. Using SOCKS proxy.")
		dialer, err := proxy.SOCKS5("tcp", ProxyAddr, nil, proxy.Direct)
		CheckError(err)
		httpTransp.Dial = dialer.Dial
	}

	request, err := http.NewRequest("POST", host, bytes.NewBuffer(data))
	CheckError(err)
	request.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(request)
	CheckError(err)

	return resp
}

// GenRandomASCII returns a random ASCII string of a given length.
func GenRandomASCII(length int) (string, error) {
	var res string
	for {
		if len(res) >= length {
			return res, nil
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		CheckError(err)

		n := num.Int64()
		if n > 32 && n < 127 {
			res += string(n)
		}
	}
}
