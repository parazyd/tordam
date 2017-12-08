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
		log.Fatalln(err)
	}
}

// FetchHSPubkey fetches a hidden service's RSA pubkey by running an external
// program, giving it an onion address.
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
	var cnt = 0
	log.Println(req["address"], "seems valid")
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
	// Validate signature.
	msg := []byte(req["message"])
	sig := []byte(req["signature"])
	pub, err := ParsePubkey([]byte(pubkey))
	CheckError(err)

	val, err := VerifyMsg(msg, sig, pub)
	CheckError(err)
	if val != true {
		return nil, false
	}

	return []byte(pubkey), true
}

// HTTPPost sends an HTTP POST request to the given host. It sends data as
// application/json.
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
