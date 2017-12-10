package damlib

// See LICENSE file for copyright and license details.

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

// ProxyAddr is the address of our Tor SOCKS port.
const ProxyAddr = "127.0.0.1:9050"

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
