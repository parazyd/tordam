package damlib

// See LICENSE file for copyright and license details.

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/proxy"
)

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

// HTTPDownload tries to download a given uri and return it as a slice of bytes.
// On failure it will return an error.
func HTTPDownload(uri string) ([]byte, error) {
	res, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	d, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return d, nil
}
