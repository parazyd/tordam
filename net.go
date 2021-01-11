package main

/*
 * Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
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
	"bytes"
	"io/ioutil"
	"net"
	"net/http"

	"golang.org/x/net/proxy"
)

func getListener() (*net.TCPAddr, error) {
	addr, err := net.ResolveTCPAddr("tcp4", "localhost:0")
	if err != nil {
		return nil, err
	}

	l, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr), nil
}

func httpPost(host string, data []byte) (*http.Response, error) {
	httpTransp := &http.Transport{}
	httpClient := &http.Client{Transport: httpTransp}
	dialer, err := proxy.SOCKS5("tcp", torAddr.String(), nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	httpTransp.Dial = dialer.Dial

	request, err := http.NewRequest("POST", host, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")
	return httpClient.Do(request)
}

func httpGet(uri string) ([]byte, error) {
	httpTransp := &http.Transport{}
	httpClient := &http.Client{Transport: httpTransp}
	dialer, err := proxy.SOCKS5("tcp", torAddr.String(), nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	httpTransp.Dial = dialer.Dial

	request, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	res, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return ioutil.ReadAll(res.Body)
}
