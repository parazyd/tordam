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
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	noremote = flag.Bool("n", false, "Don't fetch remote entrypoints")
	generate = flag.Bool("g", false, "(Re)generate keys and exit")
	annint   = flag.Int("i", 5, "Announce interval (in minutes)")
	remote   = flag.String("r", "https://parazyd.org/pub/tmp/tor-dam-dirs.txt",
		"Remote list of entrypoints (comma-separated)")
	portmap = flag.String("p", "13010:13010,13011:13011,5000:5000",
		"Map of ports forwarded to/from Tor")
	expiry   = flag.Int64("e", 0, "Node expiry time in minutes (0=unlimited)")
	trustall = flag.Bool("t", false, "Trust all new nodes automatically")
	listen   = "127.0.0.1:49371"
	//listen   = flag.String("l", "127.0.0.1:49371",
	//"Listen address for daemon (Will also map in Tor HS)")
	workdir = flag.String("d", os.Getenv("HOME")+"/.dam", "Working directory")
)

func flagSanity() error {
	for _, i := range strings.Split(*remote, ",") {
		if _, err := url.ParseRequestURI(i); err != nil {
			return fmt.Errorf("invalid URL \"%s\" in remote entrypoints", i)
		}
	}

	for _, i := range strings.Split(*portmap, ",") {
		t := strings.Split(i, ":")
		if len(t) != 2 {
			return fmt.Errorf("invalid portmap: %s (len != 2)", i)
		}
		if _, err := strconv.Atoi(t[0]); err != nil {
			return fmt.Errorf("invalid portmap: %s (%s)", i, err)
		}
		if _, err := strconv.Atoi(t[1]); err != nil {
			return fmt.Errorf("invalid portmap: %s (%s)", i, err)
		}
	}

	if _, err := net.ResolveTCPAddr("tcp", listen); err != nil {
		return fmt.Errorf("invalid listen address: %s (%s)", listen, err)
	}

	return nil
}

func main() {
	flag.Parse()
	var wg sync.WaitGroup
	var err error

	if err := flagSanity(); err != nil {
		log.Fatal(err)
	}

	if *generate {
		if err := generateED25519Keypair(*workdir); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	signingKey, err = loadED25519Seed(strings.Join(
		[]string{*workdir, seedName}, "/"))
	if err != nil {
		log.Fatal(err)
	}

	tor, err := spawnTor()
	defer tor.Process.Kill()
	if err != nil {
		log.Fatal(err)
	}

	red, err := spawnRedis()
	defer red.Process.Kill()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/announce", handleAnnounce)
	mux.HandleFunc("/", handleElse)
	srv := &http.Server{
		Addr:         listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go srv.ListenAndServe()
	log.Println("tor-dam directory listening on", listen)

	if *trustall {
		log.Println("Trustall enabled, will mark all nodes trusted by default")
	}

	if *expiry > 0 {
		log.Printf("Enabling db prune polling (%d minute interval)\n", *expiry)
		go pollPrune(*expiry)
	}

	onionaddr, err := ioutil.ReadFile(strings.Join([]string{
		*workdir, "hs", "hostname"}, "/"))
	if err != nil {
		log.Fatal(err)
	}
	onionaddr = []byte(strings.TrimSuffix(string(onionaddr), "\n"))
	log.Printf("Our hostname is: %s\n", string(onionaddr))

	// Network entrypoints. These files hold the lists of nodes we can announce
	// to initially. Format is "DIR:unlikelynameforan.onion", other lines are
	// ignored and can be used as comments or siimilar.
	epLists := strings.Split(*remote, ",")

	for {
		log.Println("Announcing to nodes...")
		var ann = 0 // Track of successful authentications
		nodes, err := fetchNodeList(epLists, *noremote)
		if err != nil {
			// No route to host, or failed download. Try later.
			log.Printf("Failed to fetch nodes, retrying in 1m (%s)\n", err)
			time.Sleep(60 * time.Second)
			continue
		}

		sigmsg := []byte("Hi tor-dam!")

		nv := map[string]string{
			"address":   string(onionaddr),
			"pubkey":    base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey)),
			"message":   string(sigmsg),
			"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, sigmsg)),
			"secret":    "",
		}

		for _, i := range nodes {
			wg.Add(1)
			go func(x string) {
				valid, err := announce(x, nv)
				if err != nil {
					log.Printf("%s: %s\n", x, err)
				}
				if valid {
					ann++
				}
				wg.Done()
			}(i)
		}
		wg.Wait()

		log.Printf("%d successful authentications\n", ann)
		log.Printf("Waiting %d min before next announce\n", *annint)
		time.Sleep(time.Duration(*annint) * time.Minute)
	}
}
