// Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
//
// This file is part of tordam
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/handler"
	"github.com/creachadair/jrpc2/server"
	"github.com/parazyd/tordam"
)

var (
	generate = flag.Bool("g", false, "(Re)generate keys and exit")
	portmap  = flag.String("m", "13010:13010,13011:13011",
		"Map of ports forwarded to/from Tor")
	listen  = flag.String("l", "127.0.0.1:49371", "Local listen address")
	datadir = flag.String("d", os.Getenv("HOME")+"/.dam", "Data directory")
	seeds   = flag.String("s",
		"p7qaewjgnvnaeihhyybmoofd5avh665kr3awoxlh5rt6ox743kjdr6qd.onion:49371",
		"List of initial peers (comma-separated)")
	noannounce = flag.Bool("n", false, "Do not announce to peers")
)

// generateED25519Keypair is a helper function to generate it, and save the
// seed to a file for later reuse.
func generateED25519Keypair(dir string) error {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	seedpath := filepath.Join(dir, "ed25519.seed")
	log.Println("Writing ed25519 key seed to", seedpath)
	return ioutil.WriteFile(seedpath,
		[]byte(base64.StdEncoding.EncodeToString(sk.Seed())), 0600)
}

// loadED25519Seed is a helper function to read an existing key seed and
// return an ed25519.PrivateKey.
func loadED25519Seed(file string) (ed25519.PrivateKey, error) {
	log.Println("Reading ed25519 seed from", file)

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	dec, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(dec), nil
}

// main here is the reference workflow of tor-dam's peer discovery. Its steps
// are commented and implement a generic way of using the tordam library.
func main() {
	flag.Parse()
	var wg sync.WaitGroup
	var err error

	// Initialize tordam logger
	tordam.LogInit(os.Stdout)

	// Assign the global tordam data directory
	tordam.Cfg.Datadir = *datadir

	// Generate the ed25519 keypair used for signing and validating
	if *generate {
		if err := generateED25519Keypair(tordam.Cfg.Datadir); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	// Assign portmap to tordam Cfg global and validate it
	tordam.Cfg.Portmap = strings.Split(*portmap, ",")
	if err := tordam.ValidatePortmap(tordam.Cfg.Portmap); err != nil {
		log.Fatal(err)
	}

	// Validate and assign the local listening address
	tordam.Cfg.Listen, err = net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		log.Fatalf("invalid listen address: %s (%v)", *listen, err)
	}

	// Load the ed25519 signing key into the tordam global
	tordam.SignKey, err = loadED25519Seed(
		filepath.Join(tordam.Cfg.Datadir, "ed25519.seed"))
	if err != nil {
		log.Fatal(err)
	}

	// Spawn Tor daemon and let it settle
	tor, err := tordam.SpawnTor(tordam.Cfg.Listen, tordam.Cfg.Portmap,
		tordam.Cfg.Datadir)
	defer func() {
		if err := tor.Process.Kill(); err != nil {
			log.Println(err)
		}
	}()
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	log.Println("Started Tor daemon on", tordam.Cfg.TorAddr.String())

	// Read the onion hostname from the datadir and map it into the
	// global tordam.Onion variable
	onionaddr, err := ioutil.ReadFile(
		filepath.Join(tordam.Cfg.Datadir, "hs", "hostname"))
	if err != nil {
		log.Fatal(err)
	}
	onionaddr = []byte(strings.TrimSuffix(string(onionaddr), "\n"))
	tordam.Onion = strings.Join([]string{
		string(onionaddr), fmt.Sprint(tordam.Cfg.Listen.Port)}, ":")
	log.Println("Our onion address is:", tordam.Onion)

	// Start the JSON-RPC server with announce endpoints.
	// This is done in the program rather than internally in the library
	// because it is more useful and easier to add additional JSON-RPC
	// endpoints to the same server if necessary.
	l, err := net.Listen(jrpc2.Network(tordam.Cfg.Listen.String()),
		tordam.Cfg.Listen.String())
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	// JSON-RPC endpoints are assigned here
	assigner := handler.ServiceMap{
		// "ann" is the JSON-RPC endpoint for peer discovery/announcement
		"ann": handler.NewService(tordam.Ann{}),
	}
	go func() {
		if err := server.Loop(l, server.NewStatic(assigner), nil); err != nil {
			log.Println(err)
		}
	}()
	log.Println("Started JSON-RPC server on", tordam.Cfg.Listen.String())

	// If decided to not announce to anyone
	if *noannounce {
		// We shall sit here and wait
		wg.Add(1)
		wg.Wait()
	}

	// Validate given seeds
	for _, i := range strings.Split(*seeds, ",") {
		if err := tordam.ValidateOnionInternal(i); err != nil {
			log.Fatalf("invalid seed %s (%v)", i, err)
		}
	}

	// Announce to initial seeds
	var succ int = 0 // Track of successful announces
	for _, i := range strings.Split(*seeds, ",") {
		wg.Add(1)
		go func(x string) {
			if err := tordam.Announce(x); err != nil {
				log.Println("error in announce:", err)
			} else {
				succ++
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	if succ < 1 {
		log.Println("No successful announces.")
	} else {
		log.Printf("Successfully announced to %d peers.", succ)
	}

	// Marshal the global Peers map to JSON and print it out.
	j, _ := json.Marshal(tordam.Peers)
	fmt.Println(string(j))
}
