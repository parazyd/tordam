Tor Distributed Announce Mechanism (Tor DAM)
============================================

Protocol and tooling for mapping machines in the Tor network running
this software.

[![GoDoc](https://godoc.org/github.com/parazyd/tor-dam?status.svg)](https://godoc.org/github.com/parazyd/tor-dam)

Installation
------------

```
go get -u github.com/parazyd/tor-dam/...
```

### Dependencies

#### Go

```
golang.org/x/crypto/ed25519
golang.org/x/crypto/sha3
golang.org/x/net/proxy
github.com/go-redis/redis
```

#### Python 3

```
https://stem.torproject.org/
```

The Go dependencies should be pulled in with `go get`. You can install
`stem` possibly with your package manager, or download it from the
website itself. `stem` needs to be at least version `1.7.0`.

To install everything else, go to the directory where go has downloaded
tor-dam and run `make install` as root.

External software dependendies include `redis` and `tor`. You can
retrieve them using your package manager. Tor has to be at least version
`0.3`, to support V3 hidden services.

Tor needs to have ControlPort enabled, and has to allow either
CookieAuthentication or a password, for stem to authenticate and be able
to create hidden services and retrieve hidden service descriptors.

Redis is our storage backend where information about nodes is held.

Working configurations are provided in the `contrib` directory.
