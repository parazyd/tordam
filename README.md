Tor-DECODE Announce Mechanism (Tor-DAM)
=======================================

Protocol and tooling for finding DECODE nodes in the Tor network.


Installation
------------

```
go get -u github.com/parazyd/tor-dam/...
```

### Dependencies

#### Go

```
golang.org/x/net/proxy
github.com/go-redis/redis
```

#### Python 3
```
https://stem.torproject.org/
```

The Go dependencies should be pulled in with `go get`. You can install
`stem` possibly with your package manager, or download it from the
website itself.

To install the Python scripts, go to the directory where go has
downloaded tor-dam, enter the `python` directory and run `make install`
as root.

External software dependendies include `redis` and `tor`. You can
retrieve them using your package manager.

Tor needs to have ControlPort enabled, and has to allow either
CookieAuthentication or a password, for stem to authenticate and be able
to create hidden services and retrieve hidden service descriptors.

Redis is our storage backend where information about nodes is held.
