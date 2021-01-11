tor-dam (Tor Distributed Announce Mechanism)
============================================

Protocol and tooling for mapping machines in the Tor network running
this software.

![Network visualization](https://raw.githubusercontent.com/parazyd/tor-dam/master/contrib/network.gif)


Installation
------------

```
go get github.com/parazyd/tor-dam
```

Usage
-----

```
Usage of ./tor-dam:
  -d string
        Working directory (default "/home/parazyd/.dam")
  -e int
        Node expiry time in minutes (0=unlimited)
  -g    (Re)generate keys and exit
  -i int
        Announce interval (in minutes) (default 5)
  -n    Don't fetch remote entrypoints
  -p string
        Map of ports forwarded to/from Tor (default "13010:13010,13011:13011,5000:5000")
  -r string
        Remote list of entrypoints (comma-separated) (default "https://parazyd.org/pub/tmp/tor-dam-dirs.txt")
  -t    Trust all new nodes automatically
```

Protocol
--------

* Every node has an HTTP API allowing to list other nodes and announce
  new ones.
* They keep propagating to all trusted nodes they know.
* Announcing implies the need of knowledge of at least one node.
  * It is possible to make this random enough once there are at least
    6 nodes in the network.
* A node announces itself to others by sending a JSON-formatted HTTP
  POST request to one or more active nodes.
  * Once the initial POST request is received, the receiving node will
    ACK and return a random string (nonce) back to the requester for
    them to sign with their cryptographic key.
  * The requester will try to sign this nonce and return it back to
    the node it's announcing to, so the node can confirm the requester
    is in actual posession of the private key.
* tor-dam **does not validate** if a node should be trusted or not.
  This is a layer that has to be implemented with external software.
