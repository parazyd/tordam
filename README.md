Tor-DECODE Announce Mechanism (Tor-DAM)
=======================================

Protocol and tooling for finding DECODE nodes in the Tor network.


Installation
------------

```
go get -u github.com/parazyd/tor-dam/...
```

From the source, install python/dirauth.py to your `$PATH`.

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


Abstract
--------

* Every DECODE node can be an opt-in directory.
  * This implies running the directory daemon on the node.
* Every directory has a HTTP API allowing to list other nodes and
  announce new ones.
* They keep propagating to all valid nodes/directories they know.
* Announcing implies the need of knowledge of at least one or two nodes.
  * It is possible to make this random enough once there are at least 6
    nodes in the network.
* A node announces itself to directories by sending a JSON-formatted
  HTTP POST request to one or more active DECODE nodes/directories.
  * Once the POST request is received, the directory will validate the
    request and return a secret encrypted with the requester's private
	key.
  * The requester will try to decrypt this secret, and return it plain
    back to the directory, so the directory can confirm the requester is
	in actual possession of the private key.
* Tor-DAM **does not validate** if a node is malicious or not. This is
  a layer that has to be established on top. Tor-DAM is just the entry
  point into the network.


Protocol
--------

A node announcing itself has to do a JSON-formatted HTTP POST request
to one or more active DECODE directories with the format explained
below. N.B. The strings shown in this document might not be valid, but
they represent a correct example.

* `type` reflects the type of the node (currently just a placeholder)
* `address` holds the address of the Tor hidden service
* `message` is the message that has to be signed using the private key
  of this same hidden service.
* `signature` is the base64 encoded signature of the above message.
* `secret` is a string that is used for exchanging messages between
  the client and server.


```
{
  "type": "node",
  "address": "qzhpi3jsbuvndnaw.onion",
  "message": "I am a DECODE node!",
  "signature": "ACkwtGGedX1ibHnlwtHlgJYndEMu0HhJaK3DLnH1B+r8/xx7jNDerOU7zrZVuzvf5mH9aZyHAOSHleaD52CsbT3lZrsrVWh4sVsJCD9VbEKuuPV/hx+T8f385V5dv2nDvBtJP32eQhwAxKz8YQvBjQOX8Y/o13vq+bxnxLd1j7g=",
  "secret": ""
}
```

Sending this as a POST request to a directory will make the directory
ask for the public key of the given address from a HSDir in the Tor
network. It will retrieve the public key and try to validate the
signature that was made. Validating this, we assume that the requester
is in possession of the private key.

Following up, the directory will generate a cryptographically secure
random string and encrypt it using the before acquired private key. It
will then be encoded using base64 and sent back to the client:


```
{
	"secret": "NzN1amZoeTUvc3V1OTE5KDkzOTQ4NTc2Z3VyanNrbnZtbTU0NyY3eWR1ZWtqdmJza2sxOSg5NzNAOTg0Mgo="
}
```

The client will try to decode and decrypt this secret, and send it back
to the directory to complete its part of the handshake. The POST request
will again contained the data that was sent the first time as well:


```
{
  "type": "node",
  "address": "qzhpi3jsbuvndnaw.onion",
  "message": "I am a DECODE node!",
  "signature": "ACkwtGGedX1ibHnlwtHlgJYndEMu0HhJaK3DLnH1B+r8/xx7jNDerOU7zrZVuzvf5mH9aZyHAOSHleaD52CsbT3lZrsrVWh4sVsJCD9VbEKuuPV/hx+T8f385V5dv2nDvBtJP32eQhwAxKz8YQvBjQOX8Y/o13vq+bxnxLd1j7g=",
  "secret": "NzN1amZoeTUvc3V1OTE5KDkzOTQ4NTc2Z3Vyaj8/Pz9tbTU0NyY3eWR1ZWtqdmJza2sxOSg5NzNAOTg0Mgo="
}
```

The directory will verify the received plain secret against what it has
encrypted to validate. If the comparison yields no errors, we assume that
the requester is actually in possession of the private key. We will now
complete the handshake by welcoming the client into the network:


```
{
	"secret": "Welcome to the DECODE network!"
}
```

Further on, the directory will append useful metadata to the struct.
We will add the encoded public key, timestamps of when the client was
first seen and last seen, and a field to indicate if the node is valid.
The latter is not to be handled by Tor-DAM, but rather the upper layer,
which actually has consensus handling.

Once a node is considered not malicious by a defined number of nodes, the
directories can then keep propagating addresses of other nodes to it.
