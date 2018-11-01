Tor DAM Protocol
================

Abstract
--------

* Every node has a HTTP API allowing to list other nodes and announce
  new ones.
* They keep propagating to all valid nodes they know.
* Announcing implies the need of knowledge of at least one node.
  * It is possible to make this random enough once there are at least 6
    nodes in the network.
* A node announces itself to others by sending a JSON-formatted HTTP
  POST request to one or more active node.
  * Once the POST request is received, the node will validate the
    request and return a random string (nonce) back to the requester for
    them to sign with their cryptographic key.
  * The requester will try to sign this nonce and return it back to the
    node it's announcing to, so the node can confirm the requester is in
    actual posession of the private key.
* Tor DAM **does not validate** if a node is malicious or not. This is a
  layer that has to be established with external software.


Protocol
--------

A node announcing itself has to do a JSON-formatted HTTP POST request to
one or more active nodes with the format explained below. **N.B.** The
strings shown in this document might not be valid, but they represent a
correct example.

* `address` holds the address of the Tor hidden service.
* `pubkey` is the base64 encoded ed25519 public key of the Tor hidden
  service.
* `message` is the message that has to be signed using the private key
  of this same hidden service.
* `signature` is the base64 encoded signature of the above message.
* `secret` is a string that is used for exchanging messages between the
  client and server.


```
{
  "address": "gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion",
  "pubkey": "M86S9NsfcWIe0R/FXYs4ZMYvHB74YPXewZPv+aHXn80=",
  "message" "I am a DAM node!",
  "signature": "CWqptO9ZRIvYMIHd3XHXaVny+W23P8FGkfbn5lvUqeJbDcY3G8+B4G8iCCIQiZkxkMofe6RbstHn3L1x88c3AA==",
  "secret": ""
}
```

Sending this as a POST request to a node will make it verify the
signature, and following that, the node will generate a
cryptographically secure random string, encode it using base64 and
return it back to the client for them to sign:


```
{
  "secret": "NmtDOEsrLGI8eCk1TyxOfXcwRV5lI0Y5fnhbXlAhV1dGfTl8K2JAYEQrU2lAJ2UuJ2kjQF15Q30+SWVXTkFnXw=="
}
```

The client will try to decode and sign this secret. Then it will be
reencoded using base64 and sent back for verification to complete its
part of the handshake. The POST request this time will contain the
following data:


```
{
  "address": "gphjf5g3d5ywehwrd7cv3czymtdc6ha67bqplxwbspx7tioxt7gxqiid.onion",
  "pubkey": "M86S9NsfcWIe0R/FXYs4ZMYvHB74YPXewZPv+aHXn80=",
  "message": "NFU5PXU4LT4xVy5NW303IWo1SD0odSohOHEvPThoemM3LHdcW3NVcm1TU3RAPGM8Pi1UUXpKIipWWnlTUk5kIg==",
  "signature": "1cocZey3KpuRDfRrKcI3tc4hhJpwfXU3BC3o3VE8wkkCpCFJ5Xl3wl58GLSVS4BdbDAFrf+KFpjtDLhOuSMYAw==",
  "secret": "NFU5PXU4LT4xVy5NW303IWo1SD0odSohOHEvPThoemM3LHdcW3NVcm1TU3RAPGM8Pi1UUXpKIipWWnlTUk5kIg=="
}
```


The node will verify the received secret against the public key it has
archived already. If the verification yields no errors, we assume that
the requester is actually in possession of the private key. If the node
is not valid in our database, we will complete the handshake by
welcoming the client into the network:

```
{
  "secret": "Welcome to the DAM network!"
}
```


Further on, the node will append useful metadata to the struct. We will
add the encoded public key, timestamps of when the client was first seen
and last seen, and a field to indicate if the node is valid. The latter
is not to be handled by Tor DAM, but rather an upper layer, which
actually has consensus handling.

If a requesting/announcing node is valid in another node's database, the
remote node will then propagate back all the valid nodes it knows back
to the client in a gzipped and base64 encoded JSON struct. The client
will then process this and update its own database accordingly.
