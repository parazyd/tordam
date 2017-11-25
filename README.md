Tor-DECODE announce mechanism for nodes (Tor-DAMN)
==================================================

Short PoC of finding DECODE nodes in the Tor network.


Abstract
--------

* Every DECODE node can be an opt-in directory.
  * This implies running the directory API daemon on the node.
* Every directory would have a RESTful/HTTP API allowing to list other
  nodes and announce new ones.
* They keep propagating to all the nodes they know.
* Announcing implies the need of knowledge of at least one or two nodes.
  It is possible to make this random enough once there are at least 6
  nodes.
* A node announces itself to the directory by sending a JSON-formatted
  POST request to one or more active DECODE nodes.


Protocol
--------

A node announcing itself has to do a JSON-formatted POST request to a
known and active DECODE directory with the format explained below.
* `type` reflects the type of the node (currently just a placeholder)
* `address` should hold the address of the Tor hidden service.
* `message` is the message that has to be signed using the private key
  of this same hidden service.
* `signature` is the base64 encoded signature of the above message.


```
{
  "type": "node",
  "address": "qzhpi3jsbuvndnaw.onion",
  "message": "I am a DECODE node!",
  "signature": "ACkwtGGedX1ibHnlwtHlgJYndEMu0HhJaK3DLnH1B+r8/xx7jNDerOU7zrZVuzvf5mH9aZyHAOSHleaD52CsbT3lZrsrVWh4sVsJCD9VbEKuuPV/hx+T8f385V5dv2nDvBtJP32eQhwAxKz8YQvBjQOX8Y/o13vq+bxnxLd1j7g="
}
```

Sending this as a POST request to a directory will make the directory
ask for the public key of the given address from a HSDir in the Tor
network. It will retrieve the public key and try to validate the
signature that was made. Validating this, we assume that the requester
is in possession of the private key.

Once validated, the directory will append to the JSON struct, which will
result in the following:


```
{
  "type": "node",
  "address": "qzhpi3jsbuvndnaw.onion",
  "message": "I am a DECODE node!",
  "signature": "ACkwtGGedX1ibHnlwtHlgJYndEMu0HhJaK3DLnH1B+r8/xx7jNDerOU7zrZVuzvf5mH9aZyHAOSHleaD52CsbT3lZrsrVWh4sVsJCD9VbEKuuPV/hx+T8f385V5dv2nDvBtJP32eQhwAxKz8YQvBjQOX8Y/o13vq+bxnxLd1j7g=",
  "firstseen": 1511577084,
  "lastseen": 1511577084,
  "publickey": "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBALrCIYHP38IEJXJAKhbVz/G6Q/OKTkKOfWXg1IlSRUtUKr+6pVMIRXni\ndeluaVRyCPkHA1g2o/MTHxVAgZspbUkTMYGrUYV0TOdcsbD29tPTXCmy5ZxyjsvO\nd7b3dxadT+9621q2H8/XYvHGWYZnnvyZgndjFsI/vBx9GYW8ial9AgMBAAE=\n-----END RSA PUBLIC KEY-----"
}
```


The directory will then save this locally on the machine, and propagate
it through the network of nodes/directories further on.


Questions and concerns
----------------------

* Handling consensus?
* Validating nodes further on?
* How to keep track of node status?
* Could the DECODE website could host a list of ultimately-trusted
  nodes/directories?
