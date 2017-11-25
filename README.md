Tor-DECODE announce mechanism for nodes (Tor-DAMN)
==================================================

Short PoC of finding DECODE nodes in the Tor network.


Abstract
--------

* Every DECODE node can be an opt-in directory.
* Every directory would have a RESTful/HTTP API allowing to list other
  nodes and announce new ones.
* They keep propagating to all the nodes they know.
* Implies the need of knowledge of at least one or two nodes. It is
  possible to make this random enough once there are at least 6 nodes.


Questions
---------

* Handling consensus?
* How to keep track of node status?
* Could the DECODE website could host a directory?
