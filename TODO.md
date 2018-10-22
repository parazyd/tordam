* Network tags, part of network A, part of network B
	* keep it in redis

* node expiration after a period of inactivity
	* TTL

* redis pub-sub channel(s) for nodes
	* Modify when a node is announced again
	* Add when it's new
	* (optional TTL) delete
