contrib
=======

Some files here could be helpful for you to find a usecase for tor-dam.

### `echo_send.py` and `echo_recv.py`

These two Python programs can be seen as a reference echo client/server
implementation for working over SOCKS5. With these, you can use some
onion address and port created and opened by tor-dam.

```
$ tor-dam -p "6969:6969" -d ./echo-dam
$ sleep 1
$ hostname="$(cat ./echo-dam/hs/hostname)"
$ ./echo_recv.py -l 127.0.0.1 -p 6969 &
$ ./echo_send.py -a "$hostname" -p 6969 -t "$torsocksport"
```

N.B. You can find `$torsocksport` using `netstat(8)` or whatever
similar too.


### `gource.go`

This is a Golang implementation of a Redis pubsub client, and was used
to create [network.gif](network.gif) that can be seen in this directory.
The internal format used for publishing is:

```
%s|%s|%s|%s
```

which translates to:

```
timestamp|onion_address|modification_type|onion_address
```

```
$ redishost="127.0.0.1:35918" # You can find this in netstat
$ go run gource.go -r "$redishost" | gource --log-format custom -
```
