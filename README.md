tor-dam (Tor Distributed Announce Mechanism)
============================================

![tordam](contrib/tordam.png)

A library for peer discovery inside the Tor network.

![Build Status](https://github.com/parazyd/tordam/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/parazyd/tordam)](https://goreportcard.com/report/github.com/parazyd/tordam)
[![Go Reference](https://pkg.go.dev/badge/github.com/parazyd/tordam.svg)](https://pkg.go.dev/github.com/parazyd/tordam)

Installation
------------

```
go get github.com/parazyd/tordam
```

Documentation
-------------

https://pkg.go.dev/github.com/parazyd/tordam

tor-dam is a small library that can be used to facilitate peer to
peer services in the Tor network with simple mechanisms.

An integration example can be found and reviewed in the form of a
single go file: [cmd/tor-dam/tor-dam.go](cmd/tor-dam/tor-dam.go). It
is procedural and well-documented so it should serve well for learning
how to integrate the library into a Go program.

Most of the library's code is documented in the source, along with
godoc.


Feature list
------------

* Anonymous peer mapping in the Tor network
* Launching Tor and Hidden Services
* Port mapping to launched hidden service for easy anonymous services
* Exporting available peers through any marshaling interface (think
  peer list as JSON)
