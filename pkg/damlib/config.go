package damlib

import "os"

// Cwd holds the path to the directory where we will Chdir on startup.
var Cwd = os.Getenv("HOME") + "/.dam"

// RsaBits holds the size of our RSA private key. Tor standard is 1024.
const RsaBits = 1024

// Privpath holds the name of where our private key is.
const Privpath = "dam-private.key"

// PostMsg holds the message we are signing with our private key.
const PostMsg = "I am a DAM node!"

// WelcomeMsg holds the message we return when welcoming a node.
const WelcomeMsg = "Welcome to the DAM network!"

// ProxyAddr is the address of our Tor SOCKS port.
const ProxyAddr = "127.0.0.1:9050"
