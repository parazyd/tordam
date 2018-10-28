package main

import (
	"fmt"
	"os"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

func main() {
	pubsub := lib.RedisCli.Subscribe(lib.PubSubChan)
	_, err := pubsub.Receive()
	lib.CheckError(err)
	fmt.Fprintf(os.Stderr, "Subscribed to %s channel in Redis\n", lib.PubSubChan)

	ch := pubsub.Channel()

	fmt.Fprintf(os.Stderr, "Listening to messages...\n")
	for msg := range ch {
		fmt.Println(msg.Payload)
	}
}
