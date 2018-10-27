package main

import (
	"fmt"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

func main() {
	pubsub := lib.RedisCli.Subscribe(lib.PubSubChan)
	_, err := pubsub.Receive()
	lib.CheckError(err)

	ch := pubsub.Channel()

	for msg := range ch {
		fmt.Println(msg.Payload)
	}
}
