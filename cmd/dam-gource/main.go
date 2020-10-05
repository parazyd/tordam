package main

/*
 * Copyright (c) 2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan Jelincic <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"os"

	lib "github.com/parazyd/tor-dam/pkg/damlib"
)

func main() {
	pubsub := lib.RedisCli.Subscribe(lib.Rctx, lib.PubSubChan)
	_, err := pubsub.Receive(lib.Rctx)
	lib.CheckError(err)
	fmt.Fprintf(os.Stderr, "Subscribed to %s channel in Redis\n", lib.PubSubChan)

	ch := pubsub.Channel()

	fmt.Fprintf(os.Stderr, "Listening to messages...\n")
	for msg := range ch {
		fmt.Println(msg.Payload)
	}
}
