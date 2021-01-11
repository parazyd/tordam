package main

/*
 * Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
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
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/go-redis/redis"
)

var (
	redisAddr = flag.String("-r", "127.0.0.1:39148", "host:port for redis")
	rctx      = context.Background()
	rcli      *redis.Client
)

func main() {
	flag.Parse()

	rcli = redis.NewClient(&redis.Options{
		Addr:     *redisAddr,
		Password: "",
		DB:       0,
	})

	// "tordam" is the hardcoded name of the channel
	pubsub := rcli.Subscribe(rctx, "tordam")
	_, err := pubsub.Receive(rctx)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Subscribed to channel in redis")

	ch := pubsub.Channel()
	for msg := range ch {
		fmt.Println(msg.Payload)
	}
}
