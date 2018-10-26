package damlib

/*
 * Copyright (c) 2017-2018 Dyne.org Foundation
 * tor-dam is written and maintained by Ivan J. <parazyd@dyne.org>
 *
 * This file is part of tor-dam
 *
 * This source code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this source code. If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"fmt"

	"github.com/go-redis/redis"
)

// RedisAddress points us to our Redis instance.
const RedisAddress = "127.0.0.1:6379"

// RedisCli is our global Redis client
var RedisCli = redis.NewClient(&redis.Options{
	Addr:     RedisAddress,
	Password: "",
	DB:       0,
})

// PublishToRedis is a function that publishes a node's status to Redis.
// This is used for Gource visualization.
func PublishToRedis(address string) {
	var timestamp, username, modtype, onion, pubstr string

	nodedata, err := RedisCli.HGetAll(address).Result()
	CheckError(err)

	timestamp = nodedata["lastseen"]
	if timestamp == nodedata["firstseen"] {
		modtype = "A"
	} else {
		modtype = "M"
	}
	username = address
	onion = address

	pubstr = fmt.Sprintf("%s|%s|%s|%s\n", timestamp, username, modtype, onion)

	RedisCli.Publish(PubSubChan, pubstr)
}
