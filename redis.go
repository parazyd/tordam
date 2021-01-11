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
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis"
)

// rctx is the Redis context (necessary in newer go-redis)
var rctx = context.Background()
var rcli *redis.Client

func pollPrune(interval int64) {
	for {
		log.Println("Polling redis for expired nodes")
		nodes, err := rcli.Keys(rctx, "*.onion").Result()
		if err != nil {
			log.Println("WARNING: Nonfatal error in pollPrune:", err.Error())
		}
		now := time.Now().Unix()

		for _, i := range nodes {
			res, err := rcli.HGet(rctx, i, "lastseen").Result()
			if err != nil {
				log.Println("WARNING: Nonfatal error in pollPrune:", err.Error())
				continue
			}
			ls, err := strconv.Atoi(res)
			if err != nil {
				log.Println("WARNING: Nonfatal error in pollPrune:", err.Error())
				continue
			}

			diff := (now - int64(ls)) / 60
			if diff > interval {
				log.Printf("Deleting %s (expired)\n", i)
				publishToRedis('D', i)
				rcli.Del(rctx, i)
			}
		}
		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

func publishToRedis(mt rune, addr string) {
	data, err := rcli.HGetAll(rctx, addr).Result()
	if err != nil {
		log.Println("WARNING: Nonfatal err in publishToRedis:", err.Error())
		return
	}

	if data["lastseen"] == data["firstseen"] {
		mt = 'A'
	} else if mt != 'D' {
		mt = 'M'
	}

	// TODO: First of the "addr" references could be alias/nickname

	rcli.Publish(rctx, pubsubChan, fmt.Sprintf("%s|%s|%v|%s",
		data["lastseen"], addr, mt, addr))
}

func newredisrc(dir string) string {
	return fmt.Sprintf(`daemonize no
bind %s
port %d
databases 1
dir %s
dbfilename tor-dam.rdb
save 900 1
save 300 10
save 60 10000
rdbcompression yes
rdbchecksum yes
stop-writes-on-bgsave-error no`,
		redisAddr.IP.String(), redisAddr.Port, dir)
}

func spawnRedis() (*exec.Cmd, error) {
	var err error
	redisAddr, err = getListener()
	if err != nil {
		return nil, err
	}

	rcli = redis.NewClient(&redis.Options{
		Addr:     redisAddr.String(),
		Password: "",
		DB:       0,
	})

	log.Println("Forking Redis daemon on", redisAddr.String())

	cmd := exec.Command("redis-server", "-")
	cmd.Stdin = strings.NewReader(newredisrc(*workdir))

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	time.Sleep(500 * time.Millisecond)
	if _, err := rcli.Ping(rctx).Result(); err != nil {
		return cmd, err
	}

	pubsub := rcli.Subscribe(rctx, pubsubChan)
	if _, err := pubsub.Receive(rctx); err != nil {
		return cmd, err
	}

	log.Printf("Created \"%s\" channel in Redis\n", pubsubChan)

	return cmd, nil
}
