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
	"fmt"
	"log"
	"os/exec"
	"strings"
)

func newtorrc(dir string) string {
	var pm []string

	for _, i := range strings.Split(*portmap, ",") {
		p := strings.Split(i, ":")
		pm = append(pm, fmt.Sprintf("HiddenServicePort %s %s",
			p[0], strings.Join([]string{"127.0.0.1", p[1]}, ":")))
	}

	return fmt.Sprintf(`Log warn syslog
RunAsDaemon 0
DataDirectory %s/tor
SocksPort %s
HiddenServiceDir %s/hs
HiddenServicePort %s %s
%s
`,
		dir, torAddr.String(), dir, strings.Split(listen, ":")[1],
		listen, strings.Join(pm, "\n"))
}

func spawnTor() (*exec.Cmd, error) {
	var err error
	torAddr, err = getListener()
	if err != nil {
		return nil, err
	}

	log.Println("Forking Tor daemon on", torAddr.String())

	cmd := exec.Command("tor", "-f", "-")
	cmd.Stdin = strings.NewReader(newtorrc(*workdir))

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
