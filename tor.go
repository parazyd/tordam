// Copyright (c) 2017-2021 Ivan Jelincic <parazyd@dyne.org>
//
// This file is part of tordam
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package tordam

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func newtorrc(listener, torlistener *net.TCPAddr, portmap []string) string {
	var pm []string

	for _, i := range pm {
		p := strings.Split(i, ":")
		pm = append(pm, fmt.Sprintf("HiddenServicePort %s %s",
			p[0], strings.Join([]string{"127.0.0.1", p[1]}, ":")))
	}

	return fmt.Sprintf(`
Log warn syslog
RunAsDaemon 0
DataDirectory tor
SocksPort %s
HiddenServiceDir hs
HiddenServicePort %d %s
%s
`, torlistener.String(),
		listener.Port, listener.String(), strings.Join(pm, "\n"))
}

func SpawnTor(listener *net.TCPAddr, portmap []string, datadir string) (*exec.Cmd, error) {
	var err error

	if err = ValidatePortmap(portmap); err != nil {
		return nil, err
	}

	Cfg.TorAddr, err = GetAvailableListener()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(datadir, 0700); err != nil {
		return nil, err
	}

	cmd := exec.Command("tor", "-f", "-")
	cmd.Stdin = strings.NewReader(newtorrc(listener, Cfg.TorAddr, portmap))
	cmd.Dir = datadir
	return cmd, cmd.Start()
}
