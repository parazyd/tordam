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
	"log"
	"strings"
)

func rpcWarn(msg ...string) {
	text := strings.Join(msg[1:], " ")
	log.Printf("RPC warning: (%s) %s", msg[0], text)
}
func rpcInfo(msg ...string) {
	text := strings.Join(msg[1:], " ")
	log.Printf("RPC info: (%s) %s", msg[0], text)
}
func rpcInternalErr(msg ...string) {
	text := strings.Join(msg[1:], " ")
	log.Printf("RPC internal error: (%s) %s", msg[0], text)
}
