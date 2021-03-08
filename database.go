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
	"encoding/json"
	"io/ioutil"
	"log"
)

// WritePeersDB marshals the Peers global to JSON and writes to given file.
// Please note that this should be probably used in conjunction with some sort
// of semaphore.
func WritePeersDB(file string) error {
	j, err := json.Marshal(Peers)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, j, 0600)
}

// writePeersDBWithSem is an internal function to call WritePeersDB safely
// using an internal semaphore. Programs using this library should probably
// implement something similar if they want to write Peers to a file.
func writePeersDBWithSem(file string) {
	if err := dbSem.Acquire(dbSemCtx, 1); err != nil {
		log.Println("warning: failed to acquire sem for writing:", err)
		return
	}
	go func() {
		if err := WritePeersDB(file); err != nil {
			log.Println("warning: failed to write peers db:", err)
		}
		dbSem.Release(1)
	}()
}
