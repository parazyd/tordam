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
	"os"
	"testing"
)

func TestSpawnTor(t *testing.T) {
	l, err := GetAvailableListener()
	if err != nil {
		t.Fatal(err)
	}
	tor, err := SpawnTor(l, []string{"1234:1234"}, "tor_test")
	defer func() {
		if err := tor.Process.Kill(); err != nil {
			t.Fatal(err)
		}
	}()
	defer os.RemoveAll("tor_test")
	if err != nil {
		t.Fatal(err)
	}
}
