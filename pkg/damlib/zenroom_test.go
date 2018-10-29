package damlib

/*
 * Copyright (c) 2018 Dyne.org Foundation
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
	"testing"
)

func TestZenroomExec(t *testing.T) {
	ret := ZenroomExec(`print ("hello")`, "", "", "", 1)
	if ret != 0 {
		t.Fatal("ZenroomExec returned:", ret)
	}

	t.Log("ZenroomExec returned:", ret)
}

func TestZenroomExecToBuf(t *testing.T) {
	ret, stdout, _ := ZenroomExecToBuf(`print ("hello")`, "", "", "", 1)
	if ret != 0 {
		t.Fatal("ZenroomExec returned:", ret)
	}

	if string(stdout) != "hello" {
		t.Log("ZenroomExecToBuf stdout is not 'hello'")
		t.Log("Stdout is rather", string(stdout))
		t.Fatal("ZenroomExecToBuf returned:", ret)
	}

	t.Log("ZenroomExecToBuf returned:", ret)
}
