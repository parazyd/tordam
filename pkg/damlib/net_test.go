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
	"io/ioutil"
	"testing"
)

func TestHTTPPost(t *testing.T) {
	data := []byte("foobar")

	resp, err := HTTPPost("https://requestb.in/ykdug2yk", data)
	if err != nil {
		t.Fatal("Unable to HTTPPost:", err.Error())
	}

	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Unable to read response:", err.Error())
	}

	t.Log("Got:", string(res))
}

func TestHTTPDownload(t *testing.T) {
	data, err := HTTPDownload("https://requestb.in/ykdug2yk")
	if err != nil {
		t.Fatal("Unable to HTTPDownload:", err.Error())
	}

	t.Log("Got:", string(data))
}
