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

// #cgo LDFLAGS: -lzenroomgo
//
// #include <stddef.h>
// #include "zenroom.h"
import "C"
import "unsafe"

// ZenroomExec is Zenroom's simple API call.
func ZenroomExec(script, conf, keys, data string, verbosity int) int {
	return int(C.zenroom_exec(C.CString(script), C.CString(conf),
		C.CString(keys), C.CString(data), C.int(verbosity)))
}

// ZenroomExecToBuf is Zenroom's simple API call with buffers. It will return
// stdout and stderr.
func ZenroomExecToBuf(script, conf, keys, data string, verbosity int) (int, []byte, []byte) {
	var bufsize = 1024 * 8

	outbuf := make([]byte, bufsize)
	errbuf := make([]byte, bufsize)

	return int(C.zenroom_exec_tobuf(C.CString(script), C.CString(conf),
		C.CString(keys), C.CString(data), C.int(verbosity),
		(*C.char)(unsafe.Pointer(&outbuf[0])), C.size_t(bufsize),
		(*C.char)(unsafe.Pointer(&errbuf[0])), C.size_t(bufsize))), outbuf, errbuf
}
