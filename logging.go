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
	"os"
	"path"
	"runtime"
)

var (
	inte *log.Logger
	warn *log.Logger
	info *log.Logger
)

// LogInit is the initializer for the internal tordam logging functions.
// It should be called from programs using the library, with something like:
//  tordam.LogInit(os.Stdout)
func LogInit(f *os.File) {
	inte = log.New(f, "INTERNAL ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	warn = log.New(f, "WARNING: ", log.Ldate|log.Ltime)
	info = log.New(f, "INFO: ", log.Ldate|log.Ltime)
}

func fname() string {
	pc, _, _, _ := runtime.Caller(2)
	if fn := runtime.FuncForPC(pc); fn != nil {
		return path.Base(fn.Name()) + "()"
	} else {
		return "?()"
	}
}

func rpcWarn(msg string) {
	warn.Printf("%s: %s", fname(), msg)
}

func rpcInfo(msg string) {
	info.Printf("%s: %s", fname(), msg)
}

func rpcInternalErr(msg string) {
	inte.Printf("%s: %s", fname(), msg)
}
