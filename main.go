// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"html"
	"strings"
	"syscall/js"
	"unsafe"
)

func log(format string, a ...any) {
	resultDiv := js.Global().Get("document").Call("getElementById", "result")
	str := resultDiv.Get("innerHTML").String()
	str += html.EscapeString(fmt.Sprintf(format, a...)) + "\n<br>\n"
	resultDiv.Set("innerHTML", str)
}

func main() {
	wait := make(chan struct{}, 0)

	log("WASM: main()")

	runButton := js.Global().Get("document").Call("getElementById", "runButton")
	runButton.Set("disabled", false)

	<-wait
}

//export update
func update() {
	js.Global().Get("document").Call("getElementById", "result").Set("value", "WASM: update()")
}

//export readFile
func readFile(ptr *uint8, length int) int {
	data := unsafe.Slice(ptr, length)
	//log("WASM: readFile(ptr=%v, length=%d) data=%s", ptr, length, string(data))

	reader := bytes.NewReader(data)

	file, err := elf.NewFile(reader)
	if err != nil {
		log("failed to parse ELF file: %v", err)
		return 1
	}
	defer file.Close()

	log("Programs:\n")
	for _, sec := range file.Sections {
		if sec.Type == elf.SHT_PROGBITS && (sec.Flags&elf.SHF_EXECINSTR) != 0 && sec.Size > 0 {
			log("Name: %s\n", sec.Name)
		}
	}
	log("Maps:\n")
	for _, sec := range file.Sections {
		if sec.Name == ".maps" || strings.HasPrefix(sec.Name, "maps") {
			log("Name: %s\n", sec.Name)
		}
	}

	return 0
}
