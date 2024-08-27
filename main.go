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
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"path/filepath"
	"strings"
	"syscall/js"
	"unsafe"

	"github.com/cilium/ebpf"
)

type Node struct {
	ID       string  `json:"id"`
	Text     string  `json:"text"`
	Icon     string  `json:"icon"`
	Children []*Node `json:"children,omitempty"`
}

func AppendNode(root *Node, path string, newNode *Node) {
	if root == nil {
		return
	}

	if len(path) == 0 {
		root.Children = append(root.Children, newNode)
		return
	}

	segments := strings.Split(path, "/")

	for _, child := range root.Children {
		if child.ID == segments[0] {
			AppendNode(child, strings.Join(segments[1:], "/"), newNode)
			return
		}
	}
	// If child node not found, create a new node and insert it
	newChild := &Node{
		ID:       segments[0],
		Text:     segments[0],
		Children: []*Node{},
	}
	root.Children = append(root.Children, newChild)
	AppendNode(newChild, strings.Join(segments[1:], "/"), newNode)
}

func clear() {
	resultDiv := js.Global().Get("document").Call("getElementById", "result")
	resultDiv.Set("innerHTML", "")
}

func log(format string, a ...any) {
	resultDiv := js.Global().Get("document").Call("getElementById", "result")
	str := resultDiv.Get("innerHTML").String()
	str += html.EscapeString(fmt.Sprintf(format, a...)) + "\n<br>\n"
	resultDiv.Set("innerHTML", str)
}

func main() {
	wait := make(chan struct{}, 0)

	log("Ready.")

	runButton := js.Global().Get("document").Call("getElementById", "runButton")
	runButton.Set("disabled", false)

	<-wait
}

//export update
func update() {
	js.Global().Get("document").Call("getElementById", "result").Set("value", "WASM: update()")
}

func parseBPF(tree *Node, code_out *string, fileName string, reader *bytes.Reader) {
	*code_out += fmt.Sprintf("// File: %s\n\n", fileName)

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log("failed to load collection spec: %v", err)
		return
	}

	for name, m := range spec.Maps {
		AppendNode(tree, fmt.Sprintf("%s/Maps", fileName), &Node{
			ID:   name,
			Text: fmt.Sprintf("%s (%s)", name, m.Type.String()),
			Icon: "fa fa-database",
		})

		*code_out += fmt.Sprintf(`struct {
        __uint(type, %s);
        __uint(max_entries, %d);
        __uint(key_size, %d);
        __uint(value_size, %d);
} %s SEC(".maps");

`,
			m.Type.String(), m.MaxEntries, m.KeySize, m.ValueSize, name)
	}

	for name, prog := range spec.Programs {
		AppendNode(tree, fmt.Sprintf("%s/Programs", fileName), &Node{
			ID:   name,
			Text: fmt.Sprintf("%s %s", prog.Type.String(), name),
			Icon: "fa fa-gear",
		})

		*code_out += fmt.Sprintf(`// SEC("%s")
// %s %s
`,
			prog.SectionName, prog.Type.String(), name)

		*code_out += fmt.Sprintf("%v\n", prog.Instructions)
	}
}

func isElf(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ELF magic: 0x7f 45 4c 46
	return data[0] == 0x7f && data[1] == 0x45 && data[2] == 0x4c && data[3] == 0x46
}

func isTar(data []byte) bool {
	if len(data) < 262 {
		return false
	}
	tarExpectedMagic := []byte("ustar")
	tarActualMagic := data[257:262]
	return string(tarExpectedMagic) == string(tarActualMagic)
}

func parseTar(tree *Node, code_out *string, reader io.Reader) error {
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeReg:
			var buf bytes.Buffer
			_, err := io.Copy(&buf, tarReader)
			if err != nil {
				return err
			}
			b := buf.Bytes()
			if isElf(b) {
				log("ELF file: %s", header.Name)

				parseBPF(tree, code_out, header.Name, bytes.NewReader(b))
			} else {
				dirName := filepath.Dir(header.Name)
				baseName := filepath.Base(header.Name)

				AppendNode(tree, dirName, &Node{
					ID:   baseName,
					Text: baseName,
					Icon: "fa fa-file",
				})
			}
		}
	}

	return nil
}

//export readFile
func readFile(ptr *uint8, length int) int {
	var code_out string

	fileName := js.Global().Get("uploadedFileName").String()

	tree := &Node{
		ID:       "root",
		Text:     fileName,
		Icon:     "fa fa-box",
		Children: []*Node{},
	}

	clear()

	data := unsafe.Slice(ptr, length)

	if len(data) < 265 {
		log("cannot parse file (%d bytes)", len(data))
		return 1
	}

	if isElf(data) {
		log("ELF file detected")
		parseBPF(tree, &code_out, fileName, bytes.NewReader(data))
	} else if isTar(data) {
		log("TAR file detected")
		tarReader := bytes.NewReader(data)
		err := parseTar(tree, &code_out, tarReader)
		if err != nil {
			log(err.Error())
		}
	} else {
		log("Cannot identify file. Please give either a tar file generated by 'ig image export' or an ELF file.")
		return 1
	}

	out, err := json.Marshal([]*Node{tree})
	if err != nil {
		log("failed to marshal tree: %v", err)
		return 1
	}
	js.Global().Set("tree_out", string(out))

	js.Global().Set("code_out", code_out)

	return 0
}
