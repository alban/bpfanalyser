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
	"sort"
	"strings"
	"syscall/js"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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

func TitleFromFileName(fileName string) string {
	if len(fileName) < 16 {
		return fileName
	}
	fileName = strings.TrimSuffix(fileName, ".tar")
	fileName = strings.TrimSuffix(fileName, ".o")
	fileName = strings.TrimSuffix(fileName, "_bpfel")
	fileName = strings.TrimSuffix(fileName, "_x86")

	if len(fileName) < 16 {
		return fileName
	}

	return "..." + fileName[len(fileName)-16:]
}

func parseBPF(tree *Node, fileName string, reader *bytes.Reader, results map[string]interface{}) {
	code := fmt.Sprintf("// File: %s\n\n", fileName)
	graph := "flowchart LR\n"

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log("failed to load collection spec: %v", err)
		return
	}

	var mapsList []*ebpf.MapSpec
	for _, m := range spec.Maps {
		if m.Name == ".rodata" || m.Name == ".bss" {
			continue
		}
		mapsList = append(mapsList, m)
	}
	sort.Slice(mapsList, func(i, j int) bool {
		return mapsList[i].Name < mapsList[j].Name
	})

	var progsList []*ebpf.ProgramSpec
	for _, p := range spec.Programs {
		progsList = append(progsList, p)
	}
	sort.Slice(progsList, func(i, j int) bool {
		return progsList[i].Name < progsList[j].Name
	})

	for _, m := range mapsList {
		AppendNode(tree, fmt.Sprintf("%s/Maps", fileName), &Node{
			ID:   m.Name,
			Text: fmt.Sprintf("%s (%s)", m.Name, m.Type.String()),
			Icon: "fa fa-database",
		})

		code += fmt.Sprintf(`struct {
        __uint(type, %s);
        __uint(max_entries, %d);
        __uint(key_size, %d);
        __uint(value_size, %d);
} %s SEC(".maps");

`,
			m.Type.String(), m.MaxEntries, m.KeySize, m.ValueSize, m.Name)

		graph += fmt.Sprintf("%s[(\"%s\")]\n", m.Name, m.Name)
	}

	for _, prog := range progsList {
		AppendNode(tree, fmt.Sprintf("%s/Programs", fileName), &Node{
			ID:   prog.Name,
			Text: fmt.Sprintf("%s %s", prog.Type.String(), prog.Name),
			Icon: "fa fa-gear",
		})

		code += fmt.Sprintf(`// SEC("%s")
// %s %s
`,
			prog.SectionName, prog.Type.String(), prog.Name)

		code += fmt.Sprintf("%v\n", prog.Instructions)

		references := make(map[string]bool)
		previousRef := map[asm.Register]string{}
		for _, ins := range prog.Instructions {
			if ins.IsBuiltinCall() {
				builtinFunc := asm.BuiltinFunc(ins.Constant)
				builtinFuncName := fmt.Sprint(builtinFunc)
				ref := ""
				if strings.HasPrefix(builtinFuncName, "FnMap") &&
					strings.HasSuffix(builtinFuncName, "Elem") {
					builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnMap")
					builtinFuncName = strings.TrimSuffix(builtinFuncName, "Elem")
					ref, _ = previousRef[asm.R1]
				} else if builtinFuncName == "FnPerfEventOutput" {
					builtinFuncName = strings.TrimPrefix(builtinFuncName, "FnPerf")
					ref, _ = previousRef[asm.R2]
				}
				if ref != "" {
					references[ref+"\000"+builtinFuncName] = true
				}
			}
			if ref := ins.Reference(); ref != "" {
				previousRef[ins.Dst] = ref
			}
		}
		possibleVerbs := []string{
			"Lookup",
			"Update",
			"Delete",
		}

		referencesList := []string{}
		for ref := range references {
			referencesList = append(referencesList, ref)
		}
		sort.Strings(referencesList)
		for _, ref := range referencesList {
			if !references[ref] {
				continue
			}
			parts := strings.SplitN(ref, "\000", 2)
			fnName := parts[1]
			mapName := parts[0]
			// If several arrows exist, merge them
			verbs := []string{}
			for _, verb := range possibleVerbs {
				if references[mapName+"\000"+verb] {
					verbs = append(verbs, verb)
				}
			}
			if len(verbs) > 1 {
				for _, verb := range verbs {
					references[mapName+"\000"+verb] = false
				}
				fnName = strings.Join(verbs, "+")
			}
			graph += fmt.Sprintf("%s -- \"%s\" --> %s\n", prog.Name, fnName, mapName)
		}
		graph += fmt.Sprintf("%s[\"%s\"]\n", prog.Name, prog.Name)
	}

	results["code:"+fileName] = map[string]interface{}{
		"name":     "source " + fileName,
		"title":    "Source (" + TitleFromFileName(fileName) + ")",
		"type":     "source",
		"data":     code,
		"position": "Source",
	}
	results["graph:"+fileName] = map[string]interface{}{
		"name":     "graph " + fileName,
		"title":    "Graph (" + TitleFromFileName(fileName) + ")",
		"type":     "mermaid",
		"data":     graph,
		"position": "Graph",
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

func parseTar(tree *Node, reader io.Reader, results map[string]interface{}) error {
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
			if header.Name == "index.json" {
				results["Index"] = map[string]interface{}{
					"name":       "Index",
					"title":      "Index",
					"type":       "source",
					"jsonPretty": "true",
					"data":       string(b),
					"position":   "Index",
				}
			} else if isElf(b) {
				log("ELF file: %s", header.Name)

				parseBPF(tree, header.Name, bytes.NewReader(b), results)
			} else if b[0] == '{' {
				results["Metadata"+header.Name] = map[string]interface{}{
					"name":       "Metadata",
					"title":      "Metadata (" + TitleFromFileName(header.Name) + ")",
					"type":       "source",
					"jsonPretty": "true",
					"data":       string(b),
					"position":   "Metadata",
				}
			}

			dirName := filepath.Dir(header.Name)
			if dirName == "." {
				dirName = ""
			}
			baseName := filepath.Base(header.Name)

			AppendNode(tree, dirName, &Node{
				ID:   baseName,
				Text: baseName,
				Icon: "fa fa-file",
			})
		}
	}

	return nil
}

//export readFile
func readFile(ptr *uint8, length int) int {
	results := make(map[string]interface{})

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
		parseBPF(tree, fileName, bytes.NewReader(data), results)
	} else if isTar(data) {
		log("TAR file detected")
		tarReader := bytes.NewReader(data)
		err := parseTar(tree, tarReader, results)
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

	results["Overview"] = map[string]interface{}{
		"name":     "Overview",
		"title":    "Overview",
		"type":     "tree",
		"data":     string(out),
		"position": "Overview",
	}

	js.Global().Set("gadgetResults", results)

	return 0
}
