'use strict';

const WASM_URL = 'wasm.wasm';

var wasm;

function init() {
  const go = new Go();
  if ('instantiateStreaming' in WebAssembly) {
    WebAssembly.instantiateStreaming(fetch(WASM_URL), go.importObject).then(function (obj) {
      wasm = obj.instance;
      go.run(wasm);
    })
  } else {
    fetch(WASM_URL).then(resp =>
      resp.arrayBuffer()
    ).then(bytes =>
      WebAssembly.instantiate(bytes, go.importObject).then(function (obj) {
        wasm = obj.instance;
        go.run(wasm);
      })
    )
  }
}

async function readFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!file) {
        document.getElementById('result').textContent = `No file selected`;
        return;
    }

    const reader = new FileReader();
    reader.onload = async (event) => {
        const fileData = new Uint8Array(event.target.result);

	const ptr = wasm.exports.malloc(fileData.length);
	const buf = new Uint8Array(wasm.exports.memory.buffer, ptr, fileData.length);
	buf.set(fileData);
	
        const result = wasm.exports.readFile(ptr, fileData.length);
	wasm.exports.free(ptr);
    };

    reader.readAsArrayBuffer(file);
}

init();
