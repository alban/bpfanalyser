'use strict';

const WASM_URL = 'wasm.wasm';

var wasm;

function init() {
  $('#gadget_jstree').jstree({
      core: {
          data: []
      },
      plugins: ["themes", "icons", "state"],
      state: {
          max_opened: -1 // Set to -1 for unlimited opened nodes
      }
    })
      .bind("refresh.jstree", function(event, data) {
          $(this).jstree("open_all");
      });

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
    document.getElementById('progress').textContent = `Loading file...`;

    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];

    if (!file) {
        document.getElementById('result').textContent = `No file selected`;
        return;
    }
    window.uploadedFileName = file.name;

    const reader = new FileReader();
    reader.onload = async (event) => {
        const fileData = new Uint8Array(event.target.result);

	    const ptr = wasm.exports.malloc(fileData.length);
	    const buf = new Uint8Array(wasm.exports.memory.buffer, ptr, fileData.length);
	    buf.set(fileData);

        try {
            const result = wasm.exports.readFile(ptr, fileData.length);
        } catch (e) {
            console.error(e);
            document.getElementById('progress').textContent = `Error: ${e}`;
            return;
        }
        wasm.exports.free(ptr);

        var newTreeData = JSON.parse(window.tree_out);

        // Replace the existing tree with the new tree data
        $('#gadget_jstree').jstree(true).settings.core.data = newTreeData;
        $('#gadget_jstree').jstree('open_all');
        $('#gadget_jstree').jstree(true).refresh();

        var gadgetCode = document.getElementById('gadget_code')
        gadgetCode.textContent = window.code_out
        gadgetCode.removeAttribute('data-highlighted');
        hljs.highlightElement(gadgetCode);

        const gadgetGraph = document.getElementById('gadget_graph');
        const gadgetGraphChild = document.createElement('gadget_graph_child');
        const { svg } = await mermaid.render('gadget_graph_child', window.graph_out);
        gadgetGraph.innerHTML = svg;

        document.getElementById('progress').textContent = `Done`;
    };

    reader.readAsArrayBuffer(file);
}

init();
