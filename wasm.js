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
            wasm.exports.readFile(ptr, fileData.length);
        } catch (e) {
            console.error(e);
            document.getElementById('progress').textContent = `Error: ${e}`;
            return;
        }
        wasm.exports.free(ptr);

        for (let key in window.gadgetResults) {
            const entry = window.gadgetResults[key];

            var num_tabs = $("div#tabs ul li").length + 1;
            const newTabHTML = "<li><a href='#tab-dyn" + num_tabs + "'>" + entry.title + "</a></li>"

            if ($('#tabMarker' + entry.position).length > 0) {
                var placeholder = $('#tabMarker' + entry.position);
                placeholder.before(newTabHTML);
            } else {
                var placeholder = $("div#tabs ul")
                placeholder.append(newTabHTML);
            }
            $("div#tabs").append(
                "<div id='tab-dyn" + num_tabs + "'>" + entry.title + "</div>"
            );
            $("div#tabs").tabs("refresh");
            const newTab = document.getElementById('tab-dyn'+ num_tabs);

            switch (entry.type) {
                case 'source':
                    newTab.innerHTML = '<pre><code id="tabCode'+num_tabs+'"></code></pre>';
                    const codeElement = document.getElementById('tabCode'+num_tabs);
                    if ("jsonPretty" in entry) {
                        codeElement.textContent = JSON.stringify(JSON.parse(entry.data), null, 2);
                    } else {
                        codeElement.textContent = entry.data;
                    }
                    codeElement.removeAttribute('data-highlighted');
                    hljs.highlightElement(codeElement);
                    break;

                case 'tree':
                    newTab.innerHTML = '<div id="tabTree'+num_tabs+'"></div>'
                    var treeElement = document.getElementById('emptyDiv').cloneNode(true);
                    treeElement.id = 'tabTree'+num_tabs;
                    newTab.appendChild(treeElement);
                    // Add jQuery attributes
                    treeElement = $('#'+treeElement.id)
                    var newTreeData = JSON.parse(entry.data);
                    treeElement.jstree({
                        core: {
                            data: []
                        },
                        plugins: ["themes", "icons", "state"],
                        state: {
                            max_opened: -1 // Set to -1 for unlimited opened nodes
                        }
                    });
                    treeElement.bind("refresh.jstree", function(event, data) {
                            $(this).jstree("open_all");
                        });

                    treeElement.jstree(true).settings.core.data = newTreeData;
                    treeElement.jstree('open_all');
                    treeElement.jstree(true).refresh();

                    break;

                case 'mermaid':
                    newTab.innerHTML = '<div id="tabMermaid'+num_tabs+'"></div>'
                    const mermaidElement = $('#tabMermaid'+num_tabs)
                    const gadgetGraphChild = document.createElement('div');
                    gadgetGraphChild.id = 'tabMermaid'+num_tabs+'Child';
                    const { svg } = await mermaid.render(gadgetGraphChild.id, entry.data);
                    newTab.innerHTML = svg;

                    break;

                default:
                    console.log("Unknown entry type: " + entry.type)
            }
        }

        document.getElementById('progress').textContent = `Done`;
    };

    reader.readAsArrayBuffer(file);
}

init();
