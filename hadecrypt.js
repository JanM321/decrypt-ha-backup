function printStatus(str) {
    document.getElementById("status").innerHTML += str + "<br>";
}
async function getPasswordHash(pw) {
    let encoder = new TextEncoder();
    let data = encoder.encode(pw);
    for (let i = 0; i < 100; i++) {
        data = await window.crypto.subtle.digest("SHA-256", data);
    }
    return new Uint8Array(data.slice(0, 16));
}
async function generateIV(key, salt) {
    let iv = new Uint8Array([...key, ...salt]);
    for (var i = 0; i < 100; i++) {
        iv = await window.crypto.subtle.digest("SHA-256", iv);
    }
    return iv.slice(0, 16);
}
async function processFile(file, keyInput) {
    try {
        const reader = file.stream().getReader();
        const keyRaw = await getPasswordHash(keyInput);
        const key = await crypto.subtle.importKey("raw", keyRaw, { name: "AES-CBC" }, true, ["decrypt", "encrypt"]);

        // Create handle to unencrypted file.
        const root = await navigator.storage.getDirectory();
        const targetFilename = "unencrypted-" + file.name;
        const handle = await root.getFileHandle(targetFilename, { create: true });
        const writable = await handle.createWritable();

        const blocksize = 16;
        const chunkSize = 64 * 1024 * blocksize; // 1 MB
        const numChunks = Math.ceil((file.size - 16) / chunkSize);

        // Decompress in chunks to avoid loading the whole file in memory.
        // WebCrypto code based on https://stackoverflow.com/a/75839277.
        let index = 0;
        let cbcRand, iv;
        let availableData = new Uint8Array();
        while (true) {
            let availableBytes = availableData.length;
            if (availableBytes < chunkSize) {
                let parts = [availableData];
                while (availableBytes < chunkSize) {
                    let data = await reader.read();
                    if (data.done) {
                        break;
                    }
                    parts.push(data.value);
                    availableBytes += data.value.length;
                }
                let buf = new Uint8Array(availableBytes);
                let offset = 0;
                parts.forEach(chunk => {
                    buf.set(chunk, offset);
                    offset += chunk.byteLength;
                });
                availableData = buf;
            }
            if (index === 0) {
                cbcRand = availableData.slice(0, 16);
                availableData = availableData.slice(16);
                iv = await generateIV(keyRaw, cbcRand);
            }

            if (index === numChunks - 1) {
                // Last chunk.
                const unencrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, availableData);
                await writable.write(unencrypted);
                break;
            }

            const chunk = availableData.slice(0, chunkSize);
            const lastCiphertextBlock = chunk.slice(-blocksize);
            const padCiphertextBlock = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: lastCiphertextBlock }, key, new Uint8Array());
            const fullCiphertextChunk = new Uint8Array([...chunk, ...new Uint8Array(padCiphertextBlock)]);
            const unencrypted = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, fullCiphertextChunk);
            await writable.write(unencrypted);
            iv = lastCiphertextBlock;
            index++;
            availableData = availableData.slice(chunkSize);
        }

        await writable.close();

        printStatus(`<span style="color:green">Decrypted ${file.name}!</span>`);

        const targetFile = await handle.getFile();
        const uri = window.URL.createObjectURL(targetFile);
        const a = document.createElement("a");
        a.style.display = "none";
        a.download = targetFilename;
        a.href = uri;
        document.body.appendChild(a);
        a.click();
    } catch (e) {
        printStatus(`<span style="color:red">Error (wrong key?): ${e.message}</span>`);
    }
}
function processFiles(files, keyInput) {
    for (let file of files) {
        printStatus(`Decrypting ${file.name}...`);
        processFile(file, keyInput);
    }
}
