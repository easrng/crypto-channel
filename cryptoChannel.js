let aes = (() => {
    async function _makeIv() {
        return window
            .crypto
            .getRandomValues(new Uint8Array(12));
    }

    async function _generateKey() {
        return await window
            .crypto
            .subtle
            .generateKey({
                name: "AES-GCM", length: 256 //can be  128, 192, or 256
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            );
    }

    async function _importJwk(jwk) {
        return await window
            .crypto
            .subtle
            .importKey("jwk", //can be "jwk" or "raw"
                    jwk, {
                //this is the algorithm options
                name: "AES-GCM"
            }, true, //whether the key is extractable (i.e. can be used in exportKey)
                    ["encrypt", "decrypt"] //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"
            );
    }

    async function _exportJwk(key) {
        return await window
            .crypto
            .subtle
            .exportKey("jwk", //can be "jwk" or "raw"
                    key //extractable must be true
            );
    }

    async function _encrypt(key, data, iv) {
        return await window
            .crypto
            .subtle
            .encrypt({
                name: "AES-GCM",

                // Don't re-use initialization vectors! Always generate a new iv every time you
                // encrypt! Recommended to use 12 bytes length
                iv: iv,

                //Tag length (optional)
                tagLength: 128 //can be 32, 64, 96, 104, 112, 120 or 128 (default)
            }, key, //from generateKey or importKey above
                    data //ArrayBuffer of data you want to encrypt
            );
    }
    async function _decrypt(key, data, iv) {
        return await window
            .crypto
            .subtle
            .decrypt({
                name: "AES-GCM", iv: iv, //The initialization vector you used to encrypt
                tagLength: 128 //The tagLength you used to encrypt (if any)
            }, key, //from generateKey or importKey above
                    data //ArrayBuffer of the data
            );
    }

    async function _ab2str(buf) {
        return new TextDecoder().decode(buf);
    }
    async function _str2ab(str) {
        return new TextEncoder().encode(str);
    }

    async function _arrayBufferToBase64(buffer) {
        var binary = "";
        var bytes = new Uint8Array(buffer);
        var len = bytes.byteLength;
        for (var i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }
    async function _base64ToArrayBuffer(base64) {
        var binary_string = window.atob(base64);
        var len = binary_string.length;
        var bytes = new Uint8Array(len);
        for (var i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }

    async function generateState() {
        return {key: await _generateKey()};
    }

    async function encrypt(str, state) {
        let iv = await _makeIv();
        let d = await _arrayBufferToBase64(await _encrypt(state.key, await _str2ab(str), iv));
        return btoa(JSON.stringify({
            data: d,
            iv: new Array(...iv)
        }));
    }
    async function decrypt(str, state) {
        let eo = JSON.parse(atob(str));
        let r = await _decrypt(state.key, await _base64ToArrayBuffer(eo.data), new Uint8Array(eo.iv));
        r = await _ab2str(r);
        return r;
    }

    async function exportState(state) {
        return JSON.stringify({
            key: await _exportJwk(state.key)
            //iv: new Array(...state.iv)
        });
    }

    async function importState(state) {
        state = JSON.parse(state);
        return {
            key: await _importJwk(state.key)
            //iv: new Uint8Array(state.iv)
        };
    }
    return {importState,exportState,encrypt,decrypt,generateState,_base64ToArrayBuffer,_arrayBufferToBase64}
})();
import * as sockly from "https://cdn.pika.dev/sockly";
let onMsg;
let keypair = crypto
    .subtle
    .generateKey({
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
    }, true, ["encrypt", "decrypt"]);
let state = aes.generateState();
export async function encrypt(data, k) {
    let key = await window
        .crypto
        .subtle
        .importKey("jwk", JSON.parse(atob(k)), {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        }, true, ["encrypt"]);
    data = new TextEncoder().encode(data);
    return await aes._arrayBufferToBase64(await window.crypto.subtle.encrypt({
        name: "RSA-OAEP"
    }, key, data));
}
async function decrypt(data) {
    return new TextDecoder().decode(await window.crypto.subtle.decrypt({
        name: "RSA-OAEP"
    }, (await keypair).privateKey, await aes._base64ToArrayBuffer(data)));
}
let onKey,
    gotKey = false,
    rcrypto;
let exposed = {
    getKey: async function () {
        return btoa(JSON.stringify(await crypto.subtle.exportKey("jwk", (await keypair).publicKey)));
    },
    keyReply: async function (m) {
        state = aes.importState(await decrypt(m));
        if (onKey) 
            onKey();
        gotKey = true;
    },
    onSend: async function (msg) {
        try {
            onMsg(await aes.decrypt(msg, await state));
        } catch (e) {
            console.error(e);
        }
    }
};
export async function connect(peer) {
    if (!peer._connected) 
        await new Promise(r => peer.on("connect", r))
    sockly.expose(this.getExposed(), peer._channel);
    rcrypto = sockly.link(peer._channel);
    await exchange(peer.initiator);
}
export async function send(msg) {
    await rcrypto.onSend(await aes.encrypt(msg, await state));
}
export function messageHandler(cb) {
    onMsg = cb;
}
export function getExposed() {
    return exposed;
}
async function exchange(isHosting) {
    if (!isHosting) {
        await rcrypto.keyReply(await encrypt(await aes.exportState(await state), await rcrypto.getKey()));
    } else {
        if (gotKey) {
            return;
        } else {
            return await new Promise(r => {
                onKey = r;
            });
        }
    }
}
