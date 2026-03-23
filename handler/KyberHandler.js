const { deriveAesKey, aesGcmEncrypt } = require("../util/CryptUtils");
const crypto = require('node:crypto');

async function loadLibs() {
  const liboqs = await import("@oqs/liboqs-js");
  createMLKEM768 = liboqs.createMLKEM768;
  createMLDSA65 = liboqs.createMLDSA65;
}

let createMLKEM768, createMLDSA65;

class KyberHandler {
    constructor(client, data, identifier) {
        this.data       = data;
        this.client     = client;
        this.identifier = identifier;
    }

    async handleKyber() {
        await loadLibs();

        if (this.data.id !== this.identifier) {
            client.close();
            return;
        }

        let replyPayload = {};
    
        try {
            const kem = await createMLKEM768();
            const signer = await createMLDSA65();

            const publicKeyBytes = new Uint8Array(Buffer.from(this.data.publicKey, "base64"));
            const { publicKey: mldsaPublicKey, secretKey: mldsaSecretKey } = signer.generateKeyPair();
            const { publicKey: ed25519PublicKey, privateKey: ed25519PrivateKey } = crypto.generateKeyPairSync('ed25519');

            const { ciphertext, sharedSecret } = kem.encapsulate(publicKeyBytes);
            const aesKey = await deriveAesKey(Buffer.from(sharedSecret));
            
            this.client.sessionKey = aesKey;

            const timestamp = Date.now();
            const messageToSign = Buffer.concat([
                Buffer.from(ciphertext),
                Buffer.from(timestamp.toString())
            ]);

            const signature = signer.sign(new Uint8Array(messageToSign), mldsaSecretKey);
            const ed25519Signature = crypto.sign(null, messageToSign, ed25519PrivateKey);
            
            const der = ed25519PublicKey.export({
                format: 'der',
                type: 'spki',
            });

            const ed25519PublicKeyRaw = der.slice(-32);

            replyPayload = {
                type: "kyber_key_response",
                status: "success",
                body: {
                    ciphertext:        Buffer.from(ciphertext).toString("base64"),
                    authPublicKey:     Buffer.from(mldsaPublicKey).toString("base64"),
                    signature:         Buffer.from(signature).toString("base64"),
                    ed25519PublicKey:  ed25519PublicKeyRaw.toString("base64"),
                    ed25519Signature:  ed25519Signature.toString("base64"),
                    timestamp:         timestamp
                },
            };
    
            this.client.send(JSON.stringify(replyPayload));
            console.log("WS: AES-Key gesetzt.");
        }
    
        catch (e) {
            console.error("Kyber-Key Fehler:", e.message);
            this.client.close();
        }

        if (!isEmptyObject(replyPayload)) {
            const enc = aesGcmEncrypt(this.client.sessionKey, JSON.stringify(replyPayload));
            this.client.send(JSON.stringify({ type: "enc", iv: enc.iv, data: enc.data, tag: enc.tag }));

            //console.log("Server → (enc):", JSON.stringify(replyPayload));
        }
    }
}

function isEmptyObject(obj) {
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      return false;
    }
  }
  return true;
}

module.exports = { KyberHandler };