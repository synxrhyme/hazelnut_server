class KyberHandler {
    constructor(client, data, identifier) {
        this.data       = data;
        this.client     = client;
        this.identifier = identifier;
    }

    async handleKyber() {
        if (this.data.id !== this.identifier) {
            client.close();
            return;
        }

        let replyPayload = {};
    
        try {
            const keyBytes = new Uint8Array(Buffer.from(this.data.publicKey, "base64"));
            const {cyphertext, secret} = await kyber.encrypt(keyBytes);
            const cyphertextBase64 = Buffer.from(cyphertext).toString('base64');
    
            const aesKeyRaw = await deriveAesKey(Buffer.from("password", "utf-8"));
            const aesKey = Buffer.from(aesKeyRaw);
            
            this.client.sessionKey = aesKey;
    
            console.log("shared secret:", secret.toString("hex"));
            console.log("aes key:",       aesKey.toString("hex"));
    
            replyPayload = {
                type: "kyber_key_response",
                status: "success",
                body: {
                    ciphertext: cyphertextBase64,
                    timestamp: Date.now()
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

            console.log("Server → (enc):", JSON.stringify(replyPayload));
        }
    }
}