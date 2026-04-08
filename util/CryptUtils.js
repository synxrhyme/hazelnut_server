const crypto = require("crypto");

async function aesGcmDecrypt(aesKey, ivBase64, ciphertextBase64, authTagBase64) {
    const iv = new Uint8Array(Buffer.from(ivBase64, "base64"));
    const data = Buffer.from(ciphertextBase64, "base64");
    const authTag = Buffer.from(authTagBase64, "base64");

    const ciphertext = Buffer.concat([data, authTag]);

    const crypt_key = await crypto.subtle.importKey(
        "raw",
        aesKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        crypt_key,
        ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
}

async function aesGcmEncrypt(aesKey, plaintextStr) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(plaintextStr);

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        aesKey,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const ciphertextBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        plaintext
    );

    const fullBuffer = Buffer.from(ciphertextBuffer);
    const data       = fullBuffer.slice(0, -16);
    const authTag    = fullBuffer.slice(-16);

    return {
        iv:   Buffer.from(iv).toString("base64"),
        data: Buffer.from(data).toString("base64"),
        tag:  Buffer.from(authTag).toString("base64")
    };
}

async function deriveAesKey(sharedSecret, salt = null, info = null) {
    const actualSalt = salt ?? Buffer.alloc(32, 0);
    const actualInfo = info ?? Buffer.from('mlkem768-hkdf-aes256gcm-v1', 'utf8');

    const derivedKey = await crypto.hkdfSync(
        'sha256',        // Hash-Algorithmus
        sharedSecret,    // IKM (Input Key Material)
        actualSalt,      // Salt
        actualInfo,      // Info
        32               // 32 Bytes = 256-bit
    );

    return Buffer.from(derivedKey);
}

module.exports = { aesGcmDecrypt, aesGcmEncrypt, deriveAesKey };