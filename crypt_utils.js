const crypto = require("crypto");

function aesGcmDecrypt(sessionKeyBuf, ivB64, dataB64, tagB64) {
    const iv = Buffer.from(ivB64, "base64");
    const ciphertext = Buffer.from(dataB64, "base64");
    const authTag = Buffer.from(tagB64, "base64");

    const decipher = crypto.createDecipheriv("aes-256-gcm", sessionKeyBuf, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
}

function aesGcmEncrypt(sessionKeyBuf, plaintextStr) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", sessionKeyBuf, iv);
    const enc = Buffer.concat([cipher.update(Buffer.from(plaintextStr, "utf8")), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { iv: iv.toString("base64"), data: enc.toString("base64"), tag: tag.toString("base64") };
}

async function deriveAesKey(sharedSecret, length = 32) {
  const salt = Buffer.from("Hazelnut-PBKDF2-Salt", "utf8");

  return await new Promise((resolve, reject) => {
    crypto.pbkdf2(sharedSecret, salt, 100000, length, "sha512", (err, derivedKey) => {
      if (err) return reject(err);
      resolve(derivedKey);
    });
  });
}

module.exports = { aesGcmDecrypt, aesGcmEncrypt, deriveAesKey };