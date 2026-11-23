const crypto = require('crypto');

const {
    measureCrypto
} = require('../utils/metrics');

/**
 * Memproses pesan menggunakan AES-256-GCM.
 *
 * Proses:
 * 1. Generate AES key
 * 2. Generate IV
 * 3. Encrypt plaintext
 * 4. Generate authentication tag
 * 5. Decrypt ciphertext
 * 6. Validasi hasil dekripsi
 */
function processAES(message) {
    const plaintext = String(message ?? '');

    const result = measureCrypto(() => {
        // Generate AES-256 key (32 bytes)
        const key = crypto.randomBytes(32);

        // Generate IV (12 bytes recommended for GCM)
        const iv = crypto.randomBytes(12);

        // =========================
        // ENCRYPTION
        // =========================
        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            key,
            iv
        );

        const encryptedBuffer = Buffer.concat([
            cipher.update(plaintext, 'utf8'),
            cipher.final()
        ]);

        const authTag = cipher.getAuthTag();

        // =========================
        // DECRYPTION
        // =========================
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            iv
        );

        decipher.setAuthTag(authTag);

        const decryptedBuffer = Buffer.concat([
            decipher.update(encryptedBuffer),
            decipher.final()
        ]);

        const decryptedMessage = decryptedBuffer.toString('utf8');

        return {
            encryptedBuffer,
            iv,
            authTag,
            decryptedMessage
        };
    });

    const cryptoResult = result.result;

    // Validasi hasil dekripsi
    const isVerified = cryptoResult.decryptedMessage === plaintext;

    return {
        method: 'aes',
        encrypted: true,
        algorithm: 'AES-256-GCM',

        encryptedMessage: cryptoResult.encryptedBuffer.toString('base64'),
        iv: cryptoResult.iv.toString('base64'),
        authTag: cryptoResult.authTag.toString('base64'),

        decryptedMessage: cryptoResult.decryptedMessage,
        verified: isVerified,

        cryptoProcessMs: result.cryptoProcessMs
    };
}

module.exports = {
    processAES
};