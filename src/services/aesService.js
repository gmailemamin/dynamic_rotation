const crypto = require('crypto');
const {
    measureCrypto
} = require('../utils/metrics');

/**
 * AES-256-GCM Client-Server Service
 *
 * Proses:
 * 1. Client mengirim ciphertext.
 * 2. Server mendekripsi pesan menggunakan shared AES key.
 * 3. Server mengenkripsi pesan balasan menggunakan shared key.
 * 4. Server mengembalikan ciphertext respons.
 */

function validateAESKey(key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
        throw new Error(
            'AES-256 key harus berupa Buffer sepanjang 32 byte.'
        );
    }
}

/**
 * Dekripsi pesan dari client dan enkripsi respons server.
 */
function processAES({
    encryptedMessage,
    iv,
    authTag
}, key) {

    validateAESKey(key);

    if (!encryptedMessage || !iv || !authTag) {
        throw new Error(
            'Ciphertext, IV, dan Authentication Tag wajib tersedia.'
        );
    }

    const result = measureCrypto(() => {

        // ==================================
        // DECRYPTION: CLIENT -> SERVER
        // ==================================

        const ciphertextBuffer = Buffer.from(
            encryptedMessage,
            'base64'
        );

        const ivBuffer = Buffer.from(iv, 'base64');
        const authTagBuffer = Buffer.from(
            authTag,
            'base64'
        );

        if (
            ivBuffer.length !== 12 ||
            authTagBuffer.length !== 16
        ) {
            throw new Error(
                'Format IV atau Authentication Tag tidak valid.'
            );
        }

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            ivBuffer
        );

        decipher.setAuthTag(authTagBuffer);

        const decryptedBuffer = Buffer.concat([
            decipher.update(ciphertextBuffer),
            decipher.final()
        ]);

        const decryptedMessage = decryptedBuffer.toString('utf8');

        // ==================================
        // ENCRYPTION: SERVER -> CLIENT
        // ==================================

        const responseIV = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(
            'aes-256-gcm',
            key,
            responseIV
        );

        const responseBuffer = Buffer.concat([
            cipher.update(decryptedMessage, 'utf8'),
            cipher.final()
        ]);

        const responseAuthTag = cipher.getAuthTag();

        return {
            decryptedMessage,

            encryptedResponse: responseBuffer.toString('base64'),
            responseIV: responseIV.toString('base64'),
            responseAuthTag: responseAuthTag.toString('base64')
        };
    });

    return {
        method: 'aes',
        algorithm: 'AES-256-GCM',

        decryptedMessage: result.result.decryptedMessage,
        encryptedResponse: result.result.encryptedResponse,
        responseIV: result.result.responseIV,
        responseAuthTag: result.result.responseAuthTag,
        verified: true,

        cryptoProcessMs: result.cryptoProcessMs
    };
}

module.exports = {
    processAES
};