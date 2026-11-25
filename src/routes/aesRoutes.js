const express = require('express');
const router = express.Router();

const {
    processAES
} = require('../services/aesService');

const {
    startMeasurement,
    endMeasurement
} = require('../utils/metrics');

// Membaca AES Shared Key dari environment
function getAESKey() {
    const encodedKey = process.env.AES_SHARED_KEY;

    if (!encodedKey) {
        throw new Error('AES_SHARED_KEY belum dikonfigurasi.');
    }

    const key = Buffer.from(encodedKey, 'base64');

    if (
        key.length !== 32 ||
        key.toString('base64') !== encodedKey
    ) {
        throw new Error('AES_SHARED_KEY tidak valid.');
    }

    return key;
}

// POST /api/aes/message
router.post('/message', (req, res) => {
    const measurement = startMeasurement();

    const {
        seq,
        encryptedMessage,
        iv,
        authTag,
        sentAt
    } = req.body || {};

    try {
        // 1. Ambil AES Shared Key
        const aesKey = getAESKey();

        // 2. Validasi input
        if (
            typeof encryptedMessage !== 'string' ||
            typeof iv !== 'string' ||
            typeof authTag !== 'string'
        ) {
            return res.status(400).json({
                status: 'error',
                method: 'aes',
                seq: seq ?? null,
                error: 'Format pesan terenkripsi tidak valid.'
            });
        }

        // 3. Dekripsi request dan enkripsi response
        const result = processAES(
            {
                encryptedMessage,
                iv,
                authTag
            },
            aesKey
        );

        const receivedAt = new Date().toISOString();

        // 4. Susun response tanpa mengirim plaintext
        const responsePayload = {
            status: 'received',
            method: 'aes',
            seq: seq ?? null,
            crypto: {
                algorithm: result.algorithm,
                encryptedMessage: result.encryptedResponse,
                iv: result.responseIV,
                authTag: result.responseAuthTag,
                verified: result.verified
            },
            sentAt: sentAt ?? null,
            receivedAt
        };

        // 5. Pengukuran server
        const backendMetrics = endMeasurement(measurement);

        // 6. Ukuran payload
        const reqBytes = Buffer.byteLength(
            JSON.stringify(req.body || {}),
            'utf8'
        );

        const respBytes = Buffer.byteLength(
            JSON.stringify(responsePayload),
            'utf8'
        );

        const totalBytes = reqBytes + respBytes;

        // 7. Kirim ciphertext response kepada client
        return res.json({
            ...responsePayload,
            metrics: {
                serverProcessMs: backendMetrics.serverProcessMs,
                cryptoProcessMs: result.cryptoProcessMs,
                cpuServerMs: backendMetrics.cpuServerMs,
                ramRssMb: backendMetrics.ramRssMb,
                ramHeapMb: backendMetrics.ramHeapMb,
                reqBytes,
                respBytes,
                totalBytes
            }
        });

    } catch (error) {
        console.error('AES error:', error.message);

        // Kesalahan konfigurasi server
        if (error.message.includes('AES_SHARED_KEY')) {
            return res.status(500).json({
                status: 'error',
                method: 'aes',
                seq: seq ?? null,
                error: 'Konfigurasi AES server tidak valid.'
            });
        }

        // Kesalahan autentikasi/dekripsi AES-GCM
        if (
            error.code === 'ERR_CRYPTO_INVALID_AUTH_TAG' ||
            error.message.includes('Unsupported state') ||
            error.message.includes('Invalid authentication tag')
        ) {
            return res.status(400).json({
                status: 'error',
                method: 'aes',
                seq: seq ?? null,
                error: 'Autentikasi atau dekripsi pesan AES gagal.'
            });
        }

        return res.status(500).json({
            status: 'error',
            method: 'aes',
            seq: seq ?? null,
            error: 'Terjadi kesalahan saat memproses AES.'
        });
    }
});

module.exports = router;