const express = require('express');
const router = express.Router();

const {
    processAES
} = require('../services/aesService');

const {
    startMeasurement,
    endMeasurement
} = require('../utils/metrics');

// POST /api/aes/message
router.post('/message', (req, res) => {

    const measurement = startMeasurement();

    const {
        seq,
        message,
        sentAt
    } = req.body || {};

    try {
        // Proses pesan menggunakan AES
        const result = processAES(message);

        const receivedAt = new Date().toISOString();

        const responsePayload = {
            status: 'received',
            method: 'aes',
            seq: seq ?? null,
            echoMessage: result.decryptedMessage,
            crypto: result,
            sentAt: sentAt ?? null,
            receivedAt
        };

        // Pengukuran server menggunakan shared metrics
        const backendMetrics = endMeasurement(measurement);

        // Ukuran payload request
        const reqBytes = Buffer.byteLength(
            JSON.stringify(req.body || {}),
            'utf8'
        );

        // Ukuran payload response sebelum metrics
        const respBytes = Buffer.byteLength(
            JSON.stringify(responsePayload),
            'utf8'
        );

        const totalBytes = reqBytes + respBytes;

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
        console.error('AES error:', error);

        return res.status(500).json({
            status: 'error',
            method: 'aes',
            seq: seq ?? null,
            error: 'Terjadi kesalahan saat memproses AES'
        });
    }
});

module.exports = router;