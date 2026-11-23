const express = require('express');
const router = express.Router();

const {
    processNoEncryption
} = require('../services/noEncryptionService');

const {
    startMeasurement,
    endMeasurement
} = require('../utils/metrics');

// POST /api/no-encryption/message
router.post('/message', (req, res) => {

    const measurement = startMeasurement();

    const {
        seq,
        message,
        sentAt
    } = req.body || {};

    try {
        // Proses pesan tanpa enkripsi
        const result = processNoEncryption(message);

        const receivedAt = new Date().toISOString();

        const responsePayload = {
            status: 'received',
            method: 'no-encryption',
            seq: seq ?? null,
            echoMessage: result.receivedMessage,
            crypto: result,
            sentAt: sentAt ?? null,
            receivedAt
        };

        // Pengukuran server menggunakan metrics.js
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
                cryptoProcessMs: 0,
                cpuServerMs: backendMetrics.cpuServerMs,
                ramRssMb: backendMetrics.ramRssMb,
                ramHeapMb: backendMetrics.ramHeapMb,
                reqBytes,
                respBytes,
                totalBytes
            }
        });

    } catch (error) {
        console.error('No Encryption error:', error);

        return res.status(500).json({
            status: 'error',
            method: 'no-encryption',
            seq: seq ?? null,
            error: 'Terjadi kesalahan saat memproses pesan'
        });
    }
});

module.exports = router;

// const express = require('express');
// const router = express.Router();

// const {
//     processNoEncryption
// } = require('../services/noEncryptionService');

// // POST /api/no-encryption/message
// router.post('/message', (req, res) => {
//     const startTime = process.hrtime.bigint();
//     const startCpu = process.cpuUsage();

//     const {
//         seq,
//         message,
//         sentAt
//     } = req.body || {};

//     try {
//         // Proses pesan tanpa enkripsi
//         const result = processNoEncryption(message);
//         const receivedAt = new Date().toISOString();
//         const responsePayload = {
//             status: 'received',
//             method: 'no-encryption',
//             seq: seq ?? null,
//             echoMessage: result.receivedMessage,
//             crypto: result,
//             sentAt: sentAt ?? null,
//             receivedAt
//         };

//         // Waktu pemrosesan server
//         const elapsedMs = Number(process.hrtime.bigint() - startTime) / 1e6;

//         // Pengukuran CPU process
//         const cpuDiff = process.cpuUsage(startCpu);
//         const cpuServerMs = (cpuDiff.user + cpuDiff.system) / 1000;
//         const cpuServerMsPrecise = Number(cpuServerMs.toFixed(6));

//         // Pengukuran memory
//         const memory = process.memoryUsage();
//         const ramRssMb = memory.rss / (1024 * 1024);

//         const ramHeapMb = memory.heapUsed / (1024 * 1024);

//         // Ukuran payload request
//         const reqBytes = Buffer.byteLength(
//             JSON.stringify(req.body || {}),
//             'utf8'
//         );

//         // Ukuran payload response sebelum metrics
//         const respBytes = Buffer.byteLength(
//             JSON.stringify(responsePayload),
//             'utf8'
//         );

//         const totalBytes = reqBytes + respBytes;

//         return res.json({
//             ...responsePayload,
//             metrics: {
//                 serverProcessMs: Number(elapsedMs.toFixed(3)),
//                 cryptoProcessMs: 0,
//                 cpuServerMs: cpuServerMsPrecise,
//                 ramRssMb: Number(ramRssMb.toFixed(2)),
//                 ramHeapMb: Number(ramHeapMb.toFixed(2)),
//                 reqBytes,
//                 respBytes,
//                 totalBytes
//             }
//         });

//     } catch (error) {
//         console.error('No Encryption error:', error);

//         return res.status(500).json({
//             status: 'error',
//             method: 'no-encryption',
//             seq: seq ?? null,
//             error: 'Terjadi kesalahan saat memproses pesan'
//         });
//     }
// });

// module.exports = router;
