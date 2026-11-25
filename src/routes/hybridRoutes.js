
const express = require('express');
const router = express.Router();

const {
    getHybridPublicKey,
    establishSession,
    processHybridMessage,
    terminateSession,
    HybridError
} = require('../services/hybridService');

const {
    startMeasurement,
    endMeasurement
} = require('../utils/metrics');

// ==========================================
// GET SERVER PUBLIC KEY
// GET /api/hybrid/public-key
// ==========================================

router.get('/public-key', (req, res) => {
    try {
        const result = getHybridPublicKey();
        res.json(result);
    } catch (error) {
        console.error('Hybrid public key error:', error);

        res.status(500).json({
            status: 'error',
            error: error.message
        });
    }
});

// ==========================================
// ESTABLISH HYBRID SESSION
// POST /api/hybrid/session
// ==========================================

router.post('/session', (req, res) => {
    const measurement = startMeasurement();

    try {
        const { encryptedSessionKey } = req.body || {};

        if (typeof encryptedSessionKey !== 'string') {
            return res.status(400).json({
                status: 'error',
                method: 'hybrid',
                error: 'Encrypted session key wajib tersedia.'
            });
        }

        const result = establishSession(
            encryptedSessionKey
        );

        const responsePayload = {
            status: 'established',
            method: 'hybrid',
            algorithm: result.algorithm,
            sessionId: result.sessionId,
            establishedAt: new Date().toISOString()
        };

        const backendMetrics = endMeasurement(measurement);

        const reqBytes = Buffer.byteLength(
            JSON.stringify(req.body || {}),
            'utf8'
        );

        const respBytes = Buffer.byteLength(
            JSON.stringify(responsePayload),
            'utf8'
        );

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
                totalBytes: reqBytes + respBytes
            }
        });

    } catch (error) {
        console.error('Hybrid session error:', error.message);

        if (error instanceof HybridError) {
            return res.status(error.statusCode).json({
                status: 'error',
                method: 'hybrid',
                error: error.message
            });
        }

        return res.status(500).json({
            status: 'error',
            method: 'hybrid',
            error: 'Gagal membentuk hybrid session.'
        });
    }
});

// ==========================================
// POST HYBRID MESSAGE
// POST /api/hybrid/message
// ==========================================

router.post('/message', (req, res) => {
    const measurement = startMeasurement();

    const {
        seq,
        sessionId,
        encryptedMessage,
        iv,
        authTag,
        sentAt
    } = req.body || {};

    try {
        const result = processHybridMessage({
            sessionId,
            encryptedMessage,
            iv,
            authTag
        });

        const responsePayload = {
            status: 'received',
            method: 'hybrid',
            seq: seq ?? null,

            crypto: {
                algorithm: result.algorithm,
                encryptedMessage: result.encryptedResponse,
                iv: result.responseIV,
                authTag: result.responseAuthTag,
                verified: result.verified
            },

            sentAt: sentAt ?? null,
            receivedAt: new Date().toISOString()
        };

        const backendMetrics = endMeasurement(measurement);

        const reqBytes = Buffer.byteLength(
            JSON.stringify(req.body || {}),
            'utf8'
        );

        const respBytes = Buffer.byteLength(
            JSON.stringify(responsePayload),
            'utf8'
        );

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
                totalBytes: reqBytes + respBytes
            }
        });

    } catch (error) {
        console.error('Hybrid message error:', error.message);

        if (error instanceof HybridError) {
            return res.status(error.statusCode).json({
                status: 'error',
                method: 'hybrid',
                seq: seq ?? null,
                error: error.message
            });
        }

        return res.status(500).json({
            status: 'error',
            method: 'hybrid',
            seq: seq ?? null,
            error: 'Terjadi kesalahan saat memproses pesan Hybrid.'
        });
    }
});

// ==========================================
// CLOSE HYBRID SESSION
// POST /api/hybrid/session/close
// ==========================================

router.post('/session/close', (req, res) => {
    const { sessionId } = req.body || {};

    if (typeof sessionId !== 'string' || !sessionId) {
        return res.status(400).json({
            status: 'error',
            method: 'hybrid',
            error: 'Session ID wajib tersedia.'
        });
    }

    const closed = terminateSession(sessionId);

    return res.json({
        status: 'ok',
        method: 'hybrid',
        sessionClosed: closed
    });
});

module.exports = router;
