
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
// METRICS HELPER
// ==========================================

function getRequestBytes(req) {
    return Buffer.byteLength(
        JSON.stringify(req.body || {}),
        'utf8'
    );
}

function buildMetrics(measurement, requestBytes, responsePayload, cryptoProcessMs = 0) {
    const backendMetrics = endMeasurement(measurement);

    // Ukuran payload respons dihitung sebelum metadata metrics
    // dimasukkan agar tidak terjadi perhitungan melingkar.
    const responseBytes = Buffer.byteLength(
        JSON.stringify(responsePayload),
        'utf8'
    );

    return {
        serverProcessMs: Number(
            backendMetrics.serverProcessMs || 0
        ),

        cryptoProcessMs: Number(
            cryptoProcessMs || 0
        ),

        cpuServerMs: Number(
            backendMetrics.cpuServerMs || 0
        ),

        ramRssMb: Number(
            backendMetrics.ramRssMb || 0
        ),

        ramHeapMb: Number(
            backendMetrics.ramHeapMb || 0
        ),

        requestBytes,
        responseBytes,
        totalBytes: requestBytes + responseBytes
    };
}

// ==========================================
// ERROR HANDLER
// ==========================================

function handleRouteError(res, error) {
    console.error('[HYBRID ERROR]', error);

    const statusCode = error instanceof HybridError
        ? error.statusCode
        : 500;

    res.status(statusCode).json({
        status: 'error',
        error: error.message || 'Terjadi kesalahan pada server.'
    });
}

// ==========================================
// 1. GET /api/hybrid/public-key
// ==========================================

router.get('/public-key', (req, res) => {
    try {
        const result = getHybridPublicKey();

        res.json(result);

    } catch (error) {
        handleRouteError(res, error);
    }
});

// ==========================================
// 2. POST /api/hybrid/session
// Membentuk session RSA-AES
// ==========================================

router.post('/session', (req, res) => {
    const measurement = startMeasurement();
    const requestBytes = getRequestBytes(req);

    try {
        const { encryptedSessionKey } = req.body || {};

        if (!encryptedSessionKey) {
            throw new HybridError(
                'Encrypted session key wajib dikirim.'
            );
        }

        // Server membuka encrypted AES key menggunakan RSA private key.
        const result = establishSession(encryptedSessionKey);

        const responsePayload = {
            status: 'ok',
            method: 'hybrid',
            sessionId: result.sessionId,
            algorithm: result.algorithm,
            keyLength: result.keyLength,
            sessionTTL: result.sessionTTL
        };

        const metrics = buildMetrics(
            measurement,
            requestBytes,
            responsePayload,
            result.cryptoProcessMs
        );

        res.status(200).json({
            ...responsePayload,
            metrics
        });

    } catch (error) {
        handleRouteError(res, error);
    }
});

// ==========================================
// 3. POST /api/hybrid/message
// Komunikasi AES-256-GCM
// ==========================================

router.post('/message', (req, res) => {
    const measurement = startMeasurement();
    const requestBytes = getRequestBytes(req);

    try {
        const {
            sessionId,
            seq,
            encryptedMessage,
            iv,
            authTag,
            sentAt
        } = req.body || {};

        if (!sessionId) {
            throw new HybridError(
                'Session ID wajib dikirim.',
                401
            );
        }

        if (!encryptedMessage || !iv || !authTag) {
            throw new HybridError(
                'Encrypted message, IV, dan Auth Tag wajib dikirim.'
            );
        }

        // Proses dekripsi pesan dan enkripsi respons.
        const result = processHybridMessage({
            sessionId,
            encryptedMessage,
            iv,
            authTag
        });

        // Jangan mengirim plaintext hasil dekripsi server.
        const responsePayload = {
            status: 'ok',
            method: 'hybrid',
            seq: seq ?? null,
            sentAt: sentAt ?? null,

            crypto: {
                encryptedMessage: result.encryptedResponse,
                iv: result.responseIV,
                authTag: result.responseAuthTag,
                verified: result.verified,
                cryptoProcessMs: result.cryptoProcessMs
            }
        };

        const metrics = buildMetrics(
            measurement,
            requestBytes,
            responsePayload,
            result.cryptoProcessMs
        );

        res.status(200).json({
            ...responsePayload,
            metrics
        });

    } catch (error) {
        handleRouteError(res, error);
    }
});

// ==========================================
// 4. POST /api/hybrid/session/close
// Mengakhiri session
// ==========================================

router.post('/session/close', (req, res) => {
    try {
        const { sessionId } = req.body || {};

        if (!sessionId) {
            throw new HybridError(
                'Session ID wajib dikirim.',
                401
            );
        }

        const result = terminateSession(sessionId);

        if (!result.terminated) {
            return res.status(404).json({
                status: 'error',
                error: 'Session tidak ditemukan atau sudah berakhir.'
            });
        }

        res.status(200).json({
            status: 'ok',
            method: 'hybrid',
            message: 'Hybrid session berhasil diakhiri.'
        });

    } catch (error) {
        handleRouteError(res, error);
    }
});

module.exports = router;
