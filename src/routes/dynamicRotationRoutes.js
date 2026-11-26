const express = require('express');
const router = express.Router();

const {
    getDynamicRotationPublicKey,
    establishDynamicSession,
    processDynamicMessage,
    rotateDynamicSession,
    confirmDynamicRotation,
    getDynamicSessionStatus,
    closeDynamicSession
} = require('../services/dynamicRotationService');

// =====================================================
// ERROR HANDLER
// =====================================================

function handleServiceError(res, error, operation) {
    console.error(
        `[DYNAMIC ROTATION] ${operation} error:`,
        error.message
    );

    if (error.code === 'ROTATION_REQUIRED') {
        return res.status(409).json({
            status: 'error',
            code: 'ROTATION_REQUIRED',
            error: error.message
        });
    }

    const message = error.message || 'Terjadi kesalahan server.';

    if (
        message.includes('Session tidak ditemukan') ||
        message.includes('Session telah kedaluwarsa')
    ) {
        return res.status(404).json({
            status: 'error',
            error: message
        });
    }

    return res.status(400).json({
        status: 'error',
        error: message
    });
}

// =====================================================
// 1. GET RSA PUBLIC KEY
// GET /api/dynamic-rotation/public-key
// =====================================================

router.get('/public-key', (req, res) => {
    try {
        const result = getDynamicRotationPublicKey();

        return res.status(200).json(result);

    } catch (error) {
        console.error(
            '[DYNAMIC ROTATION] Public key error:',
            error.message
        );

        return res.status(500).json({
            status: 'error',
            error: 'Gagal mengambil RSA Public Key.'
        });
    }
});

// =====================================================
// 2. ESTABLISH SECURE SESSION
// POST /api/dynamic-rotation/session
// =====================================================

router.post('/session', (req, res) => {
    try {
        const {
            encryptedSessionKey,
            rotationIntervalMessages,
            rotationIntervalSec
        } = req.body || {};

        if (!encryptedSessionKey) {
            return res.status(400).json({
                status: 'error',
                error: 'Encrypted AES Session Key wajib dikirim.'
            });
        }

        const result = establishDynamicSession({
            encryptedSessionKey,
            rotationIntervalMessages,
            rotationIntervalSec
        });

        return res.status(201).json({
            status: 'success',
            message: 'Secure Session berhasil dibentuk.',
            data: result
        });

    } catch (error) {
        return handleServiceError(
            res,
            error,
            'Session'
        );
    }
});

// =====================================================
// 3. PREPARE DYNAMIC SESSION KEY ROTATION
// POST /api/dynamic-rotation/rotate
// =====================================================

router.post('/rotate', (req, res) => {
    try {
        const {
            sessionId,
            sequence,
            iv,
            ciphertext,
            authTag,
            encryptedNewSessionKey
        } = req.body || {};

        if (
            !sessionId ||
            !Number.isSafeInteger(sequence) ||
            sequence < 1 ||
            !iv ||
            !ciphertext ||
            !authTag ||
            !encryptedNewSessionKey
        ) {
            return res.status(400).json({
                status: 'error',
                error: 'Data permintaan rotasi tidak lengkap atau tidak valid.'
            });
        }

        const result = rotateDynamicSession({
            sessionId,
            sequence,
            iv,
            ciphertext,
            authTag,
            encryptedNewSessionKey
        });

        return res.status(200).json({
            status: 'success',
            message: result.message,
            data: result
        });

    } catch (error) {
        return handleServiceError(
            res,
            error,
            'Rotation'
        );
    }
});

// =====================================================
// 4. CONFIRM DYNAMIC SESSION KEY ROTATION
// POST /api/dynamic-rotation/rotate/confirm
// =====================================================

router.post('/rotate/confirm', (req, res) => {
    try {
        const {
            sessionId,
            sequence,
            keyVersion,
            iv,
            ciphertext,
            authTag
        } = req.body || {};

        if (
            !sessionId ||
            !Number.isSafeInteger(sequence) ||
            sequence < 1 ||
            !Number.isSafeInteger(keyVersion) ||
            keyVersion < 2 ||
            !iv ||
            !ciphertext ||
            !authTag
        ) {
            return res.status(400).json({
                status: 'error',
                error: 'Data konfirmasi rotasi tidak lengkap atau tidak valid.'
            });
        }

        const result = confirmDynamicRotation({
            sessionId,
            sequence,
            keyVersion,
            iv,
            ciphertext,
            authTag
        });

        return res.status(200).json({
            status: 'success',
            message: result.message,
            data: result
        });

    } catch (error) {
        return handleServiceError(
            res,
            error,
            'Rotation confirmation'
        );
    }
});

// =====================================================
// 5. PROCESS ENCRYPTED MESSAGE
// POST /api/dynamic-rotation/message
// =====================================================

router.post('/message', (req, res) => {
    try {
        const {
            sessionId,
            sequence,
            iv,
            ciphertext,
            authTag
        } = req.body || {};

        if (
            !sessionId ||
            !Number.isSafeInteger(sequence) ||
            sequence < 1 ||
            !iv ||
            !ciphertext ||
            !authTag
        ) {
            return res.status(400).json({
                status: 'error',
                error: 'Data pesan tidak lengkap atau tidak valid.'
            });
        }

        const result = processDynamicMessage({
            sessionId,
            sequence,
            iv,
            ciphertext,
            authTag
        });

        return res.status(200).json({
            status: 'success',
            message: 'Pesan berhasil diproses.',
            data: result
        });

    } catch (error) {
        return handleServiceError(
            res,
            error,
            'Message'
        );
    }
});

// =====================================================
// 6. GET SESSION STATUS
// GET /api/dynamic-rotation/session/:sessionId
// =====================================================

router.get('/session/:sessionId', (req, res) => {
    try {
        const result = getDynamicSessionStatus(
            req.params.sessionId
        );

        return res.status(200).json({
            status: 'success',
            data: result
        });

    } catch (error) {
        return handleServiceError(
            res,
            error,
            'Status'
        );
    }
});

// =====================================================
// 7. CLOSE SESSION
// POST /api/dynamic-rotation/session/close
// =====================================================

router.post('/session/close', (req, res) => {
    try {
        const { sessionId } = req.body || {};

        if (!sessionId) {
            return res.status(400).json({
                status: 'error',
                error: 'Session ID wajib dikirim.'
            });
        }

        const result = closeDynamicSession(sessionId);

        return res.status(200).json({
            status: 'success',
            message: 'Secure Session berhasil diakhiri.',
            data: result
        });

    } catch (error) {
        return handleServiceError(
            res,
            error,
            'Close session'
        );
    }
});

// =====================================================
// EXPORT ROUTER
// =====================================================

module.exports = router;