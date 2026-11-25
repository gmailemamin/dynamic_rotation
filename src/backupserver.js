const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// ============================================================================
// Batas Awal AES Only//
// ============================================================================
function getAesKey() {
    if (process.env.AES_256_KEY_HEX) {
        const buf = Buffer.from(process.env.AES_256_KEY_HEX, 'hex');
        if (buf.length === 32) return buf;
    }
    if (process.env.AES_256_KEY) {
        return crypto.createHash('sha256').update(process.env.AES_256_KEY).digest();
    }
    return crypto.createHash('sha256').update('rs-aes-dev-default-key-256').digest();
}

const AES_KEY = getAesKey();

function encryptDecryptAes256Gcm(plaintext) {
    const cryptoStart = process.hrtime.bigint();

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);

    const encryptedBuf = Buffer.concat([
        cipher.update(String(plaintext ?? ''), 'utf8'),
        cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(authTag);

    const decryptedBuf = Buffer.concat([
        decipher.update(encryptedBuf),
        decipher.final()
    ]);

    const cryptoProcessMs = Number(process.hrtime.bigint() - cryptoStart) / 1e6;

    return {
        ivHex: iv.toString('hex'),
        authTagHex: authTag.toString('hex'),
        ciphertextHex: encryptedBuf.toString('hex'),
        decryptedMessage: decryptedBuf.toString('utf8'),
        integrityVerified: true,
        cryptoProcessMs: Number(cryptoProcessMs.toFixed(3))
    };
}
// ============================================================================
// Batas Akhir AES Only //
// ============================================================================

// ============================================================================
// Batas awal RSA Only //
// ============================================================================
const { publicKey: RSA_PUBLIC_KEY, privateKey: RSA_PRIVATE_KEY } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function encryptDecryptRsaOaep(plaintext) {
    const cryptoStart = process.hrtime.bigint();
    const plainStr = String(plaintext ?? '');
    const plainBuf = Buffer.from(plainStr, 'utf8');

    // Batas maksimum plaintext untuk RSA-2048 + OAEP-SHA256 adalah 190 byte
    const maxBytes = 190;
    if (plainBuf.length > maxBytes) {
        const err = new Error(`Pesan terlalu panjang untuk RSA-2048 OAEP (${plainBuf.length} byte > maks ${maxBytes} byte).`);
        err.statusCode = 400;
        throw err;
    }

    const encryptedBuf = crypto.publicEncrypt(
        {
            key: RSA_PUBLIC_KEY,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        plainBuf
    );

    const decryptedBuf = crypto.privateDecrypt(
        {
            key: RSA_PRIVATE_KEY,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        encryptedBuf
    );

    const cryptoProcessMs = Number(process.hrtime.bigint() - cryptoStart) / 1e6;

    return {
        keyBits: 2048,
        oaepHash: 'SHA-256',
        ciphertextHex: encryptedBuf.toString('hex'),
        ciphertextBytes: encryptedBuf.length,
        decryptedMessage: decryptedBuf.toString('utf8'),
        cryptoProcessMs: Number(cryptoProcessMs.toFixed(3))
    };
}
// ============================================================================
// Batas Akhir RSA Only //
// ============================================================================

// ============================================================================
// Bagian awal RSA-AES (hybrid) //
// ============================================================================
function encryptDecryptRsaAesHybrid(plaintext) {
    const cryptoStart = process.hrtime.bigint();
    const plainBuf = Buffer.from(String(plaintext ?? ''), 'utf8');

    // --- [GABUNGAN RSA-AES] Langkah 1: Bangkitkan Session Key AES-256 & IV ---
    const sessionKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    // --- [GABUNGAN RSA-AES] Langkah 2: Enkripsi Payload dengan AES-256-GCM ---
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
    const encryptedPayload = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // --- [GABUNGAN RSA-AES] Langkah 3: Enkripsi Session Key dengan RSA-2048 OAEP ---
    const encryptedSessionKey = crypto.publicEncrypt(
        {
            key: RSA_PUBLIC_KEY,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        sessionKey
    );

    // --- [GABUNGAN RSA-AES] Langkah 4: Dekripsi Session Key (RSA) & Payload (AES-GCM) ---
    const recoveredSessionKey = crypto.privateDecrypt(
        {
            key: RSA_PRIVATE_KEY,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        encryptedSessionKey
    );

    const decipher = crypto.createDecipheriv('aes-256-gcm', recoveredSessionKey, iv);
    decipher.setAuthTag(authTag);
    const decryptedBuf = Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);

    const cryptoProcessMs = Number(process.hrtime.bigint() - cryptoStart) / 1e6;

    return {
        keyExchange: 'RSA-2048 OAEP (SHA-256)',
        payloadCipher: 'AES-256-GCM',
        encryptedSessionKeyHex: encryptedSessionKey.toString('hex'),
        encryptedSessionKeyBytes: encryptedSessionKey.length,
        ivHex: iv.toString('hex'),
        authTagHex: authTag.toString('hex'),
        ciphertextHex: encryptedPayload.toString('hex'),
        decryptedMessage: decryptedBuf.toString('utf8'),
        integrityVerified: true,
        cryptoProcessMs: Number(cryptoProcessMs.toFixed(3))
    };
}
// ============================================================================
// Batas Akhir RSA-AES (hybrid) //
// ============================================================================

// ============================================================================
// Bagian awal Dynamic Session Key Rotation //
// ============================================================================
let dynamicSessionActive = false;
let dynamicTotalRequests = 0;
let dynamicRotationIntervalSec = 300;
let dynamicRotationTimer = null;

const dynamicKeyState = {
    currentKeyId: null,
    currentSessionKey: null,
    currentEncryptedKeyHex: null,
    currentCreatedAtMs: 0,
    messagesWithCurrentKey: 0,
    totalRotations: 0,
    keyRing: new Map() // Menyimpan beberapa sesi terakhir untuk verifikasi dekripsi
};

function createNewDynamicSessionKey() {
    const nextSeq = dynamicKeyState.totalRotations + 1;
    const keyId = `dyn-ses-${nextSeq}-${crypto.randomBytes(3).toString('hex')}`;
    const sessionKey = crypto.randomBytes(32);
    const encryptedSessionKey = crypto.publicEncrypt(
        {
            key: RSA_PUBLIC_KEY,
            oaepHash: 'sha256',
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        },
        sessionKey
    );

    dynamicKeyState.currentKeyId = keyId;
    dynamicKeyState.currentSessionKey = sessionKey;
    dynamicKeyState.currentEncryptedKeyHex = encryptedSessionKey.toString('hex');
    dynamicKeyState.currentCreatedAtMs = Date.now();
    dynamicKeyState.messagesWithCurrentKey = 0;
    dynamicKeyState.totalRotations = nextSeq;

    dynamicKeyState.keyRing.set(keyId, sessionKey);
    if (dynamicKeyState.keyRing.size > 10) {
        const oldestKey = dynamicKeyState.keyRing.keys().next().value;
        dynamicKeyState.keyRing.delete(oldestKey);
    }
}

function stopDynamicRotationTimer() {
    if (dynamicRotationTimer) {
        clearInterval(dynamicRotationTimer);
        dynamicRotationTimer = null;
    }
}

function startDynamicRotationTimer() {
    stopDynamicRotationTimer();
    dynamicRotationTimer = setInterval(() => {
        if (!dynamicSessionActive || !dynamicKeyState.currentSessionKey || !dynamicKeyState.currentCreatedAtMs) {
            return;
        }
        const intervalMs = Math.max(1, Number(dynamicRotationIntervalSec) || 300) * 1000;
        if ((Date.now() - dynamicKeyState.currentCreatedAtMs) >= intervalMs) {
            createNewDynamicSessionKey();
        }
    }, 1000);
}

function encryptDecryptDynamicRotation(plaintext, options = {}) {
    const cryptoStart = process.hrtime.bigint();
    const plainBuf = Buffer.from(String(plaintext ?? ''), 'utf8');

    const intervalMessages = Math.max(1, Number(options.rotationIntervalMessages) || 100);
    const intervalSec = Math.max(1, Number(options.rotationIntervalSec) || 300);
    dynamicRotationIntervalSec = intervalSec;
    const forceRotate = Boolean(options.forceRotate);

    if (!dynamicSessionActive || !dynamicKeyState.currentSessionKey) {
        const err = new Error('Sesi dynamic belum aktif. Silakan klik "Mulai Sesi" terlebih dahulu.');
        err.statusCode = 400;
        throw err;
    }

    let rotatedThisRequest = false;
    let rotationReason = 'none';

    if (forceRotate) {
        createNewDynamicSessionKey();
        rotatedThisRequest = true;
        rotationReason = 'manual_force_rotate';
    } else if (dynamicKeyState.messagesWithCurrentKey >= intervalMessages) {
        createNewDynamicSessionKey();
        rotatedThisRequest = true;
        rotationReason = `message_interval_${intervalMessages}`;
    } else if ((Date.now() - dynamicKeyState.currentCreatedAtMs) >= intervalSec * 1000) {
        createNewDynamicSessionKey();
        rotatedThisRequest = true;
        rotationReason = `time_interval_${intervalSec}s`;
    }

    const activeKeyId = dynamicKeyState.currentKeyId;
    const activeKey = dynamicKeyState.currentSessionKey;
    const iv = crypto.randomBytes(12);

    // Enkripsi payload dengan session key AES-256-GCM aktif
    const cipher = crypto.createCipheriv('aes-256-gcm', activeKey, iv);
    const encryptedPayload = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Simulasi pembungkusan/pemulihan session key via RSA-2048 OAEP saat rotasi atau verifikasi
    const wrappedKeyHex = dynamicKeyState.currentEncryptedKeyHex;
    const wrappedKeyBuf = Buffer.from(wrappedKeyHex, 'hex');

    let keyForDecrypt = dynamicKeyState.keyRing.get(activeKeyId);
    if (!keyForDecrypt) {
        keyForDecrypt = crypto.privateDecrypt(
            {
                key: RSA_PRIVATE_KEY,
                oaepHash: 'sha256',
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
            },
            wrappedKeyBuf
        );
        dynamicKeyState.keyRing.set(activeKeyId, keyForDecrypt);
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', keyForDecrypt, iv);
    decipher.setAuthTag(authTag);
    const decryptedBuf = Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);

    dynamicKeyState.messagesWithCurrentKey += 1;

    const cryptoProcessMs = Number(process.hrtime.bigint() - cryptoStart) / 1e6;

    return {
        keyExchange: 'RSA-2048 OAEP (SHA-256) + Dynamic Session Key',
        payloadCipher: 'AES-256-GCM',
        keyId: activeKeyId,
        rotationCount: dynamicKeyState.totalRotations,
        rotatedThisRequest,
        rotationReason,
        messagesInCurrentKey: dynamicKeyState.messagesWithCurrentKey,
        rotationPolicy: {
            intervalMessages,
            intervalSec
        },
        encryptedSessionKeyHex: wrappedKeyHex,
        encryptedSessionKeyBytes: wrappedKeyBuf.length,
        ivHex: iv.toString('hex'),
        authTagHex: authTag.toString('hex'),
        ciphertextHex: encryptedPayload.toString('hex'),
        decryptedMessage: decryptedBuf.toString('utf8'),
        integrityVerified: true,
        cryptoProcessMs: Number(cryptoProcessMs.toFixed(3))
    };
}
// ============================================================================
// Batas Akhir Dynamic Session Key Rotation //
// ============================================================================

app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        message: 'Server Express berjalan dengan baik',
        timestamp: new Date().toISOString()
    });
});

app.post('/api/message', (req, res) => {
    const startHr = process.hrtime.bigint();
    const startCpu = process.cpuUsage();

    const {
        scheme,
        seq,
        message,
        sentAt,
        rotationIntervalMessages,
        rotationIntervalSec,
        forceRotate
    } = req.body || {};summary
    const activeScheme = scheme || 'no-encryption';

    let cryptoResult = null;
    let outputMessage = message ?? '';

    try {
        if (activeScheme === 'aes-256-gcm') {
            // [AES ONLY]
            cryptoResult = encryptDecryptAes256Gcm(message ?? '');
            outputMessage = cryptoResult.decryptedMessage;
        } else if (activeScheme === 'rsa-oaep') {
            // [RSA ONLY]
            cryptoResult = encryptDecryptRsaOaep(message ?? '');
            outputMessage = cryptoResult.decryptedMessage;
        } else if (activeScheme === 'rsa-aes-hybrid') {
            // [GABUNGAN RSA-AES HYBRID]
            cryptoResult = encryptDecryptRsaAesHybrid(message ?? '');
            outputMessage = cryptoResult.decryptedMessage;
        } else if (activeScheme === 'dynamic-rotation') {
            // [DYNAMIC SESSION KEY ROTATION]
            dynamicTotalRequests += 1;
            cryptoResult = encryptDecryptDynamicRotation(message ?? '', {
                rotationIntervalMessages,
                rotationIntervalSec,
                forceRotate
            });
            outputMessage = cryptoResult.decryptedMessage;
        }
    } 
    
    catch (err) {
        return res.status(err.statusCode || 400).json({
            status: 'error',
            scheme: activeScheme,
            seq: seq ?? null,
            error: err.message
        });
    }

    const responsePayload = {
        status: 'received',
        scheme: activeScheme,
        seq: seq ?? null,
        echoMessage: outputMessage,
        crypto: cryptoResult,
        sentAt: sentAt || null,
        receivedAt: new Date().toISOString()
    };

    const rawResp = JSON.stringify(responsePayload);
    const elapsedMs = Number(process.hrtime.bigint() - startHr) / 1e6;
    const cpuDiff = process.cpuUsage(startCpu);
    const cpuServerMs = (cpuDiff.user + cpuDiff.system) / 1000;

    const mem = process.memoryUsage();
    const ramRssMb = mem.rss / (1024 * 1024);
    const ramHeapMb = mem.heapUsed / (1024 * 1024);

    const reqBytes = Buffer.byteLength(JSON.stringify(req.body || {}), 'utf8');
    const respBytes = Buffer.byteLength(rawResp, 'utf8');
    const totalBytes = reqBytes + respBytes;

    res.json({
        ...responsePayload,
        metrics: {
            serverProcessMs: Number(elapsedMs.toFixed(3)),
            cryptoProcessMs: cryptoResult ? cryptoResult.cryptoProcessMs : 0,
            cpuServerMs: Number(cpuServerMs.toFixed(3)),
            ramRssMb: Number(ramRssMb.toFixed(2)),
            ramHeapMb: Number(ramHeapMb.toFixed(2)),
            reqBytes,
            respBytes,
            totalBytes
        }
    });
});

// Khusus Dynamic Session Key Rotation
app.get('/api/session', (req, res) => {
    res.json({
        active: dynamicSessionActive && Boolean(dynamicKeyState.currentSessionKey),
        sessionId: dynamicSessionActive ? dynamicKeyState.currentKeyId : null,
        publicKeyVerified: true,
        keyBits: 2048,
        rotationIntervalSec: dynamicRotationIntervalSec,
        totalRequests: dynamicTotalRequests,
        totalRotations: dynamicKeyState.totalRotations,
        messagesInCurrentKey: dynamicKeyState.messagesWithCurrentKey,
        lastRotationMs: dynamicSessionActive ? dynamicKeyState.currentCreatedAtMs : 0
    });
});

app.post('/api/session', (req, res) => {
    const { action, rotationIntervalSec } = req.body || {};

    if (action === 'end') {
        stopDynamicRotationTimer();
        dynamicSessionActive = false;
        dynamicTotalRequests = 0;
        dynamicKeyState.currentSessionKey = null;
        dynamicKeyState.currentKeyId = null;
        dynamicKeyState.currentEncryptedKeyHex = null;
        dynamicKeyState.currentCreatedAtMs = 0;
        dynamicKeyState.messagesWithCurrentKey = 0;
        dynamicKeyState.totalRotations = 0;
        dynamicKeyState.keyRing.clear();

        return res.json({
            active: false,
            sessionId: null,
            publicKeyVerified: true,
            keyBits: 2048,
            rotationIntervalSec: dynamicRotationIntervalSec,
            totalRequests: 0,
            totalRotations: 0,
            lastRotationMs: 0
        });
    }

    dynamicRotationIntervalSec = Math.max(1, Number(rotationIntervalSec) || 300);
    dynamicSessionActive = true;
    dynamicTotalRequests = 0;
    dynamicKeyState.totalRotations = 0;
    dynamicKeyState.keyRing.clear();
    createNewDynamicSessionKey();
    startDynamicRotationTimer();

    return res.json({
        active: true,
        sessionId: dynamicKeyState.currentKeyId,
        publicKeyVerified: true,
        keyBits: 2048,
        rotationIntervalSec: dynamicRotationIntervalSec,
        totalRequests: 0,
        totalRotations: dynamicKeyState.totalRotations,
        lastRotationMs: dynamicKeyState.currentCreatedAtMs
    });
});
// Penutup kode Khusus Dynamic Session Key Rotation

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server berjalan di port ${PORT}`);
    console.log(`Akses lokal: http://localhost:${PORT}`);

    const interfaces = os.networkInterfaces();

    for (const [name, addresses] of Object.entries(interfaces)) {
        for (const address of addresses || []) {
            if (address.family === "IPv4" && !address.internal) {
                console.log(
                    `Akses dari laptop client (${name}): http://${address.address}:${PORT}`
                );
            }
        }
    }
});