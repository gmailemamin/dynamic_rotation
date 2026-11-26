const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_DIR = path.join(__dirname, '..', 'keys');
const PRIVATE_KEY_PATH = path.join(KEY_DIR, 'dynamic_rotation_private.pem');
const PUBLIC_KEY_PATH = path.join(KEY_DIR, 'dynamic_rotation_public.pem');

const RSA_KEY_SIZE = 2048;
const AES_KEY_LENGTH = 32;
const AES_IV_LENGTH = 12;
const AES_AUTH_TAG_LENGTH = 16;

const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_MESSAGE_BYTES = 1024 * 1024;

const sessions = new Map();

// =====================================================
// 1. RSA KEY MANAGEMENT
// =====================================================

function initializeRSAKeys() {
    if (!fs.existsSync(KEY_DIR)) {
        fs.mkdirSync(KEY_DIR, { recursive: true });
    }

    if (
        !fs.existsSync(PRIVATE_KEY_PATH) ||
        !fs.existsSync(PUBLIC_KEY_PATH)
    ) {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: RSA_KEY_SIZE,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, {
            mode: 0o600
        });

        fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, {
            mode: 0o644
        });

        console.log('[DYNAMIC ROTATION] RSA key pair berhasil dibuat.');
    }
}

function getPrivateKey() {
    initializeRSAKeys();
    return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

function getPublicKeyBase64() {
    initializeRSAKeys();

    const publicKeyPem = fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
    const publicKey = crypto.createPublicKey(publicKeyPem);

    return publicKey.export({
        type: 'spki',
        format: 'der'
    }).toString('base64');
}

// =====================================================
// 2. BASE64 VALIDATION
// =====================================================

function decodeBase64(value, fieldName) {
    if (
        typeof value !== 'string' ||
        value.length === 0 ||
        value.length % 4 !== 0 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    ) {
        throw new Error(
            `${fieldName} harus menggunakan format Base64 yang valid.`
        );
    }

    const buffer = Buffer.from(value, 'base64');

    if (buffer.toString('base64') !== value) {
        throw new Error(
            `${fieldName} memiliki format Base64 yang tidak valid.`
        );
    }

    return buffer;
}

// =====================================================
// 3. SESSION VALIDATION
// =====================================================

function getActiveSession(sessionId) {
    if (
        typeof sessionId !== 'string' ||
        sessionId.length === 0
    ) {
        throw new Error('Session ID wajib dikirim.');
    }

    const session = sessions.get(sessionId);

    if (!session) {
        throw new Error(
            'Session tidak ditemukan atau sudah berakhir.'
        );
    }

    if (Date.now() - session.lastActivity > SESSION_TTL_MS) {
        session.key.fill(0);

        if (session.pendingRotation?.key) {
            session.pendingRotation.key.fill(0);
        }

        sessions.delete(sessionId);

        throw new Error('Session telah kedaluwarsa.');
    }

    return session;
}

// =====================================================
// DYNAMIC ROTATION CONDITION
// =====================================================

function isDynamicRotationDue(session, now = Date.now()) {
    const requestLimitReached =
        session.messagesInCurrentKey >=
        session.rotationIntervalMessages;

    const timeLimitReached =
        now - session.lastRotationAt >=
        session.rotationIntervalSec * 1000;

    return requestLimitReached || timeLimitReached;
}

// =====================================================
// 4. GET RSA PUBLIC KEY
// =====================================================

function getDynamicRotationPublicKey() {
    return {
        status: 'ok',
        algorithm: 'RSA-2048-OAEP-SHA256',
        publicKey: getPublicKeyBase64(),
        keyBits: RSA_KEY_SIZE
    };
}

// =====================================================
// 5. ESTABLISH SECURE SESSION
// =====================================================

function establishDynamicSession({
    encryptedSessionKey,
    rotationIntervalMessages,
    rotationIntervalSec
}) {
    if (
        typeof encryptedSessionKey !== 'string' ||
        encryptedSessionKey.length === 0
    ) {
        throw new Error(
            'Encrypted AES Session Key wajib dikirim.'
        );
    }

    const encryptedKeyBuffer = decodeBase64(
        encryptedSessionKey,
        'Encrypted AES Session Key'
    );

    if (encryptedKeyBuffer.length !== RSA_KEY_SIZE / 8) {
        throw new Error(
            'Ukuran encrypted AES key tidak sesuai RSA-2048.'
        );
    }

    const intervalMessages = Number(rotationIntervalMessages);
    const intervalSec = Number(rotationIntervalSec);

    if (
        !Number.isInteger(intervalMessages) ||
        intervalMessages < 1 ||
        intervalMessages > 10000
    ) {
        throw new Error(
            'Konfigurasi batas request tidak valid.'
        );
    }

    if (
        !Number.isInteger(intervalSec) ||
        intervalSec < 1 ||
        intervalSec > 86400
    ) {
        throw new Error(
            'Konfigurasi interval waktu tidak valid.'
        );
    }

    const cryptoStart = process.hrtime.bigint();

    let sessionKey;

    try {
        sessionKey = crypto.privateDecrypt(
            {
                key: getPrivateKey(),
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            encryptedKeyBuffer
        );
    } catch {
        throw new Error(
            'Gagal mendekripsi AES Session Key menggunakan RSA Private Key.'
        );
    }

    const cryptoEnd = process.hrtime.bigint();

    if (sessionKey.length !== AES_KEY_LENGTH) {
        sessionKey.fill(0);

        throw new Error(
            'AES Session Key harus memiliki panjang 32 byte.'
        );
    }

    const sessionId = crypto.randomUUID();
    const now = Date.now();

    sessions.set(sessionId, {
        sessionId,
        key: sessionKey,

        keyVersion: 1,
        lastSeq: 0,

        totalRequests: 0,
        messagesInCurrentKey: 0,
        rotationCount: 0,

        rotationIntervalMessages: intervalMessages,
        rotationIntervalSec: intervalSec,

        createdAt: now,
        lastActivity: now,
        lastRotationAt: now,

        pendingRotation: null,
        lastRotationConfirmation: null
    });

    return {
        sessionId,
        status: 'active',

        algorithm: 'AES-256-GCM',
        keyExchange: 'RSA-2048-OAEP-SHA256',

        keyLength: AES_KEY_LENGTH * 8,
        keyVersion: 1,

        sequence: 0,
        totalRequests: 0,
        rotationCount: 0,

        rotationIntervalMessages: intervalMessages,
        rotationIntervalSec: intervalSec,

        createdAt: new Date(now).toISOString(),

        cryptoProcessMs: Number(
            (Number(cryptoEnd - cryptoStart) / 1e6).toFixed(3)
        )
    };
}

// =====================================================
// 6. AES-256-GCM DECRYPTION
// =====================================================

function decryptAESGCM(
    ciphertext,
    iv,
    authTag,
    sessionKey,
    aad
) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        sessionKey,
        iv,
        {
            authTagLength: AES_AUTH_TAG_LENGTH
        }
    );

    // Autentikasi metadata session dan sequence.
    decipher.setAAD(aad);

    decipher.setAuthTag(authTag);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);
}

// =====================================================
// 7. AES-256-GCM ENCRYPTION
// =====================================================

function encryptAESGCM(
    plaintext,
    sessionKey,
    aad
) {
    // IV acak baru untuk setiap enkripsi.
    const iv = crypto.randomBytes(AES_IV_LENGTH);

    const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        sessionKey,
        iv,
        {
            authTagLength: AES_AUTH_TAG_LENGTH
        }
    );

    // AAD harus sama dengan yang digunakan client.
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return {
        ciphertext,
        iv,
        authTag
    };
}

// =====================================================
// 8. PROCESS ENCRYPTED MESSAGE
// =====================================================

function processDynamicMessage({
    sessionId,
    sequence,
    iv,
    ciphertext,
    authTag
}) {
    const session = getActiveSession(sessionId);

    // Rotasi wajib dilakukan sebelum pesan berikutnya.
    if (isDynamicRotationDue(session)) {
        const error = new Error(
            'Dynamic Session Key Rotation wajib dilakukan sebelum mengirim pesan berikutnya.'
        );

        error.code = 'ROTATION_REQUIRED';
        throw error;
    }

    // -------------------------------------------------
    // A. VALIDASI SEQUENCE NUMBER
    // -------------------------------------------------

    if (
        !Number.isSafeInteger(sequence) ||
        sequence < 1
    ) {
        throw new Error(
            'Sequence number harus berupa integer positif.'
        );
    }

    const expectedSequence = session.lastSeq + 1;

    if (sequence !== expectedSequence) {
        throw new Error(
            `Sequence tidak valid. Diharapkan ${expectedSequence}, diterima ${sequence}.`
        );
    }

    // -------------------------------------------------
    // B. VALIDASI INPUT BASE64
    // -------------------------------------------------

    const ivBuffer = decodeBase64(iv, 'IV');

    const ciphertextBuffer = decodeBase64(
        ciphertext,
        'Ciphertext'
    );

    const authTagBuffer = decodeBase64(
        authTag,
        'Authentication Tag'
    );

    if (ivBuffer.length !== AES_IV_LENGTH) {
        throw new Error(
            'IV AES-GCM harus memiliki panjang 12 byte.'
        );
    }

    if (authTagBuffer.length !== AES_AUTH_TAG_LENGTH) {
        throw new Error(
            'Authentication Tag harus memiliki panjang 16 byte.'
        );
    }

    if (ciphertextBuffer.length > MAX_MESSAGE_BYTES) {
        throw new Error(
            'Ukuran pesan melebihi batas 1 MB.'
        );
    }

    // -------------------------------------------------
    // C. MEMBENTUK ADDITIONAL AUTHENTICATED DATA
    // -------------------------------------------------

    const aad = Buffer.from(
        `${sessionId}:${sequence}:${session.keyVersion}`,
        'utf8'
    );

    const cryptoStart = process.hrtime.bigint();

    let decryptedMessage;
    let encryptedResponse;

    try {
        // ---------------------------------------------
        // D. DEKRIPSI PESAN CLIENT
        // ---------------------------------------------

        decryptedMessage = decryptAESGCM(
            ciphertextBuffer,
            ivBuffer,
            authTagBuffer,
            session.key,
            aad
        );

        // ---------------------------------------------
        // E. ENKRIPSI ULANG RESPONSE SERVER
        // ---------------------------------------------

        encryptedResponse = encryptAESGCM(
            decryptedMessage,
            session.key,
            aad
        );

    } catch {
        throw new Error(
            'Autentikasi AES-GCM gagal. Ciphertext, IV, authentication tag, atau AAD tidak valid.'
        );
    }

    const cryptoEnd = process.hrtime.bigint();

    const cryptoProcessMs = Number(
        (Number(cryptoEnd - cryptoStart) / 1e6).toFixed(3)
    );

    // -------------------------------------------------
    // F. UPDATE SESSION SETELAH BERHASIL
    // -------------------------------------------------

    // Sequence baru disimpan hanya setelah autentikasi berhasil.
    session.lastSeq = sequence;

    session.totalRequests += 1;
    session.messagesInCurrentKey += 1;
    session.lastActivity = Date.now();

    // Bersihkan plaintext dari buffer setelah digunakan.
    decryptedMessage.fill(0);

    // -------------------------------------------------
    // G. RESPONSE
    // -------------------------------------------------

    return {
        status: 'success',
        message: 'Pesan berhasil diverifikasi dan diproses.',

        sessionId: session.sessionId,
        sequence: session.lastSeq,
        keyVersion: session.keyVersion,

        algorithm: 'AES-256-GCM',

        encryptedResponse:
            encryptedResponse.ciphertext.toString('base64'),

        responseIV:
            encryptedResponse.iv.toString('base64'),

        responseAuthTag:
            encryptedResponse.authTag.toString('base64'),

        totalRequests: session.totalRequests,

        cryptoProcessMs
    };
}

// =====================================================
// DYNAMIC SESSION KEY ROTATION
// =====================================================

function rotateDynamicSession({
    sessionId,
    sequence,
    iv,
    ciphertext,
    authTag,
    encryptedNewSessionKey
}) {
    const session = getActiveSession(sessionId);

    // Jika request rotasi sebelumnya sudah diproses tetapi responsnya
    // tidak sampai ke client, kirim ulang acknowledgement yang sama.
    if (session.pendingRotation) {
        const pending = session.pendingRotation;

        if (
            sequence === pending.sequence &&
            encryptedNewSessionKey === pending.encryptedNewSessionKey
        ) {
            return pending.response;
        }

        throw new Error(
            'Rotasi sebelumnya masih menunggu konfirmasi dari client.'
        );
    }

    if (!isDynamicRotationDue(session)) {
        throw new Error(
            'Rotasi belum diperlukan berdasarkan konfigurasi sesi.'
        );
    }

    const expectedSequence = session.lastSeq + 1;

    if (
        !Number.isSafeInteger(sequence) ||
        sequence !== expectedSequence
    ) {
        throw new Error(
            `Sequence rotasi tidak valid. Diharapkan ${expectedSequence}, diterima ${sequence}.`
        );
    }

    const ivBuffer = decodeBase64(iv, 'Rotation IV');
    const ciphertextBuffer = decodeBase64(
        ciphertext,
        'Rotation ciphertext'
    );
    const authTagBuffer = decodeBase64(
        authTag,
        'Rotation authentication tag'
    );
    const encryptedKeyBuffer = decodeBase64(
        encryptedNewSessionKey,
        'Encrypted new AES Session Key'
    );

    if (ivBuffer.length !== AES_IV_LENGTH) {
        throw new Error(
            'Rotation IV harus memiliki panjang 12 byte.'
        );
    }

    if (authTagBuffer.length !== AES_AUTH_TAG_LENGTH) {
        throw new Error(
            'Rotation authentication tag harus memiliki panjang 16 byte.'
        );
    }

    if (ciphertextBuffer.length > 1024) {
        throw new Error(
            'Rotation control payload terlalu besar.'
        );
    }

    if (encryptedKeyBuffer.length !== RSA_KEY_SIZE / 8) {
        throw new Error(
            'Ukuran encrypted AES key tidak sesuai RSA-2048.'
        );
    }

    const oldKeyVersion = session.keyVersion;

    const rotationAAD = Buffer.from(
        `${sessionId}:${sequence}:${oldKeyVersion}:ROTATE:${encryptedNewSessionKey}`,
        'utf8'
    );

    const cryptoStart = process.hrtime.bigint();

    let rotationCommand;
    let newSessionKey;
    let encryptedAcknowledgement;

    try {
        // Autentikasi perintah rotasi menggunakan key lama.
        rotationCommand = decryptAESGCM(
            ciphertextBuffer,
            ivBuffer,
            authTagBuffer,
            session.key,
            rotationAAD
        );

        if (rotationCommand.toString('utf8') !== 'ROTATE') {
            throw new Error(
                'Rotation command tidak valid.'
            );
        }

        // Buka AES Session Key baru menggunakan RSA Private Key.
        newSessionKey = crypto.privateDecrypt(
            {
                key: getPrivateKey(),
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            encryptedKeyBuffer
        );

        if (newSessionKey.length !== AES_KEY_LENGTH) {
            newSessionKey.fill(0);
            newSessionKey = null;

            throw new Error(
                'AES Session Key baru harus memiliki panjang 32 byte.'
            );
        }

        // Siapkan acknowledgement menggunakan key baru.
        const newKeyVersion = oldKeyVersion + 1;

        const acknowledgement = Buffer.from(
            `${sessionId}:${sequence}:${newKeyVersion}:ROTATED`,
            'utf8'
        );

        const acknowledgementAAD = Buffer.from(
            `${sessionId}:${sequence}:${newKeyVersion}:ROTATE_ACK`,
            'utf8'
        );

        encryptedAcknowledgement = encryptAESGCM(
            acknowledgement,
            newSessionKey,
            acknowledgementAAD
        );

        acknowledgement.fill(0);

    } catch (error) {
        if (newSessionKey) {
            newSessionKey.fill(0);
        }

        if (error.message === 'Rotation command tidak valid.') {
            throw error;
        }

        throw new Error(
            'Rotasi gagal. Autentikasi kunci lama atau pertukaran kunci baru tidak valid.'
        );

    } finally {
        if (rotationCommand) {
            rotationCommand.fill(0);
        }
    }

    const cryptoEnd = process.hrtime.bigint();

    const cryptoProcessMs = Number(
        (Number(cryptoEnd - cryptoStart) / 1e6).toFixed(3)
    );

    // Key lama tetap aktif sampai client mengirim konfirmasi
    // yang valid menggunakan key baru.
    const response = {
        status: 'pending',
        message: 'Kunci baru disiapkan. Menunggu konfirmasi client.',

        sessionId,
        sequence,
        keyVersion: oldKeyVersion + 1,

        algorithm: 'AES-256-GCM',
        keyExchange: 'RSA-2048-OAEP-SHA256',

        encryptedAcknowledgement:
            encryptedAcknowledgement.ciphertext.toString('base64'),

        acknowledgementIV:
            encryptedAcknowledgement.iv.toString('base64'),

        acknowledgementAuthTag:
            encryptedAcknowledgement.authTag.toString('base64'),

        cryptoProcessMs
    };

    session.pendingRotation = {
        sequence,
        oldKeyVersion,
        newKeyVersion: oldKeyVersion + 1,
        encryptedNewSessionKey,
        key: newSessionKey,
        response,
        createdAt: Date.now()
    };

    session.lastActivity = Date.now();

    return response;
}

// =====================================================
// CONFIRM DYNAMIC SESSION KEY ROTATION
// =====================================================

function confirmDynamicRotation({
    sessionId,
    sequence,
    keyVersion,
    iv,
    ciphertext,
    authTag
}) {
    const session = getActiveSession(sessionId);

    const ivBuffer = decodeBase64(
        iv,
        'Confirmation IV'
    );

    const ciphertextBuffer = decodeBase64(
        ciphertext,
        'Confirmation ciphertext'
    );

    const authTagBuffer = decodeBase64(
        authTag,
        'Confirmation authentication tag'
    );

    if (
        ivBuffer.length !== AES_IV_LENGTH ||
        authTagBuffer.length !== AES_AUTH_TAG_LENGTH
    ) {
        throw new Error(
            'Format konfirmasi rotasi tidak valid.'
        );
    }

    if (ciphertextBuffer.length > 1024) {
        throw new Error(
            'Confirmation payload terlalu besar.'
        );
    }

    const pending = session.pendingRotation;

    // Konfirmasi ulang setelah commit.
    // Digunakan jika respons commit pertama hilang di jaringan.
    if (
        !pending &&
        session.lastRotationConfirmation &&
        sequence === session.lastRotationConfirmation.sequence &&
        keyVersion === session.lastRotationConfirmation.keyVersion
    ) {
        const aad = Buffer.from(
            `${sessionId}:${sequence}:${keyVersion}:ROTATE_COMMIT`,
            'utf8'
        );

        let confirmation;

        try {
            confirmation = decryptAESGCM(
                ciphertextBuffer,
                ivBuffer,
                authTagBuffer,
                session.key,
                aad
            );

            const expected =
                `COMMIT:${sessionId}:${sequence}:${keyVersion}`;

            if (confirmation.toString('utf8') !== expected) {
                throw new Error(
                    'Konfirmasi rotasi tidak valid.'
                );
            }

            return {
                status: 'success',
                message: 'Rotasi sudah dikonfirmasi sebelumnya.',

                sessionId,
                sequence,
                keyVersion: session.keyVersion,

                totalRequests: session.totalRequests,
                rotationCount: session.rotationCount,
                messagesInCurrentKey: session.messagesInCurrentKey,

                alreadyCommitted: true
            };

        } finally {
            if (confirmation) {
                confirmation.fill(0);
            }
        }
    }

    if (!pending) {
        throw new Error(
            'Tidak ada rotasi yang menunggu konfirmasi.'
        );
    }

    if (
        sequence !== pending.sequence ||
        keyVersion !== pending.newKeyVersion
    ) {
        throw new Error(
            'Sequence atau key version konfirmasi tidak sesuai.'
        );
    }

    const aad = Buffer.from(
        `${sessionId}:${sequence}:${keyVersion}:ROTATE_COMMIT`,
        'utf8'
    );

    let confirmation;

    try {
        confirmation = decryptAESGCM(
            ciphertextBuffer,
            ivBuffer,
            authTagBuffer,
            pending.key,
            aad
        );

        const expected =
            `COMMIT:${sessionId}:${sequence}:${keyVersion}`;

        if (confirmation.toString('utf8') !== expected) {
            throw new Error(
                'Konfirmasi rotasi tidak valid.'
            );
        }

    } finally {
        if (confirmation) {
            confirmation.fill(0);
        }
    }

    // Commit hanya dilakukan setelah client membuktikan
    // kepemilikan key baru melalui autentikasi AES-GCM.
    const oldSessionKey = session.key;

    session.key = pending.key;
    session.keyVersion = pending.newKeyVersion;

    session.lastSeq = sequence;
    session.totalRequests += 1;

    session.messagesInCurrentKey = 0;
    session.rotationCount += 1;

    session.lastRotationAt = Date.now();
    session.lastActivity = Date.now();

    session.lastRotationConfirmation = {
        sequence,
        keyVersion
    };

    session.pendingRotation = null;

    // Hapus key lama setelah commit berhasil.
    oldSessionKey.fill(0);
    return {
        status: 'success',
        message: 'Dynamic Session Key Rotation berhasil dikonfirmasi.',

        sessionId,
        sequence,
        keyVersion: session.keyVersion,

        totalRequests: session.totalRequests,
        messagesInCurrentKey: session.messagesInCurrentKey,
        rotationCount: session.rotationCount,

        lastRotationAt: new Date(
            session.lastRotationAt
        ).toISOString(),

        alreadyCommitted: false
    };
}

// =====================================================
// 9. GET SESSION STATUS
// =====================================================

function getDynamicSessionStatus(sessionId) {
    const session = getActiveSession(sessionId);

    return {
        sessionId: session.sessionId,
        status: 'active',

        keyVersion: session.keyVersion,
        sequence: session.lastSeq,

        totalRequests: session.totalRequests,
        messagesInCurrentKey: session.messagesInCurrentKey,
        rotationCount: session.rotationCount,

        rotationIntervalMessages: session.rotationIntervalMessages,
        rotationIntervalSec: session.rotationIntervalSec,

        createdAt: new Date(
            session.createdAt
        ).toISOString(),

        lastRotationAt: new Date(
            session.lastRotationAt
        ).toISOString(),

        lastActivity: new Date(
            session.lastActivity
        ).toISOString()
    };
}

// =====================================================
// 10. CLOSE SESSION
// =====================================================

function closeDynamicSession(sessionId) {
    const session = sessions.get(sessionId);

    if (!session) {
        throw new Error('Session tidak ditemukan.');
    }

    // Bersihkan AES Session Key dari buffer.
    session.key.fill(0);

    // Bersihkan pending key jika rotasi belum selesai.
    if (session.pendingRotation?.key) {
        session.pendingRotation.key.fill(0);
    }

    sessions.delete(sessionId);

    return {
        sessionId,
        status: 'closed',
        message: 'Secure Session berhasil diakhiri.'
    };
}

// =====================================================
// EXPORT
// =====================================================

module.exports = {
    getDynamicRotationPublicKey,
    establishDynamicSession,
    processDynamicMessage,
    rotateDynamicSession,
    confirmDynamicRotation,
    getDynamicSessionStatus,
    closeDynamicSession
};