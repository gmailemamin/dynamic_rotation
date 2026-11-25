
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ==========================================
// CONFIGURATION
// ==========================================

const RSA_KEY_SIZE = 2048;
const RSA_OAEP_HASH = 'sha256';

const AES_KEY_LENGTH = 32; // 256 bit
const AES_IV_LENGTH = 12;  // 96 bit
const AES_AUTH_TAG_LENGTH = 16; // 128 bit

const SESSION_TTL_MS = 30 * 60 * 1000; // 30 menit

// ==========================================
// RSA KEY STORAGE
// ==========================================

const KEY_DIRECTORY = path.join(__dirname, '..', 'keys');

const PRIVATE_KEY_PATH = path.join(
    KEY_DIRECTORY,
    'hybrid_private.pem'
);

const PUBLIC_KEY_PATH = path.join(
    KEY_DIRECTORY,
    'hybrid_public.pem'
);

if (!fs.existsSync(KEY_DIRECTORY)) {
    fs.mkdirSync(KEY_DIRECTORY, { recursive: true });
}

function ensureRSAKeyPair() {
    const privateExists = fs.existsSync(PRIVATE_KEY_PATH);
    const publicExists = fs.existsSync(PUBLIC_KEY_PATH);

    if (privateExists && publicExists) {
        return;
    }

    // Jika salah satu file hilang, buat pasangan kunci baru.
    const { publicKey, privateKey } = crypto.generateKeyPairSync(
        'rsa',
        {
            modulusLength: RSA_KEY_SIZE,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        }
    );

    fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, {
        mode: 0o600
    });

    fs.writeFileSync(PUBLIC_KEY_PATH, publicKey, {
        mode: 0o644
    });
}

ensureRSAKeyPair();

function getPrivateKey() {
    return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

function getPublicKeyBase64() {
    const publicKeyPem = fs.readFileSync(
        PUBLIC_KEY_PATH,
        'utf8'
    );

    const publicKey = crypto.createPublicKey(publicKeyPem);

    return publicKey.export({
        type: 'spki',
        format: 'der'
    }).toString('base64');
}

// ==========================================
// SESSION STORAGE
// ==========================================

// Penyimpanan sementara session di memori server.
// Session akan hilang ketika server dihentikan/restart.
const sessions = new Map();

class HybridError extends Error {
    constructor(message, statusCode = 400) {
        super(message);
        this.name = 'HybridError';
        this.statusCode = statusCode;
    }
}

// ==========================================
// INPUT VALIDATION
// ==========================================

function decodeBase64(value, fieldName) {
    if (typeof value !== 'string' || !value.length) {
        throw new HybridError(`${fieldName} tidak boleh kosong.`);
    }

    // Base64 standar tanpa whitespace.
    const base64Pattern =
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

    if (!base64Pattern.test(value)) {
        throw new HybridError(`${fieldName} bukan Base64 yang valid.`);
    }

    const buffer = Buffer.from(value, 'base64');

    if (buffer.toString('base64') !== value) {
        throw new HybridError(`${fieldName} memiliki format Base64 tidak valid.`);
    }

    return buffer;
}

// ==========================================
// SESSION CLEANUP
// ==========================================

function cleanupExpiredSessions() {
    const now = Date.now();

    for (const [sessionId, session] of sessions.entries()) {
        if (now - session.lastActivity > SESSION_TTL_MS) {
            // Bersihkan buffer key sebelum menghapus session.
            session.key.fill(0);
            sessions.delete(sessionId);
        }
    }
}

function getSession(sessionId) {
    cleanupExpiredSessions();

    if (typeof sessionId !== 'string' || !sessionId) {
        throw new HybridError('Session ID tidak valid.', 401);
    }

    const session = sessions.get(sessionId);

    if (!session) {
        throw new HybridError(
            'Session tidak ditemukan atau sudah kedaluwarsa.',
            401
        );
    }

    session.lastActivity = Date.now();

    return session;
}

// ==========================================
// 1. GET RSA PUBLIC KEY
// ==========================================

function getHybridPublicKey() {
    return {
        status: 'ok',
        method: 'hybrid',
        algorithm: 'RSA-2048-OAEP-SHA256 + AES-256-GCM',
        publicKey: getPublicKeyBase64()
    };
}

// ==========================================
// 2. ESTABLISH HYBRID SESSION
// ==========================================

function establishSession(encryptedSessionKeyBase64) {
    const encryptedSessionKey = decodeBase64(
        encryptedSessionKeyBase64,
        'Encrypted session key'
    );

    // RSA-2048 menghasilkan ciphertext sepanjang 256 byte.
    if (encryptedSessionKey.length !== RSA_KEY_SIZE / 8) {
        throw new HybridError(
            'Ukuran encrypted session key tidak sesuai RSA-2048.'
        );
    }

    // Dekripsi AES session key menggunakan private key RSA.
  const rsaStart = process.hrtime.bigint();

let sessionKey;

try {
    sessionKey = crypto.privateDecrypt(
        {
            key: getPrivateKey(),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: RSA_OAEP_HASH
        },
        encryptedSessionKey
    );
} catch (error) {
    throw new HybridError(
        'Gagal mendekripsi AES session key menggunakan RSA-OAEP.'
    );
}

const rsaEnd = process.hrtime.bigint();

const rsaProcessMs = Number(
    (Number(rsaEnd - rsaStart) / 1e6).toFixed(3)
);

    // Pastikan panjang AES key adalah 32 byte.
    if (sessionKey.length !== AES_KEY_LENGTH) {
        sessionKey.fill(0);

        throw new HybridError(
            'Panjang AES session key harus 32 byte.'
        );
    }

    // Buat session ID acak.
    const sessionId = crypto.randomUUID();

    sessions.set(sessionId, {
        key: sessionKey,
        createdAt: Date.now(),
        lastActivity: Date.now()
    });

    return {
        sessionId,
        algorithm: 'AES-256-GCM',
        keyLength: AES_KEY_LENGTH,
        sessionTTL: SESSION_TTL_MS,
        cryptoProcessMs: rsaProcessMs
    };
}

// ==========================================
// 3. AES-256-GCM DECRYPTION
// ==========================================

function decryptAESGCM(ciphertext, iv, authTag, sessionKey) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        sessionKey,
        iv,
        {
            authTagLength: AES_AUTH_TAG_LENGTH
        }
    );

    decipher.setAuthTag(authTag);

    return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);
}

// ==========================================
// 4. AES-256-GCM ENCRYPTION
// ==========================================

function encryptAESGCM(plaintext, sessionKey) {
    // IV baru untuk setiap enkripsi.
    const iv = crypto.randomBytes(AES_IV_LENGTH);

    const cipher = crypto.createCipheriv(
        'aes-256-gcm',
        sessionKey,
        iv,
        {
            authTagLength: AES_AUTH_TAG_LENGTH
        }
    );

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

// ==========================================
// 5. PROCESS HYBRID MESSAGE
// ==========================================

function processHybridMessage({
    sessionId,
    encryptedMessage,
    iv,
    authTag
}) {
    const session = getSession(sessionId);

    const ciphertextBuffer = decodeBase64(
        encryptedMessage,
        'Encrypted message'
    );

    const ivBuffer = decodeBase64(iv, 'IV');
    const authTagBuffer = decodeBase64(authTag, 'Auth Tag');

    if (ivBuffer.length !== AES_IV_LENGTH) {
        throw new HybridError(
            'Panjang IV AES-GCM harus 12 byte.'
        );
    }

    if (authTagBuffer.length !== AES_AUTH_TAG_LENGTH) {
        throw new HybridError(
            'Panjang Auth Tag AES-GCM harus 16 byte.'
        );
    }

    const cryptoStart = process.hrtime.bigint();

    let decryptedMessage;

    try {
        // Dekripsi pesan dari client.
        decryptedMessage = decryptAESGCM(
            ciphertextBuffer,
            ivBuffer,
            authTagBuffer,
            session.key
        );
    } catch (error) {
        throw new HybridError(
            'Dekripsi gagal: ciphertext atau authentication tag tidak valid.'
        );
    }

    // Untuk penelitian ini server mengembalikan pesan yang sama
    // sebagai echo response.
    const encryptedResponse = encryptAESGCM(
        decryptedMessage,
        session.key
    );

    const cryptoEnd = process.hrtime.bigint();

    const cryptoProcessMs = Number(
        (Number(cryptoEnd - cryptoStart) / 1e6).toFixed(3)
    );

    return {
        encryptedResponse: encryptedResponse.ciphertext.toString('base64'),
        responseIV: encryptedResponse.iv.toString('base64'),
        responseAuthTag: encryptedResponse.authTag.toString('base64'),

        // Nilai ini hanya untuk proses internal server.
        // Jangan kirim plaintext ini ke client.
        decryptedMessage: decryptedMessage.toString('utf8'),

        verified: true,
        cryptoProcessMs
    };
}

// ==========================================
// 6. TERMINATE SESSION
// ==========================================

function terminateSession(sessionId) {
    const session = sessions.get(sessionId);

    if (!session) {
        return {
            terminated: false
        };
    }

    // Bersihkan AES key dari buffer.
    session.key.fill(0);

    sessions.delete(sessionId);

    return {
        terminated: true
    };
}

// ==========================================
// EXPORTS
// ==========================================

module.exports = {
    getHybridPublicKey,
    getPublicKeyBase64,
    establishSession,
    processHybridMessage,
    terminateSession,
    cleanupExpiredSessions,
    HybridError
};
