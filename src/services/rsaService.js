const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {
    measureCrypto
} = require('../utils/metrics');

// ==========================================
// RSA CONFIGURATION
// ==========================================

const RSA_KEY_SIZE = 2048;
const OAEP_HASH = 'sha256';

const KEY_DIRECTORY = path.join(__dirname, '..', 'keys');

const PRIVATE_KEY_PATH = path.join(
    KEY_DIRECTORY,
    'rsa_private.pem'
);

const PUBLIC_KEY_PATH = path.join(
    KEY_DIRECTORY,
    'rsa_public.pem'
);

// ==========================================
// ERROR CLASS
// ==========================================

class RSAError extends Error {
    constructor(message, statusCode = 400) {
        super(message);
        this.name = 'RSAError';
        this.statusCode = statusCode;
    }
}

// ==========================================
// KEY MANAGEMENT
// ==========================================

function ensureRSAKeyPair() {
    if (
        fs.existsSync(PRIVATE_KEY_PATH) &&
        fs.existsSync(PUBLIC_KEY_PATH)
    ) {
        return;
    }

    fs.mkdirSync(KEY_DIRECTORY, {
        recursive: true
    });

    const { publicKey, privateKey } =
        crypto.generateKeyPairSync('rsa', {
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

    fs.writeFileSync(
        PRIVATE_KEY_PATH,
        privateKey,
        { mode: 0o600 }
    );

    fs.writeFileSync(
        PUBLIC_KEY_PATH,
        publicKey
    );
}

function getPrivateKey() {
    ensureRSAKeyPair();

    return fs.readFileSync(
        PRIVATE_KEY_PATH,
        'utf8'
    );
}

function getPublicKey() {
    ensureRSAKeyPair();

    return fs.readFileSync(
        PUBLIC_KEY_PATH,
        'utf8'
    );
}

// ==========================================
// PUBLIC KEY EXPORT
// ==========================================

function getPublicKeyBase64() {
    const publicKey = crypto.createPublicKey(
        getPublicKey()
    );

    const der = publicKey.export({
        type: 'spki',
        format: 'der'
    });

    return der.toString('base64');
}

// ==========================================
// INPUT VALIDATION
// ==========================================

function decodeBase64(value, fieldName) {
    if (
        typeof value !== 'string' ||
        !value ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
    ) {
        throw new RSAError(
            `${fieldName} tidak memiliki format Base64 yang valid.`
        );
    }

    return Buffer.from(value, 'base64');
}

function importClientPublicKey(publicKeyBase64) {
    const publicKeyDER = decodeBase64(
        publicKeyBase64,
        'Client public key'
    );

    try {
        const publicKey = crypto.createPublicKey({
            key: publicKeyDER,
            format: 'der',
            type: 'spki'
        });

        const details = publicKey.asymmetricKeyDetails;

        if (
            publicKey.asymmetricKeyType !== 'rsa' ||
            details?.modulusLength !== RSA_KEY_SIZE
        ) {
            throw new Error('RSA-2048 key required.');
        }

        return publicKey;

    } catch {
        throw new RSAError(
            'Client public key tidak valid.'
        );
    }
}

// ==========================================
// RSA-OAEP PROCESS
// ==========================================

function processRSA({
    encryptedMessage,
    clientPublicKey
}) {
    const ciphertext = decodeBase64(
        encryptedMessage,
        'Encrypted message'
    );

    const serverPrivateKey = getPrivateKey();

    const clientKey = importClientPublicKey(
        clientPublicKey
    );

    const result = measureCrypto(() => {

        // ==================================
        // DECRYPTION: CLIENT -> SERVER
        // ==================================

        let decryptedBuffer;

        try {
            decryptedBuffer = crypto.privateDecrypt(
                {
                    key: serverPrivateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: OAEP_HASH
                },
                ciphertext
            );

        } catch {
            throw new RSAError(
                'Dekripsi RSA-OAEP gagal. Ciphertext tidak valid atau tidak sesuai dengan private key server.'
            );
        }

        const decryptedMessage =
            decryptedBuffer.toString('utf8');

        // ==================================
        // ENCRYPTION: SERVER -> CLIENT
        // ==================================

        let encryptedResponse;

        try {
            encryptedResponse = crypto.publicEncrypt(
                {
                    key: clientKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: OAEP_HASH
                },
                Buffer.from(decryptedMessage, 'utf8')
            );

        } catch {
            throw new RSAError(
                'Pesan terlalu panjang untuk dienkripsi menggunakan RSA-OAEP.'
            );
        }

        return {
            decryptedMessage,
            encryptedResponse:
                encryptedResponse.toString('base64')
        };
    });

    return {
        method: 'rsa',
        algorithm: 'RSA-2048-OAEP-SHA256',

        decryptedMessage:
            result.result.decryptedMessage,

        encryptedResponse:
            result.result.encryptedResponse,

        cryptoProcessMs:
            result.cryptoProcessMs
    };
}

// ==========================================
// EXPORT
// ==========================================

module.exports = {
    getPublicKeyBase64,
    processRSA,
    RSAError
};
