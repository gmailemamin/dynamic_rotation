'use strict';

/*
   Implementasi:
   1. Mengambil RSA Public Key dari backend.
   2. Membuat AES-256-GCM Session Key di browser.
   3. Mengenkripsi AES Session Key menggunakan RSA-OAEP.
   4. Mengirim encrypted AES key ke backend.
   5. Membentuk secure session.
   6. Mengenkripsi pesan menggunakan AES-256-GCM.
   7. Mengirim ciphertext ke backend.
   8. Memvalidasi sequence dan response.
   9. Menjalankan Dynamic Session Key Rotation secara otomatis.
   10. Memverifikasi acknowledgement rotasi.
   11. Menutup secure session.

   Catatan:
   Batch testing belum diimplementasikan.
*/

const SCHEME_ID = 'dynamic-rotation';
const API_BASE = '/api/dynamic-rotation';
const MAX_BATCH_REQUESTS = 10000;

// =========================================================
// 1. DOM ELEMENTS
// =========================================================

const $ = (id) => document.getElementById(id);

const cfgMaxRequestsInput = $('cfgMaxRequests');
const cfgIntervalSecSelect = $('cfgIntervalSec');

const btnStartSession = $('btnStartSession');
const btnEndSession = $('btnEndSession');

const statusPublicKeyEl = $('statusPublicKey');
const statusSessionStateEl = $('statusSessionState');
const statusSessionIdEl = $('statusSessionId');
const statusPublicKeyBitsEl = $('statusPublicKeyBits');

const statCurrentTimeEl = $('statCurrentTime');
const statCurrentDateEl = $('statCurrentDate');
const statTotalRequestsEl = $('statTotalRequests');
const statRotationCountEl = $('statRotationCount');
const statRotationThresholdEl = $('statRotationThreshold');
const statIntervalLabelEl = $('statIntervalLabel');
const statSinceLastRotationEl = $('statSinceLastRotation');
const statUntilNextRotationEl = $('statUntilNextRotation');
const statLastRotationClockEl = $('statLastRotationClock');

const manualForm = $('manualForm');
const manualMessageInput = $('manualMessage');
const forceRotateCheckInput = $('forceRotateCheck');
const btnManualSend = $('btnManualSend');

const rotSessionBoxEl = $('rotSessionBox');
const rotIvTagBoxEl = $('rotIvTagBox');
const rotCipherBoxEl = $('rotCipherBox');
const rotDecryptedBoxEl = $('rotDecryptedBox');

const manualStatusEl = $('manualStatus');
const manualTimingEl = $('manualTiming');
const manualSummaryLineEl = $('manualSummaryLine');

const batchForm = $('batchForm');
const batchPresetSelect = $('batchPreset');
const batchCountInput = $('batchCount');
const batchPrefixInput = $('batchPrefix');
const btnBatchStart = $('btnBatchStart');

const batchStatusTextEl = $('batchStatusText');
const progressTextEl = $('progressText');
const progressFillEl = $('progressFill');
const batchTableBodyEl = $('batchTableBody');

const recapTotalReqEl = $('recapTotalReq');
const recapSuccessCountEl = $('recapSuccessCount');
const recapFailedCountEl = $('recapFailedCount');

const recapAvgRespEl = $('recapAvgResp');
const recapMinRespEl = $('recapMinResp');
const recapMaxRespEl = $('recapMaxResp');

const recapTotalTimeEl = $('recapTotalTime');
const recapRpsEl = $('recapRps');
const recapSuccessRateEl = $('recapSuccessRate');

const recapAvgLatEl = $('recapAvgLat');
const recapAvgTputEl = $('recapAvgTput');
const recapTotalBytesEl = $('recapTotalBytes');

const recapAvgCpuEl = $('recapAvgCpu');
const recapAvgRssEl = $('recapAvgRss');
const recapAvgHeapEl = $('recapAvgHeap');

const recapFooterStatusEl = $('recapFooterStatus');
const exportInfoEl = $('exportInfo');
const btnExportCsv = $('btnExportCsv');

// =========================================================
// 2. SESSION STATE
// =========================================================

let clientSessionKey = null;

// RSA Public Key untuk proses Dynamic Rotation.
let serverRsaPublicKey = null;

// Mencegah dua request berjalan bersamaan.
let isProcessingRequest = false;

// Menyimpan waktu rotasi terakhir dari client.
let lastRotationTime = 0;

let sessionStats = {
    active: false,
    sessionId: null,
    totalRequests: 0,
    rotationCount: 0,
    lastRotationMs: 0,
    startedAtMs: 0,
    keyVersion: 1,
    lastSequence: 0
};

let batchRecords = [];
let lastBatchElapsedMs = 0;

// =========================================================
// 3. GENERAL HELPER
// =========================================================

function setText(element, value) {
    if (element) {
        element.textContent = String(value);
    }
}

function sanitizePositiveInt(
    rawValue,
    fallback,
    max = MAX_BATCH_REQUESTS
) {
    const cleaned = String(rawValue ?? '').replace(/[^\d]/g, '');
    const number = Number(cleaned);

    if (!Number.isFinite(number) || number <= 0) {
        return fallback;
    }

    return Math.max(1, Math.min(max, Math.floor(number)));
}

function getRotationThreshold() {
    const value = sanitizePositiveInt(
        cfgMaxRequestsInput?.value,
        100,
        10000
    );

    if (cfgMaxRequestsInput) {
        cfgMaxRequestsInput.value = String(value);
    }

    return value;
}

function getRotationIntervalSec() {
    const value = Number(cfgIntervalSecSelect?.value);

    if (!Number.isFinite(value) || value <= 0) {
        return 300;
    }

    return Math.floor(value);
}

function formatIntervalText(seconds) {
    if (seconds % 60 === 0) {
        return `${seconds / 60} menit`;
    }

    return `${seconds} detik`;
}

function formatClockDot(date) {
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    return `${hours}.${minutes}.${seconds}`;
}

function formatDurationHms(totalSeconds) {
    const seconds = Math.max(0, Math.floor(totalSeconds));

    const hours = String(
        Math.floor(seconds / 3600)
    ).padStart(2, '0');

    const minutes = String(
        Math.floor((seconds % 3600) / 60)
    ).padStart(2, '0');

    const remainingSeconds = String(
        seconds % 60
    ).padStart(2, '0');

    return `${hours}:${minutes}:${remainingSeconds}`;
}

// =========================================================
// 4. BASE64 HELPER
// =========================================================

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

// =========================================================
// AES-256-GCM CLIENT ENCRYPTION / DECRYPTION
// =========================================================

const AES_GCM_IV_LENGTH = 12;
const AES_GCM_TAG_LENGTH = 16;

// ---------------------------------------------------------
// ENCRYPT MESSAGE
// ---------------------------------------------------------

async function encryptClientMessage(
    message,
    sequence,
    keyVersion
) {
    if (!clientSessionKey) {
        throw new Error('AES Session Key tidak tersedia.');
    }

    const iv = crypto.getRandomValues(
        new Uint8Array(AES_GCM_IV_LENGTH)
    );

    const plaintext = new TextEncoder().encode(message);

    // AAD harus identik dengan yang dibuat backend.
    const aad = new TextEncoder().encode(
        `${sessionStats.sessionId}:${sequence}:${keyVersion}`
    );

    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            additionalData: aad,
            tagLength: 128
        },
        clientSessionKey,
        plaintext
    );

    // Web Crypto menghasilkan ciphertext + authentication tag.
    const encryptedBytes = new Uint8Array(encryptedBuffer);

    const ciphertext = encryptedBytes.slice(
        0,
        encryptedBytes.length - AES_GCM_TAG_LENGTH
    );

    const authTag = encryptedBytes.slice(
        encryptedBytes.length - AES_GCM_TAG_LENGTH
    );

    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(ciphertext),
        authTag: arrayBufferToBase64(authTag)
    };
}

// ---------------------------------------------------------
// DECRYPT SERVER RESPONSE
// ---------------------------------------------------------

async function decryptServerResponse({
    ciphertext,
    iv,
    authTag,
    sequence,
    keyVersion
}) {
    if (!clientSessionKey) {
        throw new Error('AES Session Key tidak tersedia.');
    }

    const ciphertextBytes = new Uint8Array(
        base64ToArrayBuffer(ciphertext)
    );

    const authTagBytes = new Uint8Array(
        base64ToArrayBuffer(authTag)
    );

    const ivBytes = new Uint8Array(
        base64ToArrayBuffer(iv)
    );

    if (ivBytes.length !== AES_GCM_IV_LENGTH) {
        throw new Error('Response IV tidak valid.');
    }

    if (authTagBytes.length !== AES_GCM_TAG_LENGTH) {
        throw new Error('Response authentication tag tidak valid.');
    }

    const aad = new TextEncoder().encode(
        `${sessionStats.sessionId}:${sequence}:${keyVersion}`
    );

    const encryptedResponse = new Uint8Array(
        ciphertextBytes.length + authTagBytes.length
    );

    encryptedResponse.set(ciphertextBytes, 0);

    encryptedResponse.set(
        authTagBytes,
        ciphertextBytes.length
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: ivBytes,
            additionalData: aad,
            tagLength: 128
        },
        clientSessionKey,
        encryptedResponse
    );

    return new TextDecoder('utf-8', {
        fatal: true
    }).decode(decryptedBuffer);
}

// =========================================================
// 5. HTTP RESPONSE HELPER
// =========================================================

async function readJsonResponse(response) {
    const responseText = await response.text();

    let data;

    try {
        data = responseText
            ? JSON.parse(responseText)
            : {};
    } catch {
        throw new Error(
            `Respons server bukan JSON yang valid. HTTP ${response.status}.`
        );
    }

    if (!response.ok) {
        const error = new Error(
            data?.error ||
            data?.message ||
            `Permintaan gagal. HTTP ${response.status}.`
        );

        // Informasi ini diperlukan untuk mendeteksi
        // respons ROTATION_REQUIRED dari backend.
        error.code = data?.code || null;
        error.status = response.status;
        error.payload = data;

        throw error;
    }

    if (data?.status === 'error') {
        const error = new Error(
            data.message || 'Server mengembalikan status error.'
        );

        error.code = data?.code || null;
        error.status = response.status;
        error.payload = data;

        throw error;
    }

    return data;
}

// =========================================================
// 6. SESSION UI
// =========================================================

function applySessionLockUI(isActive) {
    if (btnStartSession) {
        btnStartSession.disabled = isActive;
    }

    if (btnEndSession) {
        btnEndSession.disabled = !isActive;
    }

    // Pengujian manual aktif jika secure session tersedia.
    if (btnManualSend) {
        btnManualSend.disabled = !isActive;

        btnManualSend.textContent = isActive
            ? 'Kirim & Uji AES-256-GCM'
            : 'Aktifkan Sesi Terlebih Dahulu';
    }

    // Batch testing belum diaktifkan karena endpoint
    // dan mekanisme pengukurannya belum divalidasi.
    if (btnBatchStart) {
        btnBatchStart.disabled = true;

        btnBatchStart.textContent =
            'Batch Testing Belum Tersedia';
    }

    // Rotasi dilakukan otomatis berdasarkan respons backend.
    if (forceRotateCheckInput) {
        forceRotateCheckInput.disabled = true;

        forceRotateCheckInput.title =
            'Rotasi kunci dijalankan otomatis berdasarkan batas pesan atau waktu.';
    }

    if (isActive) {
        setText(
            manualStatusEl,
            'Secure session berhasil diaktifkan.'
        );

        setText(
            manualSummaryLineEl,
            'Sesi aktif. Pengujian pesan AES-256-GCM siap dilakukan.'
        );

        setText(
            batchStatusTextEl,
            'Status: Menunggu implementasi batch testing.'
        );

    } else {
        setText(
            manualStatusEl,
            'Menunggu aktivasi sesi'
        );

        if (manualStatusEl) {
            manualStatusEl.className = '';
        }

        setText(
            manualSummaryLineEl,
            'Klik tombol Mulai Sesi untuk membentuk secure session.'
        );

        setText(
            batchStatusTextEl,
            'Status: Sesi belum aktif'
        );
    }
}

// =========================================================
// 7. SESSION STATISTICS
// =========================================================

function renderSessionStatistics() {
    const now = new Date();

    setText(
        statCurrentTimeEl,
        formatClockDot(now)
    );

    setText(
        statCurrentDateEl,
        now.toLocaleDateString('id-ID', {
            weekday: 'long',
            day: 'numeric',
            month: 'long',
            year: 'numeric'
        })
    );

    setText(
        statTotalRequestsEl,
        sessionStats.totalRequests
    );

    setText(
        statRotationCountEl,
        sessionStats.rotationCount
    );

    setText(
        statRotationThresholdEl,
        getRotationThreshold()
    );

    setText(
        statIntervalLabelEl,
        formatIntervalText(getRotationIntervalSec())
    );

    if (!sessionStats.active) {
        setText(statSinceLastRotationEl, '00:00:00');
        setText(statUntilNextRotationEl, 'Belum tersedia');
        setText(statLastRotationClockEl, '-');

        return;
    }

    if (sessionStats.lastRotationMs > 0) {
        const elapsedSeconds = Math.max(
            0,
            (Date.now() - sessionStats.lastRotationMs) / 1000
        );

        setText(
            statSinceLastRotationEl,
            formatDurationHms(elapsedSeconds)
        );

        setText(
            statLastRotationClockEl,
            formatClockDot(
                new Date(sessionStats.lastRotationMs)
            )
        );

    } else {
        setText(statSinceLastRotationEl, '00:00:00');
        setText(statLastRotationClockEl, '-');
    }

    setText(
        statUntilNextRotationEl,
        'Rotasi otomatis aktif berdasarkan batas pesan/waktu'
    );
}

// =========================================================
// 8. UPDATE SESSION STATUS UI
// =========================================================

function updateSessionStatusUI({
    active = false,
    sessionId = null,
    keyBits = 2048,
    totalRequests = 0,
    rotationCount = 0,
    lastRotationMs = 0
} = {}) {
    sessionStats.active = Boolean(active);

    sessionStats.sessionId = active
        ? sessionId
        : null;

    sessionStats.totalRequests =
        Number(totalRequests) || 0;

    sessionStats.rotationCount =
        Number(rotationCount) || 0;

    sessionStats.lastRotationMs =
        Number(lastRotationMs) || 0;

    setText(
        statusPublicKeyEl,
        active
            ? 'Public key diterima'
            : 'Belum mengambil public key'
    );

    setText(
        statusSessionStateEl,
        active
            ? 'Session aktif'
            : 'Sesi belum aktif'
    );

    if (statusSessionStateEl) {
        statusSessionStateEl.style.color = active
            ? '#4ade80'
            : '#f87171';
    }

    setText(
        statusSessionIdEl,
        sessionStats.sessionId || '-'
    );

    setText(
        statusPublicKeyBitsEl,
        `${keyBits} bit`
    );

    applySessionLockUI(active);
    renderSessionStatistics();
}

// =========================================================
// 9. GET RSA PUBLIC KEY
// =========================================================

async function fetchDynamicPublicKey() {
    const response = await fetch(
        `${API_BASE}/public-key`,
        {
            method: 'GET',
            headers: {
                Accept: 'application/json'
            },
            cache: 'no-store'
        }
    );

    const result = await readJsonResponse(response);

    if (!result.publicKey) {
        throw new Error('RSA Public Key tidak ditemukan.');
    }

    if (result.algorithm !== 'RSA-2048-OAEP-SHA256') {
        throw new Error('Algoritma RSA Public Key tidak sesuai.');
    }

    const publicKeyBuffer =
        base64ToArrayBuffer(result.publicKey);

    serverRsaPublicKey =
        await crypto.subtle.importKey(
            'spki',
            publicKeyBuffer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        );

    return result;
}

// =========================================================
// 10. GENERATE AES KEY AND ENCRYPT WITH RSA
// =========================================================

async function createAndWrapAesSessionKey(publicKeyBase64) {
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error(
            'Web Crypto API tidak tersedia. Gunakan localhost atau HTTPS.'
        );
    }

    // Import RSA Public Key.
    const publicKeyBuffer =
        base64ToArrayBuffer(publicKeyBase64);

    const rsaPublicKey =
        await crypto.subtle.importKey(
            'spki',
            publicKeyBuffer,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        );

    // Generate AES-256-GCM Session Key.
    const temporaryAesKey =
        await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );

    const rawAesKey = new Uint8Array(
        await crypto.subtle.exportKey(
            'raw',
            temporaryAesKey
        )
    );

    try {
        // Encrypt AES Session Key menggunakan RSA.
        const encryptedKeyBuffer =
            await crypto.subtle.encrypt(
                {
                    name: 'RSA-OAEP'
                },
                rsaPublicKey,
                rawAesKey
            );

        // Import ulang sebagai non-extractable CryptoKey.
        const clientAesKey =
            await crypto.subtle.importKey(
                'raw',
                rawAesKey,
                {
                    name: 'AES-GCM'
                },
                false,
                ['encrypt', 'decrypt']
            );

        return {
            encryptedSessionKey:
                arrayBufferToBase64(encryptedKeyBuffer),

            clientAesKey
        };

    } finally {
        // Best effort membersihkan buffer raw AES key.
        rawAesKey.fill(0);
    }
}

// =========================================================
// 11. GENERATE NEW SESSION KEY FOR ROTATION
// =========================================================

async function generateNewSessionKey() {
    if (!serverRsaPublicKey) {
        throw new Error('RSA Public Key belum tersedia.');
    }

    const temporaryKey = await crypto.subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256
        },
        true,
        ['encrypt', 'decrypt']
    );

    const rawKey = new Uint8Array(
        await crypto.subtle.exportKey('raw', temporaryKey)
    );

    try {
        const encryptedKey = await crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            serverRsaPublicKey,
            rawKey
        );

        const clientKey = await crypto.subtle.importKey(
            'raw',
            rawKey,
            {
                name: 'AES-GCM'
            },
            false,
            ['encrypt', 'decrypt']
        );

        return {
            clientKey,
            encryptedNewSessionKey:
                arrayBufferToBase64(encryptedKey)
        };

    } finally {
        rawKey.fill(0);
    }
}

// =========================================================
// 12. START SECURE SESSION
// =========================================================

async function startSecureSession() {
    if (sessionStats.active) {
        throw new Error(
            'Sesi masih aktif. Akhiri sesi terlebih dahulu.'
        );
    }

    if (!window.crypto?.subtle) {
        throw new Error(
            'Browser tidak mendukung Web Crypto API.'
        );
    }

    // STEP 1: Mengambil RSA Public Key dari backend.
    const publicKeyData =
        await fetchDynamicPublicKey();

    // STEP 2: Membuat AES Session Key dan mengenkripsinya.
    const {
        encryptedSessionKey,
        clientAesKey
    } = await createAndWrapAesSessionKey(
        publicKeyData.publicKey
    );

    // STEP 3: Mengirim encrypted AES key ke backend.
    const response = await fetch(
        `${API_BASE}/session`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: JSON.stringify({
                encryptedSessionKey,
                rotationIntervalMessages:
                    getRotationThreshold(),
                rotationIntervalSec:
                    getRotationIntervalSec()
            })
        }
    );

    const result =
        await readJsonResponse(response);

    const sessionData = result.data || result;

    if (!sessionData.sessionId) {
        throw new Error(
            'Session ID tidak ditemukan pada respons backend.'
        );
    }

    // STEP 4: Menyimpan AES CryptoKey di memori halaman.
    clientSessionKey = clientAesKey;

    sessionStats.startedAtMs = Date.now();

    sessionStats.keyVersion =
        Number(sessionData.keyVersion) || 1;

    sessionStats.lastSequence =
        Number(sessionData.sequence) || 0;

    // STEP 5: Memperbarui tampilan sesi.
    updateSessionStatusUI({
        active: true,
        sessionId: sessionData.sessionId,
        keyBits: Number(publicKeyData.keyBits) || 2048,
        totalRequests: Number(sessionData.totalRequests) || 0,
        rotationCount: Number(sessionData.rotationCount) || 0,
        lastRotationMs: 0
    });

    setText(
        rotSessionBoxEl,
        `Session ID: ${sessionData.sessionId} | Key Version: ${sessionStats.keyVersion}`
    );

    setText(
        rotIvTagBoxEl,
        'IV: Belum tersedia | Tag: Belum tersedia'
    );

    setText(
        rotCipherBoxEl,
        'Ciphertext belum tersedia'
    );

    setText(
        rotDecryptedBoxEl,
        'Belum ada pesan yang didekripsi'
    );

    setText(
        manualTimingEl,
        '-'
    );

    setText(
        manualSummaryLineEl,
        'Secure session berhasil dibentuk. AES-256 Session Key telah dibuat di browser dan dikirim ke backend dalam bentuk RSA-OAEP ciphertext.'
    );

    return sessionData;
}

// =========================================================
// 13. END SECURE SESSION
// =========================================================

async function endSecureSession() {
    if (
        !sessionStats.active ||
        !sessionStats.sessionId
    ) {
        throw new Error(
            'Tidak ada secure session yang aktif.'
        );
    }

    const response = await fetch(
        `${API_BASE}/session/close`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: JSON.stringify({
                sessionId: sessionStats.sessionId
            })
        }
    );

    const result =
        await readJsonResponse(response);

    /*
     * Menghapus referensi AES CryptoKey dari halaman.
     * Ini tidak menjamin seluruh salinan memori terhapus.
     */

    clientSessionKey = null;

    sessionStats.startedAtMs = 0;
    sessionStats.keyVersion = 1;
    sessionStats.lastSequence = 0;

    lastRotationTime = 0;
    isProcessingRequest = false;

    updateSessionStatusUI({
        active: false,
        sessionId: null,
        keyBits: 2048,
        totalRequests: 0,
        rotationCount: 0,
        lastRotationMs: 0
    });

    setText(
        rotSessionBoxEl,
        'Key ID: - | Rotasi: - | Pesan pada Kunci: -'
    );

    setText(
        rotIvTagBoxEl,
        'IV: - | Tag: -'
    );

    setText(
        rotCipherBoxEl,
        '-'
    );

    setText(
        rotDecryptedBoxEl,
        '-'
    );

    setText(
        manualTimingEl,
        '-'
    );

    setText(
        manualSummaryLineEl,
        result.message || 'Secure session berhasil ditutup.'
    );

    return result;
}

// =========================================================
// 14. SEND ENCRYPTED MESSAGE
// POST /api/dynamic-rotation/message
// =========================================================

async function sendDynamicMessageOnce(message) {
    if (!sessionStats.active || !sessionStats.sessionId) {
        throw new Error('Secure Session belum aktif.');
    }

    if (!clientSessionKey) {
        throw new Error('AES Session Key tidak tersedia.');
    }

    if (!message || !message.trim()) {
        throw new Error('Pesan tidak boleh kosong.');
    }

    // Sequence berikutnya.
    const sequence = sessionStats.lastSequence + 1;

    const keyVersion = sessionStats.keyVersion;
    const sessionId = sessionStats.sessionId;

    const encoder = new TextEncoder();

    // 1. Enkripsi pesan di browser.
    const encryptionStart = performance.now();

    const encryptedRequest = await encryptClientMessage(
        message,
        sequence,
        keyVersion
    );

    const encryptionEnd = performance.now();

    const clientEncryptionMs =
        encryptionEnd - encryptionStart;

    // 2. Siapkan request.
    const requestBody = {
        sessionId,
        sequence,
        iv: encryptedRequest.iv,
        ciphertext: encryptedRequest.ciphertext,
        authTag: encryptedRequest.authTag
    };

    const requestJson = JSON.stringify(requestBody);

    const requestBytes = encoder.encode(requestJson).length;

    // 3. Kirim ke backend.
    const requestStart = performance.now();

    const response = await fetch(
        `${API_BASE}/message`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: requestJson
        }
    );

    const result = await readJsonResponse(response);

    const responseEnd = performance.now();

    const responseTimeMs = responseEnd - requestStart;

    const responseData = result.data || result;

    if (
        !responseData.encryptedResponse ||
        !responseData.responseIV ||
        !responseData.responseAuthTag
    ) {
        throw new Error(
            'Respons backend tidak memiliki data enkripsi yang lengkap.'
        );
    }

    // Pastikan backend mengembalikan sequence yang sama.
    if (Number(responseData.sequence) !== sequence) {
        throw new Error(
            'Sequence response tidak sesuai dengan sequence request.'
        );
    }

    if (Number(responseData.keyVersion) !== keyVersion) {
        throw new Error(
            'Key version response tidak sesuai.'
        );
    }

    // 4. Dekripsi response.
    const decryptionStart = performance.now();

    const decryptedResponse = await decryptServerResponse({
        ciphertext: responseData.encryptedResponse,
        iv: responseData.responseIV,
        authTag: responseData.responseAuthTag,
        sequence,
        keyVersion
    });

    const decryptionEnd = performance.now();

    const clientDecryptionMs =
        decryptionEnd - decryptionStart;

    // 5. Verifikasi hasil.
    if (decryptedResponse !== message) {
        throw new Error(
            'Verifikasi gagal: pesan hasil dekripsi berbeda dari pesan awal.'
        );
    }

    // 6. Update sequence hanya setelah verifikasi response.
    sessionStats.lastSequence = sequence;

    sessionStats.totalRequests =
        Number(responseData.totalRequests) ||
        sessionStats.totalRequests + 1;

    renderSessionStatistics();

    const responseBytes = encoder.encode(
        JSON.stringify(result)
    ).length;

    // 7. Tampilkan hasil.
    setText(
        rotSessionBoxEl,
        `Session ID: ${sessionId} | Key Version: ${keyVersion} | Sequence: ${sequence} | Total Request: ${sessionStats.totalRequests}`
    );

    setText(
        rotIvTagBoxEl,
        `Request IV: ${encryptedRequest.iv} | Request Tag: ${encryptedRequest.authTag} | Response IV: ${responseData.responseIV} | Response Tag: ${responseData.responseAuthTag}`
    );

    setText(
        rotCipherBoxEl,
        `Request Ciphertext: ${encryptedRequest.ciphertext}\n\nResponse Ciphertext: ${responseData.encryptedResponse}`
    );

    setText(
        rotDecryptedBoxEl,
        decryptedResponse
    );

    setText(
        manualStatusEl,
        `Berhasil — Sequence ${sequence} Terverifikasi`
    );

    if (manualStatusEl) {
        manualStatusEl.className = 'text-success';
    }

    setText(
        manualTimingEl,
        `Enkripsi Client: ${clientEncryptionMs.toFixed(3)} ms | Backend Crypto: ${Number(responseData.cryptoProcessMs || 0).toFixed(3)} ms | Dekripsi Client: ${clientDecryptionMs.toFixed(3)} ms`
    );

    setText(
        manualSummaryLineEl,
        `Pesan berhasil dikirim dan diverifikasi. Response Time: ${responseTimeMs.toFixed(3)} ms | Request: ${requestBytes} bytes | Response: ${responseBytes} bytes`
    );

    return {
        success: true,
        verified: true,
        sequence,
        responseTimeMs,
        clientEncryptionMs,
        clientDecryptionMs,
        cryptoProcessMs: Number(responseData.cryptoProcessMs || 0),
        requestBytes,
        responseBytes,
        totalBytes: requestBytes + responseBytes
    };
}

// =========================================================
// 14. SEND ENCRYPTED MESSAGE
// POST /api/dynamic-rotation/message
// =========================================================

async function sendDynamicMessageOnce(message) {
    if (!sessionStats.active || !sessionStats.sessionId) {
        throw new Error('Secure Session belum aktif.');
    }

    if (!clientSessionKey) {
        throw new Error('AES Session Key tidak tersedia.');
    }

    if (!message || !message.trim()) {
        throw new Error('Pesan tidak boleh kosong.');
    }

    // Sequence berikutnya.
    const sequence = sessionStats.lastSequence + 1;

    const keyVersion = sessionStats.keyVersion;
    const sessionId = sessionStats.sessionId;

    const encoder = new TextEncoder();

    // 1. Enkripsi pesan di browser.
    const encryptionStart = performance.now();

    const encryptedRequest = await encryptClientMessage(
        message,
        sequence,
        keyVersion
    );

    const encryptionEnd = performance.now();

    const clientEncryptionMs =
        encryptionEnd - encryptionStart;

    // 2. Siapkan request.
    const requestBody = {
        sessionId,
        sequence,
        iv: encryptedRequest.iv,
        ciphertext: encryptedRequest.ciphertext,
        authTag: encryptedRequest.authTag
    };

    const requestJson = JSON.stringify(requestBody);

    const requestBytes = encoder.encode(requestJson).length;

    // 3. Kirim ke backend.
    const requestStart = performance.now();

    const response = await fetch(
        `${API_BASE}/message`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: requestJson
        }
    );

    const result = await readJsonResponse(response);

    const responseEnd = performance.now();

    const responseTimeMs = responseEnd - requestStart;

    const responseData = result.data || result;

    if (
        !responseData.encryptedResponse ||
        !responseData.responseIV ||
        !responseData.responseAuthTag
    ) {
        throw new Error(
            'Respons backend tidak memiliki data enkripsi yang lengkap.'
        );
    }

    // Pastikan backend mengembalikan sequence yang sama.
    if (Number(responseData.sequence) !== sequence) {
        throw new Error(
            'Sequence response tidak sesuai dengan sequence request.'
        );
    }

    if (Number(responseData.keyVersion) !== keyVersion) {
        throw new Error(
            'Key version response tidak sesuai.'
        );
    }

    // 4. Dekripsi response.
    const decryptionStart = performance.now();

    const decryptedResponse = await decryptServerResponse({
        ciphertext: responseData.encryptedResponse,
        iv: responseData.responseIV,
        authTag: responseData.responseAuthTag,
        sequence,
        keyVersion
    });

    const decryptionEnd = performance.now();

    const clientDecryptionMs =
        decryptionEnd - decryptionStart;

    // 5. Verifikasi hasil.
    if (decryptedResponse !== message) {
        throw new Error(
            'Verifikasi gagal: pesan hasil dekripsi berbeda dari pesan awal.'
        );
    }

    // 6. Update sequence hanya setelah verifikasi response.
    sessionStats.lastSequence = sequence;

    sessionStats.totalRequests =
        Number(responseData.totalRequests) ||
        sessionStats.totalRequests + 1;

    renderSessionStatistics();

    const responseBytes = encoder.encode(
        JSON.stringify(result)
    ).length;

    // 7. Tampilkan hasil.
    setText(
        rotSessionBoxEl,
        `Session ID: ${sessionId} | Key Version: ${keyVersion} | Sequence: ${sequence} | Total Request: ${sessionStats.totalRequests}`
    );

    setText(
        rotIvTagBoxEl,
        `Request IV: ${encryptedRequest.iv} | Request Tag: ${encryptedRequest.authTag} | Response IV: ${responseData.responseIV} | Response Tag: ${responseData.responseAuthTag}`
    );

    setText(
        rotCipherBoxEl,
        `Request Ciphertext: ${encryptedRequest.ciphertext}\n\nResponse Ciphertext: ${responseData.encryptedResponse}`
    );

    setText(
        rotDecryptedBoxEl,
        decryptedResponse
    );

    setText(
        manualStatusEl,
        `Berhasil — Sequence ${sequence} Terverifikasi`
    );

    if (manualStatusEl) {
        manualStatusEl.className = 'text-success';
    }

    setText(
        manualTimingEl,
        `Enkripsi Client: ${clientEncryptionMs.toFixed(3)} ms | Backend Crypto: ${Number(responseData.cryptoProcessMs || 0).toFixed(3)} ms | Dekripsi Client: ${clientDecryptionMs.toFixed(3)} ms`
    );

    setText(
        manualSummaryLineEl,
        `Pesan berhasil dikirim dan diverifikasi. Response Time: ${responseTimeMs.toFixed(3)} ms | Request: ${requestBytes} bytes | Response: ${responseBytes} bytes`
    );

    return {
        success: true,
        verified: true,
        sequence,
        responseTimeMs,
        clientEncryptionMs,
        clientDecryptionMs,
        cryptoProcessMs: Number(responseData.cryptoProcessMs || 0),
        requestBytes,
        responseBytes,
        totalBytes: requestBytes + responseBytes
    };
}

// =========================================================
// SEND MESSAGE WITH AUTOMATIC KEY ROTATION
// =========================================================

async function sendDynamicMessage(message) {
    if (isProcessingRequest) {
        throw new Error(
            'Masih ada proses komunikasi yang sedang berjalan.'
        );
    }

    isProcessingRequest = true;

    const overallStart = performance.now();

    try {
        let rotationResult = null;
        let messageResult;

        try {
            // Percobaan pertama mengirim pesan.
            messageResult = await sendDynamicMessageOnce(message);

        } catch (error) {

            // Jika server meminta rotasi, lakukan rotasi otomatis.
            if (
                error.code !== 'ROTATION_REQUIRED' ||
                error.status !== 409
            ) {
                throw error;
            }

            console.log(
                '[DYNAMIC ROTATION] Server meminta rotasi kunci.'
            );

            rotationResult = await requestDynamicRotation();

            console.log(
                '[DYNAMIC ROTATION] Rotasi berhasil:',
                rotationResult
            );

            // Kirim ulang pesan menggunakan key dan sequence baru.
            messageResult = await sendDynamicMessageOnce(message);
        }

        const totalElapsedMs =
            performance.now() - overallStart;

        setText(
            manualTimingEl,
            `Response Time Total: ${totalElapsedMs.toFixed(3)} ms | Waktu Rotasi: ${(rotationResult?.rotationTimeMs || 0).toFixed(3)} ms`
        );

        return {
            ...messageResult,

            // Waktu total mencakup rotasi dan pengiriman ulang.
            responseTimeMs: totalElapsedMs,

            rotationPerformed: Boolean(rotationResult),

            rotationTimeMs:
                rotationResult?.rotationTimeMs || 0,

            requestBytes:
                messageResult.requestBytes +
                (rotationResult?.requestBytes || 0),

            responseBytes:
                messageResult.responseBytes +
                (rotationResult?.responseBytes || 0),

            totalBytes:
                messageResult.totalBytes +
                (rotationResult?.totalBytes || 0)
        };

    } finally {
        isProcessingRequest = false;
    }
}


// =========================================================
// 12. START SESSION BUTTON
// =========================================================

btnStartSession?.addEventListener(
    'click',
    async () => {
        btnStartSession.disabled = true;

        setText(
            statusSessionStateEl,
            'Membentuk secure session...'
        );

        setText(
            manualStatusEl,
            'Mengambil RSA Public Key...'
        );

        if (manualStatusEl) {
            manualStatusEl.className = '';
        }

        try {
            await startSecureSession();

            setText(
                manualStatusEl,
                'Berhasil — Secure Session Aktif'
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-success';
            }

        } catch (error) {
            console.error(
                'Gagal mengaktifkan sesi:',
                error
            );

            clientSessionKey = null;

            updateSessionStatusUI({
                active: false
            });

            setText(
                manualStatusEl,
                `Gagal: ${error.message}`
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-danger';
            }

            setText(
                manualSummaryLineEl,
                error.message
            );

        } finally {
            btnStartSession.disabled =
                sessionStats.active;
        }
    }
);

// =========================================================
// 13. END SESSION BUTTON
// =========================================================

btnEndSession?.addEventListener(
    'click',
    async () => {
        btnEndSession.disabled = true;

        setText(
            statusSessionStateEl,
            'Menutup secure session...'
        );

        try {
            await endSecureSession();

            setText(
                manualStatusEl,
                'Sesi berhasil ditutup'
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-success';
            }

        } catch (error) {
            console.error(
                'Gagal menutup sesi:',
                error
            );

            setText(
                manualStatusEl,
                `Gagal menutup sesi: ${error.message}`
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-danger';
            }

        } finally {
            btnEndSession.disabled =
                !sessionStats.active;
        }
    }
);

// =========================================================
// 14. ROTATION CONFIGURATION EVENTS
// =========================================================

cfgMaxRequestsInput?.addEventListener(
    'input',
    renderSessionStatistics
);

cfgMaxRequestsInput?.addEventListener(
    'change',
    () => {
        getRotationThreshold();
        renderSessionStatistics();
    }
);

cfgIntervalSecSelect?.addEventListener(
    'change',
    renderSessionStatistics
);

// =========================================================
// 15. BATCH INPUT CONFIGURATION
// =========================================================

if (batchPresetSelect && batchCountInput) {
    batchPresetSelect.addEventListener(
        'change',
        () => {
            batchCountInput.value =
                batchPresetSelect.value;
        }
    );

    batchCountInput.addEventListener(
        'input',
        () => {
            const value = String(batchCountInput.value);

            const matchingOption =
                Array.from(batchPresetSelect.options)
                    .find((option) => option.value === value);

            if (matchingOption) {
                batchPresetSelect.value = value;
            }
        }
    );
}

// =========================================================
// 16. MANUAL TESTING
// =========================================================

manualForm?.addEventListener(
    'submit',
    async (event) => {
        event.preventDefault();

        if (!sessionStats.active || !clientSessionKey) {
            setText(
                manualStatusEl,
                'Aktifkan secure session terlebih dahulu.'
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-danger';
            }

            return;
        }

        const message = manualMessageInput?.value || '';

        if (!message.trim()) {
            setText(
                manualStatusEl,
                'Pesan tidak boleh kosong.'
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-danger';
            }

            return;
        }

        btnManualSend.disabled = true;

        btnManualSend.textContent = 'Mengirim Pesan...';

        setText(
            manualStatusEl,
            'Mengenkripsi dan mengirim pesan...'
        );

        if (manualStatusEl) {
            manualStatusEl.className = '';
        }

        try {
            const result = await sendDynamicMessage(message);

            console.log(
                '[DYNAMIC ROTATION] Manual test berhasil:',
                result
            );

        } catch (error) {
            console.error(
                '[DYNAMIC ROTATION] Manual test gagal:',
                error
            );

            setText(
                manualStatusEl,
                `Pengujian gagal: ${error.message}`
            );

            if (manualStatusEl) {
                manualStatusEl.className = 'text-danger';
            }

            setText(
                manualSummaryLineEl,
                error.message
            );

        } finally {
            btnManualSend.disabled = !sessionStats.active;

            btnManualSend.textContent =
                sessionStats.active
                    ? 'Kirim & Uji AES-256-GCM'
                    : 'Aktifkan Sesi Terlebih Dahulu';
        }
    }
);

// =========================================================
// 17. BATCH TESTING
// =========================================================

batchForm?.addEventListener(
    'submit',
    (event) => {
        event.preventDefault();

        if (!sessionStats.active) {
            setText(
                batchStatusTextEl,
                'Status: Aktifkan sesi terlebih dahulu.'
            );

            return;
        }

        setText(
            batchStatusTextEl,
            'Status: Batch testing menunggu endpoint komunikasi Dynamic Rotation.'
        );
    }
);

// =========================================================
// 18. RESET RECAP
// =========================================================

function resetRecap() {
    const defaults = [
        [recapTotalReqEl, '0'],
        [recapSuccessCountEl, '0'],
        [recapFailedCountEl, '0'],

        [recapAvgRespEl, '0.000 ms'],
        [recapMinRespEl, '0.000 ms'],
        [recapMaxRespEl, '0.000 ms'],

        [recapTotalTimeEl, '0.000 ms'],
        [recapRpsEl, '0.000 request/detik'],
        [recapSuccessRateEl, '0.00%'],

        [recapAvgLatEl, '0.000 ms'],
        [recapAvgTputEl, '0.000 KB/s'],
        [recapTotalBytesEl, '0 bytes'],

        [recapAvgCpuEl, '0.000 ms'],
        [recapAvgRssEl, '0.00 MB'],
        [recapAvgHeapEl, '0.00 MB']
    ];

    defaults.forEach(([element, value]) => {
        setText(element, value);
    });

    if (recapFooterStatusEl) {
        recapFooterStatusEl.style.display = 'none';
    }

    setText(
        exportInfoEl,
        'Hasil pengujian belum tersedia untuk diunduh.'
    );

    if (btnExportCsv) {
        btnExportCsv.disabled = true;
    }
}


async function createRotationCommand(
    sequence,
    oldKeyVersion,
    encryptedNewSessionKey
) {
    if (!clientSessionKey) {
        throw new Error('AES Session Key lama tidak tersedia.');
    }

    const iv = crypto.getRandomValues(
        new Uint8Array(AES_GCM_IV_LENGTH)
    );

    const aad = new TextEncoder().encode(
        `${sessionStats.sessionId}:${sequence}:${oldKeyVersion}:ROTATE:${encryptedNewSessionKey}`
    );

    const plaintext = new TextEncoder().encode('ROTATE');

    const encrypted = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            additionalData: aad,
            tagLength: 128
        },
        clientSessionKey,
        plaintext
    );

    const bytes = new Uint8Array(encrypted);

    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(
            bytes.slice(0, bytes.length - AES_GCM_TAG_LENGTH)
        ),
        authTag: arrayBufferToBase64(
            bytes.slice(bytes.length - AES_GCM_TAG_LENGTH)
        )
    };
}

async function verifyRotationAcknowledgement(
    response,
    newSessionKey,
    sequence,
    newKeyVersion
) {
    const ciphertext = new Uint8Array(
        base64ToArrayBuffer(response.encryptedAcknowledgement)
    );

    const iv = new Uint8Array(
        base64ToArrayBuffer(response.acknowledgementIV)
    );

    const authTag = new Uint8Array(
        base64ToArrayBuffer(response.acknowledgementAuthTag)
    );

    if (
        iv.length !== AES_GCM_IV_LENGTH ||
        authTag.length !== AES_GCM_TAG_LENGTH
    ) {
        throw new Error('Format konfirmasi rotasi tidak valid.');
    }

    const combined = new Uint8Array(
        ciphertext.length + authTag.length
    );

    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const aad = new TextEncoder().encode(
        `${sessionStats.sessionId}:${sequence}:${newKeyVersion}:ROTATE_ACK`
    );

    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv,
            additionalData: aad,
            tagLength: 128
        },
        newSessionKey,
        combined
    );

    const acknowledgement = new TextDecoder(
        'utf-8',
        { fatal: true }
    ).decode(decrypted);

    const expected =
        `${sessionStats.sessionId}:${sequence}:${newKeyVersion}:ROTATED`;

    if (acknowledgement !== expected) {
        throw new Error('Konfirmasi rotasi tidak valid.');
    }

    return true;
}

async function createRotationCommit(
    sequence,
    newKeyVersion,
    newSessionKey
) {
    const sessionId = sessionStats.sessionId;

    const plaintext = `COMMIT:${sessionId}:${sequence}:${newKeyVersion}`;

    const additionalData = new TextEncoder().encode(
        `${sessionId}:${sequence}:${newKeyVersion}:ROTATE_COMMIT`
    );

    const iv = crypto.getRandomValues(
        new Uint8Array(AES_GCM_IV_LENGTH)
    );

    const encrypted = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            additionalData: additionalData,
            tagLength: 128
        },
        newSessionKey,
        new TextEncoder().encode(plaintext)
    );

    const encryptedBytes = new Uint8Array(encrypted);

    const tagLength = AES_GCM_TAG_LENGTH;

    const ciphertext = encryptedBytes.slice(
        0,
        encryptedBytes.length - tagLength
    );

    const authTag = encryptedBytes.slice(
        encryptedBytes.length - tagLength
    );

    return {
        iv: arrayBufferToBase64(iv),
        ciphertext: arrayBufferToBase64(ciphertext),
        authTag: arrayBufferToBase64(authTag)
    };
}

// =========================================================
// DYNAMIC SESSION KEY ROTATION
// POST /api/dynamic-rotation/rotate
// =========================================================

async function requestDynamicRotation() {
    if (!sessionStats.active || !sessionStats.sessionId) {
        throw new Error('Tidak ada secure session aktif untuk dirotasi.');
    }

    if (!clientSessionKey) {
        throw new Error('AES Session Key lama tidak tersedia.');
    }

    const rotationStart = performance.now();

    const sequence = sessionStats.lastSequence + 1;
    const oldKeyVersion = sessionStats.keyVersion;

    // 1. Buat AES Session Key baru dan bungkus menggunakan RSA.
    const {
        clientKey: newSessionKey,
        encryptedNewSessionKey
    } = await generateNewSessionKey();

    // 2. Buat perintah ROTATE menggunakan AES key lama.
    const rotationCommand = await createRotationCommand(
        sequence,
        oldKeyVersion,
        encryptedNewSessionKey
    );

    const requestBody = {
        sessionId: sessionStats.sessionId,
        sequence,
        iv: rotationCommand.iv,
        ciphertext: rotationCommand.ciphertext,
        authTag: rotationCommand.authTag,
        encryptedNewSessionKey
    };

    const encoder = new TextEncoder();
    const requestJson = JSON.stringify(requestBody);
    const requestBytes = encoder.encode(requestJson).length;

    // 3. Kirim permintaan rotasi ke backend.
    const response = await fetch(
        `${API_BASE}/rotate`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: requestJson
        }
    );

    const result = await readJsonResponse(response);
    const responseData = result.data || result;

    const responseBytes = encoder.encode(
        JSON.stringify(result)
    ).length;

    // 4. Validasi session, sequence, dan key version.
    const newKeyVersion = Number(responseData.keyVersion);

    if (responseData.sessionId !== sessionStats.sessionId) {
        throw new Error('Session ID pada respons rotasi tidak sesuai.');
    }

    if (Number(responseData.sequence) !== sequence) {
        throw new Error('Sequence pada respons rotasi tidak sesuai.');
    }

    if (newKeyVersion !== oldKeyVersion + 1) {
        throw new Error('Key version baru tidak sesuai.');
    }

    // 5. Verifikasi acknowledgement dengan AES key baru.
    await verifyRotationAcknowledgement(
        responseData,
        newSessionKey,
        sequence,
        newKeyVersion
    );

    // 6. Ganti key client hanya setelah acknowledgement valid.
    clientSessionKey = newSessionKey;

    sessionStats.keyVersion = newKeyVersion;
    sessionStats.lastSequence = sequence;

    sessionStats.totalRequests =
        Number(responseData.totalRequests) ||
        sessionStats.totalRequests + 1;

    sessionStats.rotationCount =
        Number(responseData.rotationCount) ||
        sessionStats.rotationCount + 1;

    sessionStats.lastRotationMs = Date.now();

    lastRotationTime = Date.now();

    renderSessionStatistics();

    const rotationTimeMs =
        performance.now() - rotationStart;

    setText(
        manualStatusEl,
        `Rotasi berhasil — Key Version ${newKeyVersion}`
    );

    if (manualStatusEl) {
        manualStatusEl.className = 'text-success';
    }

    setText(
        manualSummaryLineEl,
        `Dynamic Session Key Rotation berhasil. Sequence: ${sequence} | Key Version: ${newKeyVersion} | Waktu rotasi: ${rotationTimeMs.toFixed(3)} ms`
    );

    return {
        success: true,
        sequence,
        keyVersion: newKeyVersion,
        rotationTimeMs,
        requestBytes,
        responseBytes,
        totalBytes: requestBytes + responseBytes
    };
}

// =========================================================
// 19. EXPORT CSV
// =========================================================

btnExportCsv?.addEventListener(
    'click',
    () => {
        if (!batchRecords.length) {
            return;
        }

        const headers = [
            'Request',
            'Status HTTP',
            'Response Time (ms)',
            'Latency (ms)',
            'Throughput (KB/s)',
            'Total Bytes',
            'Crypto Process (ms)',
            'CPU Server (ms)',
            'RAM RSS (MB)',
            'RAM Heap (MB)'
        ];

        const rows = batchRecords.map((record) => [
            record.seq,
            record.httpStatus,
            record.responseTimeMs,
            record.latencyMs,
            record.throughputKBs,
            record.totalBytes,
            record.cryptoProcessMs,
            record.cpuServerMs,
            record.ramRssMb,
            record.ramHeapMb
        ]);

        const csv = [headers, ...rows]
            .map((row) => {
                return row.map((value) => {
                    const text = String(value ?? '');
                    return `"${text.replace(/"/g, '""')}"`;
                }).join(',');
            })
            .join('\r\n');

        const blob = new Blob(
            ['\uFEFF', csv],
            {
                type: 'text/csv;charset=utf-8;'
            }
        );

        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');

        anchor.href = url;
        anchor.download =
            `hasil-dynamic-rotation-${Date.now()}.csv`;

        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        URL.revokeObjectURL(url);
    }
);

// =========================================================
// 20. INITIALIZATION
// =========================================================

/*
 * Sesi tidak dipulihkan setelah halaman direload.
 *
 * Session ID tidak dapat digunakan untuk memulihkan AES
 * CryptoKey yang sebelumnya hanya tersimpan di memori browser.
 */

updateSessionStatusUI({
    active: false,
    sessionId: null,
    keyBits: 2048,
    totalRequests: 0,
    rotationCount: 0,
    lastRotationMs: 0
});

resetRecap();

if (batchTableBodyEl) {
    batchTableBodyEl.innerHTML =
        '<tr><td colspan="8" class="empty-cell">Belum ada data pengujian batch.</td></tr>';
}

setText(
    statusPublicKeyEl,
    'Public key akan diambil saat tombol Mulai Sesi ditekan'
);

renderSessionStatistics();

window.setInterval(
    renderSessionStatistics,
    1000
);

// =========================================================
// 21. DEBUGGING
// =========================================================

console.log(
    `[${SCHEME_ID}] Dynamic Rotation frontend berhasil dimuat.`
);

// // =========================================================
// // 5. HTTP RESPONSE HELPER
// // =========================================================

// async function readJsonResponse(response) {
//     const responseText = await response.text();

//     let data;

//     try {
//         data = responseText
//             ? JSON.parse(responseText)
//             : {};
//     } catch {
//         throw new Error(
//             `Respons server bukan JSON yang valid. HTTP ${response.status}.`
//         );
//     }

//     if (!response.ok) {
//         const error = new Error(
//             data?.error ||
//             data?.message ||
//             `Permintaan gagal. HTTP ${response.status}.`
//         );

//         error.code = data?.code || null;
//         error.status = response.status;
//         error.payload = data;

//         throw error;
//     }

//     if (data?.status === 'error') {
//         throw new Error(
//             data.message || 'Server mengembalikan status error.'
//         );
//     }

//     return data;
// }

// // =========================================================
// // 6. SESSION UI
// // =========================================================

// function applySessionLockUI(isActive) {
//     if (btnStartSession) {
//         btnStartSession.disabled = isActive;
//     }

//     if (btnEndSession) {
//         btnEndSession.disabled = !isActive;
//     }

//     // Pengujian manual aktif jika secure session tersedia.
//     if (btnManualSend) {
//         btnManualSend.disabled = !isActive;

//         btnManualSend.textContent = isActive
//             ? 'Kirim & Uji AES-256-GCM'
//             : 'Aktifkan Sesi Terlebih Dahulu';
//     }

//     // Batch testing menunggu implementasi dan validasi manual.
//     if (btnBatchStart) {
//         btnBatchStart.disabled = true;

//         btnBatchStart.textContent =
//             'Batch Testing Belum Tersedia';
//     }

//     if (forceRotateCheckInput) {
//         forceRotateCheckInput.disabled = true;
//         forceRotateCheckInput.title =
//             'Rotasi kunci dijalankan otomatis berdasarkan batas pesan atau waktu.';
//     }

//     if (isActive) {
//         setText(
//             manualStatusEl,
//             'Secure session berhasil diaktifkan.'
//         );

//         setText(
//             manualSummaryLineEl,
//             'Sesi aktif. Pengujian pesan AES-256-GCM siap dilakukan.'
//         );

//         setText(
//             batchStatusTextEl,
//             'Status: Menunggu implementasi batch testing.'
//         );

//     } else {
//         setText(
//             manualStatusEl,
//             'Menunggu aktivasi sesi'
//         );

//         if (manualStatusEl) {
//             manualStatusEl.className = '';
//         }

//         setText(
//             manualSummaryLineEl,
//             'Klik tombol Mulai Sesi untuk membentuk secure session.'
//         );

//         setText(
//             batchStatusTextEl,
//             'Status: Sesi belum aktif'
//         );
//     }
// }

// // =========================================================
// // 7. SESSION STATISTICS
// // =========================================================

// function renderSessionStatistics() {
//     const now = new Date();

//     setText(
//         statCurrentTimeEl,
//         formatClockDot(now)
//     );

//     setText(
//         statCurrentDateEl,
//         now.toLocaleDateString('id-ID', {
//             weekday: 'long',
//             day: 'numeric',
//             month: 'long',
//             year: 'numeric'
//         })
//     );

//     setText(
//         statTotalRequestsEl,
//         sessionStats.totalRequests
//     );

//     setText(
//         statRotationCountEl,
//         sessionStats.rotationCount
//     );

//     setText(
//         statRotationThresholdEl,
//         getRotationThreshold()
//     );

//     setText(
//         statIntervalLabelEl,
//         formatIntervalText(getRotationIntervalSec())
//     );

//     /*
//      * Belum ada rotasi aktual.
//      * Countdown tidak boleh dianggap sebagai bukti rotasi.
//      */

//     if (!sessionStats.active) {
//         setText(statSinceLastRotationEl, '00:00:00');
//         setText(statUntilNextRotationEl, 'Belum tersedia');
//         setText(statLastRotationClockEl, '-');

//         return;
//     }

//     if (sessionStats.lastRotationMs > 0) {
//         const elapsedSeconds = Math.max(
//             0,
//             (Date.now() - sessionStats.lastRotationMs) / 1000
//         );

//         setText(
//             statSinceLastRotationEl,
//             formatDurationHms(elapsedSeconds)
//         );

//         setText(
//             statLastRotationClockEl,
//             formatClockDot(
//                 new Date(sessionStats.lastRotationMs)
//             )
//         );
//     } else {
//         setText(statSinceLastRotationEl, '00:00:00');
//         setText(statLastRotationClockEl, '-');
//     }

//     setText(
//         statUntilNextRotationEl,
//         'Menunggu implementasi rotasi'
//     );
// }

// function updateSessionStatusUI({
//     active = false,
//     sessionId = null,
//     keyBits = 2048,
//     totalRequests = 0,
//     rotationCount = 0,
//     lastRotationMs = 0
// } = {}) {
//     sessionStats.active = Boolean(active);

//     sessionStats.sessionId = active
//         ? sessionId
//         : null;

//     sessionStats.totalRequests =
//         Number(totalRequests) || 0;

//     sessionStats.rotationCount =
//         Number(rotationCount) || 0;

//     sessionStats.lastRotationMs =
//         Number(lastRotationMs) || 0;

//     setText(
//         statusPublicKeyEl,
//         active
//             ? 'Public key diterima'
//             : 'Belum mengambil public key'
//     );

//     setText(
//         statusSessionStateEl,
//         active
//             ? 'Session aktif'
//             : 'Sesi belum aktif'
//     );

//     if (statusSessionStateEl) {
//         statusSessionStateEl.style.color = active
//             ? '#4ade80'
//             : '#f87171';
//     }

//     setText(
//         statusSessionIdEl,
//         sessionStats.sessionId || '-'
//     );

//     setText(
//         statusPublicKeyBitsEl,
//         `${keyBits} bit`
//     );

//     applySessionLockUI(active);
//     renderSessionStatistics();
// }

// // =========================================================
// // 8. GET RSA PUBLIC KEY
// // =========================================================


// async function fetchDynamicPublicKey() {
//     const response = await fetch(
//         `${API_BASE}/public-key`,
//         {
//             method: 'GET',
//             headers: {
//                 Accept: 'application/json'
//             },
//             cache: 'no-store'
//         }
//     );

//     const result = await readJsonResponse(response);

//     if (!result.publicKey) {
//         throw new Error('RSA Public Key tidak ditemukan.');
//     }

//     if (result.algorithm !== 'RSA-2048-OAEP-SHA256') {
//         throw new Error('Algoritma RSA Public Key tidak sesuai.');
//     }

//     const publicKeyBuffer =
//         base64ToArrayBuffer(result.publicKey);

//     serverRsaPublicKey =
//         await crypto.subtle.importKey(
//             'spki',
//             publicKeyBuffer,
//             {
//                 name: 'RSA-OAEP',
//                 hash: 'SHA-256'
//             },
//             false,
//             ['encrypt']
//         );

//     return result;
// }


// // =========================================================
// // 9. GENERATE AES KEY AND ENCRYPT WITH RSA
// // =========================================================

// async function createAndWrapAesSessionKey(publicKeyBase64) {
//     if (!window.crypto || !window.crypto.subtle) {
//         throw new Error(
//             'Web Crypto API tidak tersedia. Gunakan localhost atau HTTPS.'
//         );
//     }

//     /*
//      * Import RSA Public Key.
//      *
//      * Format backend:
//      * DER / SPKI / Base64
//      */

//     const publicKeyBuffer =
//         base64ToArrayBuffer(publicKeyBase64);

//     const rsaPublicKey =
//         await crypto.subtle.importKey(
//             'spki',
//             publicKeyBuffer,
//             {
//                 name: 'RSA-OAEP',
//                 hash: 'SHA-256'
//             },
//             false,
//             ['encrypt']
//         );

//     /*
//      * Generate AES-256-GCM Session Key.
//      *
//      * Key dibuat extractable sementara agar dapat
//      * diekspor dan dibungkus menggunakan RSA.
//      */

//     const temporaryAesKey =
//         await crypto.subtle.generateKey(
//             {
//                 name: 'AES-GCM',
//                 length: 256
//             },
//             true,
//             ['encrypt', 'decrypt']
//         );

//     const rawAesKey = new Uint8Array(
//         await crypto.subtle.exportKey(
//             'raw',
//             temporaryAesKey
//         )
//     );

//     try {
//         /*
//          * Encrypt AES Session Key menggunakan RSA.
//          */

//         const encryptedKeyBuffer =
//             await crypto.subtle.encrypt(
//                 {
//                     name: 'RSA-OAEP'
//                 },
//                 rsaPublicKey,
//                 rawAesKey
//             );

//         /*
//          * Import ulang sebagai non-extractable CryptoKey.
//          */

//         const clientAesKey =
//             await crypto.subtle.importKey(
//                 'raw',
//                 rawAesKey,
//                 {
//                     name: 'AES-GCM'
//                 },
//                 false,
//                 ['encrypt', 'decrypt']
//             );

//         return {
//             encryptedSessionKey:
//                 arrayBufferToBase64(encryptedKeyBuffer),

//             clientAesKey
//         };

//     } finally {
//         /*
//          * Best effort membersihkan buffer raw AES key.
//          */
//         rawAesKey.fill(0);
//     }
// }


// async function generateNewSessionKey() {
//     if (!serverRsaPublicKey) {
//         throw new Error('RSA Public Key belum tersedia.');
//     }

//     const temporaryKey = await crypto.subtle.generateKey(
//         {
//             name: 'AES-GCM',
//             length: 256
//         },
//         true,
//         ['encrypt', 'decrypt']
//     );

//     const rawKey = new Uint8Array(
//         await crypto.subtle.exportKey('raw', temporaryKey)
//     );

//     try {
//         const encryptedKey = await crypto.subtle.encrypt(
//             {
//                 name: 'RSA-OAEP'
//             },
//             serverRsaPublicKey,
//             rawKey
//         );

//         const clientKey = await crypto.subtle.importKey(
//             'raw',
//             rawKey,
//             {
//                 name: 'AES-GCM'
//             },
//             false,
//             ['encrypt', 'decrypt']
//         );

//         return {
//             clientKey,
//             encryptedNewSessionKey:
//                 arrayBufferToBase64(encryptedKey)
//         };

//     } finally {
//         rawKey.fill(0);
//     }
// }


// // =========================================================
// // 10. START SECURE SESSION
// // =========================================================

// async function startSecureSession() {
//     if (sessionStats.active) {
//         throw new Error(
//             'Sesi masih aktif. Akhiri sesi terlebih dahulu.'
//         );
//     }

//     if (!window.crypto?.subtle) {
//         throw new Error(
//             'Browser tidak mendukung Web Crypto API.'
//         );
//     }

//     /*
//      * STEP 1
//      * Mengambil RSA Public Key dari backend.
//      */

//     const publicKeyData =
//         await fetchDynamicPublicKey();

//     /*
//      * STEP 2
//      * Membuat AES Session Key dan mengenkripsinya.
//      */

//     const {
//         encryptedSessionKey,
//         clientAesKey
//     } = await createAndWrapAesSessionKey(
//         publicKeyData.publicKey
//     );

//     /*
//      * STEP 3
//      * Mengirim encrypted AES key ke backend.
//      */

//     const response = await fetch(
//         `${API_BASE}/session`,
//         {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//                 Accept: 'application/json'
//             },
//             body: JSON.stringify({
//                 encryptedSessionKey,
//                 rotationIntervalMessages:
//                     getRotationThreshold(),
//                 rotationIntervalSec:
//                     getRotationIntervalSec()
//             })
//         }
//     );

//     const result =
//         await readJsonResponse(response);

//     /*
//      * Mendukung format respons:
//      * { status, message, data: { sessionId, ... } }
//      *
//      * maupun:
//      * { sessionId, ... }
//      */

//     const sessionData = result.data || result;

//     if (!sessionData.sessionId) {
//         throw new Error(
//             'Session ID tidak ditemukan pada respons backend.'
//         );
//     }

//     /*
//      * STEP 4
//      * Menyimpan AES CryptoKey di memori halaman.
//      */

//     clientSessionKey = clientAesKey;

//     sessionStats.startedAtMs = Date.now();

//     sessionStats.keyVersion =
//         Number(sessionData.keyVersion) || 1;
//     sessionStats.lastSequence =
//         Number(sessionData.sequence) || 0;

//     /*
//      * STEP 5
//      * Memperbarui tampilan sesi.
//      */

//     updateSessionStatusUI({
//         active: true,
//         sessionId: sessionData.sessionId,
//         keyBits: Number(publicKeyData.keyBits) || 2048,
//         totalRequests: Number(sessionData.totalRequests) || 0,
//         rotationCount: Number(sessionData.rotationCount) || 0,
//         lastRotationMs: 0
//     });

//     setText(
//         rotSessionBoxEl,
//         `Session ID: ${sessionData.sessionId} | Key Version: ${sessionStats.keyVersion}`
//     );

//     setText(
//         rotIvTagBoxEl,
//         'IV: Belum tersedia | Tag: Belum tersedia'
//     );

//     setText(
//         rotCipherBoxEl,
//         'Ciphertext belum tersedia'
//     );

//     setText(
//         rotDecryptedBoxEl,
//         'Belum ada pesan yang didekripsi'
//     );

//     setText(
//         manualTimingEl,
//         '-'
//     );

//     setText(
//         manualSummaryLineEl,
//         'Secure session berhasil dibentuk. AES-256 Session Key telah dibuat di browser dan dikirim ke backend dalam bentuk RSA-OAEP ciphertext.'
//     );

//     return sessionData;
// }

// // =========================================================
// // 11. END SECURE SESSION
// // =========================================================

// async function endSecureSession() {
//     if (
//         !sessionStats.active ||
//         !sessionStats.sessionId
//     ) {
//         throw new Error(
//             'Tidak ada secure session yang aktif.'
//         );
//     }

//     const response = await fetch(
//         `${API_BASE}/session/close`,
//         {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//                 Accept: 'application/json'
//             },
//             body: JSON.stringify({
//                 sessionId: sessionStats.sessionId
//             })
//         }
//     );

//     const result =
//         await readJsonResponse(response);

//     /*
//      * Menghapus referensi AES CryptoKey dari halaman.
//      * Ini tidak menjamin seluruh salinan memori terhapus.
//      */

//     clientSessionKey = null;

//     sessionStats.startedAtMs = 0;
//     sessionStats.keyVersion = 1;
//     sessionStats.lastSequence = 0;

//     updateSessionStatusUI({
//         active: false,
//         sessionId: null,
//         keyBits: 2048,
//         totalRequests: 0,
//         rotationCount: 0,
//         lastRotationMs: 0
//     });

//     setText(
//         rotSessionBoxEl,
//         'Key ID: - | Rotasi: - | Pesan pada Kunci: -'
//     );

//     setText(
//         rotIvTagBoxEl,
//         'IV: - | Tag: -'
//     );

//     setText(
//         rotCipherBoxEl,
//         '-'
//     );

//     setText(
//         rotDecryptedBoxEl,
//         '-'
//     );

//     setText(
//         manualTimingEl,
//         '-'
//     );

//     setText(
//         manualSummaryLineEl,
//         result.message || 'Secure session berhasil ditutup.'
//     );

//     return result;
// }

// // =========================================================
// // SEND ENCRYPTED MESSAGE
// // POST /api/dynamic-rotation/message
// // =========================================================


// async function sendDynamicMessageOnce(message) {
//     if (!sessionStats.active || !sessionStats.sessionId) {
//         throw new Error('Secure Session belum aktif.');
//     }

//     if (!clientSessionKey) {
//         throw new Error('AES Session Key tidak tersedia.');
//     }

//     if (!message || !message.trim()) {
//         throw new Error('Pesan tidak boleh kosong.');
//     }

//     // Sequence berikutnya.
//     const sequence = sessionStats.lastSequence + 1;

//     const keyVersion = sessionStats.keyVersion;
//     const sessionId = sessionStats.sessionId;

//     const encoder = new TextEncoder();

//     // 1. Enkripsi pesan di browser.
//     const encryptionStart = performance.now();

//     const encryptedRequest = await encryptClientMessage(
//         message,
//         sequence,
//         keyVersion
//     );

//     const encryptionEnd = performance.now();

//     const clientEncryptionMs =
//         encryptionEnd - encryptionStart;

//     // 2. Siapkan request.
//     const requestBody = {
//         sessionId,
//         sequence,
//         iv: encryptedRequest.iv,
//         ciphertext: encryptedRequest.ciphertext,
//         authTag: encryptedRequest.authTag
//     };

//     const requestJson = JSON.stringify(requestBody);

//     const requestBytes = encoder.encode(requestJson).length;

//     // 3. Kirim ke backend.
//     const requestStart = performance.now();

//     const response = await fetch(
//         `${API_BASE}/message`,
//         {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//                 Accept: 'application/json'
//             },
//             body: requestJson
//         }
//     );

//     const result = await readJsonResponse(response);

//     const responseEnd = performance.now();

//     const responseTimeMs = responseEnd - requestStart;

//     const responseData = result.data || result;

//     if (
//         !responseData.encryptedResponse ||
//         !responseData.responseIV ||
//         !responseData.responseAuthTag
//     ) {
//         throw new Error(
//             'Respons backend tidak memiliki data enkripsi yang lengkap.'
//         );
//     }

//     // Pastikan backend mengembalikan sequence yang sama.
//     if (Number(responseData.sequence) !== sequence) {
//         throw new Error(
//             'Sequence response tidak sesuai dengan sequence request.'
//         );
//     }

//     if (Number(responseData.keyVersion) !== keyVersion) {
//         throw new Error(
//             'Key version response tidak sesuai.'
//         );
//     }

//     // 4. Dekripsi response.
//     const decryptionStart = performance.now();

//     const decryptedResponse = await decryptServerResponse({
//         ciphertext: responseData.encryptedResponse,
//         iv: responseData.responseIV,
//         authTag: responseData.responseAuthTag,
//         sequence,
//         keyVersion
//     });

//     const decryptionEnd = performance.now();

//     const clientDecryptionMs =
//         decryptionEnd - decryptionStart;

//     // 5. Verifikasi hasil.
//     if (decryptedResponse !== message) {
//         throw new Error(
//             'Verifikasi gagal: pesan hasil dekripsi berbeda dari pesan awal.'
//         );
//     }

//     // 6. Update sequence hanya setelah verifikasi response.
//     sessionStats.lastSequence = sequence;

//     sessionStats.totalRequests =
//         Number(responseData.totalRequests) ||
//         sessionStats.totalRequests + 1;

//     renderSessionStatistics();

//     const responseBytes = encoder.encode(
//         JSON.stringify(result)
//     ).length;

//     // 7. Tampilkan hasil.
//     setText(
//         rotSessionBoxEl,
//         `Session ID: ${sessionId} | Key Version: ${keyVersion} | Sequence: ${sequence} | Total Request: ${sessionStats.totalRequests}`
//     );

//     setText(
//         rotIvTagBoxEl,
//         `Request IV: ${encryptedRequest.iv} | Request Tag: ${encryptedRequest.authTag} | Response IV: ${responseData.responseIV} | Response Tag: ${responseData.responseAuthTag}`
//     );

//     setText(
//         rotCipherBoxEl,
//         `Request Ciphertext: ${encryptedRequest.ciphertext}\n\nResponse Ciphertext: ${responseData.encryptedResponse}`
//     );

//     setText(
//         rotDecryptedBoxEl,
//         decryptedResponse
//     );

//     setText(
//         manualStatusEl,
//         `Berhasil — Sequence ${sequence} Terverifikasi`
//     );

//     if (manualStatusEl) {
//         manualStatusEl.className = 'text-success';
//     }

//     setText(
//         manualTimingEl,
//         `Enkripsi Client: ${clientEncryptionMs.toFixed(3)} ms | Backend Crypto: ${Number(responseData.cryptoProcessMs || 0).toFixed(3)} ms | Dekripsi Client: ${clientDecryptionMs.toFixed(3)} ms`
//     );

//     setText(
//         manualSummaryLineEl,
//         `Pesan berhasil dikirim dan diverifikasi. Response Time: ${responseTimeMs.toFixed(3)} ms | Request: ${requestBytes} bytes | Response: ${responseBytes} bytes`
//     );

//     return {
//         success: true,
//         verified: true,
//         sequence,
//         responseTimeMs,
//         clientEncryptionMs,
//         clientDecryptionMs,
//         cryptoProcessMs: Number(responseData.cryptoProcessMs || 0),
//         requestBytes,
//         responseBytes,
//         totalBytes: requestBytes + responseBytes
//     };
// }

// // =========================================================
// // SEND MESSAGE WITH AUTOMATIC KEY ROTATION
// // =========================================================

// async function sendDynamicMessage(message) {
//     if (isProcessingRequest) {
//         throw new Error(
//             'Masih ada proses komunikasi yang sedang berjalan.'
//         );
//     }

//     isProcessingRequest = true;

//     const overallStart = performance.now();

//     try {
//         let rotationResult = null;
//         let messageResult;

//         try {
//             // Percobaan pertama mengirim pesan.
//             messageResult = await sendDynamicMessageOnce(message);

//         } catch (error) {

//             // Jika server meminta rotasi, lakukan rotasi otomatis.
//             if (
//                 error.code !== 'ROTATION_REQUIRED' ||
//                 error.status !== 409
//             ) {
//                 throw error;
//             }

//             console.log(
//                 '[DYNAMIC ROTATION] Server meminta rotasi kunci.'
//             );

//             rotationResult = await requestDynamicRotation();

//             console.log(
//                 '[DYNAMIC ROTATION] Rotasi berhasil:',
//                 rotationResult
//             );

//             // Kirim ulang pesan menggunakan key dan sequence baru.
//             messageResult = await sendDynamicMessageOnce(message);
//         }

//         const totalElapsedMs =
//             performance.now() - overallStart;

//         setText(
//             manualTimingEl,
//             `Response Time Total: ${totalElapsedMs.toFixed(3)} ms | Waktu Rotasi: ${(rotationResult?.rotationTimeMs || 0).toFixed(3)} ms`
//         );

//         return {
//             ...messageResult,

//             // Waktu total mencakup rotasi dan pengiriman ulang.
//             responseTimeMs: totalElapsedMs,

//             rotationPerformed: Boolean(rotationResult),

//             rotationTimeMs:
//                 rotationResult?.rotationTimeMs || 0,

//             requestBytes:
//                 messageResult.requestBytes +
//                 (rotationResult?.requestBytes || 0),

//             responseBytes:
//                 messageResult.responseBytes +
//                 (rotationResult?.responseBytes || 0),

//             totalBytes:
//                 messageResult.totalBytes +
//                 (rotationResult?.totalBytes || 0)
//         };

//     } finally {
//         isProcessingRequest = false;
//     }
// }


// // =========================================================
// // 12. START SESSION BUTTON
// // =========================================================

// btnStartSession?.addEventListener(
//     'click',
//     async () => {
//         btnStartSession.disabled = true;

//         setText(
//             statusSessionStateEl,
//             'Membentuk secure session...'
//         );

//         setText(
//             manualStatusEl,
//             'Mengambil RSA Public Key...'
//         );

//         if (manualStatusEl) {
//             manualStatusEl.className = '';
//         }

//         try {
//             await startSecureSession();

//             setText(
//                 manualStatusEl,
//                 'Berhasil — Secure Session Aktif'
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-success';
//             }

//         } catch (error) {
//             console.error(
//                 'Gagal mengaktifkan sesi:',
//                 error
//             );

//             clientSessionKey = null;

//             updateSessionStatusUI({
//                 active: false
//             });

//             setText(
//                 manualStatusEl,
//                 `Gagal: ${error.message}`
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-danger';
//             }

//             setText(
//                 manualSummaryLineEl,
//                 error.message
//             );

//         } finally {
//             btnStartSession.disabled =
//                 sessionStats.active;
//         }
//     }
// );

// // =========================================================
// // 13. END SESSION BUTTON
// // =========================================================

// btnEndSession?.addEventListener(
//     'click',
//     async () => {
//         btnEndSession.disabled = true;

//         setText(
//             statusSessionStateEl,
//             'Menutup secure session...'
//         );

//         try {
//             await endSecureSession();

//             setText(
//                 manualStatusEl,
//                 'Sesi berhasil ditutup'
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-success';
//             }

//         } catch (error) {
//             console.error(
//                 'Gagal menutup sesi:',
//                 error
//             );

//             setText(
//                 manualStatusEl,
//                 `Gagal menutup sesi: ${error.message}`
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-danger';
//             }

//         } finally {
//             btnEndSession.disabled =
//                 !sessionStats.active;
//         }
//     }
// );

// // =========================================================
// // 14. ROTATION CONFIGURATION EVENTS
// // =========================================================

// cfgMaxRequestsInput?.addEventListener(
//     'input',
//     renderSessionStatistics
// );

// cfgMaxRequestsInput?.addEventListener(
//     'change',
//     () => {
//         getRotationThreshold();
//         renderSessionStatistics();
//     }
// );

// cfgIntervalSecSelect?.addEventListener(
//     'change',
//     renderSessionStatistics
// );

// // =========================================================
// // 15. BATCH INPUT CONFIGURATION
// // =========================================================

// if (batchPresetSelect && batchCountInput) {
//     batchPresetSelect.addEventListener(
//         'change',
//         () => {
//             batchCountInput.value =
//                 batchPresetSelect.value;
//         }
//     );

//     batchCountInput.addEventListener(
//         'input',
//         () => {
//             const value = String(batchCountInput.value);

//             const matchingOption =
//                 Array.from(batchPresetSelect.options)
//                     .find((option) => option.value === value);

//             if (matchingOption) {
//                 batchPresetSelect.value = value;
//             }
//         }
//     );
// }

// // =========================================================
// // 16. MANUAL TESTING
// // =========================================================

// manualForm?.addEventListener(
//     'submit',
//     async (event) => {
//         event.preventDefault();

//         if (!sessionStats.active || !clientSessionKey) {
//             setText(
//                 manualStatusEl,
//                 'Aktifkan secure session terlebih dahulu.'
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-danger';
//             }

//             return;
//         }

//         const message = manualMessageInput?.value || '';

//         if (!message.trim()) {
//             setText(
//                 manualStatusEl,
//                 'Pesan tidak boleh kosong.'
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-danger';
//             }

//             return;
//         }

//         btnManualSend.disabled = true;

//         btnManualSend.textContent = 'Mengirim Pesan...';

//         setText(
//             manualStatusEl,
//             'Mengenkripsi dan mengirim pesan...'
//         );

//         if (manualStatusEl) {
//             manualStatusEl.className = '';
//         }

//         try {
//             const result = await sendDynamicMessage(message);

//             console.log(
//                 '[DYNAMIC ROTATION] Manual test berhasil:',
//                 result
//             );

//         } catch (error) {
//             console.error(
//                 '[DYNAMIC ROTATION] Manual test gagal:',
//                 error
//             );

//             setText(
//                 manualStatusEl,
//                 `Pengujian gagal: ${error.message}`
//             );

//             if (manualStatusEl) {
//                 manualStatusEl.className = 'text-danger';
//             }

//             setText(
//                 manualSummaryLineEl,
//                 error.message
//             );

//         } finally {
//             btnManualSend.disabled = !sessionStats.active;

//             btnManualSend.textContent =
//                 sessionStats.active
//                     ? 'Kirim & Uji AES-256-GCM'
//                     : 'Aktifkan Sesi Terlebih Dahulu';
//         }
//     }
// );

// // =========================================================
// // 17. BATCH TESTING
// // =========================================================

// batchForm?.addEventListener(
//     'submit',
//     (event) => {
//         event.preventDefault();

//         if (!sessionStats.active) {
//             setText(
//                 batchStatusTextEl,
//                 'Status: Aktifkan sesi terlebih dahulu.'
//             );

//             return;
//         }

//         setText(
//             batchStatusTextEl,
//             'Status: Batch testing menunggu endpoint komunikasi Dynamic Rotation.'
//         );
//     }
// );

// // =========================================================
// // 18. RESET RECAP
// // =========================================================

// function resetRecap() {
//     const defaults = [
//         [recapTotalReqEl, '0'],
//         [recapSuccessCountEl, '0'],
//         [recapFailedCountEl, '0'],

//         [recapAvgRespEl, '0.000 ms'],
//         [recapMinRespEl, '0.000 ms'],
//         [recapMaxRespEl, '0.000 ms'],

//         [recapTotalTimeEl, '0.000 ms'],
//         [recapRpsEl, '0.000 request/detik'],
//         [recapSuccessRateEl, '0.00%'],

//         [recapAvgLatEl, '0.000 ms'],
//         [recapAvgTputEl, '0.000 KB/s'],
//         [recapTotalBytesEl, '0 bytes'],

//         [recapAvgCpuEl, '0.000 ms'],
//         [recapAvgRssEl, '0.00 MB'],
//         [recapAvgHeapEl, '0.00 MB']
//     ];

//     defaults.forEach(([element, value]) => {
//         setText(element, value);
//     });

//     if (recapFooterStatusEl) {
//         recapFooterStatusEl.style.display = 'none';
//     }

//     setText(
//         exportInfoEl,
//         'Hasil pengujian belum tersedia untuk diunduh.'
//     );

//     if (btnExportCsv) {
//         btnExportCsv.disabled = true;
//     }
// }


// async function createRotationCommand(
//     sequence,
//     oldKeyVersion,
//     encryptedNewSessionKey
// ) {
//     if (!clientSessionKey) {
//         throw new Error('AES Session Key lama tidak tersedia.');
//     }

//     const iv = crypto.getRandomValues(
//         new Uint8Array(AES_GCM_IV_LENGTH)
//     );

//     const aad = new TextEncoder().encode(
//         `${sessionStats.sessionId}:${sequence}:${oldKeyVersion}:ROTATE:${encryptedNewSessionKey}`
//     );

//     const plaintext = new TextEncoder().encode('ROTATE');

//     const encrypted = await crypto.subtle.encrypt(
//         {
//             name: 'AES-GCM',
//             iv,
//             additionalData: aad,
//             tagLength: 128
//         },
//         clientSessionKey,
//         plaintext
//     );

//     const bytes = new Uint8Array(encrypted);

//     return {
//         iv: arrayBufferToBase64(iv),
//         ciphertext: arrayBufferToBase64(
//             bytes.slice(0, bytes.length - AES_GCM_TAG_LENGTH)
//         ),
//         authTag: arrayBufferToBase64(
//             bytes.slice(bytes.length - AES_GCM_TAG_LENGTH)
//         )
//     };
// }

// async function verifyRotationAcknowledgement(
//     response,
//     newSessionKey,
//     sequence,
//     newKeyVersion
// ) {
//     const ciphertext = new Uint8Array(
//         base64ToArrayBuffer(response.encryptedAcknowledgement)
//     );

//     const iv = new Uint8Array(
//         base64ToArrayBuffer(response.acknowledgementIV)
//     );

//     const authTag = new Uint8Array(
//         base64ToArrayBuffer(response.acknowledgementAuthTag)
//     );

//     if (
//         iv.length !== AES_GCM_IV_LENGTH ||
//         authTag.length !== AES_GCM_TAG_LENGTH
//     ) {
//         throw new Error('Format konfirmasi rotasi tidak valid.');
//     }

//     const combined = new Uint8Array(
//         ciphertext.length + authTag.length
//     );

//     combined.set(ciphertext);
//     combined.set(authTag, ciphertext.length);

//     const aad = new TextEncoder().encode(
//         `${sessionStats.sessionId}:${sequence}:${newKeyVersion}:ROTATE_ACK`
//     );

//     const decrypted = await crypto.subtle.decrypt(
//         {
//             name: 'AES-GCM',
//             iv,
//             additionalData: aad,
//             tagLength: 128
//         },
//         newSessionKey,
//         combined
//     );

//     const acknowledgement = new TextDecoder(
//         'utf-8',
//         { fatal: true }
//     ).decode(decrypted);

//     const expected =
//         `${sessionStats.sessionId}:${sequence}:${newKeyVersion}:ROTATED`;

//     if (acknowledgement !== expected) {
//         throw new Error('Konfirmasi rotasi tidak valid.');
//     }

//     return true;
// }

// // =========================================================
// // DYNAMIC SESSION KEY ROTATION
// // POST /api/dynamic-rotation/rotate
// // =========================================================

// async function requestDynamicRotation() {
//     if (!sessionStats.active || !sessionStats.sessionId) {
//         throw new Error('Tidak ada secure session aktif untuk dirotasi.');
//     }

//     if (!clientSessionKey) {
//         throw new Error('AES Session Key lama tidak tersedia.');
//     }

//     const rotationStart = performance.now();

//     const sequence = sessionStats.lastSequence + 1;
//     const oldKeyVersion = sessionStats.keyVersion;

//     // 1. Buat AES Session Key baru dan bungkus menggunakan RSA.
//     const {
//         clientKey: newSessionKey,
//         encryptedNewSessionKey
//     } = await generateNewSessionKey();

//     // 2. Buat perintah ROTATE menggunakan AES key lama.
//     const rotationCommand = await createRotationCommand(
//         sequence,
//         oldKeyVersion,
//         encryptedNewSessionKey
//     );

//     const requestBody = {
//         sessionId: sessionStats.sessionId,
//         sequence,
//         iv: rotationCommand.iv,
//         ciphertext: rotationCommand.ciphertext,
//         authTag: rotationCommand.authTag,
//         encryptedNewSessionKey
//     };

//     const encoder = new TextEncoder();
//     const requestJson = JSON.stringify(requestBody);
//     const requestBytes = encoder.encode(requestJson).length;

//     // 3. Kirim permintaan rotasi ke backend.
//     const response = await fetch(
//         `${API_BASE}/rotate`,
//         {
//             method: 'POST',
//             headers: {
//                 'Content-Type': 'application/json',
//                 Accept: 'application/json'
//             },
//             body: requestJson
//         }
//     );

//     const result = await readJsonResponse(response);
//     const responseData = result.data || result;

//     const responseBytes = encoder.encode(
//         JSON.stringify(result)
//     ).length;

//     // 4. Validasi session, sequence, dan key version.
//     const newKeyVersion = Number(responseData.keyVersion);

//     if (responseData.sessionId !== sessionStats.sessionId) {
//         throw new Error('Session ID pada respons rotasi tidak sesuai.');
//     }

//     if (Number(responseData.sequence) !== sequence) {
//         throw new Error('Sequence pada respons rotasi tidak sesuai.');
//     }

//     if (newKeyVersion !== oldKeyVersion + 1) {
//         throw new Error('Key version baru tidak sesuai.');
//     }

//     // 5. Verifikasi acknowledgement dengan AES key baru.
//     await verifyRotationAcknowledgement(
//         responseData,
//         newSessionKey,
//         sequence,
//         newKeyVersion
//     );

//     // 6. Ganti key client hanya setelah acknowledgement valid.
//     clientSessionKey = newSessionKey;

//     sessionStats.keyVersion = newKeyVersion;
//     sessionStats.lastSequence = sequence;

//     sessionStats.totalRequests =
//         Number(responseData.totalRequests) ||
//         sessionStats.totalRequests + 1;

//     sessionStats.rotationCount =
//         Number(responseData.rotationCount) ||
//         sessionStats.rotationCount + 1;

//     sessionStats.lastRotationMs = Date.now();

//     lastRotationTime = Date.now();

//     renderSessionStatistics();

//     const rotationTimeMs =
//         performance.now() - rotationStart;

//     setText(
//         manualStatusEl,
//         `Rotasi berhasil — Key Version ${newKeyVersion}`
//     );

//     if (manualStatusEl) {
//         manualStatusEl.className = 'text-success';
//     }

//     setText(
//         manualSummaryLineEl,
//         `Dynamic Session Key Rotation berhasil. Sequence: ${sequence} | Key Version: ${newKeyVersion} | Waktu rotasi: ${rotationTimeMs.toFixed(3)} ms`
//     );

//     return {
//         success: true,
//         sequence,
//         keyVersion: newKeyVersion,
//         rotationTimeMs,
//         requestBytes,
//         responseBytes,
//         totalBytes: requestBytes + responseBytes
//     };
// }

// // =========================================================
// // 19. EXPORT CSV
// // =========================================================

// btnExportCsv?.addEventListener(
//     'click',
//     () => {
//         if (!batchRecords.length) {
//             return;
//         }

//         const headers = [
//             'Request',
//             'Status HTTP',
//             'Response Time (ms)',
//             'Latency (ms)',
//             'Throughput (KB/s)',
//             'Total Bytes',
//             'Crypto Process (ms)',
//             'CPU Server (ms)',
//             'RAM RSS (MB)',
//             'RAM Heap (MB)'
//         ];

//         const rows = batchRecords.map((record) => [
//             record.seq,
//             record.httpStatus,
//             record.responseTimeMs,
//             record.latencyMs,
//             record.throughputKBs,
//             record.totalBytes,
//             record.cryptoProcessMs,
//             record.cpuServerMs,
//             record.ramRssMb,
//             record.ramHeapMb
//         ]);

//         const csv = [headers, ...rows]
//             .map((row) => {
//                 return row.map((value) => {
//                     const text = String(value ?? '');
//                     return `"${text.replace(/"/g, '""')}"`;
//                 }).join(',');
//             })
//             .join('\r\n');

//         const blob = new Blob(
//             ['\uFEFF', csv],
//             {
//                 type: 'text/csv;charset=utf-8;'
//             }
//         );

//         const url = URL.createObjectURL(blob);
//         const anchor = document.createElement('a');

//         anchor.href = url;
//         anchor.download =
//             `hasil-dynamic-rotation-${Date.now()}.csv`;

//         document.body.appendChild(anchor);
//         anchor.click();
//         anchor.remove();

//         URL.revokeObjectURL(url);
//     }
// );

// // =========================================================
// // 20. INITIALIZATION
// // =========================================================

// /*
//  * Sesi tidak dipulihkan setelah halaman direload.
//  *
//  * Session ID tidak dapat digunakan untuk memulihkan AES
//  * CryptoKey yang sebelumnya hanya tersimpan di memori browser.
//  */

// updateSessionStatusUI({
//     active: false,
//     sessionId: null,
//     keyBits: 2048,
//     totalRequests: 0,
//     rotationCount: 0,
//     lastRotationMs: 0
// });

// resetRecap();

// if (batchTableBodyEl) {
//     batchTableBodyEl.innerHTML =
//         '<tr><td colspan="8" class="empty-cell">Belum ada data pengujian batch.</td></tr>';
// }

// setText(
//     statusPublicKeyEl,
//     'Public key akan diambil saat tombol Mulai Sesi ditekan'
// );

// renderSessionStatistics();

// window.setInterval(
//     renderSessionStatistics,
//     1000
// );

// // =========================================================
// // 21. DEBUGGING
// // =========================================================

// console.log(
//     `[${SCHEME_ID}] Dynamic Rotation frontend berhasil dimuat.`
// );