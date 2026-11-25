
const SCHEME_ID = 'rsa-aes-hybrid';
const MAX_BATCH_REQUESTS = 10000;
const AES_GCM_IV_LENGTH = 12;
const AES_GCM_TAG_LENGTH = 16;

// ==========================================
// DOM ELEMENTS
// ==========================================

const manualForm = document.getElementById('manualForm');
const manualMessageInput = document.getElementById('manualMessage');
const btnManualSend = document.getElementById('btnManualSend');

const hybridKeyBoxEl = document.getElementById('hybridKeyBox');
const hybridIvTagBoxEl = document.getElementById('hybridIvTagBox');
const hybridCipherBoxEl = document.getElementById('hybridCipherBox');
const manualStatusEl = document.getElementById('manualStatus');
const manualTimingEl = document.getElementById('manualTiming');
const manualSummaryLineEl = document.getElementById('manualSummaryLine');

const batchForm = document.getElementById('batchForm');
const batchPresetSelect = document.getElementById('batchPreset');
const batchCountInput = document.getElementById('batchCount');
const batchPrefixInput = document.getElementById('batchPrefix');
const btnBatchStart = document.getElementById('btnBatchStart');

const batchStatusTextEl = document.getElementById('batchStatusText');
const progressTextEl = document.getElementById('progressText');
const progressFillEl = document.getElementById('progressFill');
const batchTableBodyEl = document.getElementById('batchTableBody');

const recapTotalReqEl = document.getElementById('recapTotalReq');
const recapSuccessCountEl = document.getElementById('recapSuccessCount');
const recapFailedCountEl = document.getElementById('recapFailedCount');

const recapAvgRespEl = document.getElementById('recapAvgResp');
const recapMinRespEl = document.getElementById('recapMinResp');
const recapMaxRespEl = document.getElementById('recapMaxResp');

const recapTotalTimeEl = document.getElementById('recapTotalTime');
const recapRpsEl = document.getElementById('recapRps');
const recapSuccessRateEl = document.getElementById('recapSuccessRate');

const recapAvgLatEl = document.getElementById('recapAvgLat');
const recapAvgTputEl = document.getElementById('recapAvgTput');
const recapTotalBytesEl = document.getElementById('recapTotalBytes');

const recapAvgCpuEl = document.getElementById('recapAvgCpu');
const recapCpuUtilEl = document.getElementById('recapCpuUtil');
const recapAvgRssEl = document.getElementById('recapAvgRss');
const recapAvgHeapEl = document.getElementById('recapAvgHeap');

const recapFooterStatusEl = document.getElementById('recapFooterStatus');
const exportInfoEl = document.getElementById('exportInfo');
const btnExportCsv = document.getElementById('btnExportCsv');

// ==========================================
// SESSION STATE
// ==========================================

let hybridSessionKey = null;
let hybridSessionId = null;
let hybridSessionReady = false;
let requestSequence = 0;

let batchRecords = [];
let lastBatchElapsedMs = 0;
let batchMetrics = null;

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

function bytesToBase64(bytes) {
    let binary = '';

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

function concatenateBytes(first, second) {
    const result = new Uint8Array(first.length + second.length);
    result.set(first, 0);
    result.set(second, first.length);
    return result;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function formatNumber(value, digits = 3) {
    return Number(value || 0).toFixed(digits);
}

function getServerMetrics(data) {
    return data?.metrics || {};
}

// ==========================================
// SERVER BATCH MEASUREMENT
// ==========================================

async function startServerBatchMeasurement() {
    const response = await fetch('/api/measurement/batch/start', {
        method: 'POST'
    });

    const data = await response.json();

    if (!response.ok || !data.batchId) {
        throw new Error(
            data.message || 'Gagal memulai pengukuran CPU batch.'
        );
    }

    return data.batchId;
}

async function endServerBatchMeasurement(batchId) {
    const response = await fetch('/api/measurement/batch/end', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ batchId })
    });

    const data = await response.json();

    if (!response.ok || !data.metrics) {
        throw new Error(
            data.message || 'Gagal mengakhiri pengukuran CPU batch.'
        );
    }

    return data.metrics;
}

// ==========================================
// 1. RSA-AES SESSION ESTABLISHMENT
// ==========================================

async function initializeHybridSession() {
    if (hybridSessionReady) {
        return;
    }

    if (!window.crypto?.subtle) {
        throw new Error(
            'Web Crypto API tidak tersedia. Gunakan localhost atau HTTPS.'
        );
    }

    manualStatusEl.textContent = 'Membentuk secure session...';
    manualStatusEl.className = '';
    manualSummaryLineEl.textContent =
        'Mengambil public key RSA dan membuat AES-256 session key.';

    let rawSessionKey = null;

    try {
        const publicKeyResponse = await fetch('/api/hybrid/public-key');
        const publicKeyData = await publicKeyResponse.json();

        if (!publicKeyResponse.ok || !publicKeyData.publicKey) {
            throw new Error(
                publicKeyData.error || 'Gagal mengambil public key server.'
            );
        }

        const serverPublicKey = await crypto.subtle.importKey(
            'spki',
            base64ToBytes(publicKeyData.publicKey),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            false,
            ['encrypt']
        );

        rawSessionKey = crypto.getRandomValues(new Uint8Array(32));

        hybridSessionKey = await crypto.subtle.importKey(
            'raw',
            rawSessionKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            ['encrypt', 'decrypt']
        );

        const encryptedSessionKey = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            serverPublicKey,
            rawSessionKey
        );

        const encryptedSessionKeyBytes =
            new Uint8Array(encryptedSessionKey);

        const sessionPayload = {
            encryptedSessionKey: bytesToBase64(
                encryptedSessionKeyBytes
            )
        };

        const sessionResponse = await fetch('/api/hybrid/session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(sessionPayload)
        });

        const sessionData = await sessionResponse.json();

        if (!sessionResponse.ok || !sessionData.sessionId) {
            throw new Error(
                sessionData.error || 'Server gagal membentuk session.'
            );
        }

        hybridSessionId = sessionData.sessionId;
        hybridSessionReady = true;

        rawSessionKey.fill(0);
        rawSessionKey = null;

        hybridKeyBoxEl.textContent =
            `[${encryptedSessionKeyBytes.length} bytes] ` +
            bytesToHex(encryptedSessionKeyBytes);

        manualStatusEl.textContent = 'Secure Session Berhasil Dibentuk';
        manualStatusEl.className = 'text-success';

        manualSummaryLineEl.textContent =
            `RSA-OAEP berhasil membungkus AES-256 session key. ` +
            `Session ID: ${hybridSessionId}`;

        console.log('Hybrid session berhasil dibentuk.');
        console.log('Algorithm:', publicKeyData.algorithm);
        console.log('Session ID:', hybridSessionId);
        console.log(
            'Encrypted session key:',
            encryptedSessionKeyBytes.length,
            'bytes'
        );

    } catch (error) {
        if (rawSessionKey) {
            rawSessionKey.fill(0);
        }

        hybridSessionKey = null;
        hybridSessionId = null;
        hybridSessionReady = false;

        manualStatusEl.textContent = 'Gagal Membentuk Session';
        manualStatusEl.className = 'text-danger';
        manualSummaryLineEl.textContent =
            `Pembentukan session gagal: ${error.message}`;

        console.error('Hybrid session error:', error);
        throw error;
    }
}

// ==========================================
// 2. AES-256-GCM ENCRYPTION
// ==========================================

async function encryptHybridMessage(message) {
    if (!hybridSessionReady || !hybridSessionKey) {
        throw new Error('Secure session belum terbentuk.');
    }

    const iv = crypto.getRandomValues(
        new Uint8Array(AES_GCM_IV_LENGTH)
    );

    const plaintext = new TextEncoder().encode(message);

    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            tagLength: 128
        },
        hybridSessionKey,
        plaintext
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);

    const ciphertext = encryptedBytes.slice(
        0,
        encryptedBytes.length - AES_GCM_TAG_LENGTH
    );

    const authTag = encryptedBytes.slice(
        encryptedBytes.length - AES_GCM_TAG_LENGTH
    );

    return {
        ciphertext,
        iv,
        authTag
    };
}

// ==========================================
// 3. AES-256-GCM DECRYPTION
// ==========================================

async function decryptHybridMessage(encryptedMessage, iv, authTag) {
    if (!hybridSessionReady || !hybridSessionKey) {
        throw new Error('Secure session belum terbentuk.');
    }

    const ciphertextBytes = base64ToBytes(encryptedMessage);
    const ivBytes = base64ToBytes(iv);
    const authTagBytes = base64ToBytes(authTag);

    if (ivBytes.length !== AES_GCM_IV_LENGTH) {
        throw new Error('Panjang IV tidak valid.');
    }

    if (authTagBytes.length !== AES_GCM_TAG_LENGTH) {
        throw new Error('Panjang authentication tag tidak valid.');
    }

    const combinedCiphertext = concatenateBytes(
        ciphertextBytes,
        authTagBytes
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: ivBytes,
            tagLength: 128
        },
        hybridSessionKey,
        combinedCiphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
}

// ==========================================
// 4. SEND ENCRYPTED MESSAGE TO SERVER
// ==========================================

async function sendMessageRequest(messageText, seq = null) {
    if (!hybridSessionReady) {
        await initializeHybridSession();
    }

    const currentSequence = seq ?? ++requestSequence;

    // Enkripsi client dilakukan sebelum pengukuran response time.
    const encrypted = await encryptHybridMessage(messageText);

    const payload = {
        sessionId: hybridSessionId,
        seq: currentSequence,
        encryptedMessage: bytesToBase64(encrypted.ciphertext),
        iv: bytesToBase64(encrypted.iv),
        authTag: bytesToBase64(encrypted.authTag),
        sentAt: new Date().toISOString()
    };

    const requestBody = JSON.stringify(payload);
    const requestBytes = new TextEncoder().encode(requestBody).length;

    const t0 = performance.now();

    const response = await fetch('/api/hybrid/message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: requestBody
    });

    const responseText = await response.text();
    const t1 = performance.now();

    const responseBytes = new TextEncoder().encode(responseText).length;
    const responseTimeMs = Number((t1 - t0).toFixed(3));

    let data;

    try {
        data = JSON.parse(responseText);
    } catch {
        throw new Error('Respons server bukan JSON yang valid.');
    }

    if (!response.ok) {
        throw new Error(data?.error || `HTTP ${response.status}`);
    }

    const cryptoData = data?.crypto || {};

    const encryptedResponse =
        cryptoData.encryptedMessage ||
        cryptoData.encryptedResponse;

    const responseIV =
        cryptoData.iv ||
        cryptoData.responseIV;

    const responseAuthTag =
        cryptoData.authTag ||
        cryptoData.responseAuthTag;

    if (!encryptedResponse || !responseIV || !responseAuthTag) {
        throw new Error(
            'Respons server tidak memiliki ciphertext, IV, atau Auth Tag.'
        );
    }

    const serverMetrics = getServerMetrics(data);

    // Dekripsi respons dilakukan setelah response time selesai diukur.
    const decryptedResponse = await decryptHybridMessage(
        encryptedResponse,
        responseIV,
        responseAuthTag
    );

    const verified = decryptedResponse === messageText;

    if (!verified) {
        throw new Error(
            'Verifikasi gagal: pesan hasil dekripsi berbeda dari pesan awal.'
        );
    }

    const totalBytes = requestBytes + responseBytes;

    return {
        seq: currentSequence,
        httpStatus: response.status,
        ok: true,
        verified,
        responseTimeMs,

        serverProcessMs: Number(
            serverMetrics.serverProcessMs ?? 0
        ),

        cryptoProcessMs: Number(
            serverMetrics.cryptoProcessMs ??
            cryptoData.cryptoProcessMs ??
            0
        ),

        requestBytes,
        responseBytes,
        totalBytes,

        cpuServerMs: Number(serverMetrics.cpuServerMs ?? 0),
        ramRssMb: Number(serverMetrics.ramRssMb ?? 0),
        ramHeapMb: Number(serverMetrics.ramHeapMb ?? 0),

        requestIVHex: bytesToHex(encrypted.iv),
        requestAuthTagHex: bytesToHex(encrypted.authTag),
        requestCiphertextHex: bytesToHex(encrypted.ciphertext),

        decryptedResponse,
        encryptedResponse
    };
}


// ==========================================
// 5. MANUAL TESTING
// ==========================================

manualForm.addEventListener('submit', async event => {
    event.preventDefault();

    const message = manualMessageInput.value;

    if (!message.trim()) {
        manualStatusEl.textContent = 'Pesan tidak boleh kosong.';
        manualStatusEl.className = 'text-danger';
        return;
    }

    btnManualSend.disabled = true;
    manualStatusEl.textContent = 'Mengirim pesan terenkripsi...';
    manualStatusEl.className = '';

    try {
        const result = await sendMessageRequest(message);

        manualStatusEl.textContent = result.verified
            ? 'Berhasil (Hybrid Terverifikasi)'
            : 'Verifikasi Gagal';

        manualStatusEl.className = result.verified
            ? 'text-success'
            : 'text-danger';

        manualTimingEl.textContent =
            `${formatNumber(result.responseTimeMs)} ms`;

        hybridIvTagBoxEl.textContent =
            `IV: ${result.requestIVHex}\n` +
            `Tag: ${result.requestAuthTagHex}`;

        hybridCipherBoxEl.textContent =
            `Ciphertext: ${result.requestCiphertextHex}\n\n` +
            `Hasil Dekripsi Client: ${result.decryptedResponse}`;

        manualSummaryLineEl.textContent =
            `Pesan berhasil dienkripsi dan didekripsi. ` +
            `Server Processing: ${formatNumber(result.serverProcessMs)} ms | ` +
            `Crypto Processing: ${formatNumber(result.cryptoProcessMs)} ms | ` +
            `Response: ${formatNumber(result.responseTimeMs)} ms`;

    } catch (error) {
        manualStatusEl.textContent = `Gagal: ${error.message}`;
        manualStatusEl.className = 'text-danger';
        manualSummaryLineEl.textContent = error.message;

        console.error('Manual Hybrid Test:', error);

    } finally {
        btnManualSend.disabled = false;
    }
});

// ==========================================
// 6. BATCH TABLE
// ==========================================

function renderBatchTable(rows) {
    if (!rows.length) {
        batchTableBodyEl.innerHTML =
            '<tr><td colspan="16" class="empty-cell">' +
            'Belum ada data pengujian batch.</td></tr>';
        return;
    }

    batchTableBodyEl.innerHTML = rows.map(row => `
        <tr>
            <td>${row.seq}</td>
            <td>${row.httpStatus}</td>
            <td>${row.ok ? 'Berhasil' : 'Gagal'}</td>
            <td>${formatNumber(row.responseTimeMs)}</td>
            <td>${formatNumber(row.serverProcessMs)}</td>
            <td>${formatNumber(row.cryptoProcessMs)}</td>
            <td>${row.requestBytes}</td>
            <td>${row.responseBytes}</td>
            <td>${row.totalBytes}</td>
            <td>${formatNumber(row.cpuTimeBatchMs, 6)}</td>
            <td>${formatNumber(row.cpuUtilizationBatchPercent, 6)}</td>
            <td>${formatNumber(row.ramRssMb, 2)}</td>
            <td>${formatNumber(row.ramHeapMb, 2)}</td>
            <td>${formatNumber(row.batchDurationMs)}</td>
            <td>${formatNumber(row.requestThroughput)}</td>
            <td>${formatNumber(row.payloadThroughput)}</td>
        </tr>
    `).join('');
}

// ==========================================
// 7. BATCH RECAP
// ==========================================

function updateRecap(rows, batchElapsedMs = 0, isFinished = false) {
    const total = rows.length;
    const successRows = rows.filter(row => row.ok);
    const successCount = successRows.length;
    const failedCount = total - successCount;

    recapTotalReqEl.textContent = total;
    recapSuccessCountEl.textContent = successCount;
    recapFailedCountEl.textContent = failedCount;

    if (!total) {
        recapAvgRespEl.textContent = '0.000 ms';
        recapMinRespEl.textContent = '0.000 ms';
        recapMaxRespEl.textContent = '0.000 ms';
        recapTotalTimeEl.textContent = '0.000 ms';
        recapRpsEl.textContent = '0.000 request/detik';
        recapSuccessRateEl.textContent = '0.00%';
        recapAvgLatEl.textContent = '0.000 ms';
        recapAvgTputEl.textContent = '0.000 KB/s';
        recapTotalBytesEl.textContent = '0 bytes';
        recapAvgCpuEl.textContent = '0.000000 ms';
        recapAvgRssEl.textContent = '0.00 MB';
        recapAvgHeapEl.textContent = '0.00 MB';

        if (recapCpuUtilEl) {
            recapCpuUtilEl.textContent = '0.000000%';
        }

        recapFooterStatusEl.style.display = 'none';
        exportInfoEl.textContent =
            'Hasil pengujian belum tersedia untuk diunduh.';
        btnExportCsv.disabled = true;
        return;
    }

    const successRate = (successCount / total) * 100;
    recapSuccessRateEl.textContent = `${successRate.toFixed(2)}%`;

    const elapsedMs = batchElapsedMs > 0 ? batchElapsedMs : 0;

    const totalBytes = rows.reduce(
        (sum, row) => sum + (row.totalBytes || 0),
        0
    );

    const requestThroughput = elapsedMs > 0
        ? successCount / (elapsedMs / 1000)
        : 0;

    const payloadThroughput = elapsedMs > 0
        ? (totalBytes / 1024) / (elapsedMs / 1000)
        : 0;

    recapTotalTimeEl.textContent = `${elapsedMs.toFixed(3)} ms`;
    recapRpsEl.textContent =
        `${requestThroughput.toFixed(3)} request/detik`;
    recapTotalBytesEl.textContent = `${totalBytes} bytes`;

    if (successCount > 0) {
        const responseTimes = successRows.map(row => row.responseTimeMs);

        const average = key => successRows.reduce(
            (sum, row) => sum + (row[key] || 0),
            0
        ) / successCount;

        recapAvgRespEl.textContent =
            `${average('responseTimeMs').toFixed(3)} ms`;

        recapMinRespEl.textContent =
            `${Math.min(...responseTimes).toFixed(3)} ms`;

        recapMaxRespEl.textContent =
            `${Math.max(...responseTimes).toFixed(3)} ms`;

        recapAvgLatEl.textContent =
            `${average('serverProcessMs').toFixed(3)} ms`;

        recapAvgTputEl.textContent =
            `${payloadThroughput.toFixed(3)} KB/s`;

        recapAvgRssEl.textContent =
            `${average('ramRssMb').toFixed(2)} MB`;

        recapAvgHeapEl.textContent =
            `${average('ramHeapMb').toFixed(2)} MB`;

    } else {
        recapAvgRespEl.textContent = '0.000 ms';
        recapMinRespEl.textContent = '0.000 ms';
        recapMaxRespEl.textContent = '0.000 ms';
        recapAvgLatEl.textContent = '0.000 ms';
        recapAvgTputEl.textContent = '0.000 KB/s';
        recapAvgRssEl.textContent = '0.00 MB';
        recapAvgHeapEl.textContent = '0.00 MB';
    }

    // CPU merupakan metrik tingkat batch, bukan rata-rata per request.
    recapAvgCpuEl.textContent =
        `${Number(batchMetrics?.cpuTimeBatchMs ?? 0).toFixed(6)} ms`;

    if (recapCpuUtilEl) {
        recapCpuUtilEl.textContent =
            `${Number(
                batchMetrics?.cpuUtilizationBatchPercent ?? 0
            ).toFixed(6)}%`;
    }

    if (isFinished) {
        recapFooterStatusEl.style.display = 'inline-block';
        exportInfoEl.textContent = 'Hasil pengujian siap diunduh.';
        btnExportCsv.disabled = false;
    } else {
        recapFooterStatusEl.style.display = 'none';
        exportInfoEl.textContent =
            `Sedang memproses ${total} baris data...`;
        btnExportCsv.disabled = true;
    }
}


// ==========================================
// 8. BATCH TESTING
// ==========================================

batchPresetSelect.addEventListener('change', () => {
    batchCountInput.value = batchPresetSelect.value;
});

batchCountInput.addEventListener('input', () => {
    const value = String(batchCountInput.value);

    const matchingOption = Array.from(
        batchPresetSelect.options
    ).find(option => option.value === value);

    if (matchingOption) {
        batchPresetSelect.value = value;
    }
});

batchForm.addEventListener('submit', async event => {
    event.preventDefault();

    const rawCount = Number(batchCountInput.value);

    const count = Math.max(
        1,
        Math.min(
            MAX_BATCH_REQUESTS,
            Number.isFinite(rawCount) && rawCount > 0
                ? Math.floor(rawCount)
                : 1
        )
    );

    batchCountInput.value = count;

    const prefix = batchPrefixInput.value ||
        'RSA-AES Hybrid Batch';

    batchRecords = [];
    lastBatchElapsedMs = 0;
    batchMetrics = null;

    renderBatchTable([]);
    updateRecap([], 0, false);

    btnBatchStart.disabled = true;
    btnManualSend.disabled = true;

    batchStatusTextEl.textContent =
        'Status: Mempersiapkan secure session...';

    progressTextEl.textContent = `0 / ${count}`;
    progressFillEl.style.width = '0%';

    let batchStartTime = 0;
    let serverBatchId = null;

    try {
        // Pastikan secure session sudah terbentuk sebelum batch dimulai.
        if (!hybridSessionReady) {
            await initializeHybridSession();
        }

        // Mulai pengukuran CPU batch pada server.
        serverBatchId = await startServerBatchMeasurement();

        // Mulai pengukuran durasi batch pada client.
        batchStartTime = performance.now();

        batchStatusTextEl.textContent =
            'Status: Pengujian sedang berjalan...';

        for (let i = 1; i <= count; i++) {
            try {
                const result = await sendMessageRequest(
                    `${prefix} ${i}`,
                    ++requestSequence
                );

                batchRecords.push({
                    ...result,
                    batchDurationMs: 0,
                    requestThroughput: 0,
                    payloadThroughput: 0,
                    cpuTimeBatchMs: 0,
                    cpuUtilizationBatchPercent: 0
                });

            } catch (error) {
                console.error(`Batch request ${i} gagal:`, error);

                batchRecords.push({
                    seq: requestSequence,
                    httpStatus: 0,
                    ok: false,
                    verified: false,
                    responseTimeMs: 0,
                    serverProcessMs: 0,
                    cryptoProcessMs: 0,
                    requestBytes: 0,
                    responseBytes: 0,
                    totalBytes: 0,
                    cpuServerMs: 0,
                    ramRssMb: 0,
                    ramHeapMb: 0,
                    batchDurationMs: 0,
                    requestThroughput: 0,
                    payloadThroughput: 0,
                    cpuTimeBatchMs: 0,
                    cpuUtilizationBatchPercent: 0
                });
            }

            // Perhitungan sementara untuk tampilan progress.
            lastBatchElapsedMs =
                performance.now() - batchStartTime;

            const successfulCount = batchRecords.filter(
                row => row.ok
            ).length;

            const totalBytes = batchRecords.reduce(
                (sum, row) => sum + (row.totalBytes || 0),
                0
            );

            const currentRps = lastBatchElapsedMs > 0
                ? successfulCount / (lastBatchElapsedMs / 1000)
                : 0;

            const currentPayloadThroughput = lastBatchElapsedMs > 0
                ? (totalBytes / 1024) /
                  (lastBatchElapsedMs / 1000)
                : 0;

            batchRecords = batchRecords.map(row => ({
                ...row,
                batchDurationMs: lastBatchElapsedMs,
                requestThroughput: currentRps,
                payloadThroughput: currentPayloadThroughput,
                cpuTimeBatchMs: 0,
                cpuUtilizationBatchPercent: 0
            }));

            const percentage = Math.round((i / count) * 100);

            progressTextEl.textContent = `${i} / ${count}`;
            progressFillEl.style.width = `${percentage}%`;

            renderBatchTable(batchRecords);
            updateRecap(batchRecords, lastBatchElapsedMs, false);

            if (i < count) {
                await sleep(10);
            }
        }

        // =====================================
        // SELURUH REQUEST SELESAI
        // =====================================

        // Akhiri pengukuran CPU batch pada server satu kali.
        batchMetrics = await endServerBatchMeasurement(serverBatchId);
        serverBatchId = null;

        lastBatchElapsedMs =
            performance.now() - batchStartTime;

        // Hitung throughput akhir.
        const successfulCount = batchRecords.filter(
            row => row.ok
        ).length;

        const totalBytes = batchRecords.reduce(
            (sum, row) => sum + (row.totalBytes || 0),
            0
        );

        const finalRps = lastBatchElapsedMs > 0
            ? successfulCount / (lastBatchElapsedMs / 1000)
            : 0;

        const finalPayloadThroughput = lastBatchElapsedMs > 0
            ? (totalBytes / 1024) /
              (lastBatchElapsedMs / 1000)
            : 0;

        // Masukkan metrik batch ke setiap record.
        batchRecords = batchRecords.map(row => ({
            ...row,

            batchDurationMs: lastBatchElapsedMs,
            requestThroughput: finalRps,
            payloadThroughput: finalPayloadThroughput,

            cpuTimeBatchMs: batchMetrics.cpuTimeBatchMs,
            cpuUtilizationBatchPercent:
                batchMetrics.cpuUtilizationBatchPercent
        }));

        renderBatchTable(batchRecords);
        updateRecap(batchRecords, lastBatchElapsedMs, true);

        batchStatusTextEl.textContent =
            'Status: Pengujian selesai';

    } catch (error) {
        batchStatusTextEl.textContent =
            `Status: Gagal - ${error.message}`;

        console.error('Batch testing error:', error);

        // Tetap coba akhiri pengukuran jika terjadi error.
        if (serverBatchId) {
            try {
                batchMetrics =
                    await endServerBatchMeasurement(serverBatchId);

                serverBatchId = null;

            } catch (measurementError) {
                console.error(
                    'Gagal mengakhiri pengukuran CPU batch:',
                    measurementError
                );
            }
        }

        // Simpan hasil CPU jika pengukuran berhasil diperoleh.
        if (batchMetrics) {
            batchRecords = batchRecords.map(row => ({
                ...row,
                cpuTimeBatchMs: batchMetrics.cpuTimeBatchMs,
                cpuUtilizationBatchPercent:
                    batchMetrics.cpuUtilizationBatchPercent
            }));
        }

        if (batchRecords.length > 0) {
            renderBatchTable(batchRecords);
            updateRecap(batchRecords, lastBatchElapsedMs, true);
        } else {
            updateRecap([], 0, false);
        }

    } finally {
        btnBatchStart.disabled = false;
        btnManualSend.disabled = false;
    }
});

// ==========================================
// 9. CSV EXPORT - 16 METRICS
// ==========================================

btnExportCsv.addEventListener('click', () => {
    if (!batchRecords.length) {
        return;
    }

    const headers = [
        'Request',
        'Status HTTP',
        'Success',
        'Response Time (ms)',
        'Server Processing Time (ms)',
        'Crypto Processing Time (ms)',
        'Request Bytes',
        'Response Bytes',
        'Total Bytes',
        'CPU Time Batch (ms)',
        'CPU Utilization Batch (%)',
        'RAM RSS (MB)',
        'RAM Heap (MB)',
        'Batch Duration (ms)',
        'Request Throughput (req/s)',
        'Payload Throughput (KB/s)'
    ];

    const rows = batchRecords.map(row => [
        row.seq,
        row.httpStatus,
        row.ok ? 'TRUE' : 'FALSE',
        row.responseTimeMs,
        row.serverProcessMs,
        row.cryptoProcessMs,
        row.requestBytes,
        row.responseBytes,
        row.totalBytes,
        row.cpuTimeBatchMs,
        row.cpuUtilizationBatchPercent,
        row.ramRssMb,
        row.ramHeapMb,
        row.batchDurationMs,
        row.requestThroughput,
        row.payloadThroughput
    ]);

    // Format angka dengan desimal koma untuk CSV lokal Indonesia.
    const formatCsvValue = value => {
        if (typeof value === 'number') {
            return value.toFixed(6).replace('.', ',');
        }

        return String(value ?? '');
    };

    const csvLines = [
        headers.join(';'),
        ...rows.map(row =>
            row.map(formatCsvValue).join(';')
        )
    ];

    const csvContent = '\uFEFF' + csvLines.join('\r\n');

    const blob = new Blob(
        [csvContent],
        { type: 'text/csv;charset=utf-8;' }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download =
        `hasil-rsa-aes-hybrid-${Date.now()}.csv`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
});

// ==========================================
// 10. INITIALIZE PAGE
// ==========================================

document.addEventListener('DOMContentLoaded', () => {
    initializeHybridSession().catch(error => {
        console.error('Gagal menginisialisasi Hybrid:', error);
    });
});
