const SCHEME_ID = 'rsa-oaep';

const manualForm = document.getElementById('manualForm');
const manualMessageInput = document.getElementById('manualMessage');
const btnManualSend = document.getElementById('btnManualSend');

const rsaMetaBoxEl = document.getElementById('rsaMetaBox');
const rsaCipherBoxEl = document.getElementById('rsaCipherBox');
const rsaDecryptedBoxEl = document.getElementById('rsaDecryptedBox');
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
const recapAvgRssEl = document.getElementById('recapAvgRss');
const recapAvgHeapEl = document.getElementById('recapAvgHeap');

const recapFooterStatusEl = document.getElementById('recapFooterStatus');
const exportInfoEl = document.getElementById('exportInfo');
const btnExportCsv = document.getElementById('btnExportCsv');

const MAX_BATCH_REQUESTS = 10000;

let batchRecords = [];
let lastBatchElapsedMs = 0;
let batchMetrics = null;


// ==========================================
// RSA-OAEP CLIENT CRYPTOGRAPHY
// ==========================================

const RSA_CONFIG = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
};

const RSA_MAX_PLAINTEXT_BYTES = 190;

let serverPublicKey = null;
let clientKeyPair = null;
let clientPublicKeyBase64 = null;

// Uint8Array -> Base64
function bytesToBase64(bytes) {
    let binary = '';

    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(
            ...bytes.subarray(i, i + chunkSize)
        );
    }

    return btoa(binary);
}

// Base64 -> Uint8Array
function base64ToBytes(base64) {
    const binary = atob(base64);

    return Uint8Array.from(
        binary,
        character => character.charCodeAt(0)
    );
}

// Uint8Array -> Hexadecimal
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

// ==========================================
// RSA INITIALIZATION
// ==========================================

let rsaReady = false;

const rsaInitialization = initializeRSA()
    .then(() => {
        rsaReady = true;
        console.log('RSA siap digunakan.');
    })
    .catch(error => {
        console.error('RSA initialization failed:', error);
    });

// ==========================================
// INITIALIZE RSA KEYS
// ==========================================

async function initializeRSA() {
    // 1. Ambil public key server
    const response = await fetch('/api/rsa/public-key');

    if (!response.ok) {
        throw new Error('Gagal mengambil public key server.');
    }

    const data = await response.json();

    if (!data.publicKey) {
        throw new Error('Public key server tidak tersedia.');
    }

    const serverKeyBytes = base64ToBytes(data.publicKey);

    serverPublicKey = await window.crypto.subtle.importKey(
        'spki',
        serverKeyBytes,
        RSA_CONFIG,
        false,
        ['encrypt']
    );

    // 2. Buat pasangan key client satu kali
    clientKeyPair = await window.crypto.subtle.generateKey(
        RSA_CONFIG,
        false,
        ['encrypt', 'decrypt']
    );

    // 3. Export public key client
    const clientPublicKeyBuffer =
        await window.crypto.subtle.exportKey(
            'spki',
            clientKeyPair.publicKey
        );

    clientPublicKeyBase64 = bytesToBase64(
        new Uint8Array(clientPublicKeyBuffer)
    );

    console.log('RSA Client initialized.');
}

// ==========================================
// RSA ENCRYPTION
// ==========================================

async function encryptRSAMessage(message) {
    if (!serverPublicKey) {
        throw new Error('RSA belum diinisialisasi.');
    }

    const plaintext = new TextEncoder().encode(message);

    if (plaintext.length > RSA_MAX_PLAINTEXT_BYTES) {
        throw new Error(
            `Pesan terlalu panjang. Maksimal ${RSA_MAX_PLAINTEXT_BYTES} byte untuk RSA-2048 OAEP SHA-256.`
        );
    }

    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP'
        },
        serverPublicKey,
        plaintext
    );

    return new Uint8Array(encryptedBuffer);
}

// ==========================================
// RSA DECRYPTION
// ==========================================

async function decryptRSAResponse(encryptedBase64) {
    if (!clientKeyPair) {
        throw new Error('Private key client tidak tersedia.');
    }

    const ciphertext = base64ToBytes(encryptedBase64);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
            name: 'RSA-OAEP'
        },
        clientKeyPair.privateKey,
        ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
}


batchPresetSelect.addEventListener('change', () => {
    batchCountInput.value = batchPresetSelect.value;
});

batchCountInput.addEventListener('input', () => {
    const val = String(batchCountInput.value);
    const matchingOption = Array.from(batchPresetSelect.options).find((opt) => opt.value === val);
    if (matchingOption) {
        batchPresetSelect.value = val;
    }
});


async function sendMessageRequest(messageText, seq = null) {

    await rsaInitialization;

    if (!rsaReady) {
        throw new Error('RSA belum siap digunakan.');
    }

    // 1. Enkripsi pesan di browser
    const encryptedBytes = await encryptRSAMessage(messageText);

    const payload = {
        seq,
        encryptedMessage: bytesToBase64(encryptedBytes),
        clientPublicKey: clientPublicKeyBase64,
        sentAt: new Date().toISOString()
    };

    const requestBody = JSON.stringify(payload);

    const requestBytes = new TextEncoder().encode(
        requestBody
    ).length;

    // 2. Mulai pengukuran Response Time
    const t0 = performance.now();

    const response = await fetch('/api/rsa/message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: requestBody
    });

    // 3. Baca seluruh response body
    const responseBuffer = await response.arrayBuffer();

    const t1 = performance.now();

    const responseBytes = responseBuffer.byteLength;

    const responseText = new TextDecoder().decode(
        responseBuffer
    );

    let data;

    try {
        data = JSON.parse(responseText);
    } catch {
        throw new Error('Respons server bukan JSON yang valid.');
    }

    if (!response.ok) {
        throw new Error(data?.error || `HTTP ${response.status}`);
    }

    // 4. Ambil ciphertext respons
    const encryptedResponse = data?.crypto?.encryptedMessage;

    if (!encryptedResponse) {
        throw new Error('Ciphertext respons RSA tidak ditemukan.');
    }

    // 5. Dekripsi respons menggunakan private key client
    const decryptedMessage = await decryptRSAResponse(
        encryptedResponse
    );

    // 6. Verifikasi hasil dekripsi
    const verified = decryptedMessage === messageText;

    // 7. Hitung metrik
    const responseTimeMs = Number(
        (t1 - t0).toFixed(3)
    );

    const serverProcessingMs = Number(
        data?.metrics?.serverProcessMs ?? 0
    );

    const totalBytes = requestBytes + responseBytes;

    const responseCipherBytes = base64ToBytes(
        encryptedResponse
    );

    const cryptoData = {
        keyBits: 2048,
        oaepHash: 'SHA-256',
        ciphertextBytes: responseCipherBytes.length,
        ciphertextHex: bytesToHex(responseCipherBytes),
        encryptedMessage: encryptedResponse,
        decryptedMessage
    };

    return {
        seq: seq ?? 1,

        httpStatus: response.status,
        ok: response.ok && verified,

        responseTimeMs,
        serverProcessingMs,
        cryptoProcessMs: Number(
            data?.metrics?.cryptoProcessMs ?? 0
        ),

        requestBytes,
        responseBytes,
        totalBytes,

        cpuServerMs: Number(
            data?.metrics?.cpuServerMs ?? 0
        ),

        ramRssMb: Number(
            data?.metrics?.ramRssMb ?? 0
        ),

        ramHeapMb: Number(
            data?.metrics?.ramHeapMb ?? 0
        ),

        crypto: cryptoData,
        echoMessage: decryptedMessage,
        verified
    };
}


manualForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = manualMessageInput.value;

    btnManualSend.disabled = true;
    manualStatusEl.textContent = 'Mengirim...';
    manualStatusEl.className = '';

    try {
        const result = await sendMessageRequest(text);
        if (result.verified) {
            manualStatusEl.textContent = 'Berhasil - Terverifikasi';
            manualStatusEl.className = 'text-success';
        } else {
            manualStatusEl.textContent = 'Gagal - Verifikasi Tidak Valid';
            manualStatusEl.className = 'text-danger';
        }

        manualTimingEl.textContent =
            `Response Time: ${result.responseTimeMs.toFixed(3)} ms | ` +
            `Server Processing: ${result.serverProcessingMs.toFixed(3)} ms | ` +
            `Crypto Processing: ${result.cryptoProcessMs.toFixed(3)} ms`;

        if (result.crypto) {
            rsaMetaBoxEl.textContent =
                `Key: RSA-${result.crypto.keyBits} | Padding: OAEP (${result.crypto.oaepHash}) | Ciphertext: ${result.crypto.ciphertextBytes} bytes`;
            rsaCipherBoxEl.textContent = result.crypto.ciphertextHex || '-';
            rsaDecryptedBoxEl.textContent = result.crypto.decryptedMessage || '-';
        } else {
            rsaMetaBoxEl.textContent = 'Key: - | Padding: - | Ciphertext Size: -';
            rsaCipherBoxEl.textContent = '-';
            rsaDecryptedBoxEl.textContent = result.echoMessage || '-';
        }

        manualSummaryLineEl.textContent =
            `Pengujian ${result.verified ? 'berhasil' : 'gagal diverifikasi'}. ` +
            `Response Time: ${result.responseTimeMs.toFixed(3)} ms | ` +
            `Total Data: ${result.totalBytes} bytes | ` +
            `CPU Server: ${result.cpuServerMs.toFixed(3)} ms`;
    } catch (err) {
        manualStatusEl.textContent = `Gagal (${err.message})`;
        manualStatusEl.className = 'text-danger';
        manualSummaryLineEl.textContent = `Pengujian gagal: ${err.message}`;
    } finally {
        btnManualSend.disabled = false;
    }
});


function renderBatchTable(rows) {
    if (!rows.length) {
        batchTableBodyEl.innerHTML = `
            <tr>
                <td colspan="15" class="empty-cell">
                    Belum ada data pengujian batch.
                </td>
            </tr>
        `;
        return;
    }

    const durationMs = lastBatchElapsedMs;

    const successRows = rows.filter(row => row.ok);
    const successCount = successRows.length;

    const totalBytes = rows.reduce(
        (total, row) => total + (Number(row.totalBytes) || 0),
        0
    );

    const requestThroughput = durationMs > 0
        ? successCount / (durationMs / 1000)
        : 0;

    const payloadThroughput = durationMs > 0
        ? (totalBytes / 1024) / (durationMs / 1000)
        : 0;

    batchTableBodyEl.innerHTML = rows.map(row => `
        <tr>
            <td>${row.seq ?? '-'}</td>
            <td>${row.httpStatus ?? '-'}</td>
            <td>${row.ok ? 'true' : 'false'}</td>
            <td>${Number(row.responseTimeMs || 0).toFixed(3)}</td>
            <td>${Number(row.serverProcessingMs || 0).toFixed(3)}</td>
            <td>${Number(row.cryptoProcessMs || 0).toFixed(3)}</td>
            <td>${row.requestBytes ?? 0}</td>
            <td>${row.responseBytes ?? 0}</td>
            <td>${row.totalBytes ?? 0}</td>
            <td>${Number(row.cpuServerMs || 0).toFixed(3)}</td>
            <td>${Number(row.ramRssMb || 0).toFixed(2)}</td>
            <td>${Number(row.ramHeapMb || 0).toFixed(2)}</td>
            <td>${durationMs.toFixed(3)}</td>
            <td>${requestThroughput.toFixed(3)}</td>
            <td>${payloadThroughput.toFixed(3)}</td>
        </tr>
    `).join('');
}



function updateRecap(
    rows,
    batchElapsedMs = lastBatchElapsedMs,
    isFinished = false
) {
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

        recapAvgCpuEl.textContent = '0.000 ms';
        recapAvgRssEl.textContent = '0.00 MB';
        recapAvgHeapEl.textContent = '0.00 MB';

        recapFooterStatusEl.style.display = 'none';
        exportInfoEl.textContent =
            'Hasil pengujian belum tersedia untuk diunduh.';

        btnExportCsv.disabled = true;
        return;
    }

    const effectiveElapsedMs = batchElapsedMs > 0
        ? batchElapsedMs
        : rows.reduce(
            (sum, row) => sum + (Number(row.responseTimeMs) || 0),
            0
        );

    // Total durasi batch
    recapTotalTimeEl.textContent =
        `${effectiveElapsedMs.toFixed(3)} ms`;

    // Request Throughput
    const requestThroughput = effectiveElapsedMs > 0
        ? successCount / (effectiveElapsedMs / 1000)
        : 0;

    recapRpsEl.textContent =
        `${requestThroughput.toFixed(3)} request/detik`;

    // Success Rate
    const successRate = (successCount / total) * 100;

    recapSuccessRateEl.textContent =
        `${successRate.toFixed(2)}%`;

    // Total payload bytes
    const totalBytes = rows.reduce(
        (sum, row) => sum + (Number(row.totalBytes) || 0),
        0
    );

    recapTotalBytesEl.textContent = `${totalBytes} bytes`;

    if (!successCount) {
        recapAvgRespEl.textContent = '0.000 ms';
        recapMinRespEl.textContent = '0.000 ms';
        recapMaxRespEl.textContent = '0.000 ms';

        recapAvgLatEl.textContent = '0.000 ms';
        recapAvgTputEl.textContent = '0.000 KB/s';

        recapAvgCpuEl.textContent = '0.000 ms';
        recapAvgRssEl.textContent = '0.00 MB';
        recapAvgHeapEl.textContent = '0.00 MB';

    } else {
        const responseTimes = successRows.map(
            row => Number(row.responseTimeMs) || 0
        );

        const average = (key) => {
            return successRows.reduce(
                (sum, row) => sum + (Number(row[key]) || 0),
                0
            ) / successCount;
        };

        // Response Time
        const avgResponseTime =
            responseTimes.reduce((a, b) => a + b, 0) /
            successCount;

        recapAvgRespEl.textContent =
            `${avgResponseTime.toFixed(3)} ms`;

        recapMinRespEl.textContent =
            `${Math.min(...responseTimes).toFixed(3)} ms`;

        recapMaxRespEl.textContent =
            `${Math.max(...responseTimes).toFixed(3)} ms`;

        // Server Processing Time
        recapAvgLatEl.textContent =
            `${average('serverProcessingMs').toFixed(3)} ms`;

        // Payload Throughput
        const payloadThroughput = effectiveElapsedMs > 0
            ? (totalBytes / 1024) / (effectiveElapsedMs / 1000)
            : 0;

        recapAvgTputEl.textContent =
            `${payloadThroughput.toFixed(3)} KB/s`;

        // CPU dan Memory
        recapAvgCpuEl.textContent =
            `${average('cpuServerMs').toFixed(6)} ms`;

        recapAvgRssEl.textContent =
            `${average('ramRssMb').toFixed(2)} MB`;

        recapAvgHeapEl.textContent =
            `${average('ramHeapMb').toFixed(2)} MB`;
    }

    if (isFinished) {
        recapFooterStatusEl.style.display = 'inline-block';
        exportInfoEl.textContent =
            'Hasil pengujian siap diunduh.';

        btnExportCsv.disabled = false;

    } else {
        recapFooterStatusEl.style.display = 'none';
        exportInfoEl.textContent =
            `Sedang memproses ${total} baris data...`;

        btnExportCsv.disabled = true;
    }
}


function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

batchForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const rawCount = Number(batchCountInput.value);
    const count = Math.max(
        1,
        Math.min(
            MAX_BATCH_REQUESTS,
            Number.isFinite(rawCount) && rawCount > 0 ? Math.floor(rawCount) : 1
        )
    );
    batchCountInput.value = count;

    const prefix = batchPrefixInput.value || 'RSA-OAEP Batch #';

    batchRecords = [];
    lastBatchElapsedMs = 0;
    renderBatchTable(batchRecords);
    updateRecap(batchRecords, 0, false);

    btnBatchStart.disabled = true;
    btnManualSend.disabled = true;
    batchStatusTextEl.textContent = 'Status: Sedang berjalan...';
    progressTextEl.textContent = `0 / ${count}`;
    progressFillEl.style.width = '0%';

    const batchStartT = performance.now();

    for (let i = 1; i <= count; i++) {
        try {
            const res = await sendMessageRequest(`${prefix} ${i}`, i);
            batchRecords.push(res);
        } catch (err) {
            batchRecords.push({
                seq: i,
                httpStatus: 0,
                ok: false,

                responseTimeMs: 0,
                serverProcessingMs: 0,
                cryptoProcessMs: 0,

                requestBytes: 0,
                responseBytes: 0,
                totalBytes: 0,

                cpuServerMs: 0,
                ramRssMb: 0,
                ramHeapMb: 0,

                verified: false,
                error: err.message
            });
        }

        lastBatchElapsedMs = Number((performance.now() - batchStartT).toFixed(3));

        const pct = Math.round((i / count) * 100);
        progressTextEl.textContent = `${i} / ${count}`;
        progressFillEl.style.width = `${pct}%`;

        renderBatchTable(batchRecords);
        updateRecap(batchRecords, lastBatchElapsedMs, false);

        if (i < count) {
            await sleep(10);
        }
    }

    lastBatchElapsedMs = Number(
        (performance.now() - batchStartT).toFixed(3)
    );

    renderBatchTable(batchRecords);
    updateRecap(batchRecords, lastBatchElapsedMs, true);

    batchStatusTextEl.textContent = 'Status: Pengujian selesai';
    btnBatchStart.disabled = false;
    btnManualSend.disabled = false;
});


btnExportCsv.addEventListener('click', () => {
    if (!batchRecords.length) return;

    const successRows = batchRecords.filter(
        row => row.ok
    );

    const totalBytes = batchRecords.reduce(
        (sum, row) => sum + (Number(row.totalBytes) || 0),
        0
    );

    const requestThroughput = lastBatchElapsedMs > 0
        ? successRows.length / (lastBatchElapsedMs / 1000)
        : 0;

    const payloadThroughput = lastBatchElapsedMs > 0
        ? (totalBytes / 1024) / (lastBatchElapsedMs / 1000)
        : 0;

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
        'CPU Server (ms)',
        'RAM RSS (MB)',
        'RAM Heap (MB)',
        'Batch Duration (ms)',
        'Request Throughput (req/s)',
        'Payload Throughput (KB/s)'
    ];

    const rows = batchRecords.map(row => [
        row.seq,
        row.httpStatus,
        row.ok,
        row.responseTimeMs,
        row.serverProcessingMs,
        row.cryptoProcessMs,
        row.requestBytes,
        row.responseBytes,
        row.totalBytes,
        row.cpuServerMs,
        row.ramRssMb,
        row.ramHeapMb,
        lastBatchElapsedMs,
        requestThroughput,
        payloadThroughput
    ]);

    function formatCsvNumber(value) {
        if (
            value === null ||
            value === undefined ||
            value === ''
        ) {
            return '';
        }

        if (
            typeof value !== 'number' ||
            !Number.isFinite(value)
        ) {
            return String(value ?? '');
        }

        return value.toFixed(6).replace('.', ',');
    }

    function escapeCsv(value) {
        const text = String(value ?? '');
        return `"${text.replace(/"/g, '""')}"`;
    }

    const csvContent = [
        headers.map(escapeCsv).join(';'),

        ...rows.map(row =>
            row.map(value =>
                escapeCsv(
                    typeof value === 'number'
                        ? formatCsvNumber(value)
                        : value
                )
            ).join(';')
        )
    ].join('\r\n');

    const blob = new Blob(
        ['\uFEFF', csvContent],
        { type: 'text/csv;charset=utf-8;' }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = `hasil-rsa-oaep-${Date.now()}.csv`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
});