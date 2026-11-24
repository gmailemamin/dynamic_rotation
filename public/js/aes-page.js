
const SCHEME_ID = 'aes-256-gcm';
const MAX_BATCH_REQUESTS = 10000;

// DOM ELEMENTS
const manualForm = document.getElementById('manualForm');
const manualMessageInput = document.getElementById('manualMessage');
const btnManualSend = document.getElementById('btnManualSend');

const aesIvTagBoxEl = document.getElementById('aesIvTagBox');
const aesCipherBoxEl = document.getElementById('aesCipherBox');
const aesDecryptedBoxEl = document.getElementById('aesDecryptedBox');
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

// GLOBAL STATE
let batchRecords = [];
let lastBatchElapsedMs = 0;

// UTILITIES
function formatNumber(value, decimals = 3) {
    const number = Number(value ?? 0);

    return Number.isFinite(number)
        ? number.toFixed(decimals)
        : (0).toFixed(decimals);
}

function average(rows, key) {
    if (!rows.length) return 0;

    return rows.reduce(
        (total, row) => total + (Number(row[key]) || 0),
        0
    ) / rows.length;
}

function sum(rows, key) {
    return rows.reduce(
        (total, row) => total + (Number(row[key]) || 0),
        0
    );
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function sanitizeCount(value) {
    const number = Number(value);

    if (!Number.isFinite(number) || number <= 0) {
        return 1;
    }

    return Math.max(
        1,
        Math.min(MAX_BATCH_REQUESTS, Math.floor(number))
    );
}

// BATCH INPUT HANDLERS
batchPresetSelect?.addEventListener('change', () => {
    batchCountInput.value = batchPresetSelect.value;
});

batchCountInput?.addEventListener('input', () => {
    const value = String(batchCountInput.value);

    const matchingOption = Array.from(batchPresetSelect.options)
        .find((option) => option.value === value);

    batchPresetSelect.value = matchingOption ? value : '';
});

// REQUEST FUNCTION
async function sendMessageRequest(messageText, seq = null) {
    const payload = {
        seq,
        message: messageText,
        sentAt: new Date().toISOString()
    };

    const requestBody = JSON.stringify(payload);
    const requestBytes = new TextEncoder().encode(requestBody).length;

    // Response Time dimulai sebelum request dikirim
    const t0 = performance.now();

    const response = await fetch('/api/aes/message', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: requestBody
    });

    // Membaca seluruh response body
    const responseBuffer = await response.arrayBuffer();

    // Response Time berakhir setelah seluruh body diterima
    const t1 = performance.now();

    const responseBytes = responseBuffer.byteLength;
    const responseText = new TextDecoder().decode(responseBuffer);

    let data;

    try {
        data = JSON.parse(responseText);
    } catch {
        throw new Error('Respons server bukan JSON yang valid.');
    }

    if (!response.ok) {
        throw new Error(data?.error || `HTTP ${response.status}`);
    }

    const responseTimeMs = Number((t1 - t0).toFixed(3));

    const crypto = data?.crypto ?? {};

    const cryptoProcessMs = Number(
        data?.metrics?.cryptoProcessMs ??
        crypto.cryptoProcessMs ??
        0
    );

    const serverProcessingMs = Number(
        data?.metrics?.serverProcessMs ?? 0
    );

    const totalBytes = requestBytes + responseBytes;

    return {
        seq: seq ?? 1,

        httpStatus: response.status,
        ok: response.ok,

        responseTimeMs,
        serverProcessingMs,
        cryptoProcessMs,

        requestBytes,
        responseBytes,
        totalBytes,

        cpuServerMs: Number(data?.metrics?.cpuServerMs ?? 0),
        ramRssMb: Number(data?.metrics?.ramRssMb ?? 0),
        ramHeapMb: Number(data?.metrics?.ramHeapMb ?? 0),

        iv: crypto.iv ?? '',
        authTag: crypto.authTag ?? '',
        encryptedMessage: crypto.encryptedMessage ?? '',
        decryptedMessage: crypto.decryptedMessage ?? '',

        verified: crypto.verified === true,

        echoMessage: data?.echoMessage ?? ''
    };
}

// MANUAL TESTING
manualForm?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const message = manualMessageInput.value;

    btnManualSend.disabled = true;
    manualStatusEl.textContent = 'Mengirim...';
    manualStatusEl.className = '';

    try {
        const result = await sendMessageRequest(message);

        aesIvTagBoxEl.textContent =
            `IV: ${result.iv || '-'}\n` +
            `Auth Tag: ${result.authTag || '-'}`;

        aesCipherBoxEl.textContent =
            result.encryptedMessage || '-';

        aesDecryptedBoxEl.textContent =
            result.decryptedMessage || '-';

        if (result.verified) {
            manualStatusEl.textContent = 'Berhasil - Terverifikasi';
            manualStatusEl.className = 'text-success';
        } else {
            manualStatusEl.textContent = 'Gagal - Verifikasi Tidak Valid';
            manualStatusEl.className = 'text-danger';
        }

        manualTimingEl.textContent =
            `Response Time: ${formatNumber(result.responseTimeMs)} ms | ` +
            `Server Processing: ${formatNumber(result.serverProcessingMs)} ms | ` +
            `Crypto Processing: ${formatNumber(result.cryptoProcessMs)} ms`;

        manualSummaryLineEl.textContent =
            `Pengujian ${result.verified ? 'berhasil' : 'gagal diverifikasi'}. ` +
            `CPU Server: ${formatNumber(result.cpuServerMs)} ms | ` +
            `Total Data: ${result.totalBytes} bytes`;

    } catch (error) {
        manualStatusEl.textContent = `Gagal (${error.message})`;
        manualStatusEl.className = 'text-danger';

        manualSummaryLineEl.textContent =
            `Pengujian gagal: ${error.message}`;

        aesIvTagBoxEl.textContent = 'IV: - | Auth Tag: -';
        aesCipherBoxEl.textContent = '-';
        aesDecryptedBoxEl.textContent = '-';

    } finally {
        btnManualSend.disabled = false;
    }
});

// BATCH TABLE
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

    const successRows = rows.filter((row) => row.ok);
    const successCount = successRows.length;

    const totalBytes = sum(rows, 'totalBytes');

    const requestThroughput = durationMs > 0
        ? successCount / (durationMs / 1000)
        : 0;

    const payloadThroughput = durationMs > 0
        ? (totalBytes / 1024) / (durationMs / 1000)
        : 0;

    batchTableBodyEl.innerHTML = rows.map((row) => `
        <tr>
            <td>${row.seq ?? '-'}</td>
            <td>${row.httpStatus ?? '-'}</td>
            <td>${row.ok ? 'true' : 'false'}</td>
            <td>${formatNumber(row.responseTimeMs)}</td>
            <td>${formatNumber(row.serverProcessingMs)}</td>
            <td>${formatNumber(row.cryptoProcessMs)}</td>
            <td>${row.requestBytes ?? 0}</td>
            <td>${row.responseBytes ?? 0}</td>
            <td>${row.totalBytes ?? 0}</td>
            <td>${formatNumber(row.cpuServerMs)}</td>
            <td>${formatNumber(row.ramRssMb, 2)}</td>
            <td>${formatNumber(row.ramHeapMb, 2)}</td>
            <td>${formatNumber(durationMs)}</td>
            <td>${formatNumber(requestThroughput)}</td>
            <td>${formatNumber(payloadThroughput)}</td>
        </tr>
    `).join('');
}

// BATCH RECAP
function updateRecap(
    rows,
    batchElapsedMs = lastBatchElapsedMs,
    isFinished = false
) {
    const total = rows.length;
    const successRows = rows.filter((row) => row.ok);
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
            (totalTime, row) => totalTime + row.responseTimeMs,
            0
        );

    recapTotalTimeEl.textContent =
        `${formatNumber(effectiveElapsedMs)} ms`;

    const requestThroughput = effectiveElapsedMs > 0
        ? successCount / (effectiveElapsedMs / 1000)
        : 0;

    recapRpsEl.textContent =
        `${formatNumber(requestThroughput)} request/detik`;

    recapSuccessRateEl.textContent =
        `${((successCount / total) * 100).toFixed(2)}%`;

    const totalBytes = sum(rows, 'totalBytes');

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
            (row) => row.responseTimeMs
        );

        const avgResponseTime =
            responseTimes.reduce((a, b) => a + b, 0) /
            responseTimes.length;

        recapAvgRespEl.textContent =
            `${formatNumber(avgResponseTime)} ms`;

        recapMinRespEl.textContent =
            `${formatNumber(Math.min(...responseTimes))} ms`;

        recapMaxRespEl.textContent =
            `${formatNumber(Math.max(...responseTimes))} ms`;

        recapAvgLatEl.textContent =
            `${formatNumber(average(successRows, 'serverProcessingMs'))} ms`;

        const payloadThroughput = effectiveElapsedMs > 0
            ? (totalBytes / 1024) / (effectiveElapsedMs / 1000)
            : 0;

        recapAvgTputEl.textContent =
            `${formatNumber(payloadThroughput)} KB/s`;

        recapAvgCpuEl.textContent =
            `${formatNumber(average(successRows, 'cpuServerMs'))} ms`;

        recapAvgRssEl.textContent =
            `${formatNumber(average(successRows, 'ramRssMb'), 2)} MB`;

        recapAvgHeapEl.textContent =
            `${formatNumber(average(successRows, 'ramHeapMb'), 2)} MB`;
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

// BATCH TESTING
batchForm?.addEventListener('submit', async (event) => {
    event.preventDefault();

    const count = sanitizeCount(batchCountInput.value);
    batchCountInput.value = count;

    const prefix = batchPrefixInput.value || 'AES-GCM Batch #';

    batchRecords = [];
    lastBatchElapsedMs = 0;

    renderBatchTable(batchRecords);
    updateRecap(batchRecords, 0, false);

    btnBatchStart.disabled = true;
    btnManualSend.disabled = true;

    batchStatusTextEl.textContent = 'Status: Sedang berjalan...';
    progressTextEl.textContent = `0 / ${count}`;
    progressFillEl.style.width = '0%';

    const batchStartTime = performance.now();

    try {
        for (let i = 1; i <= count; i++) {
            try {
                const result = await sendMessageRequest(
                    `${prefix} ${i}`,
                    i
                );

                batchRecords.push(result);

            } catch (error) {
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
                    error: error.message
                });
            }

            lastBatchElapsedMs = Number(
                (performance.now() - batchStartTime).toFixed(3)
            );

            progressTextEl.textContent = `${i} / ${count}`;

            progressFillEl.style.width =
                `${Math.round((i / count) * 100)}%`;

            renderBatchTable(batchRecords);

            updateRecap(
                batchRecords,
                lastBatchElapsedMs,
                false
            );

            if (i < count) {
                await sleep(10);
            }
        }

        lastBatchElapsedMs = Number(
            (performance.now() - batchStartTime).toFixed(3)
        );

        renderBatchTable(batchRecords);

        updateRecap(
            batchRecords,
            lastBatchElapsedMs,
            true
        );

        batchStatusTextEl.textContent = 'Status: Pengujian selesai';

    } finally {
        btnBatchStart.disabled = false;
        btnManualSend.disabled = false;
    }
});

// CSV EXPORT
btnExportCsv?.addEventListener('click', () => {
    if (!batchRecords.length) return;

    const successfulRows = batchRecords.filter(
        (row) => row.ok
    );

    const totalBytes = sum(batchRecords, 'totalBytes');

    const requestThroughput = lastBatchElapsedMs > 0
        ? successfulRows.length / (lastBatchElapsedMs / 1000)
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

    const rows = batchRecords.map((row) => [
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
        if (value === null || value === undefined || value === '') {
            return '';
        }

        if (typeof value !== 'number' || !Number.isFinite(value)) {
            return String(value ?? '');
        }

        return value.toFixed(4).replace('.', ',');
    }

    function escapeCsv(value) {
        const text = String(value ?? '');
        return `"${text.replace(/"/g, '""')}"`;
    }

    const csvContent = [
        headers.map(escapeCsv).join(';'),

        ...rows.map((row) =>
            row.map((value) =>
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
    link.download = `hasil-aes-256-gcm-${Date.now()}.csv`;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
});


// const SCHEME_ID = 'aes-256-gcm';

// const manualForm = document.getElementById('manualForm');
// const manualMessageInput = document.getElementById('manualMessage');
// const btnManualSend = document.getElementById('btnManualSend');

// const aesIvTagBoxEl = document.getElementById('aesIvTagBox');
// const aesCipherBoxEl = document.getElementById('aesCipherBox');
// const aesDecryptedBoxEl = document.getElementById('aesDecryptedBox');
// const manualStatusEl = document.getElementById('manualStatus');
// const manualTimingEl = document.getElementById('manualTiming');
// const manualSummaryLineEl = document.getElementById('manualSummaryLine');

// const batchForm = document.getElementById('batchForm');
// const batchPresetSelect = document.getElementById('batchPreset');
// const batchCountInput = document.getElementById('batchCount');
// const batchPrefixInput = document.getElementById('batchPrefix');
// const btnBatchStart = document.getElementById('btnBatchStart');

// const batchStatusTextEl = document.getElementById('batchStatusText');
// const progressTextEl = document.getElementById('progressText');
// const progressFillEl = document.getElementById('progressFill');
// const batchTableBodyEl = document.getElementById('batchTableBody');

// const recapTotalReqEl = document.getElementById('recapTotalReq');
// const recapSuccessCountEl = document.getElementById('recapSuccessCount');
// const recapFailedCountEl = document.getElementById('recapFailedCount');

// const recapAvgRespEl = document.getElementById('recapAvgResp');
// const recapMinRespEl = document.getElementById('recapMinResp');
// const recapMaxRespEl = document.getElementById('recapMaxResp');

// const recapTotalTimeEl = document.getElementById('recapTotalTime');
// const recapRpsEl = document.getElementById('recapRps');
// const recapSuccessRateEl = document.getElementById('recapSuccessRate');

// const recapAvgLatEl = document.getElementById('recapAvgLat');
// const recapAvgTputEl = document.getElementById('recapAvgTput');
// const recapTotalBytesEl = document.getElementById('recapTotalBytes');

// const recapAvgCpuEl = document.getElementById('recapAvgCpu');
// const recapAvgRssEl = document.getElementById('recapAvgRss');
// const recapAvgHeapEl = document.getElementById('recapAvgHeap');

// const recapFooterStatusEl = document.getElementById('recapFooterStatus');
// const exportInfoEl = document.getElementById('exportInfo');
// const btnExportCsv = document.getElementById('btnExportCsv');

// const MAX_BATCH_REQUESTS = 10000;

// let batchRecords = [];
// let lastBatchElapsedMs = 0;

// batchPresetSelect.addEventListener('change', () => {
//     batchCountInput.value = batchPresetSelect.value;
// });

// batchCountInput.addEventListener('input', () => {
//     const val = String(batchCountInput.value);
//     const matchingOption = Array.from(batchPresetSelect.options).find((opt) => opt.value === val);
//     if (matchingOption) {
//         batchPresetSelect.value = val;
//     }
// });

// async function sendMessageRequest(messageText, seq = null) {
//     const payload = {
//         scheme: SCHEME_ID,
//         seq,
//         message: messageText,
//         sentAt: new Date().toISOString()
//     };

//     const t0 = performance.now();
//     const response = await fetch('/api/message', {
//         method: 'POST',
//         headers: { 'Content-Type': 'application/json' },
//         body: JSON.stringify(payload)
//     });
//     const t1 = performance.now();

//     const data = await response.json();
//     const responseTimeMs = Number((t1 - t0).toFixed(3));
//     const serverMs = Number(data?.metrics?.serverProcessMs ?? 0);
//     const latencyMs = Number(Math.max(0.001, responseTimeMs - serverMs).toFixed(3));

//     const totalBytes = Number(
//         data?.metrics?.totalBytes ??
//         new TextEncoder().encode(JSON.stringify(payload) + JSON.stringify(data)).length
//     );
//     const throughputKBs = Number(((totalBytes / 1024) / (responseTimeMs / 1000)).toFixed(3));

//     return {
//         seq: seq ?? 1,
//         httpStatus: response.status,
//         ok: response.ok,
//         responseTimeMs,
//         latencyMs,
//         throughputKBs,
//         totalBytes,
//         cryptoProcessMs: Number(data?.metrics?.cryptoProcessMs ?? data?.crypto?.cryptoProcessMs ?? 0),
//         cpuServerMs: Number(data?.metrics?.cpuServerMs ?? 0),
//         ramRssMb: Number(data?.metrics?.ramRssMb ?? 0),
//         ramHeapMb: Number(data?.metrics?.ramHeapMb ?? 0),
//         crypto: data?.crypto || null,
//         echoMessage: data?.echoMessage ?? ''
//     };
// }

// manualForm.addEventListener('submit', async (e) => {
//     e.preventDefault();
//     const text = manualMessageInput.value;

//     btnManualSend.disabled = true;
//     manualStatusEl.textContent = 'Mengirim...';
//     manualStatusEl.className = '';

//     try {
//         const result = await sendMessageRequest(text);
//         manualStatusEl.textContent = 'Berhasil (AEAD Terverifikasi)';
//         manualStatusEl.className = 'text-success';
//         manualTimingEl.textContent =
//             `${result.responseTimeMs.toFixed(3)} ms (Latency: ${result.latencyMs.toFixed(3)} ms | Kripto: ${result.cryptoProcessMs.toFixed(3)} ms)`;

//         if (result.crypto) {
//             aesIvTagBoxEl.textContent = `IV: ${result.crypto.ivHex}\nTag: ${result.crypto.authTagHex}`;
//             aesCipherBoxEl.textContent = result.crypto.ciphertextHex || '-';
//             aesDecryptedBoxEl.textContent = result.crypto.decryptedMessage || '-';
//         } else {
//             aesIvTagBoxEl.textContent = 'IV: - | Tag: -';
//             aesCipherBoxEl.textContent = '-';
//             aesDecryptedBoxEl.textContent = result.echoMessage || '-';
//         }

//         manualSummaryLineEl.textContent =
//             `Pengujian berhasil. Response: ${result.responseTimeMs.toFixed(3)} ms | Throughput: ${result.throughputKBs.toFixed(2)} KB/s | CPU Server: ${result.cpuServerMs.toFixed(3)} ms`;
//     } catch (err) {
//         manualStatusEl.textContent = `Gagal (${err.message})`;
//         manualStatusEl.className = 'text-danger';
//     } finally {
//         btnManualSend.disabled = false;
//     }
// });

// function renderBatchTable(rows) {
//     if (!rows.length) {
//         batchTableBodyEl.innerHTML =
//             '<tr><td colspan="8" class="empty-cell">Belum ada data pengujian batch.</td></tr>';
//         return;
//     }

//     batchTableBodyEl.innerHTML = rows
//         .map(
//             (r) => `
//       <tr>
//         <td>${r.seq}</td>
//         <td>${r.responseTimeMs.toFixed(3)}</td>
//         <td>${r.latencyMs.toFixed(3)}</td>
//         <td>${r.throughputKBs.toFixed(3)}</td>
//         <td>${r.totalBytes}</td>
//         <td>${r.cpuServerMs.toFixed(3)}</td>
//         <td>${r.ramRssMb.toFixed(2)}</td>
//         <td>${r.ramHeapMb.toFixed(2)}</td>
//       </tr>
//     `
//         )
//         .join('');
// }

// function updateRecap(rows, batchElapsedMs = lastBatchElapsedMs, isFinished = false) {
//     const total = rows.length;
//     const successRows = rows.filter((r) => r.ok);
//     const successCount = successRows.length;
//     const failedCount = total - successCount;

//     recapTotalReqEl.textContent = `${total}`;
//     recapSuccessCountEl.textContent = `${successCount}`;
//     recapFailedCountEl.textContent = `${failedCount}`;

//     if (!total) {
//         recapAvgRespEl.textContent = '0.000 ms';
//         recapMinRespEl.textContent = '0.000 ms';
//         recapMaxRespEl.textContent = '0.000 ms';
//         recapTotalTimeEl.textContent = '0.000 ms';
//         recapRpsEl.textContent = '0.000 request/detik';
//         recapSuccessRateEl.textContent = '0.00%';
//         recapAvgLatEl.textContent = '0.000 ms';
//         recapAvgTputEl.textContent = '0.000 KB/s';
//         recapTotalBytesEl.textContent = '0 bytes';
//         recapAvgCpuEl.textContent = '0.000 ms';
//         recapAvgRssEl.textContent = '0.00 MB';
//         recapAvgHeapEl.textContent = '0.00 MB';
//         recapFooterStatusEl.style.display = 'none';
//         exportInfoEl.textContent = 'Hasil pengujian belum tersedia untuk diunduh.';
//         btnExportCsv.disabled = true;
//         return;
//     }

//     const successRate = (successCount / total) * 100;
//     recapSuccessRateEl.textContent = `${successRate.toFixed(2)}%`;

//     const effectiveElapsedMs = batchElapsedMs > 0
//         ? batchElapsedMs
//         : rows.reduce((acc, r) => acc + (r.responseTimeMs || 0), 0);

//     recapTotalTimeEl.textContent = `${effectiveElapsedMs.toFixed(3)} ms`;
//     const rps = effectiveElapsedMs > 0 ? (successCount / (effectiveElapsedMs / 1000)) : 0;
//     recapRpsEl.textContent = `${rps.toFixed(3)} request/detik`;

//     const totalBytesSum = rows.reduce((acc, r) => acc + (r.totalBytes || 0), 0);
//     recapTotalBytesEl.textContent = `${totalBytesSum} bytes`;

//     if (!successCount) {
//         recapAvgRespEl.textContent = '0.000 ms';
//         recapMinRespEl.textContent = '0.000 ms';
//         recapMaxRespEl.textContent = '0.000 ms';
//         recapAvgLatEl.textContent = '0.000 ms';
//         recapAvgTputEl.textContent = '0.000 KB/s';
//         recapAvgCpuEl.textContent = '0.000 ms';
//         recapAvgRssEl.textContent = '0.00 MB';
//         recapAvgHeapEl.textContent = '0.00 MB';
//     } else {
//         const respList = successRows.map((r) => r.responseTimeMs);
//         const avg = (arr, key) => arr.reduce((acc, item) => acc + item[key], 0) / arr.length;

//         recapAvgRespEl.textContent = `${(respList.reduce((a, b) => a + b, 0) / respList.length).toFixed(3)} ms`;
//         recapMinRespEl.textContent = `${Math.min(...respList).toFixed(3)} ms`;
//         recapMaxRespEl.textContent = `${Math.max(...respList).toFixed(3)} ms`;

//         recapAvgLatEl.textContent = `${avg(successRows, 'latencyMs').toFixed(3)} ms`;
//         recapAvgTputEl.textContent = `${avg(successRows, 'throughputKBs').toFixed(3)} KB/s`;
//         recapAvgCpuEl.textContent = `${avg(successRows, 'cpuServerMs').toFixed(3)} ms`;
//         recapAvgRssEl.textContent = `${avg(successRows, 'ramRssMb').toFixed(2)} MB`;
//         recapAvgHeapEl.textContent = `${avg(successRows, 'ramHeapMb').toFixed(2)} MB`;
//     }

//     if (isFinished) {
//         recapFooterStatusEl.style.display = 'inline-block';
//         exportInfoEl.textContent = 'Hasil pengujian siap diunduh.';
//         btnExportCsv.disabled = false;
//     } else {
//         recapFooterStatusEl.style.display = 'none';
//         exportInfoEl.textContent = `Sedang memproses ${total} baris data...`;
//         btnExportCsv.disabled = true;
//     }
// }

// function sleep(ms) {
//     return new Promise((resolve) => setTimeout(resolve, ms));
// }

// batchForm.addEventListener('submit', async (e) => {
//     e.preventDefault();

//     const rawCount = Number(batchCountInput.value);
//     const count = Math.max(
//         1,
//         Math.min(
//             MAX_BATCH_REQUESTS,
//             Number.isFinite(rawCount) && rawCount > 0 ? Math.floor(rawCount) : 1
//         )
//     );
//     batchCountInput.value = count;

//     const prefix = batchPrefixInput.value || 'AES-GCM Batch #';

//     batchRecords = [];
//     lastBatchElapsedMs = 0;
//     renderBatchTable(batchRecords);
//     updateRecap(batchRecords, 0, false);

//     btnBatchStart.disabled = true;
//     btnManualSend.disabled = true;
//     batchStatusTextEl.textContent = 'Status: Sedang berjalan...';
//     progressTextEl.textContent = `0 / ${count}`;
//     progressFillEl.style.width = '0%';

//     const batchStartT = performance.now();

//     for (let i = 1; i <= count; i++) {
//         try {
//             const res = await sendMessageRequest(`${prefix} ${i}`, i);
//             batchRecords.push(res);
//         } catch (err) {
//             batchRecords.push({
//                 seq: i,
//                 httpStatus: 0,
//                 ok: false,
//                 responseTimeMs: 0,
//                 latencyMs: 0,
//                 throughputKBs: 0,
//                 totalBytes: 0,
//                 cryptoProcessMs: 0,
//                 cpuServerMs: 0,
//                 ramRssMb: 0,
//                 ramHeapMb: 0
//             });
//         }

//         lastBatchElapsedMs = Number((performance.now() - batchStartT).toFixed(3));

//         const pct = Math.round((i / count) * 100);
//         progressTextEl.textContent = `${i} / ${count}`;
//         progressFillEl.style.width = `${pct}%`;

//         renderBatchTable(batchRecords);
//         updateRecap(batchRecords, lastBatchElapsedMs, false);

//         if (i < count) {
//             await sleep(10);
//         }
//     }

//     lastBatchElapsedMs = Number((performance.now() - batchStartT).toFixed(3));
//     updateRecap(batchRecords, lastBatchElapsedMs, true);

//     batchStatusTextEl.textContent = 'Status: Pengujian selesai';
//     btnBatchStart.disabled = false;
//     btnManualSend.disabled = false;
// });

// btnExportCsv.addEventListener('click', () => {
//     if (!batchRecords.length) return;

//     const headers = [
//         'Request',
//         'Status HTTP',
//         'Response Time (ms)',
//         'Latency (ms)',
//         'Throughput (KB/s)',
//         'Total Bytes',
//         'Crypto Process (ms)',
//         'CPU Server (ms)',
//         'RAM RSS (MB)',
//         'RAM Heap (MB)'
//     ];

//     const lines = [
//         headers.join(','),
//         ...batchRecords.map((r) =>
//             [
//                 r.seq,
//                 r.httpStatus,
//                 r.responseTimeMs,
//                 r.latencyMs,
//                 r.throughputKBs,
//                 r.totalBytes,
//                 r.cryptoProcessMs,
//                 r.cpuServerMs,
//                 r.ramRssMb,
//                 r.ramHeapMb
//             ].join(',')
//         )
//     ];

//     const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
//     const url = URL.createObjectURL(blob);
//     const a = document.createElement('a');
//     a.href = url;
//     a.download = `hasil-aes-256-gcm-${Date.now()}.csv`;
//     a.click();
//     URL.revokeObjectURL(url);
// });