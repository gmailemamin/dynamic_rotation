const SCHEME_ID = 'aes-256-gcm';

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

const MAX_BATCH_REQUESTS = 10000;

let batchRecords = [];
let lastBatchElapsedMs = 0;

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
    const payload = {
        scheme: SCHEME_ID,
        seq,
        message: messageText,
        sentAt: new Date().toISOString()
    };

    const t0 = performance.now();
    const response = await fetch('/api/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const t1 = performance.now();

    const data = await response.json();
    const responseTimeMs = Number((t1 - t0).toFixed(3));
    const serverMs = Number(data?.metrics?.serverProcessMs ?? 0);
    const latencyMs = Number(Math.max(0.001, responseTimeMs - serverMs).toFixed(3));

    const totalBytes = Number(
        data?.metrics?.totalBytes ??
        new TextEncoder().encode(JSON.stringify(payload) + JSON.stringify(data)).length
    );
    const throughputKBs = Number(((totalBytes / 1024) / (responseTimeMs / 1000)).toFixed(3));

    return {
        seq: seq ?? 1,
        httpStatus: response.status,
        ok: response.ok,
        responseTimeMs,
        latencyMs,
        throughputKBs,
        totalBytes,
        cryptoProcessMs: Number(data?.metrics?.cryptoProcessMs ?? data?.crypto?.cryptoProcessMs ?? 0),
        cpuServerMs: Number(data?.metrics?.cpuServerMs ?? 0),
        ramRssMb: Number(data?.metrics?.ramRssMb ?? 0),
        ramHeapMb: Number(data?.metrics?.ramHeapMb ?? 0),
        crypto: data?.crypto || null,
        echoMessage: data?.echoMessage ?? ''
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
        manualStatusEl.textContent = 'Berhasil (AEAD Terverifikasi)';
        manualStatusEl.className = 'text-success';
        manualTimingEl.textContent =
            `${result.responseTimeMs.toFixed(3)} ms (Latency: ${result.latencyMs.toFixed(3)} ms | Kripto: ${result.cryptoProcessMs.toFixed(3)} ms)`;

        if (result.crypto) {
            aesIvTagBoxEl.textContent = `IV: ${result.crypto.ivHex}\nTag: ${result.crypto.authTagHex}`;
            aesCipherBoxEl.textContent = result.crypto.ciphertextHex || '-';
            aesDecryptedBoxEl.textContent = result.crypto.decryptedMessage || '-';
        } else {
            aesIvTagBoxEl.textContent = 'IV: - | Tag: -';
            aesCipherBoxEl.textContent = '-';
            aesDecryptedBoxEl.textContent = result.echoMessage || '-';
        }

        manualSummaryLineEl.textContent =
            `Pengujian berhasil. Response: ${result.responseTimeMs.toFixed(3)} ms | Throughput: ${result.throughputKBs.toFixed(2)} KB/s | CPU Server: ${result.cpuServerMs.toFixed(3)} ms`;
    } catch (err) {
        manualStatusEl.textContent = `Gagal (${err.message})`;
        manualStatusEl.className = 'text-danger';
    } finally {
        btnManualSend.disabled = false;
    }
});

function renderBatchTable(rows) {
    if (!rows.length) {
        batchTableBodyEl.innerHTML =
            '<tr><td colspan="8" class="empty-cell">Belum ada data pengujian batch.</td></tr>';
        return;
    }

    batchTableBodyEl.innerHTML = rows
        .map(
            (r) => `
      <tr>
        <td>${r.seq}</td>
        <td>${r.responseTimeMs.toFixed(3)}</td>
        <td>${r.latencyMs.toFixed(3)}</td>
        <td>${r.throughputKBs.toFixed(3)}</td>
        <td>${r.totalBytes}</td>
        <td>${r.cpuServerMs.toFixed(3)}</td>
        <td>${r.ramRssMb.toFixed(2)}</td>
        <td>${r.ramHeapMb.toFixed(2)}</td>
      </tr>
    `
        )
        .join('');
}

function updateRecap(rows, batchElapsedMs = lastBatchElapsedMs, isFinished = false) {
    const total = rows.length;
    const successRows = rows.filter((r) => r.ok);
    const successCount = successRows.length;
    const failedCount = total - successCount;

    recapTotalReqEl.textContent = `${total}`;
    recapSuccessCountEl.textContent = `${successCount}`;
    recapFailedCountEl.textContent = `${failedCount}`;

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
        exportInfoEl.textContent = 'Hasil pengujian belum tersedia untuk diunduh.';
        btnExportCsv.disabled = true;
        return;
    }

    const successRate = (successCount / total) * 100;
    recapSuccessRateEl.textContent = `${successRate.toFixed(2)}%`;

    const effectiveElapsedMs = batchElapsedMs > 0
        ? batchElapsedMs
        : rows.reduce((acc, r) => acc + (r.responseTimeMs || 0), 0);

    recapTotalTimeEl.textContent = `${effectiveElapsedMs.toFixed(3)} ms`;
    const rps = effectiveElapsedMs > 0 ? (successCount / (effectiveElapsedMs / 1000)) : 0;
    recapRpsEl.textContent = `${rps.toFixed(3)} request/detik`;

    const totalBytesSum = rows.reduce((acc, r) => acc + (r.totalBytes || 0), 0);
    recapTotalBytesEl.textContent = `${totalBytesSum} bytes`;

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
        const respList = successRows.map((r) => r.responseTimeMs);
        const avg = (arr, key) => arr.reduce((acc, item) => acc + item[key], 0) / arr.length;

        recapAvgRespEl.textContent = `${(respList.reduce((a, b) => a + b, 0) / respList.length).toFixed(3)} ms`;
        recapMinRespEl.textContent = `${Math.min(...respList).toFixed(3)} ms`;
        recapMaxRespEl.textContent = `${Math.max(...respList).toFixed(3)} ms`;

        recapAvgLatEl.textContent = `${avg(successRows, 'latencyMs').toFixed(3)} ms`;
        recapAvgTputEl.textContent = `${avg(successRows, 'throughputKBs').toFixed(3)} KB/s`;
        recapAvgCpuEl.textContent = `${avg(successRows, 'cpuServerMs').toFixed(3)} ms`;
        recapAvgRssEl.textContent = `${avg(successRows, 'ramRssMb').toFixed(2)} MB`;
        recapAvgHeapEl.textContent = `${avg(successRows, 'ramHeapMb').toFixed(2)} MB`;
    }

    if (isFinished) {
        recapFooterStatusEl.style.display = 'inline-block';
        exportInfoEl.textContent = 'Hasil pengujian siap diunduh.';
        btnExportCsv.disabled = false;
    } else {
        recapFooterStatusEl.style.display = 'none';
        exportInfoEl.textContent = `Sedang memproses ${total} baris data...`;
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
                latencyMs: 0,
                throughputKBs: 0,
                totalBytes: 0,
                cryptoProcessMs: 0,
                cpuServerMs: 0,
                ramRssMb: 0,
                ramHeapMb: 0
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

    lastBatchElapsedMs = Number((performance.now() - batchStartT).toFixed(3));
    updateRecap(batchRecords, lastBatchElapsedMs, true);

    batchStatusTextEl.textContent = 'Status: Pengujian selesai';
    btnBatchStart.disabled = false;
    btnManualSend.disabled = false;
});

btnExportCsv.addEventListener('click', () => {
    if (!batchRecords.length) return;

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

    const lines = [
        headers.join(','),
        ...batchRecords.map((r) =>
            [
                r.seq,
                r.httpStatus,
                r.responseTimeMs,
                r.latencyMs,
                r.throughputKBs,
                r.totalBytes,
                r.cryptoProcessMs,
                r.cpuServerMs,
                r.ramRssMb,
                r.ramHeapMb
            ].join(',')
        )
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hasil-aes-256-gcm-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
});