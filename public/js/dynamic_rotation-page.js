const SCHEME_ID = 'dynamic-rotation';
const MAX_BATCH_REQUESTS = 10000;

const cfgMaxRequestsInput = document.getElementById('cfgMaxRequests');
const cfgIntervalSecSelect = document.getElementById('cfgIntervalSec');
const btnStartSession = document.getElementById('btnStartSession');
const btnEndSession = document.getElementById('btnEndSession');

const statusPublicKeyEl = document.getElementById('statusPublicKey');
const statusSessionStateEl = document.getElementById('statusSessionState');
const statusSessionIdEl = document.getElementById('statusSessionId');
const statusPublicKeyBitsEl = document.getElementById('statusPublicKeyBits');

const statCurrentTimeEl = document.getElementById('statCurrentTime');
const statCurrentDateEl = document.getElementById('statCurrentDate');
const statTotalRequestsEl = document.getElementById('statTotalRequests');
const statRotationCountEl = document.getElementById('statRotationCount');
const statRotationThresholdEl = document.getElementById('statRotationThreshold');
const statIntervalLabelEl = document.getElementById('statIntervalLabel');
const statSinceLastRotationEl = document.getElementById('statSinceLastRotation');
const statUntilNextRotationEl = document.getElementById('statUntilNextRotation');
const statLastRotationClockEl = document.getElementById('statLastRotationClock');

const manualForm = document.getElementById('manualForm');
const manualMessageInput = document.getElementById('manualMessage');
const forceRotateCheckInput = document.getElementById('forceRotateCheck');
const btnManualSend = document.getElementById('btnManualSend');

const rotSessionBoxEl = document.getElementById('rotSessionBox');
const rotIvTagBoxEl = document.getElementById('rotIvTagBox');
const rotCipherBoxEl = document.getElementById('rotCipherBox');
const rotDecryptedBoxEl = document.getElementById('rotDecryptedBox');
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

let batchRecords = [];
let lastBatchElapsedMs = 0;

let sessionStats = {
    active: false,
    totalRequests: 0,
    rotationCount: 0,
    lastRotationMs: 0
};

function sanitizePositiveInt(rawVal, fallback, max = MAX_BATCH_REQUESTS) {
    const cleaned = String(rawVal ?? '').replace(/[^\d]/g, '');
    const num = Number(cleaned);
    if (!Number.isFinite(num) || num <= 0) return fallback;
    return Math.max(1, Math.min(max, Math.floor(num)));
}

function getRotationThreshold() {
    const val = sanitizePositiveInt(cfgMaxRequestsInput?.value, 100, MAX_BATCH_REQUESTS);
    if (cfgMaxRequestsInput) cfgMaxRequestsInput.value = String(val);
    return val;
}

function getRotationIntervalSec() {
    return Math.max(1, Number(cfgIntervalSecSelect?.value) || 300);
}

function formatIntervalText(sec) {
    if (sec % 60 === 0) {
        return `${sec / 60} menit`;
    }
    return `${sec} detik`;
}

function formatClockDot(dateObj) {
    const hh = String(dateObj.getHours()).padStart(2, '0');
    const mm = String(dateObj.getMinutes()).padStart(2, '0');
    const ss = String(dateObj.getSeconds()).padStart(2, '0');
    return `${hh}.${mm}.${ss}`;
}

function formatDurationHms(totalSec) {
    const clamped = Math.max(0, Math.floor(totalSec));
    const hh = String(Math.floor(clamped / 3600)).padStart(2, '0');
    const mm = String(Math.floor((clamped % 3600) / 60)).padStart(2, '0');
    const ss = String(clamped % 60).padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
}

function applySessionLockUI(isActive) {
    btnEndSession.disabled = !isActive;
    btnManualSend.disabled = !isActive;
    btnBatchStart.disabled = !isActive;

    if (isActive) {
        btnManualSend.innerHTML = '&#10148; Kirim &amp; Uji Dynamic Rotation';
        btnBatchStart.innerHTML = '&#9654; Mulai Batch Testing';
        if (manualStatusEl.textContent === 'Menunggu aktivasi sesi') {
            manualStatusEl.textContent = 'Siap';
            manualSummaryLineEl.textContent = 'Sesi aktif. Menunggu pengujian manual dijalankan.';
        }
        if (batchStatusTextEl.textContent === 'Status: Sesi belum aktif') {
            batchStatusTextEl.textContent = 'Status: Menunggu pengujian';
        }
    } else {
        btnManualSend.innerHTML = '&#10148; Aktifkan Sesi Terlebih Dahulu';
        btnBatchStart.innerHTML = '&#9654; Aktifkan Sesi Terlebih Dahulu';
        manualStatusEl.textContent = 'Menunggu aktivasi sesi';
        manualStatusEl.className = '';
        manualSummaryLineEl.textContent = 'Klik tombol "Mulai Sesi" di atas sebelum melakukan pengujian.';
        batchStatusTextEl.textContent = 'Status: Sesi belum aktif';
    }
}

let lastSyncedRotationMs = 0;

function renderSessionStatistics() {
    const now = new Date();
    statCurrentTimeEl.textContent = formatClockDot(now);
    statCurrentDateEl.textContent = now.toLocaleDateString('id-ID', {
        weekday: 'long',
        day: 'numeric',
        month: 'long',
        year: 'numeric'
    });

    const threshold = sanitizePositiveInt(cfgMaxRequestsInput?.value, 100, MAX_BATCH_REQUESTS);
    const intervalSec = getRotationIntervalSec();

    statTotalRequestsEl.textContent = `${sessionStats.totalRequests}`;
    statRotationCountEl.textContent = `${sessionStats.rotationCount}`;
    statRotationThresholdEl.textContent = `${threshold}`;
    statIntervalLabelEl.textContent = formatIntervalText(intervalSec);

    if (!sessionStats.active || !sessionStats.lastRotationMs) {
        statSinceLastRotationEl.textContent = '00:00:00';
        statUntilNextRotationEl.textContent = '00:00:00';
        statLastRotationClockEl.textContent = '-';
        return;
    }

    const elapsedSec = Math.max(0, (Date.now() - sessionStats.lastRotationMs) / 1000);
    const remainingSec = Math.max(0, intervalSec - elapsedSec);

    statSinceLastRotationEl.textContent = formatDurationHms(elapsedSec);
    statUntilNextRotationEl.textContent = formatDurationHms(remainingSec);
    statLastRotationClockEl.textContent = formatClockDot(new Date(sessionStats.lastRotationMs));

    if (elapsedSec >= intervalSec && lastSyncedRotationMs !== sessionStats.lastRotationMs) {
        lastSyncedRotationMs = sessionStats.lastRotationMs;
        fetch('/api/session')
            .then((res) => res.json())
            .then((data) => {
                if (data && data.active) {
                    updateSessionStatusUI({
                        active: true,
                        sessionId: data.sessionId,
                        publicKeyVerified: data.publicKeyVerified ?? true,
                        keyBits: data.keyBits ?? 2048,
                        totalRequests: data.totalRequests ?? sessionStats.totalRequests,
                        rotationCount: data.totalRotations ?? sessionStats.rotationCount,
                        lastRotationMs: data.lastRotationMs || Date.now()
                    });
                }
            })
            .catch(() => { });
    }
}

function updateSessionStatusUI({
    active,
    sessionId,
    publicKeyVerified = true,
    keyBits = 2048,
    totalRequests,
    rotationCount,
    lastRotationMs
}) {
    if (typeof active === 'boolean') sessionStats.active = active;
    if (typeof totalRequests === 'number') sessionStats.totalRequests = totalRequests;
    if (typeof rotationCount === 'number') sessionStats.rotationCount = rotationCount;
    if (typeof lastRotationMs === 'number' && lastRotationMs > 0) {
        sessionStats.lastRotationMs = lastRotationMs;
    }

    statusPublicKeyEl.textContent = publicKeyVerified ? 'Public key terverifikasi' : 'Belum terverifikasi';
    statusSessionStateEl.textContent = sessionStats.active ? 'Session aktif' : 'Sesi belum aktif';
    statusSessionStateEl.style.color = sessionStats.active ? '#fbbf24' : '#f87171';
    statusSessionIdEl.textContent = sessionStats.active && sessionId ? sessionId : '-';
    statusPublicKeyBitsEl.textContent = `${keyBits} bit`;

    applySessionLockUI(sessionStats.active);
    renderSessionStatistics();
}

cfgMaxRequestsInput?.addEventListener('input', () => {
    renderSessionStatistics();
});

cfgMaxRequestsInput?.addEventListener('change', () => {
    getRotationThreshold();
    renderSessionStatistics();
});

cfgIntervalSecSelect?.addEventListener('change', () => {
    renderSessionStatistics();
});

async function callSessionEndpoint(action) {
    const response = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            action,
            rotationIntervalMessages: getRotationThreshold(),
            rotationIntervalSec: getRotationIntervalSec()
        })
    });
    return response.json();
}

btnStartSession?.addEventListener('click', async () => {
    btnStartSession.disabled = true;
    try {
        const data = await callSessionEndpoint('start');
        updateSessionStatusUI({
            active: true,
            sessionId: data.sessionId,
            publicKeyVerified: data.publicKeyVerified ?? true,
            keyBits: data.keyBits ?? 2048,
            totalRequests: data.totalRequests ?? 0,
            rotationCount: data.totalRotations ?? 1,
            lastRotationMs: data.lastRotationMs ?? Date.now()
        });
    } catch (err) {
        console.error('Gagal memulai sesi:', err);
    } finally {
        btnStartSession.disabled = false;
    }
});

btnEndSession?.addEventListener('click', async () => {
    btnEndSession.disabled = true;
    try {
        const data = await callSessionEndpoint('end');
        sessionStats.lastRotationMs = 0;
        updateSessionStatusUI({
            active: false,
            sessionId: null,
            publicKeyVerified: data.publicKeyVerified ?? true,
            keyBits: data.keyBits ?? 2048,
            totalRequests: data.totalRequests ?? 0,
            rotationCount: data.totalRotations ?? 0
        });
    } catch (err) {
        console.error('Gagal mengakhiri sesi:', err);
    }
});

// Inisialisasi awal & interval tick 1 detik
updateSessionStatusUI({ active: false, sessionId: null });
setInterval(renderSessionStatistics, 1000);

(async function initSessionStatus() {
    try {
        const res = await fetch('/api/session');
        const data = await res.json();
        updateSessionStatusUI({
            active: Boolean(data.active),
            sessionId: data.sessionId || null,
            publicKeyVerified: data.publicKeyVerified ?? true,
            keyBits: data.keyBits ?? 2048,
            totalRequests: data.totalRequests ?? 0,
            rotationCount: data.totalRotations ?? 0,
            lastRotationMs: data.lastRotationMs ?? 0
        });
    } catch {
        updateSessionStatusUI({ active: false, sessionId: null });
    }
})();

// Sinkronisasi preset & input manual untuk "Batch Testing"
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

async function sendMessageRequest(messageText, seq = null, extraOptions = {}) {
    if (!sessionStats.active) {
        throw new Error('Sesi belum aktif. Klik "Mulai Sesi" terlebih dahulu.');
    }

    const payload = {
        scheme: SCHEME_ID,
        seq,
        message: messageText,
        rotationIntervalMessages: getRotationThreshold(),
        rotationIntervalSec: getRotationIntervalSec(),
        forceRotate: Boolean(extraOptions.forceRotate),
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
    if (!response.ok) {
        throw new Error(data?.error || `HTTP ${response.status}`);
    }

    sessionStats.totalRequests += 1;
    if (data?.crypto?.rotatedThisRequest) {
        sessionStats.lastRotationMs = Date.now();
    }

    updateSessionStatusUI({
        active: true,
        sessionId: data?.crypto?.keyId || statusSessionIdEl.textContent,
        publicKeyVerified: true,
        keyBits: 2048,
        totalRequests: sessionStats.totalRequests,
        rotationCount: typeof data?.crypto?.rotationCount === 'number'
            ? data.crypto.rotationCount
            : sessionStats.rotationCount,
        lastRotationMs: sessionStats.lastRotationMs
    });

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
    if (!sessionStats.active) {
        manualStatusEl.textContent = 'Gagal (Sesi belum aktif)';
        manualStatusEl.className = 'text-danger';
        manualSummaryLineEl.textContent = 'Klik tombol "Mulai Sesi" terlebih dahulu.';
        return;
    }

    const text = manualMessageInput.value;
    const isForced = Boolean(forceRotateCheckInput?.checked);

    btnManualSend.disabled = true;
    manualStatusEl.textContent = 'Mengirim...';
    manualStatusEl.className = '';

    try {
        const result = await sendMessageRequest(text, null, { forceRotate: isForced });
        if (forceRotateCheckInput) {
            forceRotateCheckInput.checked = false;
        }

        manualStatusEl.textContent = result.crypto?.rotatedThisRequest
            ? 'Berhasil (Kunci Sesi Baru Dirotasi)'
            : 'Berhasil (Sesi Kunci Aktif)';
        manualStatusEl.className = 'text-success';
        manualTimingEl.textContent =
            `${result.responseTimeMs.toFixed(3)} ms (Latency: ${result.latencyMs.toFixed(3)} ms | Kripto: ${result.cryptoProcessMs.toFixed(3)} ms)`;

        if (result.crypto) {
            rotSessionBoxEl.textContent =
                `Key ID: ${result.crypto.keyId} | Rotasi ke-${result.crypto.rotationCount} (${result.crypto.rotationReason}) | Pesan pd Kunci: ${result.crypto.messagesInCurrentKey}`;
            rotIvTagBoxEl.textContent =
                `IV: ${result.crypto.ivHex}\nTag: ${result.crypto.authTagHex}`;
            rotCipherBoxEl.textContent = result.crypto.ciphertextHex || '-';
            rotDecryptedBoxEl.textContent = result.crypto.decryptedMessage || '-';
        } else {
            rotSessionBoxEl.textContent = 'Key ID: - | Rotasi: - | Pesan pd Kunci: -';
            rotIvTagBoxEl.textContent = 'IV: - | Tag: -';
            rotCipherBoxEl.textContent = '-';
            rotDecryptedBoxEl.textContent = result.echoMessage || '-';
        }

        manualSummaryLineEl.textContent =
            `Pengujian berhasil. Response: ${result.responseTimeMs.toFixed(3)} ms | Throughput: ${result.throughputKBs.toFixed(2)} KB/s | CPU Server: ${result.cpuServerMs.toFixed(3)} ms`;
    } catch (err) {
        manualStatusEl.textContent = `Gagal (${err.message})`;
        manualStatusEl.className = 'text-danger';
        manualSummaryLineEl.textContent = `Pengujian gagal: ${err.message}`;
    } finally {
        btnManualSend.disabled = !sessionStats.active;
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
    if (!sessionStats.active) {
        batchStatusTextEl.textContent = 'Status: Aktifkan sesi terlebih dahulu sebelum batch testing';
        return;
    }

    const count = sanitizePositiveInt(batchCountInput.value, 1, MAX_BATCH_REQUESTS);
    batchCountInput.value = count;

    const prefix = batchPrefixInput.value || 'Dynamic Rotation Batch #';

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
        if (!sessionStats.active) break;

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
    applySessionLockUI(sessionStats.active);
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
    a.download = `hasil-dynamic-rotation-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
});