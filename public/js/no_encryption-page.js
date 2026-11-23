const SCHEME_ID = 'no-encryption';
const MAX_BATCH_REQUESTS = 10000;

const manualMessageInput = document.getElementById('manual-message-input');
const btnSendOne = document.getElementById('btn-send-one');
const manualOriginalMsgEl = document.getElementById('manual-original-msg');
const manualReceivedMsgEl = document.getElementById('manual-received-msg');
const manualStatusEl = document.getElementById('manual-status');
const manualTimingEl = document.getElementById('manual-timing');
const manualSummaryLineEl = document.getElementById('manual-summary-line');

const presetCountSelect = document.getElementById('preset-count');
const customCountInput = document.getElementById('custom-count');
const batchMessageInput = document.getElementById('batch-message-input');
const btnSendBatch = document.getElementById('btn-send-batch');

const batchStatusTextEl = document.getElementById('batch-status-text');
const batchCountTextEl = document.getElementById('batch-count-text');
const batchProgressBarEl = document.getElementById('batch-progress-bar');
const batchSummaryNoteEl = document.getElementById('batch-summary-note');
const batchTableBodyEl = document.getElementById('batch-table-body');

const recapTotalEl = document.getElementById('recap-total');
const recapSuccessEl = document.getElementById('recap-success');
const recapFailedEl = document.getElementById('recap-failed');

const recapAvgRtEl = document.getElementById('recap-avg-rt');
const recapMinRtEl = document.getElementById('recap-min-rt');
const recapMaxRtEl = document.getElementById('recap-max-rt');

const recapTotalTimeEl = document.getElementById('recap-total-time');
const recapReqPerSecEl = document.getElementById('recap-req-per-sec');
const recapSuccessRateEl = document.getElementById('recap-success-rate');

const recapAvgLatEl = document.getElementById('recap-avg-lat');
const recapAvgTpEl = document.getElementById('recap-avg-tp');
const recapBytesEl = document.getElementById('recap-bytes');

const recapAvgCpuEl = document.getElementById('recap-avg-cpu');
const recapAvgRssEl = document.getElementById('recap-avg-rss');
const recapAvgHeapEl = document.getElementById('recap-avg-heap');

const recapFooterStatusEl = document.getElementById('recap-footer-status');
const recapFooterDescEl = document.getElementById('recap-footer-desc');
const btnDownloadCsv = document.getElementById('btn-download-csv');

let batchRecords = [];
let lastBatchElapsedMs = 0;

function sanitizeCount(rawVal) {
  const num = Number(rawVal);
  if (!Number.isFinite(num) || num <= 0) return 1;
  return Math.max(1, Math.min(MAX_BATCH_REQUESTS, Math.floor(num)));
}

presetCountSelect?.addEventListener('change', () => {
  if (presetCountSelect.value) {
    customCountInput.value = presetCountSelect.value;
    batchCountTextEl.textContent = `0 / ${sanitizeCount(customCountInput.value)}`;
  }
});

customCountInput?.addEventListener('input', () => {
  const val = String(customCountInput.value);
  const match = Array.from(presetCountSelect.options).find((opt) => opt.value === val);
  presetCountSelect.value = match ? val : '';
  const safeMax = sanitizeCount(val);
  batchCountTextEl.textContent = `0 / ${safeMax}`;
});

async function sendNoEncryptionRequest(messageText, seq = null) {
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
  if (!response.ok) {
    throw new Error(data?.error || `HTTP ${response.status}`);
  }

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
    cpuServerMs: Number(data?.metrics?.cpuServerMs ?? 0),
    ramRssMb: Number(data?.metrics?.ramRssMb ?? 0),
    ramHeapMb: Number(data?.metrics?.ramHeapMb ?? 0),
    echoMessage: data?.echoMessage ?? ''
  };
}

btnSendOne?.addEventListener('click', async () => {
  const text = manualMessageInput.value;
  btnSendOne.disabled = true;
  manualStatusEl.textContent = 'Mengirim...';
  manualStatusEl.className = '';

  try {
    const result = await sendNoEncryptionRequest(text, null);
    manualOriginalMsgEl.textContent = text || '-';
    manualReceivedMsgEl.textContent = result.echoMessage || '-';
    manualStatusEl.textContent = 'Berhasil';
    manualStatusEl.className = 'text-success';
    manualTimingEl.textContent = `${result.responseTimeMs.toFixed(3)} ms (Latency: ${result.latencyMs.toFixed(3)} ms)`;
    manualSummaryLineEl.textContent =
      `Pengujian berhasil. Response: ${result.responseTimeMs.toFixed(3)} ms | Throughput: ${result.throughputKBs.toFixed(2)} KB/s | CPU Server: ${result.cpuServerMs.toFixed(3)} ms`;
  } catch (err) {
    manualStatusEl.textContent = `Gagal (${err.message})`;
    manualStatusEl.className = 'text-danger';
    manualSummaryLineEl.textContent = `Pengujian gagal: ${err.message}`;
  } finally {
    btnSendOne.disabled = false;
  }
});

function renderBatchTable(rows) {
  if (!rows.length) {
    batchTableBodyEl.innerHTML =
      '<tr><td colspan="8" class="empty-cell">Belum ada data hasil pengujian batch.</td></tr>';
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

  recapTotalEl.textContent = `${total}`;
  recapSuccessEl.textContent = `${successCount}`;
  recapFailedEl.textContent = `${failedCount}`;

  if (!total) {
    recapAvgRtEl.textContent = '0.000 ms';
    recapMinRtEl.textContent = '0.000 ms';
    recapMaxRtEl.textContent = '0.000 ms';
    recapTotalTimeEl.textContent = '0.000 ms';
    recapReqPerSecEl.textContent = '0.000 request/detik';
    recapSuccessRateEl.textContent = '0.00%';
    recapAvgLatEl.textContent = '0.000 ms';
    recapAvgTpEl.textContent = '0.000 KB/s';
    recapBytesEl.textContent = '0 bytes';
    recapAvgCpuEl.textContent = '0.000 ms';
    recapAvgRssEl.textContent = '0.00 MB';
    recapAvgHeapEl.textContent = '0.00 MB';
    recapFooterStatusEl.textContent = 'Siap menguji';
    recapFooterDescEl.textContent = 'Jalankan batch testing untuk mengunduh hasil CSV.';
    btnDownloadCsv.disabled = true;
    return;
  }

  const effectiveElapsedMs = batchElapsedMs > 0
    ? batchElapsedMs
    : rows.reduce((acc, r) => acc + (r.responseTimeMs || 0), 0);

  recapTotalTimeEl.textContent = `${effectiveElapsedMs.toFixed(3)} ms`;
  recapReqPerSecEl.textContent =
    `${(effectiveElapsedMs > 0 ? successCount / (effectiveElapsedMs / 1000) : 0).toFixed(3)} request/detik`;
  recapSuccessRateEl.textContent = `${((successCount / total) * 100).toFixed(2)}%`;
  recapBytesEl.textContent = `${rows.reduce((acc, r) => acc + (r.totalBytes || 0), 0)} bytes`;

  if (!successCount) {
    recapAvgRtEl.textContent = '0.000 ms';
    recapMinRtEl.textContent = '0.000 ms';
    recapMaxRtEl.textContent = '0.000 ms';
    recapAvgLatEl.textContent = '0.000 ms';
    recapAvgTpEl.textContent = '0.000 KB/s';
    recapAvgCpuEl.textContent = '0.000 ms';
    recapAvgRssEl.textContent = '0.00 MB';
    recapAvgHeapEl.textContent = '0.00 MB';
  } else {
    const rtList = successRows.map((r) => r.responseTimeMs);
    const avg = (key) => successRows.reduce((acc, r) => acc + r[key], 0) / successRows.length;

    recapAvgRtEl.textContent = `${(rtList.reduce((a, b) => a + b, 0) / rtList.length).toFixed(3)} ms`;
    recapMinRtEl.textContent = `${Math.min(...rtList).toFixed(3)} ms`;
    recapMaxRtEl.textContent = `${Math.max(...rtList).toFixed(3)} ms`;
    recapAvgLatEl.textContent = `${avg('latencyMs').toFixed(3)} ms`;
    recapAvgTpEl.textContent = `${avg('throughputKBs').toFixed(3)} KB/s`;
    recapAvgCpuEl.textContent = `${avg('cpuServerMs').toFixed(3)} ms`;
    recapAvgRssEl.textContent = `${avg('ramRssMb').toFixed(2)} MB`;
    recapAvgHeapEl.textContent = `${avg('ramHeapMb').toFixed(2)} MB`;
  }

  if (isFinished) {
    recapFooterStatusEl.textContent = 'Pengujian batch selesai';
    recapFooterDescEl.textContent = 'Hasil pengujian siap diunduh.';
    btnDownloadCsv.disabled = false;
  } else {
    recapFooterStatusEl.textContent = 'Sedang berjalan';
    recapFooterDescEl.textContent = `Memproses ${total} baris data...`;
    btnDownloadCsv.disabled = true;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

btnSendBatch?.addEventListener('click', async () => {
  const count = sanitizeCount(customCountInput.value);
  customCountInput.value = count;
  const prefix = batchMessageInput.value || 'No Encryption Batch #';

  batchRecords = [];
  lastBatchElapsedMs = 0;
  renderBatchTable(batchRecords);
  updateRecap(batchRecords, 0, false);

  btnSendBatch.disabled = true;
  btnSendOne.disabled = true;
  batchStatusTextEl.textContent = 'Status: Sedang berjalan...';
  batchCountTextEl.textContent = `0 / ${count}`;
  batchProgressBarEl.style.width = '0%';
  batchSummaryNoteEl.textContent = `Mengirim ${count} request...`;

  const tStart = performance.now();

  for (let i = 1; i <= count; i++) {
    try {
      const res = await sendNoEncryptionRequest(`${prefix} ${i}`, i);
      batchRecords.push(res);
    } catch {
      batchRecords.push({
        seq: i,
        httpStatus: 0,
        ok: false,
        responseTimeMs: 0,
        latencyMs: 0,
        throughputKBs: 0,
        totalBytes: 0,
        cpuServerMs: 0,
        ramRssMb: 0,
        ramHeapMb: 0
      });
    }

    lastBatchElapsedMs = Number((performance.now() - tStart).toFixed(3));
    batchCountTextEl.textContent = `${i} / ${count}`;
    batchProgressBarEl.style.width = `${Math.round((i / count) * 100)}%`;

    renderBatchTable(batchRecords);
    updateRecap(batchRecords, lastBatchElapsedMs, false);

    if (i < count) {
      await sleep(10);
    }
  }

  lastBatchElapsedMs = Number((performance.now() - tStart).toFixed(3));
  updateRecap(batchRecords, lastBatchElapsedMs, true);

  batchStatusTextEl.textContent = 'Status: Selesai';
  batchSummaryNoteEl.textContent = `Selesai mengirim ${count} request dalam ${lastBatchElapsedMs.toFixed(3)} ms.`;
  btnSendBatch.disabled = false;
  btnSendOne.disabled = false;
});

btnDownloadCsv?.addEventListener('click', () => {
  if (!batchRecords.length) return;

  const headers = [
    'Request',
    'Status HTTP',
    'Response Time (ms)',
    'Latency (ms)',
    'Throughput (KB/s)',
    'Total Bytes',
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
  a.download = `hasil-no-encryption-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
});