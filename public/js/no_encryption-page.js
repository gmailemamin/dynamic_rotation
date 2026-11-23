const SCHEME_ID = 'no-encryption';
const MAX_BATCH_REQUESTS = 10000;

// DOM ELEMENTS
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

// GLOBAL STATE
let batchRecords = [];
let lastBatchElapsedMs = 0;

// UTILITIES
function sanitizeCount(rawVal) {
  const num = Number(rawVal);

  if (!Number.isFinite(num) || num <= 0) {
    return 1;
  }

  return Math.max(
    1,
    Math.min(MAX_BATCH_REQUESTS, Math.floor(num))
  );
}

function formatNumber(value, decimals = 3) {
  const number = Number(value ?? 0);

  return Number.isFinite(number)
    ? number.toFixed(decimals)
    : '0'.padEnd(decimals + 2, '0');
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

// BATCH INPUT HANDLERS
presetCountSelect?.addEventListener('change', () => {
  if (presetCountSelect.value) {
    customCountInput.value = presetCountSelect.value;

    batchCountTextEl.textContent =
      `0 / ${sanitizeCount(customCountInput.value)}`;
  }
});

customCountInput?.addEventListener('input', () => {
  const val = String(customCountInput.value);

  const match = Array.from(presetCountSelect.options)
    .find((opt) => opt.value === val);

  presetCountSelect.value = match ? val : '';

  const safeMax = sanitizeCount(val);

  batchCountTextEl.textContent = `0 / ${safeMax}`;
});

// REQUEST FUNCTION

async function sendNoEncryptionRequest(messageText, seq = null) {
  const payload = {
    seq,
    message: messageText,
    sentAt: new Date().toISOString()
  };

  const requestBody = JSON.stringify(payload);

  // Ukuran request aktual dalam UTF-8 bytes
  const requestBytes = new TextEncoder().encode(requestBody).length;

  // Response Time dimulai sebelum request dikirim
  const t0 = performance.now();

  const response = await fetch('/api/no-encryption/message', {
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
  const data = JSON.parse(responseText);

  if (!response.ok) {
    throw new Error(data?.error || `HTTP ${response.status}`);
  }

  const responseTimeMs = Number((t1 - t0).toFixed(3));

  const serverProcessingMs = Number(
    data?.metrics?.serverProcessMs ?? 0
  );

  const cryptoProcessingMs = Number(
    data?.metrics?.cryptoProcessMs ?? 0
  );

  const totalBytes = requestBytes + responseBytes;

  return {
    seq: seq ?? 1,

    httpStatus: response.status,
    ok: response.ok,

    responseTimeMs, serverProcessingMs, cryptoProcessingMs,
    requestBytes, responseBytes, totalBytes,

    cpuServerMs: Number(data?.metrics?.cpuServerMs ?? 0),
    ramRssMb: Number(data?.metrics?.ramRssMb ?? 0),
    ramHeapMb: Number(data?.metrics?.ramHeapMb ?? 0),

    echoMessage: data?.echoMessage ?? ''
  };
}

// MANUAL TESTING

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
    manualTimingEl.textContent =
      `Response Time: ${formatNumber(result.responseTimeMs)} ms | ` +
      `Server Processing: ${formatNumber(result.serverProcessingMs)} ms`;
    manualSummaryLineEl.textContent =
      `Pengujian berhasil. ` +
      `Response Time: ${formatNumber(result.responseTimeMs)} ms | ` +
      `Server Processing: ${formatNumber(result.serverProcessingMs)} ms | ` +
      `CPU Server: ${formatNumber(result.cpuServerMs)} ms | ` +
      `Data: ${result.totalBytes} bytes`;

  } catch (err) {
    manualStatusEl.textContent = `Gagal (${err.message})`;
    manualStatusEl.className = 'text-danger';
    manualSummaryLineEl.textContent =
      `Pengujian gagal: ${err.message}`;

  } finally {
    btnSendOne.disabled = false;
  }
});

// BATCH TABLE

function renderBatchTable(rows) {
  if (!rows.length) {
    batchTableBodyEl.innerHTML =
      '<tr><td colspan="8" class="empty-cell">' +
      'Belum ada data hasil pengujian batch.' +
      '</td></tr>';

    return;
  }

  batchTableBodyEl.innerHTML = rows
    .map((r) => `
            <tr>
                <td>${r.seq}</td>
                <td>${formatNumber(r.responseTimeMs)}</td>
                <td>${formatNumber(r.serverProcessingMs)}</td>
                <td>${r.totalBytes || 0}</td>
                <td>${formatNumber(r.cpuServerMs)}</td>
                <td>${formatNumber(r.ramRssMb, 2)}</td>
                <td>${formatNumber(r.ramHeapMb, 2)}</td>
                <td>${r.ok ? 'Success' : 'Failed'}</td>
            </tr>
        `)
    .join('');
}

// BATCH RECAP
function updateRecap(
  rows,
  batchElapsedMs = lastBatchElapsedMs,
  isFinished = false
) {
  const total = rows.length;
  const successRows = rows.filter((r) => r.ok);
  const successCount = successRows.length;
  const failedCount = total - successCount;

  recapTotalEl.textContent = `${total}`;
  recapSuccessEl.textContent = `${successCount}`;
  recapFailedEl.textContent = `${failedCount}`;

  // --------------------------------------------------------
  // Empty state
  // --------------------------------------------------------

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
    recapFooterDescEl.textContent =
      'Jalankan batch testing untuk mengunduh hasil CSV.';

    btnDownloadCsv.disabled = true;

    return;
  }

  // --------------------------------------------------------
  // Batch duration
  // --------------------------------------------------------

  const effectiveElapsedMs = batchElapsedMs > 0
    ? batchElapsedMs
    : rows.reduce(
      (acc, r) => acc + (r.responseTimeMs || 0),
      0
    );

  recapTotalTimeEl.textContent =
    `${formatNumber(effectiveElapsedMs)} ms`;

  // Request throughput batch
  const requestThroughput = effectiveElapsedMs > 0
    ? successCount / (effectiveElapsedMs / 1000)
    : 0;

  recapReqPerSecEl.textContent =
    `${formatNumber(requestThroughput)} request/detik`;

  recapSuccessRateEl.textContent =
    `${((successCount / total) * 100).toFixed(2)}%`;

  // Total payload bytes
  const totalBytes = sum(rows, 'totalBytes');

  recapBytesEl.textContent = `${totalBytes} bytes`;

  // --------------------------------------------------------
  // Successful request metrics
  // --------------------------------------------------------

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
    const rtList = successRows.map(
      (r) => r.responseTimeMs
    );

    // Average Response Time
    const avgResponseTime =
      rtList.reduce((a, b) => a + b, 0) / rtList.length;

    recapAvgRtEl.textContent =
      `${formatNumber(avgResponseTime)} ms`;

    recapMinRtEl.textContent =
      `${formatNumber(Math.min(...rtList))} ms`;

    recapMaxRtEl.textContent =
      `${formatNumber(Math.max(...rtList))} ms`;

    // Server Processing Time
    recapAvgLatEl.textContent =
      `${formatNumber(average(successRows, 'serverProcessingMs'))} ms`;

    // Payload Throughput for entire batch
    const payloadThroughputKBs = effectiveElapsedMs > 0
      ? (totalBytes / 1024) / (effectiveElapsedMs / 1000)
      : 0;

    recapAvgTpEl.textContent =
      `${formatNumber(payloadThroughputKBs)} KB/s`;

    // CPU
    recapAvgCpuEl.textContent =
      `${formatNumber(average(successRows, 'cpuServerMs'))} ms`;

    // Memory
    recapAvgRssEl.textContent =
      `${formatNumber(average(successRows, 'ramRssMb'), 2)} MB`;

    recapAvgHeapEl.textContent =
      `${formatNumber(average(successRows, 'ramHeapMb'), 2)} MB`;
  }

  // --------------------------------------------------------
  // Footer
  // --------------------------------------------------------

  if (isFinished) {
    recapFooterStatusEl.textContent = 'Pengujian batch selesai';
    recapFooterDescEl.textContent =
      'Hasil pengujian siap diunduh.';

    btnDownloadCsv.disabled = false;

  } else {
    recapFooterStatusEl.textContent = 'Sedang berjalan';
    recapFooterDescEl.textContent =
      `Memproses ${total} request data...`;

    btnDownloadCsv.disabled = true;
  }
}

// BATCH TESTING
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

  batchSummaryNoteEl.textContent =
    `Mengirim ${count} request...`;

  const tStart = performance.now();

  for (let i = 1; i <= count; i++) {
    try {
      const res = await sendNoEncryptionRequest(
        `${prefix} ${i}`,
        i
      );

      batchRecords.push(res);

    } catch (err) {
      batchRecords.push({
        seq: i,
        httpStatus: 0,
        ok: false,

        responseTimeMs: 0,
        serverProcessingMs: 0,
        cryptoProcessingMs: 0,

        requestBytes: 0,
        responseBytes: 0,
        totalBytes: 0,

        cpuServerMs: 0,
        ramRssMb: 0,
        ramHeapMb: 0,

        echoMessage: '',
        error: err.message
      });
    }

    lastBatchElapsedMs = Number(
      (performance.now() - tStart).toFixed(3)
    );

    batchCountTextEl.textContent =
      `${i} / ${count}`;

    batchProgressBarEl.style.width =
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
    (performance.now() - tStart).toFixed(3)
  );

  updateRecap(
    batchRecords,
    lastBatchElapsedMs,
    true
  );

  batchStatusTextEl.textContent = 'Status: Selesai';

  batchSummaryNoteEl.textContent =
    `Selesai mengirim ${count} request dalam ` +
    `${formatNumber(lastBatchElapsedMs)} ms.`;

  btnSendBatch.disabled = false;
  btnSendOne.disabled = false;
});

// CSV EXPORT

btnDownloadCsv?.addEventListener('click', () => {
  if (!batchRecords.length) return;

  const successfulRecords = batchRecords.filter(
    (r) => r.ok
  );

  const totalBytes = batchRecords.reduce(
    (total, r) => total + (Number(r.totalBytes) || 0),
    0
  );

  const requestThroughput = lastBatchElapsedMs > 0
    ? successfulRecords.length / (lastBatchElapsedMs / 1000)
    : 0;

  const payloadThroughputKBs = lastBatchElapsedMs > 0
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

  const rows = batchRecords.map((r) => [
    r.seq,
    r.httpStatus,
    r.ok,
    r.responseTimeMs,
    r.serverProcessingMs,
    r.cryptoProcessingMs,
    r.requestBytes,
    r.responseBytes,
    r.totalBytes,
    r.cpuServerMs,
    r.ramRssMb,
    r.ramHeapMb,
    lastBatchElapsedMs,
    requestThroughput,
    payloadThroughputKBs
  ]);

  // Konversi angka ke format desimal Indonesia
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
    ['﻿', csvContent],
    {
      type: 'text/csv;charset=utf-8;'
    }
  );

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');

  a.href = url;
  a.download = `hasil-no-encryption-${Date.now()}.csv`;

  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  URL.revokeObjectURL(url);
});