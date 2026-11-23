const scheme = document.body.dataset.scheme || 'no-encryption';

// Elemen Uji Manual
const manualMessageInput = document.getElementById('manual-message-input');
const btnSendOne = document.getElementById('btn-send-one');
const manualOriginalMsg = document.getElementById('manual-original-msg');
const manualReceivedMsg = document.getElementById('manual-received-msg');
const manualStatus = document.getElementById('manual-status');
const manualTiming = document.getElementById('manual-timing');
const manualSummaryLine = document.getElementById('manual-summary-line');

// Elemen Uji Otomatis (Batch)
const presetCount = document.getElementById('preset-count');
const customCount = document.getElementById('custom-count');
const batchMessageInput = document.getElementById('batch-message-input');
const btnSendBatch = document.getElementById('btn-send-batch');

const batchStatusText = document.getElementById('batch-status-text');
const batchCountText = document.getElementById('batch-count-text');
const batchProgressBar = document.getElementById('batch-progress-bar');
const batchSummaryNote = document.getElementById('batch-summary-note');
const batchTableBody = document.getElementById('batch-table-body');

// Elemen Rekapitulasi Batch
const recapTotal = document.getElementById('recap-total');
const recapSuccess = document.getElementById('recap-success');
const recapFailed = document.getElementById('recap-failed');
const recapAvgRt = document.getElementById('recap-avg-rt');
const recapMinRt = document.getElementById('recap-min-rt');
const recapMaxRt = document.getElementById('recap-max-rt');
const recapTotalTime = document.getElementById('recap-total-time');
const recapReqPerSec = document.getElementById('recap-req-per-sec');
const recapSuccessRate = document.getElementById('recap-success-rate');
const recapAvgLat = document.getElementById('recap-avg-lat');
const recapAvgTp = document.getElementById('recap-avg-tp');
const recapBytes = document.getElementById('recap-bytes');
const recapAvgCpu = document.getElementById('recap-avg-cpu');
const recapAvgRss = document.getElementById('recap-avg-rss');
const recapAvgHeap = document.getElementById('recap-avg-heap');
const recapFooterStatus = document.getElementById('recap-footer-status');
const recapFooterDesc = document.getElementById('recap-footer-desc');
const btnDownloadCsv = document.getElementById('btn-download-csv');

let batchResults = [];
let isBatchRunning = false;

function getByteSize(str) {
  return new TextEncoder().encode(str).length;
}

function getTargetCount() {
  const val = Number(customCount?.value);
  if (!Number.isFinite(val) || val < 1) return 1;
  return Math.floor(val);
}

function syncProgressLabel(current, total, statusLabel) {
  if (batchStatusText) batchStatusText.textContent = `Status: ${statusLabel}`;
  if (batchCountText) batchCountText.textContent = `${current} / ${total}`;
  if (batchProgressBar) {
    const pct = total > 0 ? Math.min(100, (current / total) * 100) : 0;
    batchProgressBar.style.width = `${pct}%`;
  }
}

presetCount?.addEventListener('change', () => {
  if (presetCount.value && customCount) {
    customCount.value = presetCount.value;
  }
  syncProgressLabel(0, getTargetCount(), 'Siap');
});

customCount?.addEventListener('input', () => {
  if (presetCount && customCount.value !== presetCount.value) {
    presetCount.value = '';
  }
  syncProgressLabel(0, getTargetCount(), 'Siap');
});

async function sendMessageRequest(plainText, seqNumber = 1) {
  const payload = {
    scheme,
    seq: seqNumber,
    message: plainText,
    sentAt: new Date().toISOString()
  };

  const t0 = performance.now();
  const res = await fetch('/api/message', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const tHeaders = performance.now();
  const data = await res.json();
  const tEnd = performance.now();

  const responseTimeMs = Number((tEnd - t0).toFixed(3));
  const latencyMs = Number((tHeaders - t0).toFixed(3));
  const durationSec = Math.max((tEnd - t0) / 1000, 0.0001);

  const reqBytes = getByteSize(JSON.stringify(payload));
  const respBytes = getByteSize(JSON.stringify(data));
  const totalBytes = data.metrics?.totalBytes ?? (reqBytes + respBytes);
  const throughputKBs = Number(((totalBytes / 1024) / durationSec).toFixed(3));

  return {
    request: seqNumber,
    httpStatus: res.status,
    responseTimeMs,
    latencyMs,
    throughputKBs,
    totalBytes,
    cpuServerMs: Number((data.metrics?.cpuServerMs ?? 0).toFixed(3)),
    ramRssMb: Number((data.metrics?.ramRssMb ?? data.metrics?.ramMb ?? 0).toFixed(2)),
    ramHeapMb: Number((data.metrics?.ramHeapMb ?? 0).toFixed(2)),
    payloadSent: payload,
    serverResponse: data
  };
}

function renderManualResult(originalText, item) {
  const isOk = item.httpStatus >= 200 && item.httpStatus < 300;
  const receivedText = item.serverResponse?.echoMessage ?? '-';

  if (manualOriginalMsg) manualOriginalMsg.textContent = originalText;
  if (manualReceivedMsg) manualReceivedMsg.textContent = receivedText;
  if (manualStatus) {
    manualStatus.textContent = isOk ? 'Berhasil' : `Gagal (${item.httpStatus})`;
    manualStatus.className = isOk ? 'text-success' : 'text-danger';
  }
  if (manualTiming) {
    manualTiming.textContent = `${item.responseTimeMs.toFixed(3)} ms (Latency: ${item.latencyMs.toFixed(3)} ms)`;
  }
  if (manualSummaryLine) {
    manualSummaryLine.textContent = `Pengujian berhasil. Response: ${item.responseTimeMs.toFixed(3)} ms | Throughput: ${item.throughputKBs.toFixed(2)} KB/s | CPU Server: ${item.cpuServerMs.toFixed(3)} ms`;
  }
}

function renderTableRows(rows) {
  if (!batchTableBody) return;
  if (!rows.length) {
    batchTableBody.innerHTML =
      '<tr><td colspan="8" class="empty-cell">Belum ada data hasil pengujian batch.</td></tr>';
    return;
  }

  batchTableBody.innerHTML = rows
    .map(
      (r) => `
      <tr>
        <td>${r.request}</td>
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

function resetRecap() {
  if (recapTotal) recapTotal.textContent = '0';
  if (recapSuccess) recapSuccess.textContent = '0';
  if (recapFailed) recapFailed.textContent = '0';
  if (recapAvgRt) recapAvgRt.textContent = '0.000 ms';
  if (recapMinRt) recapMinRt.textContent = '0.000 ms';
  if (recapMaxRt) recapMaxRt.textContent = '0.000 ms';
  if (recapTotalTime) recapTotalTime.textContent = '0.000 ms';
  if (recapReqPerSec) recapReqPerSec.textContent = '0.000 request/detik';
  if (recapSuccessRate) recapSuccessRate.textContent = '0.00%';
  if (recapAvgLat) recapAvgLat.textContent = '0.000 ms';
  if (recapAvgTp) recapAvgTp.textContent = '0.000 KB/s';
  if (recapBytes) recapBytes.textContent = '0 bytes';
  if (recapAvgCpu) recapAvgCpu.textContent = '0.000 ms';
  if (recapAvgRss) recapAvgRss.textContent = '0.00 MB';
  if (recapAvgHeap) recapAvgHeap.textContent = '0.00 MB';
  if (recapFooterStatus) recapFooterStatus.textContent = 'Siap menguji';
  if (recapFooterDesc) recapFooterDesc.textContent = 'Jalankan batch testing untuk mengunduh hasil CSV.';
  if (btnDownloadCsv) btnDownloadCsv.disabled = true;
}

function updateRecap(rows, totalBatchMs = 0) {
  const count = rows.length;
  if (!count) {
    resetRecap();
    return;
  }

  const avg = (fn) => rows.reduce((acc, item) => acc + fn(item), 0) / count;
  const successCount = rows.filter((r) => r.httpStatus >= 200 && r.httpStatus < 300).length;
  const failedCount = count - successCount;

  const rtList = rows.map((r) => r.responseTimeMs);
  const minRt = Math.min(...rtList);
  const maxRt = Math.max(...rtList);
  const sumBytes = rows.reduce((acc, item) => acc + item.totalBytes, 0);
  const reqPerSec = totalBatchMs > 0 ? count / (totalBatchMs / 1000) : 0;
  const successRate = (successCount / count) * 100;

  if (recapTotal) recapTotal.textContent = String(count);
  if (recapSuccess) recapSuccess.textContent = String(successCount);
  if (recapFailed) recapFailed.textContent = String(failedCount);
  if (recapAvgRt) recapAvgRt.textContent = `${avg((r) => r.responseTimeMs).toFixed(3)} ms`;
  if (recapMinRt) recapMinRt.textContent = `${minRt.toFixed(3)} ms`;
  if (recapMaxRt) recapMaxRt.textContent = `${maxRt.toFixed(3)} ms`;
  if (recapTotalTime) recapTotalTime.textContent = `${totalBatchMs.toFixed(3)} ms`;
  if (recapReqPerSec) recapReqPerSec.textContent = `${reqPerSec.toFixed(3)} request/detik`;
  if (recapSuccessRate) recapSuccessRate.textContent = `${successRate.toFixed(2)}%`;
  if (recapAvgLat) recapAvgLat.textContent = `${avg((r) => r.latencyMs).toFixed(3)} ms`;
  if (recapAvgTp) recapAvgTp.textContent = `${avg((r) => r.throughputKBs).toFixed(3)} KB/s`;
  if (recapBytes) recapBytes.textContent = `${sumBytes} bytes`;
  if (recapAvgCpu) recapAvgCpu.textContent = `${avg((r) => r.cpuServerMs).toFixed(3)} ms`;
  if (recapAvgRss) recapAvgRss.textContent = `${avg((r) => r.ramRssMb).toFixed(2)} MB`;
  if (recapAvgHeap) recapAvgHeap.textContent = `${avg((r) => r.ramHeapMb).toFixed(2)} MB`;

  if (recapFooterStatus) recapFooterStatus.textContent = '✓ Pengujian batch selesai';
  if (recapFooterDesc) recapFooterDesc.textContent = 'Hasil pengujian siap diunduh.';
  if (btnDownloadCsv) btnDownloadCsv.disabled = false;
}

btnDownloadCsv?.addEventListener('click', () => {
  if (!batchResults.length) return;

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

  const csvLines = [
    headers.join(','),
    ...batchResults.map((r) =>
      [
        r.request,
        r.httpStatus,
        r.responseTimeMs.toFixed(3),
        r.latencyMs.toFixed(3),
        r.throughputKBs.toFixed(3),
        r.totalBytes,
        r.cpuServerMs.toFixed(3),
        r.ramRssMb.toFixed(2),
        r.ramHeapMb.toFixed(2)
      ].join(',')
    )
  ];

  const blob = new Blob([csvLines.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${scheme}_batch_${batchResults.length}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
});

btnSendOne?.addEventListener('click', async () => {
  const text = (manualMessageInput?.value || '').trim() || 'Pesan uji manual';
  if (btnSendOne) btnSendOne.disabled = true;
  if (manualStatus) {
    manualStatus.textContent = 'Mengirim...';
    manualStatus.className = '';
  }

  try {
    const item = await sendMessageRequest(text, 1);
    renderManualResult(text, item);
  } catch (err) {
    if (manualOriginalMsg) manualOriginalMsg.textContent = text;
    if (manualReceivedMsg) manualReceivedMsg.textContent = '-';
    if (manualStatus) {
      manualStatus.textContent = 'Error';
      manualStatus.className = 'text-danger';
    }
    if (manualTiming) manualTiming.textContent = '-';
    if (manualSummaryLine) manualSummaryLine.textContent = `Gagal mengirim pesan: ${err.message}`;
  } finally {
    if (btnSendOne) btnSendOne.disabled = false;
  }
});

btnSendBatch?.addEventListener('click', async () => {
  if (isBatchRunning) return;
  isBatchRunning = true;

  const total = getTargetCount();
  const baseText = (batchMessageInput?.value || '').trim() || 'Pesan pengujian batch';

  batchResults = [];
  renderTableRows([]);
  resetRecap();

  if (btnSendOne) btnSendOne.disabled = true;
  if (btnSendBatch) btnSendBatch.disabled = true;

  syncProgressLabel(0, total, 'Sedang berjalan...');
  if (batchSummaryNote) batchSummaryNote.textContent = 'Menjalankan pengujian batch...';

  const batchStart = performance.now();

  try {
    for (let i = 1; i <= total; i++) {
      const item = await sendMessageRequest(`${baseText} #${i}`, i);
      batchResults.push(item);

      syncProgressLabel(i, total, i === total ? 'Pengujian selesai' : 'Sedang berjalan...');
      if (i % 10 === 0 || i === total) {
        renderTableRows(batchResults);
      }
    }

    const totalBatchMs = Number((performance.now() - batchStart).toFixed(3));
    renderTableRows(batchResults);
    updateRecap(batchResults, totalBatchMs);

    if (batchSummaryNote) {
      batchSummaryNote.textContent = `Batch Testing ${scheme} telah selesai.`;
    }
  } catch (err) {
    syncProgressLabel(batchResults.length, total, 'Terhenti karena error');
    if (batchSummaryNote) batchSummaryNote.textContent = `Error: ${err.message}`;
  } finally {
    isBatchRunning = false;
    if (btnSendOne) btnSendOne.disabled = false;
    if (btnSendBatch) btnSendBatch.disabled = false;
  }
});

syncProgressLabel(0, getTargetCount(), 'Siap');
resetRecap();