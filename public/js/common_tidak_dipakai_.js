function formatTimestamp() {
  return new Date().toLocaleTimeString('id-ID');
}

function setOutput(targetEl, eventName, payload) {
  if (!targetEl) return;
  targetEl.textContent = JSON.stringify(
    {
      time: formatTimestamp(),
      event: eventName,
      data: payload
    },
    null,
    2
  );
}

async function checkServerHealth(outputEl) {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    setOutput(outputEl, 'Cek Koneksi Server', {
      httpStatus: res.status,
      response: data
    });
  } catch (err) {
    setOutput(outputEl, 'Error Koneksi', {
      message: err.message
    });
  }
}