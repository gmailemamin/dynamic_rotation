const VALID_USERS = {
  admin: 'admin123',
  peneliti: 'skripsi2026'
};

const SCHEME_LABELS = {
  'no-encryption': 'No Encryption (Baseline Tanpa Enkripsi)',
  'aes-256-gcm': 'AES-256-GCM (Symmetric Encryption)',
  'rsa-oaep': 'RSA-OAEP (Asymmetric Encryption)',
  'rsa-aes-hybrid': 'RSA-AES Hybrid',
  'dynamic-rotation': 'RSA-AES with Dynamic Session Key Rotation'
};

const TARGET_MAP = {
  'no-encryption': '/pages/no_encryption.html',
  'aes-256-gcm': '/pages/aes.html',
  'rsa-oaep': '/pages/rsa.html',
  'rsa-aes-hybrid': '/pages/rsa_aes.html',
  'dynamic-rotation': '/pages/rsa_aes_dynamicRotation.html'
};

const params = new URLSearchParams(window.location.search);
const requestedScheme = params.get('scheme') || 'dynamic-rotation';
const safeScheme = TARGET_MAP[requestedScheme] ? requestedScheme : 'dynamic-rotation';
const targetUrl = TARGET_MAP[safeScheme];

const targetLabelEl = document.getElementById('login-target-label');
const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('login-username');
const passwordInput = document.getElementById('login-password');
const errorMsgEl = document.getElementById('login-error-msg');

if (targetLabelEl) {
  targetLabelEl.textContent = SCHEME_LABELS[safeScheme] || safeScheme;
}

loginForm?.addEventListener('submit', (e) => {
  e.preventDefault();
  errorMsgEl.textContent = '';

  const username = (usernameInput.value || '').trim();
  const password = passwordInput.value || '';

  if (!VALID_USERS[username] || VALID_USERS[username] !== password) {
    errorMsgEl.textContent = 'Username atau password tidak valid. Silakan coba lagi.';
    return;
  }

  const authKey = `secure_lab_auth_${safeScheme}`;
  sessionStorage.setItem(
    authKey,
    JSON.stringify({
      username,
      scheme: safeScheme,
      authenticatedAt: new Date().toISOString()
    })
  );

  window.location.href = targetUrl;
});

// const schemeSelect = document.getElementById('scheme');
// const rotationPanel = document.getElementById('rotation-panel');
// const rotationTypeSelect = document.getElementById('rotation-type');
// const requestThresholdGroup = document.getElementById('request-threshold-group');
// const timeIntervalGroup = document.getElementById('time-interval-group');
// const requestThresholdSelect = document.getElementById('request-threshold');
// const timeIntervalSelect = document.getElementById('time-interval');

// const btnInitSession = document.getElementById('btn-init-session');
// const btnRotateNow = document.getElementById('btn-rotate-now');
// const btnLogout = document.getElementById('btn-logout');
// const btnCheck = document.getElementById('btn-check');
// const btnSend = document.getElementById('btn-send');

// const messageInput = document.getElementById('message-input');
// const output = document.getElementById('output');

// const statusScheme = document.getElementById('status-scheme');
// const statusSession = document.getElementById('status-session');
// const statusCounter = document.getElementById('status-counter');
// const statusRotation = document.getElementById('status-rotation');

// const state = {
//   sessionActive: false,
//   requestCounter: 0,
//   lastRotation: '-'
// };

// function updateUI() {
//   const isDynamic = schemeSelect.value === 'rsa-aes-dynamic';
//   rotationPanel.classList.toggle('hidden', !isDynamic);

//   const isByRequest = rotationTypeSelect.value === 'request';
//   requestThresholdGroup.classList.toggle('hidden', !isByRequest);
//   timeIntervalGroup.classList.toggle('hidden', isByRequest);

//   statusScheme.textContent = schemeSelect.options[schemeSelect.selectedIndex].text;
//   statusSession.textContent = isDynamic
//     ? (state.sessionActive ? 'Secure Session Aktif' : 'Belum Dibentuk')
//     : 'Langsung / Statis';
//   statusCounter.textContent = String(state.requestCounter);
//   statusRotation.textContent = state.lastRotation;

//   btnRotateNow.disabled = !(isDynamic && state.sessionActive);
//   btnLogout.disabled = !(isDynamic && state.sessionActive);
// }

// function appendLog(title, payload) {
//   const entry = {
//     time: new Date().toLocaleTimeString('id-ID'),
//     event: title,
//     data: payload
//   };
//   output.textContent = JSON.stringify(entry, null, 2);
// }

// schemeSelect.addEventListener('change', () => {
//   state.sessionActive = false;
//   state.requestCounter = 0;
//   state.lastRotation = '-';
//   updateUI();
//   appendLog('Perubahan Skema', { scheme: schemeSelect.value });
// });

// rotationTypeSelect.addEventListener('change', updateUI);

// btnCheck.addEventListener('click', async () => {
//   try {
//     const res = await fetch('/api/health');
//     const data = await res.json();
//     appendLog('Cek Koneksi Server', { httpStatus: res.status, response: data });
//   } catch (err) {
//     appendLog('Error Koneksi', { message: err.message });
//   }
// });

// btnInitSession.addEventListener('click', () => {
//   state.sessionActive = true;
//   state.requestCounter = 0;
//   state.lastRotation = new Date().toLocaleTimeString('id-ID') + ' (Init)';
//   updateUI();
//   appendLog('Init Secure Session (Draft UI)', {
//     rotationType: rotationTypeSelect.value,
//     threshold: rotationTypeSelect.value === 'request'
//       ? Number(requestThresholdSelect.value)
//       : Number(timeIntervalSelect.value) + ' menit'
//   });
// });

// btnRotateNow.addEventListener('click', () => {
//   state.lastRotation = new Date().toLocaleTimeString('id-ID') + ' (Manual)';
//   updateUI();
//   appendLog('Rotasi Kunci Sesi (Draft UI)', {
//     requestCounter: state.requestCounter
//   });
// });

// btnLogout.addEventListener('click', () => {
//   state.sessionActive = false;
//   state.requestCounter = 0;
//   state.lastRotation = '-';
//   updateUI();
//   appendLog('Logout / Hapus Sesi (Draft UI)', { status: 'Sesi ditutup' });
// });

// btnSend.addEventListener('click', () => {
//   state.requestCounter += 1;
//   updateUI();
//   appendLog('Kirim Pesan (Draft UI)', {
//     scheme: schemeSelect.value,
//     message: messageInput.value || '(kosong)',
//     requestCounter: state.requestCounter
//   });
// });

// updateUI();