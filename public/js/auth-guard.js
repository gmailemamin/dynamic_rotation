(function () {
  const scheme = document.documentElement.getAttribute('data-require-scheme') || 'default';
  const authKey = `secure_lab_auth_${scheme}`;
  const authRaw = sessionStorage.getItem(authKey);

  let isAuthenticated = false;
  if (authRaw) {
    try {
      const parsed = JSON.parse(authRaw);
      isAuthenticated = Boolean(parsed && parsed.username);
    } catch {
      isAuthenticated = false;
    }
  }

  if (!isAuthenticated) {
    const currentPath = window.location.pathname;
    window.location.replace(
      `/pages/login.html?scheme=${encodeURIComponent(scheme)}&target=${encodeURIComponent(currentPath)}`
    );
  }
})();

document.addEventListener('DOMContentLoaded', () => {
  const logoutBtn = document.getElementById('btnLogoutScheme');
  if (!logoutBtn) return;

  logoutBtn.addEventListener('click', () => {
    const scheme = document.documentElement.getAttribute('data-require-scheme') || 'default';
    sessionStorage.removeItem(`secure_lab_auth_${scheme}`);
    window.location.replace(`/pages/login.html?scheme=${encodeURIComponent(scheme)}`);
  });
});