
(function () {
    const scheme = document.documentElement.getAttribute('data-require-scheme');

    // Scheme wajib ditentukan pada halaman pengujian
    if (!scheme) {
        window.location.replace('/index.html');
        return;
    }

    const authKey = `secure_lab_auth_${scheme}`;
    const authRaw = sessionStorage.getItem(authKey);

    let isAuthenticated = false;

    if (authRaw) {
        try {
            const parsed = JSON.parse(authRaw);

            isAuthenticated = Boolean(
                parsed &&
                parsed.username &&
                parsed.scheme === scheme
            );
        } catch {
            isAuthenticated = false;
        }
    }

    if (!isAuthenticated) {
        window.location.replace(
            `/pages/login.html?scheme=${encodeURIComponent(scheme)}`
        );
    }
})();

document.addEventListener('DOMContentLoaded', () => {
    const logoutBtn = document.getElementById('btnLogoutScheme');

    if (!logoutBtn) return;

    logoutBtn.addEventListener('click', () => {
        const scheme = document.documentElement.getAttribute('data-require-scheme');

        if (scheme) {
            sessionStorage.removeItem(`secure_lab_auth_${scheme}`);
        }

        window.location.replace(
            `/pages/login.html?scheme=${encodeURIComponent(scheme || '')}`
        );
    });
});
