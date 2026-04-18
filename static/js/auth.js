/* ============================================
   GUARDIANHEALTH — AUTH STATE + API CLIENT
   ============================================ */
window.Auth = {
  getUser() {
    try { return JSON.parse(localStorage.getItem('gh_user')); } catch { return null; }
  },

  getToken() {
    try { return localStorage.getItem('gh_token') || ''; } catch { return ''; }
  },

  getCsrfToken() {
    try { return localStorage.getItem('gh_csrf') || ''; } catch { return ''; }
  },

  setSession(user, token, csrfToken) {
    try {
      localStorage.setItem('gh_user', JSON.stringify(user));
      if (token) localStorage.setItem('gh_token', token);
      else localStorage.removeItem('gh_token');
      if (csrfToken) localStorage.setItem('gh_csrf', csrfToken);
    } catch(e) {}
  },

  requireAuth() {
    const user = this.getUser();
    if (!user) { window.location.href = '/login'; return null; }
    return user;
  },

  requireRole(role) {
    const user = this.getUser();
    if (!user) { window.location.href = '/login'; return null; }
    if (role && user.role !== role) {
      this.redirectByRole(user.role);
      return null;
    }
    return user;
  },

  requireAnyRole(roles) {
    const user = this.getUser();
    if (!user) { window.location.href = '/login'; return null; }
    if (!roles.includes(user.role)) {
      this.redirectByRole(user.role);
      return null;
    }
    return user;
  },

  populateUI(user) {
    const sidebarEl = document.getElementById('sidebar-user');
    if (sidebarEl) {
      sidebarEl.innerHTML = `
        <div class="sidebar-user-card">
          <div class="sidebar-avatar">${user.name.charAt(0)}</div>
          <div>
            <div class="sidebar-user-name">${user.name}</div>
            <div class="sidebar-user-role">${user.role}</div>
          </div>
        </div>
        <button class="sidebar-logout" onclick="Auth.logout()">
          <i data-lucide="log-out"></i> Sign Out
        </button>`;
    }
    const topbarAvatar = document.getElementById('topbar-avatar');
    const topbarName = document.getElementById('topbar-name');
    if (topbarAvatar) topbarAvatar.textContent = user.name.charAt(0);
    if (topbarName) topbarName.textContent = user.name;
  },

  /* Legacy: kept so old code that calls Auth.login() still works during transition */
  login(email) {
    const found = window.MOCK_USERS ? window.MOCK_USERS.find(u => u.email.toLowerCase() === email.toLowerCase()) : null;
    const user = found || { id: 'guest', name: email.split('@')[0], email, role: 'patient', status: 'active', mfaEnabled: true };
    try { localStorage.setItem('gh_user', JSON.stringify(user)); } catch(e) {}
    return user;
  },

  logout() {
    var csrfToken = this.getCsrfToken();
    if (csrfToken) {
      try {
        fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          keepalive: true
        }).catch(function() {});
      } catch(e) {}
    }
    try { localStorage.removeItem('gh_user'); localStorage.removeItem('gh_token'); localStorage.removeItem('gh_csrf'); } catch(e) {}
    window.location.href = '/login';
  },

  logoutLocalOnly() {
    try { localStorage.removeItem('gh_user'); localStorage.removeItem('gh_token'); localStorage.removeItem('gh_csrf'); } catch(e) {}
    window.location.href = '/login';
  },

  redirectByRole(role) {
    const map = { admin: '/admin', doctor: '/doctor', patient: '/patient', staff: '/staff' };
    window.location.href = map[role] || '/patient';
  },

  /* ── API Client ────────────────────────────────────────────────────────── */
  async api(method, path, body) {
    const headers = {
      'Content-Type': 'application/json',
    };
    const token = this.getToken();
    if (token) headers.Authorization = 'Bearer ' + token;
    if (method !== 'GET') {
      const csrfToken = this.getCsrfToken();
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    }
    const opts = {
      method,
      headers,
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    if (res.status === 401) {
      this.logoutLocalOnly();
      return null;
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  },

  get(path) { return this.api('GET', path); },
  post(path, body) { return this.api('POST', path, body); },
  put(path, body) { return this.api('PUT', path, body); },
  del(path) { return this.api('DELETE', path); },
};

/* ============================================
   TOAST SYSTEM
   ============================================ */
window.showToast = function(title, desc, type) {
  type = type || 'default';
  const container = document.getElementById('toast-container');
  if (!container) return;
  const icons = {
    success: '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error:   '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    default: '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>'
  };
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = '<div class="toast-icon">' + (icons[type] || icons.default) + '</div><div><div class="toast-title">' + title + '</div>' + (desc ? '<div class="toast-desc">' + desc + '</div>' : '') + '</div>';
  container.appendChild(el);
  setTimeout(function() {
    el.style.animation = 'toastSlide 0.3s ease reverse';
    setTimeout(function() { el.remove(); }, 300);
  }, 3500);
};
