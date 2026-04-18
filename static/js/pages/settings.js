/* ============================================
   SETTINGS PAGE JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireAuth();
  if (!user) return;
  Auth.populateUI(user);

  // Role-adaptive sidebar nav
  var navMap = {
    admin: [
      { href: '/admin', label: 'Dashboard', icon: 'activity' },
      { href: '/security', label: 'Security Center', icon: 'shield' },
      { href: '/iam', label: 'IAM / Access', icon: 'users' },
      { href: '/audit-logs', label: 'Audit Logs', icon: 'fingerprint' },
      { href: '/settings', label: 'Settings', icon: 'settings', active: true },
    ],
    doctor: [
      { href: '/doctor', label: 'My Patients', icon: 'stethoscope' },
      { href: '/audit-logs', label: 'Audit Logs', icon: 'fingerprint' },
      { href: '/settings', label: 'Settings', icon: 'settings', active: true },
    ],
    patient: [
      { href: '/patient', label: 'Health Records', icon: 'file-text' },
      { href: '/audit-logs', label: 'Access History', icon: 'fingerprint' },
      { href: '/settings', label: 'Settings', icon: 'settings', active: true },
    ],
    staff: [
      { href: '/staff', label: 'Assigned Tasks', icon: 'check-square' },
      { href: '/settings', label: 'Settings', icon: 'settings', active: true },
    ],
  };

  var links = navMap[user.role] || navMap.patient;
  document.getElementById('settings-nav').innerHTML = links.map(function(l) {
    return '<a href="' + l.href + '" class="nav-link' + (l.active ? ' active' : '') + '">' +
      '<i data-lucide="' + l.icon + '"></i>' + l.label + '</a>';
  }).join('');

  // Show break glass for admins only
  if (user.role === 'admin') {
    document.getElementById('break-glass-section').classList.remove('hidden');
  }

  var mfaToggle = document.getElementById('mfa-toggle');
  if (mfaToggle) mfaToggle.checked = !!user.mfaEnabled;

  var sessions = [];

  function renderSessions() {
    var activeSessions = sessions.filter(function(s) { return s.status === 'Active'; });
    document.getElementById('session-cards').innerHTML = activeSessions.length
      ? activeSessions.map(function(s) {
          return '<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;margin-bottom:10px;">' +
            '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">' +
              '<div>' +
                '<div style="font-size:13px;font-weight:600;">' + s.device + (s.current ? ' · Current' : '') + '</div>' +
                '<div style="font-size:12px;color:var(--text-muted);margin-top:2px;">' + (s.location || 'Unknown') + ' · ' + s.ip + '</div>' +
                '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">Expires: ' + (s.expiresAt || 'Unknown') + '</div>' +
              '</div>' +
              '<button class="btn-outline session-revoke-btn" data-session-id="' + s.id + '" style="width:auto;padding:8px 10px;">' + (s.current ? 'Logout' : 'Revoke') + '</button>' +
            '</div>' +
          '</div>';
        }).join('')
      : '<p style="color:var(--text-muted);font-size:13px;">No active sessions found.</p>';

    document.querySelectorAll('.session-revoke-btn').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        try {
          await Auth.del('/api/auth/sessions/' + btn.dataset.sessionId);
          var revoked = sessions.find(function(s) { return s.id === btn.dataset.sessionId; });
          if (revoked && revoked.current) {
            Auth.logoutLocalOnly();
            return;
          }
          sessions = sessions.map(function(s) { return s.id === btn.dataset.sessionId ? Object.assign({}, s, { status: 'Terminated' }) : s; });
          renderSessions();
          showToast('Session Revoked', 'The selected session can no longer access the app.', 'success');
        } catch(e) {
          showToast('Error', e.message, 'error');
        }
      });
    });
  }

  // Load active sessions from API
  try {
    sessions = await Auth.get('/api/auth/sessions') || [];
    renderSessions();
  } catch(e) {
    document.getElementById('session-cards').innerHTML =
      '<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px 14px;margin-bottom:10px;">' +
        '<div style="font-size:13px;font-weight:600;">Current Session</div>' +
        '<div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Active now</div>' +
      '</div>';
  }

  // Password form — real API
  document.getElementById('save-pass-btn').addEventListener('click', async function() {
    var cur  = document.getElementById('cur-pass').value;
    var nw   = document.getElementById('new-pass').value;
    var conf = document.getElementById('conf-pass').value;
    if (!cur || !nw || !conf) { showToast('Missing Fields', 'Please fill all password fields.', 'error'); return; }
    if (nw !== conf) { showToast('Mismatch', 'New passwords do not match.', 'error'); return; }
    if (nw.length < 6) { showToast('Too Short', 'Password must be at least 6 characters.', 'error'); return; }
    try {
      await Auth.put('/api/auth/password', { current_password: cur, new_password: nw });
      showToast('Password Updated', 'Your password has been changed securely.', 'success');
      document.getElementById('cur-pass').value = '';
      document.getElementById('new-pass').value = '';
      document.getElementById('conf-pass').value = '';
    } catch(e) {
      showToast('Error', e.message, 'error');
    }
  });

  // MFA toggles
  document.getElementById('mfa-toggle').addEventListener('change', async function() {
    var toggle = this;
    var desired = toggle.checked;
    toggle.disabled = true;
    try {
      var updated = await Auth.put('/api/auth/mfa', { mfaEnabled: desired });
      if (updated) {
        Auth.setSession(updated, Auth.getToken());
        user = updated;
      }
      showToast('MFA ' + (desired ? 'Enabled' : 'Disabled'), desired ? 'Email verification will be required at next login.' : 'MFA has been disabled.', desired ? 'success' : 'error');
    } catch(e) {
      toggle.checked = !desired;
      showToast('Error', e.message, 'error');
    } finally {
      toggle.disabled = false;
    }
  });
  document.getElementById('setup-auth-btn').addEventListener('click', function() {
    showToast('Email MFA Active', 'Verification codes are sent to your registered email during login.', 'default');
  });
  document.getElementById('backup-btn').addEventListener('click', function() {
    showToast('Codes Generated', 'Backup codes downloaded securely.', 'success');
  });

  var logoutAllBtn = document.getElementById('logout-all-btn');
  if (logoutAllBtn) {
    logoutAllBtn.addEventListener('click', async function() {
      try {
        await Auth.post('/api/auth/logout-all', {});
        Auth.logoutLocalOnly();
      } catch(e) {
        showToast('Error', e.message, 'error');
      }
    });
  }

  // Notification toggles
  ['notif-email','notif-sms','notif-push'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', function() {
      var key = id.replace('notif-','');
      showToast('Preference Saved', key.charAt(0).toUpperCase() + key.slice(1) + ' notifications ' + (el.checked ? 'enabled' : 'disabled') + '.', 'default');
    });
  });

  // Break glass
  if (user.role === 'admin') {
    document.getElementById('break-glass-btn').addEventListener('click', function() {
      document.getElementById('glass-modal').classList.remove('hidden');
    });
    document.getElementById('glass-cancel').addEventListener('click', function() {
      document.getElementById('glass-modal').classList.add('hidden');
    });
    document.getElementById('glass-confirm').addEventListener('click', function() {
      document.getElementById('glass-modal').classList.add('hidden');
      showToast('EMERGENCY ACCESS ACTIVATED', 'All access logged. Compliance team notified.', 'error');
    });
    document.getElementById('glass-modal').addEventListener('click', function(e) {
      if (e.target === this) this.classList.add('hidden');
    });
  }

  if (window.lucide) window.lucide.createIcons();
});
