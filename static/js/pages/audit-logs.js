/* ============================================
   AUDIT LOGS JS — Real API
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
      { href: '/audit-logs', label: 'Audit Logs', icon: 'fingerprint', active: true },
      { href: '/settings', label: 'Settings', icon: 'settings' },
    ],
    doctor: [
      { href: '/doctor', label: 'My Patients', icon: 'stethoscope' },
      { href: '/audit-logs', label: 'Audit Logs', icon: 'fingerprint', active: true },
      { href: '/settings', label: 'Settings', icon: 'settings' },
    ],
    patient: [
      { href: '/patient', label: 'Health Records', icon: 'file-text' },
      { href: '/audit-logs', label: 'Access History', icon: 'fingerprint', active: true },
      { href: '/settings', label: 'Settings', icon: 'settings' },
    ],
    staff: [
      { href: '/staff', label: 'Assigned Tasks', icon: 'check-square' },
      { href: '/settings', label: 'Settings', icon: 'settings' },
    ],
  };

  var links = navMap[user.role] || navMap.admin;
  document.querySelector('.sidebar-nav').innerHTML = links.map(function(l) {
    return '<a href="' + l.href + '" class="nav-link' + (l.active ? ' active' : '') + '">' +
      '<i data-lucide="' + l.icon + '"></i>' + l.label + '</a>';
  }).join('');

  var allLogs = [];
  var chainValid = null;

  function renderTimeline(filtered) {
    var list = filtered || allLogs;
    document.getElementById('log-timeline').innerHTML = list.map(function(log, idx) {
      return '<div class="audit-entry">' +
        '<div class="audit-dot-col">' +
          '<div class="audit-dot ' + log.status.toLowerCase() + '"></div>' +
          (idx < list.length - 1 ? '<div class="audit-line"></div>' : '') +
        '</div>' +
        '<div style="flex:1;min-width:0;">' +
          '<div class="audit-hash"># ' + log.hash.slice(0,32) + '…</div>' +
          (log.prevHash ? '<div style="font-size:10px;color:var(--text-muted);margin-bottom:2px;">⛓ linked to ' + log.prevHash.slice(0,16) + '…</div>' : '') +
          '<div class="audit-action">' + log.action + '</div>' +
          '<div class="audit-meta">' +
            '<span><i data-lucide="user" style="width:12px;height:12px;"></i>' + log.user + '</span>' +
            (log.ip ? '<span><i data-lucide="globe" style="width:12px;height:12px;"></i>' + log.ip + '</span>' : '') +
            '<span><i data-lucide="clock" style="width:12px;height:12px;"></i>' + log.timestamp + '</span>' +
          '</div>' +
        '</div>' +
        '<div style="flex-shrink:0;margin-left:12px;margin-top:2px;">' +
          '<span class="badge ' + (log.status === 'Verified' ? 'badge-verified' : 'badge-flagged') + '" style="display:flex;align-items:center;gap:4px;">' +
            '<i data-lucide="' + (log.status === 'Verified' ? 'shield-check' : 'alert-triangle') + '" style="width:11px;height:11px;"></i>' +
            log.status +
          '</span>' +
        '</div>' +
      '</div>';
    }).join('');

    document.getElementById('stat-total').textContent = list.length;
    document.getElementById('stat-verified').textContent = list.filter(function(l) { return l.status === 'Verified'; }).length;
    document.getElementById('stat-flagged').textContent = list.filter(function(l) { return l.status === 'Flagged'; }).length;

    // Chain integrity badge (admin only)
    var chainEl = document.getElementById('chain-status');
    if (chainEl && user.role === 'admin' && chainValid !== null) {
      chainEl.innerHTML = chainValid
        ? '<span class="badge badge-verified" style="display:flex;align-items:center;gap:4px;"><i data-lucide="shield-check" style="width:11px;height:11px;"></i> Chain Intact</span>'
        : '<span class="badge badge-flagged" style="display:flex;align-items:center;gap:4px;"><i data-lucide="alert-triangle" style="width:11px;height:11px;"></i> Chain Broken</span>';
    }

    if (window.lucide) window.lucide.createIcons();
  }

  // Load data
  try {
    var result = await Auth.get('/api/audit-logs?limit=100');
    if (result) allLogs = result.logs || [];
  } catch(e) {
    showToast('Error', 'Failed to load audit logs: ' + e.message, 'error');
  }

  // Verify chain integrity (admin only)
  if (user.role === 'admin') {
    try {
      var verify = await Auth.get('/api/audit-logs/verify');
      if (verify) chainValid = verify.valid;
    } catch(e) { /* non-critical */ }
  }

  document.getElementById('log-filter').addEventListener('change', function() {
    var v = this.value;
    if (v === 'all') { renderTimeline(allLogs); return; }
    var filtered = allLogs.filter(function(l) {
      var t = l.action.toLowerCase();
      if (v === 'login') return t.includes('login');
      if (v === 'record') return t.includes('record') || t.includes('accessed') || t.includes('downloaded') || t.includes('patient');
      if (v === 'admin') return t.includes('role') || t.includes('modified') || t.includes('user') || t.includes('enforce');
      return true;
    });
    renderTimeline(filtered);
  });

  document.getElementById('export-btn').addEventListener('click', function() {
    if (!allLogs.length) { showToast('No Data', 'No logs to export.', 'error'); return; }
    var csv = ['ID,Action,User,IP,Status,Timestamp,Hash'];
    allLogs.forEach(function(l) {
      csv.push([l.id, '"'+l.action+'"', l.user, l.ip, l.status, l.timestamp, l.hash].join(','));
    });
    var blob = new Blob([csv.join('\n')], { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'guardian-audit-logs.csv';
    a.click();
    showToast('Export Ready', 'Audit log downloaded as CSV.', 'success');
  });

  renderTimeline();
});
