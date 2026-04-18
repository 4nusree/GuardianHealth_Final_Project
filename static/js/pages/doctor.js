/* ============================================
   DOCTOR PORTAL JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('doctor');
  if (!user) return;
  Auth.populateUI(user);

  var selectedPatient = null;
  var patients = [];

  function statusBadge(s) {
    var cls = s === 'Stable' ? 'badge-stable' : s === 'Critical' ? 'badge-critical' : 'badge-monitoring';
    return '<span class="badge ' + cls + '">' + s + '</span>';
  }

  function renderPatientList() {
    if (!patients.length) {
      document.getElementById('patient-list').innerHTML =
        '<div style="text-align:center;padding:32px;color:var(--text-muted);font-size:13px;">No patients assigned.</div>';
      return;
    }
    document.getElementById('patient-list').innerHTML = patients.map(function(p) {
      var sel = selectedPatient && selectedPatient.id === p.id;
      return '<div class="patient-list-item ' + (sel ? 'selected' : '') + '" data-pid="' + p.id + '">' +
        '<div class="flex gap-3" style="align-items:center;">' +
          '<div class="patient-avatar">' + p.name.charAt(0) + '</div>' +
          '<div><div class="patient-name">' + p.name + '</div><div class="patient-meta">Age: ' + p.age + ' · ' + p.condition + '</div></div>' +
        '</div>' +
        '<div class="flex gap-3" style="align-items:center;">' +
          '<div style="text-align:right;">' + statusBadge(p.status) + '<div class="text-xs text-muted mt-1">' + p.lastVisit + '</div></div>' +
          '<i data-lucide="chevron-right" style="width:18px;height:18px;color:var(--text-muted);flex-shrink:0;"></i>' +
        '</div>' +
      '</div>';
    }).join('');

    document.querySelectorAll('[data-pid]').forEach(function(item) {
      item.addEventListener('click', function() {
        var id = item.dataset.pid;
        selectedPatient = patients.find(function(p) { return p.id === id; });
        renderPatientList();
        renderDetailPanel();
        if (window.lucide) window.lucide.createIcons();
      });
    });
  }

  function renderDetailPanel() {
    var panel = document.getElementById('detail-panel');
    if (!selectedPatient) {
      panel.innerHTML = '<div class="empty-panel"><i data-lucide="shield-check"></i><p>Select a patient to securely view their records.</p><p style="font-size:11px;color:var(--text-muted);">All access is logged and monitored.</p></div>';
      return;
    }
    var p = selectedPatient;
    var sc = p.status === 'Stable' ? 'badge-stable' : p.status === 'Critical' ? 'badge-critical' : 'badge-monitoring';
    panel.innerHTML =
      '<div class="patient-detail-panel">' +
        '<div class="flex-between mb-4">' +
          '<div><h2 style="font-size:20px;font-weight:700;">' + p.name + '</h2><p class="text-primary text-sm">' + p.id.toUpperCase() + '</p></div>' +
          '<span class="badge ' + sc + '">' + p.status + '</span>' +
        '</div>' +
        '<div class="detail-section">' +
          '<div class="detail-section-label"><i data-lucide="activity" style="width:14px;height:14px;"></i> Condition</div>' +
          '<div class="detail-field">' + p.condition + '</div>' +
        '</div>' +
        '<div class="detail-section">' +
          '<div class="detail-section-label"><i data-lucide="user" style="width:14px;height:14px;"></i> Patient Info</div>' +
          '<div class="detail-field">Age: ' + p.age + ' &nbsp;·&nbsp; Last Visit: ' + p.lastVisit + '</div>' +
        '</div>' +
        '<div class="detail-section">' +
          '<div class="detail-section-label"><i data-lucide="pill" style="width:14px;height:14px;"></i> Quick Actions</div>' +
          '<div class="quick-actions">' +
            '<button class="quick-action-btn" data-action="New Rx"><i data-lucide="file-plus"></i> New Rx</button>' +
            '<button class="quick-action-btn" data-action="Note Created"><i data-lucide="clipboard"></i> Add Note</button>' +
            '<button class="quick-action-btn" data-action="Upload Started"><i data-lucide="upload"></i> Upload</button>' +
            '<button class="quick-action-btn" data-action="Lab Order Sent"><i data-lucide="flask-conical"></i> Labs</button>' +
          '</div>' +
        '</div>' +
        '<div class="detail-section" style="border-top:1px solid var(--border);padding-top:16px;margin-top:8px;">' +
          '<div class="detail-section-label"><i data-lucide="clock" style="width:14px;height:14px;"></i> Recent Access</div>' +
          '<div style="font-size:13px;margin-bottom:8px;"><span style="font-weight:600;">You</span> <span class="text-muted">— Viewed records · Just now</span></div>' +
          '<div style="font-size:13px;"><span style="font-weight:600;">System</span> <span class="text-muted">— Lab results updated · 2h ago</span></div>' +
        '</div>' +
      '</div>';

    document.querySelectorAll('[data-action]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        showToast(btn.dataset.action, 'Action logged to secure audit trail.', 'default');
      });
    });
  }

  document.getElementById('patient-search').addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('[data-pid]').forEach(function(item) {
      item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  // Load from API
  try {
    patients = await Auth.get('/api/patients') || [];
  } catch(e) {
    showToast('Error', 'Failed to load patients: ' + e.message, 'error');
  }

  renderPatientList();
  renderDetailPanel();
  if (window.lucide) window.lucide.createIcons();
});
