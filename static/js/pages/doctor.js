/* ============================================
   DOCTOR PORTAL JS — clinical updates on assigned patients
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('doctor');
  if (!user) return;
  Auth.populateUI(user);

  var selectedPatient = null;
  var patients = [];
  var STATUSES = ['Stable','Critical','Recovering','Discharged'];

  function statusBadge(s) {
    var cls = s === 'Stable' ? 'badge-stable'
            : s === 'Critical' ? 'badge-critical'
            : 'badge-monitoring';
    return '<span class="badge ' + cls + '">' + esc(s) + '</span>';
  }

  function renderPatientList() {
    if (!patients.length) {
      document.getElementById('patient-list').innerHTML =
        '<div style="text-align:center;padding:32px;color:var(--text-muted);font-size:13px;">No patients assigned to you yet.<br/><span style="font-size:11px;">Ask a staff member to assign patients to your account.</span></div>';
      return;
    }
    document.getElementById('patient-list').innerHTML = patients.map(function(p) {
      var sel = selectedPatient && selectedPatient.id === p.id;
      return '<div class="patient-list-item ' + (sel ? 'selected' : '') + '" data-pid="' + esc(p.id) + '">' +
        '<div class="flex gap-3" style="align-items:center;">' +
          '<div class="patient-avatar">' + esc((p.name || '?').charAt(0)) + '</div>' +
          '<div><div class="patient-name">' + esc(p.name) + '</div>' +
          '<div class="patient-meta">Age: ' + esc(p.age || '—') + ' · ' + esc(p.condition || '—') + '</div></div>' +
        '</div>' +
        '<div class="flex gap-3" style="align-items:center;">' +
          '<div style="text-align:right;">' + statusBadge(p.status) +
            '<div class="text-xs text-muted mt-1">' + esc(p.lastVisit || '—') + '</div></div>' +
          '<i data-lucide="chevron-right" style="width:18px;height:18px;color:var(--text-muted);flex-shrink:0;"></i>' +
        '</div>' +
      '</div>';
    }).join('');

    document.querySelectorAll('[data-pid]').forEach(function(item) {
      item.addEventListener('click', function() {
        selectedPatient = patients.find(function(p) { return p.id === item.dataset.pid; });
        renderPatientList();
        renderDetailPanel();
        if (window.lucide) window.lucide.createIcons();
      });
    });
  }

  function renderDetailPanel() {
    var panel = document.getElementById('detail-panel');
    if (!selectedPatient) {
      panel.innerHTML = '<div class="empty-panel"><i data-lucide="shield-check"></i>' +
        '<p>Select a patient to securely view and update their records.</p>' +
        '<p style="font-size:11px;color:var(--text-muted);">All access is logged and monitored.</p></div>';
      return;
    }
    var p = selectedPatient;
    var statusOpts = STATUSES.map(function(s) {
      return '<option value="' + s + '"' + (p.status === s ? ' selected' : '') + '>' + s + '</option>';
    }).join('');

    panel.innerHTML =
      '<div class="patient-detail-panel">' +
        '<div class="flex-between mb-4">' +
          '<div><h2 style="font-size:20px;font-weight:700;">' + esc(p.name) + '</h2>' +
          '<p class="text-primary text-sm">' + esc(p.id.toUpperCase()) + '</p></div>' +
          statusBadge(p.status) +
        '</div>' +

        '<div class="detail-section">' +
          '<div class="detail-section-label"><i data-lucide="user" style="width:14px;height:14px;"></i> Patient Info</div>' +
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">' +
            '<div><label class="form-label" style="font-size:11px;">Age</label>' +
              '<input id="f-age" class="form-select" type="number" min="0" max="150" value="' + esc(p.age || '') + '"/></div>' +
            '<div><label class="form-label" style="font-size:11px;">Last Visit</label>' +
              '<input id="f-visit" class="form-select" type="date" value="' + esc(p.lastVisit || '') + '"/></div>' +
          '</div>' +
        '</div>' +

        '<div class="detail-section">' +
          '<div class="detail-section-label"><i data-lucide="activity" style="width:14px;height:14px;"></i> Condition & Status</div>' +
          '<input id="f-condition" class="form-select" type="text" placeholder="e.g. Hypertension" value="' + esc(p.condition || '') + '" style="margin-bottom:10px;"/>' +
          '<select id="f-status" class="form-select">' + statusOpts + '</select>' +
        '</div>' +

        '<div class="detail-section">' +
          '<div class="detail-section-label"><i data-lucide="heart-pulse" style="width:14px;height:14px;"></i> Vitals</div>' +
          '<textarea id="f-vitals" class="form-select" rows="3" placeholder="e.g. BP 120/80, HR 72, Temp 98.6°F, Weight 165 lbs">' + esc(p.vitals || '') + '</textarea>' +
        '</div>' +

        '<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:8px;">' +
          '<button id="save-clinical" class="btn-primary">' +
            '<i data-lucide="save" style="width:15px;height:15px;"></i> Save Changes</button>' +
        '</div>' +
      '</div>';

    document.getElementById('save-clinical').addEventListener('click', saveClinical);
    if (window.lucide) window.lucide.createIcons();
  }

  async function saveClinical() {
    if (!selectedPatient) return;
    var btn = document.getElementById('save-clinical');
    btn.disabled = true;
    var payload = {
      age:       document.getElementById('f-age').value,
      lastVisit: document.getElementById('f-visit').value,
      condition: document.getElementById('f-condition').value,
      status:    document.getElementById('f-status').value,
      vitals:    document.getElementById('f-vitals').value,
    };
    try {
      var updated = await Auth.put('/api/patients/' + selectedPatient.id, payload);
      if (updated && updated.id) {
        var idx = patients.findIndex(function(x){ return x.id === updated.id; });
        if (idx >= 0) patients[idx] = updated;
        selectedPatient = updated;
        showToast('Saved', 'Clinical record updated for ' + updated.name + '.', 'success');
        renderPatientList();
        renderDetailPanel();
      } else {
        showToast('Failed', 'Server did not confirm the update.', 'error');
      }
    } catch(e) {
      showToast('Error', e.message || 'Update failed.', 'error');
    } finally {
      btn.disabled = false;
    }
  }

  document.getElementById('patient-search').addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('[data-pid]').forEach(function(item) {
      item.style.display = item.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  try {
    patients = await Auth.get('/api/patients') || [];
  } catch(e) {
    showToast('Error', 'Failed to load patients: ' + e.message, 'error');
  }

  renderPatientList();
  renderDetailPanel();
  if (window.lucide) window.lucide.createIcons();
});
