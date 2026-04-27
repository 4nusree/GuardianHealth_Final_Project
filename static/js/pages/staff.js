/* ============================================
   STAFF PORTAL JS — Patient ↔ Doctor assignment
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('staff');
  if (!user) return;
  Auth.populateUI(user);

  var patients = [];
  var doctors  = [];

  function statusBadge(s) {
    var cls = s === 'Stable' ? 'badge-stable'
            : s === 'Critical' ? 'badge-critical'
            : 'badge-monitoring';
    return '<span class="badge ' + cls + '">' + esc(s) + '</span>';
  }

  function doctorOptions(selectedId) {
    var opts = '<option value="">— Unassigned —</option>';
    doctors.forEach(function(d) {
      var sel = (selectedId && selectedId === d.id) ? ' selected' : '';
      opts += '<option value="' + esc(d.id) + '"' + sel + '>' + esc(d.name) + '</option>';
    });
    return opts;
  }

  function updateStats() {
    document.getElementById('stat-patients').textContent   = patients.length;
    document.getElementById('stat-unassigned').textContent = patients.filter(function(p){ return !p.doctorId; }).length;
    document.getElementById('stat-doctors').textContent    = doctors.length;
  }

  function renderQuickAssignDropdowns() {
    var pSel = document.getElementById('assign-patient');
    var dSel = document.getElementById('assign-doctor');
    pSel.innerHTML = '<option value="">— Select a patient —</option>' +
      patients.map(function(p) {
        var label = p.name + (p.doctorName ? ' (currently: ' + p.doctorName + ')' : ' (unassigned)');
        return '<option value="' + esc(p.id) + '">' + esc(label) + '</option>';
      }).join('');
    dSel.innerHTML = '<option value="">— Select a doctor —</option>' +
      doctors.map(function(d) {
        return '<option value="' + esc(d.id) + '">' + esc(d.name) + (d.department ? ' — ' + esc(d.department) : '') + '</option>';
      }).join('');
  }

  function renderTable() {
    var tbody = document.getElementById('patients-tbody');
    if (!patients.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);font-size:13px;">No patients yet.</td></tr>';
      return;
    }
    tbody.innerHTML = patients.map(function(p) {
      return '<tr>' +
        '<td><div class="td-name">' + esc(p.name) + '</div><div class="td-email">Age ' + esc(p.age || '—') + '</div></td>' +
        '<td class="text-sm text-muted">' + esc(p.condition || '—') + '</td>' +
        '<td>' + statusBadge(p.status) + '</td>' +
        '<td>' +
          '<select class="form-select" data-row-doctor="' + esc(p.id) + '" style="min-width:180px;">' +
             doctorOptions(p.doctorId) +
          '</select>' +
        '</td>' +
        '<td class="td-right">' +
          '<button class="btn-primary-sm" data-save="' + esc(p.id) + '">Save</button>' +
        '</td>' +
      '</tr>';
    }).join('');

    document.querySelectorAll('[data-save]').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        var pid = btn.dataset.save;
        var sel = document.querySelector('[data-row-doctor="' + pid + '"]');
        var did = sel ? sel.value : '';
        await assign(pid, did, btn);
      });
    });
  }

  async function assign(pid, did, triggerBtn) {
    if (triggerBtn) triggerBtn.disabled = true;
    try {
      var updated = await Auth.put('/api/patients/' + pid, { doctorId: did });
      if (updated && updated.id) {
        var idx = patients.findIndex(function(x){ return x.id === pid; });
        if (idx >= 0) patients[idx] = updated;
        var p = updated;
        var msg = did
          ? p.name + ' assigned to ' + (p.doctorName || 'doctor') + '.'
          : p.name + ' is now unassigned.';
        showToast('Assignment Saved', msg, 'success');
        renderTable();
        renderQuickAssignDropdowns();
        updateStats();
      } else {
        showToast('Failed', 'Server did not confirm. Please refresh.', 'error');
      }
    } catch(e) {
      showToast('Error', e.message || 'Update failed.', 'error');
    } finally {
      if (triggerBtn) triggerBtn.disabled = false;
    }
  }

  document.getElementById('assign-btn').addEventListener('click', async function() {
    var pid = document.getElementById('assign-patient').value;
    var did = document.getElementById('assign-doctor').value;
    if (!pid) { showToast('Pick a patient', 'Please select a patient first.', 'error'); return; }
    await assign(pid, did, this);
  });

  document.getElementById('patient-search').addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('#patients-tbody tr').forEach(function(row) {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  // Initial load — patients and doctors in parallel
  try {
    var results = await Promise.all([
      Auth.get('/api/patients'),
      Auth.get('/api/doctors'),
    ]);
    patients = results[0] || [];
    doctors  = results[1] || [];
  } catch(e) {
    showToast('Error', 'Failed to load data: ' + e.message, 'error');
  }

  renderQuickAssignDropdowns();
  renderTable();
  updateStats();
  if (window.lucide) window.lucide.createIcons();
});
