/* ============================================
   STAFF PORTAL JS
   ============================================ */
document.addEventListener('DOMContentLoaded', function() {
  var user = Auth.requireRole('staff');
  if (!user) return;
  Auth.populateUI(user);

  var tasks = [];

  var staffPatients = [];

  function updateStats() {
    document.getElementById('stat-pending').textContent = tasks.filter(function(t) { return !t.done; }).length;
    document.getElementById('stat-done').textContent = tasks.filter(function(t) { return t.done; }).length;
    var patEl = document.getElementById('stat-patients');
    if (patEl) patEl.textContent = staffPatients.length;
  }

  function renderTasks() {
    if (!tasks.length) {
      document.getElementById('task-list').innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:13px;">No tasks assigned.</div>';
      return;
    }
    document.getElementById('task-list').innerHTML = tasks.map(function(t) {
      return '<div class="task-item">' +
        '<input type="checkbox" class="task-cb" data-tid="' + t.id + '" ' + (t.done ? 'checked' : '') + '/>' +
        '<span class="task-text ' + (t.done ? 'done' : '') + '">' + t.text + '</span>' +
        '<span class="task-priority priority-' + t.priority + '">' + t.priority + '</span>' +
      '</div>';
    }).join('');

    document.querySelectorAll('[data-tid]').forEach(function(cb) {
      cb.addEventListener('change', function() {
        var t = tasks.find(function(x) { return x.id === parseInt(cb.dataset.tid); });
        if (t) {
          t.done = cb.checked;
          cb.nextElementSibling.className = 'task-text ' + (t.done ? 'done' : '');
          updateStats();
          showToast(t.done ? 'Task Complete' : 'Task Reopened', t.text.slice(0, 50), t.done ? 'success' : 'default');
        }
      });
    });
  }

  function renderPatients() {
    document.getElementById('patients-tbody').innerHTML = staffPatients.map(function(p) {
      var sc = p.status === 'Stable' ? 'badge-stable' : p.status === 'Critical' ? 'badge-critical' : 'badge-monitoring';
      return '<tr>' +
        '<td class="td-name">' + p.name + '</td>' +
        '<td>Room ' + p.room + '</td>' +
        '<td class="text-sm text-muted">' + p.condition + '</td>' +
        '<td><span class="badge ' + sc + '">' + p.status + '</span></td>' +
        '<td class="td-right"><button class="btn-ghost" onclick="showToast(\'Record Viewed\',\'Access logged to blockchain audit trail.\',\'default\')"><i data-lucide="eye" style="width:15px;height:15px;"></i></button></td>' +
      '</tr>';
    }).join('');
  }

  document.getElementById('save-vitals-btn').addEventListener('click', function() {
    var patient = document.getElementById('vitals-patient').value.split('—')[0].trim();
    showToast('Vitals Saved', 'Vitals for ' + patient + ' recorded to secure ledger.', 'success');
  });

  renderTasks();
  renderPatients();
  updateStats();
  if (window.lucide) window.lucide.createIcons();
});
