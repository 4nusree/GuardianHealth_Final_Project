/* ============================================
   STAFF PORTAL JS
   ============================================ */
document.addEventListener('DOMContentLoaded', function() {
  var user = Auth.requireRole('staff');
  if (!user) return;
  Auth.populateUI(user);

  var tasks = [
    { id: 1, text: 'Update vitals for Room 204 (Michael Scott)', priority: 'high', done: false },
    { id: 2, text: 'Administer medication — Emily Chen, 2PM', priority: 'high', done: false },
    { id: 3, text: 'Collect lab samples from Room 301', priority: 'medium', done: true },
    { id: 4, text: 'Update patient intake forms', priority: 'medium', done: false },
    { id: 5, text: 'Restock IV supplies in storage', priority: 'low', done: false },
    { id: 6, text: 'Sanitize examination Room 3', priority: 'low', done: true },
  ];

  var staffPatients = [
    { name: 'Emily Chen', room: '204', condition: 'Hypertension', status: 'Stable' },
    { name: 'Michael Scott', room: '301', condition: 'Type 2 Diabetes', status: 'Critical' },
    { name: 'Pam Beesly', room: '210', condition: 'Pregnancy', status: 'Monitoring' },
  ];

  function updateStats() {
    document.getElementById('stat-pending').textContent = tasks.filter(function(t) { return !t.done; }).length;
    document.getElementById('stat-done').textContent = tasks.filter(function(t) { return t.done; }).length;
  }

  function renderTasks() {
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
