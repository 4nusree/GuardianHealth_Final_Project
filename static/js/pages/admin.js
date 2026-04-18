/* ============================================
   ADMIN DASHBOARD JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('admin');
  if (!user) return;
  Auth.populateUI(user);

  var users = [];

  function rowBadge(cls, text) {
    return '<span class="badge badge-' + cls + '">' + text + '</span>';
  }

  function renderRow(u) {
    return '<tr>' +
      '<td><div class="td-name">' + u.name + '</div><div class="td-email">' + u.email + '</div></td>' +
      '<td>' + rowBadge(u.role, u.role) + '</td>' +
      '<td>' + rowBadge(u.status, u.status) + '</td>' +
      '<td><button class="badge ' + (u.mfaEnabled ? 'badge-mfa' : 'badge-mfa-off') + '" style="cursor:pointer;" data-mfa="' + u.id + '">' + (u.mfaEnabled ? 'Enforced' : 'Optional') + '</button></td>' +
      '<td class="text-sm text-muted">' + (u.lastLogin || 'Never') + '</td>' +
      '<td class="td-right">' +
        '<button class="btn-ghost" style="padding:6px;margin-right:4px;" data-edit="' + u.id + '"><i data-lucide="edit-2" style="width:15px;height:15px;"></i></button>' +
        '<button class="btn-danger" data-suspend="' + u.id + '">' + (u.status === 'active' ? 'Suspend' : 'Restore') + '</button>' +
      '</td>' +
    '</tr>';
  }

  function renderTable() {
    document.getElementById('users-tbody').innerHTML = users.map(renderRow).join('');
    document.getElementById('stat-total').textContent = users.length;
    bindRowActions();
    if (window.lucide) window.lucide.createIcons();
  }

  function bindRowActions() {
    document.querySelectorAll('[data-mfa]').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        var u = users.find(function(x) { return x.id === btn.dataset.mfa; });
        if (!u) return;
        try {
          var updated = await Auth.put('/api/users/' + u.id, { mfaEnabled: !u.mfaEnabled });
          if (updated) {
            u.mfaEnabled = updated.mfaEnabled;
            btn.textContent = u.mfaEnabled ? 'Enforced' : 'Optional';
            btn.className = 'badge ' + (u.mfaEnabled ? 'badge-mfa' : 'badge-mfa-off');
            btn.style.cursor = 'pointer';
            showToast('Policy Updated', 'MFA ' + (u.mfaEnabled ? 'enforced' : 'set optional') + ' for ' + u.name + '.', 'default');
          }
        } catch(e) {
          showToast('Error', e.message, 'error');
        }
      });
    });

    document.querySelectorAll('[data-suspend]').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        var u = users.find(function(x) { return x.id === btn.dataset.suspend; });
        if (!u) return;
        var wasActive = u.status === 'active';
        try {
          var updated = await Auth.put('/api/users/' + u.id, { status: wasActive ? 'suspended' : 'active' });
          if (updated) {
            u.status = updated.status;
            showToast(wasActive ? 'Account Suspended' : 'Account Restored', u.name + "'s account updated.", wasActive ? 'error' : 'success');
            renderTable();
          }
        } catch(e) {
          showToast('Error', e.message, 'error');
        }
      });
    });

    document.querySelectorAll('[data-edit]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var u = users.find(function(x) { return x.id === btn.dataset.edit; });
        if (u) showEditModal(u);
      });
    });
  }

  function showEditModal(u) {
    var existingModal = document.getElementById('edit-user-modal');
    if (existingModal) existingModal.remove();

    var roles = ['admin','doctor','patient','staff'];
    var modal = document.createElement('div');
    modal.id = 'edit-user-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:1000;';
    modal.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:380px;max-width:95vw;">' +
      '<h3 style="margin:0 0 20px;font-size:16px;">Edit User — ' + u.name + '</h3>' +
      '<div style="margin-bottom:14px;">' +
        '<label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:6px;">Role</label>' +
        '<select id="edit-role" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;">' +
          roles.map(function(r){ return '<option value="'+r+'"'+(u.role===r?' selected':'')+'>'+r+'</option>'; }).join('') +
        '</select></div>' +
      '<div style="margin-bottom:14px;">' +
        '<label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:6px;">Department</label>' +
        '<input id="edit-dept" type="text" value="'+(u.department||'')+'" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;box-sizing:border-box;"/></div>' +
      '<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px;">' +
        '<button id="edit-cancel" class="btn-ghost" style="padding:8px 16px;">Cancel</button>' +
        '<button id="edit-save" class="btn-primary" style="padding:8px 16px;">Save Changes</button>' +
      '</div>' +
    '</div>';

    document.body.appendChild(modal);

    document.getElementById('edit-cancel').addEventListener('click', function() { modal.remove(); });
    modal.addEventListener('click', function(e) { if (e.target === modal) modal.remove(); });

    document.getElementById('edit-save').addEventListener('click', async function() {
      var role = document.getElementById('edit-role').value;
      var dept = document.getElementById('edit-dept').value.trim();
      try {
        var updated = await Auth.put('/api/users/' + u.id, { role: role, department: dept });
        if (updated) {
          Object.assign(u, updated);
          showToast('User Updated', u.name + ' has been updated.', 'success');
          modal.remove();
          renderTable();
        }
      } catch(e) {
        showToast('Error', e.message, 'error');
      }
    });

    if (window.lucide) window.lucide.createIcons();
  }

  // Load users from API
  try {
    users = await Auth.get('/api/users') || [];
  } catch(e) {
    showToast('Error', 'Failed to load users: ' + e.message, 'error');
    users = [];
  }
  renderTable();

  document.getElementById('user-search').addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('#users-tbody tr').forEach(function(row) {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  document.getElementById('enforce-mfa-btn').addEventListener('click', async function() {
    try {
      var nonMfa = users.filter(function(u){ return !u.mfaEnabled && u.status !== 'suspended'; });
      for (var u of nonMfa) {
        var updated = await Auth.put('/api/users/' + u.id, { mfaEnabled: true });
        if (updated) Object.assign(u, updated);
      }
      renderTable();
      showToast('MFA Enforced', 'Global MFA policy activated for all active users.', 'success');
    } catch(e) {
      showToast('Error', e.message, 'error');
    }
  });

  document.getElementById('notif-btn').addEventListener('click', function() {
    showToast('3 Alerts', 'Suspicious login attempt from Moscow, RU detected.', 'error');
  });
});
