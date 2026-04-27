/* ============================================
   ADMIN DASHBOARD JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('admin');
  if (!user) return;
  Auth.populateUI(user);

  var users = [];

  function rowBadge(cls, text) {
    var safeCls  = esc(cls);
    var safeText = esc(text);
    return '<span class="badge badge-' + safeCls + '">' + safeText + '</span>';
  }

  /* Context-aware action button (Approve / Suspend / Restore) */
  function actionButton(u) {
    var cfg;
    if (u.status === 'pending') {
      cfg = { label: 'Approve',  cls: 'btn-success', target: 'active'    };
    } else if (u.status === 'active') {
      cfg = { label: 'Suspend',  cls: 'btn-danger',  target: 'suspended' };
    } else {
      cfg = { label: 'Restore',  cls: 'btn-success', target: 'active'    };
    }
    return '<button class="' + cfg.cls + '" data-action="' + esc(u.id) +
           '" data-target="' + cfg.target + '">' + cfg.label + '</button>';
  }

  function renderRow(u) {
    var safeId    = esc(u.id);
    var safeName  = esc(u.name);
    var safeEmail = esc(u.email);
    var safeRole  = esc(u.role);
    var safeStatus= esc(u.status);
    var safeLast  = esc(u.lastLogin || 'Never');

    return '<tr>' +
      '<td><div class="td-name">' + safeName + '</div><div class="td-email">' + safeEmail + '</div></td>' +
      '<td>' + rowBadge(u.role, safeRole) + '</td>' +
      '<td>' + rowBadge(u.status, safeStatus) + '</td>' +
      '<td><button class="badge ' + (u.mfaEnabled ? 'badge-mfa' : 'badge-mfa-off') +
        '" style="cursor:pointer;" data-mfa="' + safeId + '">' +
        (u.mfaEnabled ? 'Enforced' : 'Optional') + '</button></td>' +
      '<td class="text-sm text-muted">' + safeLast + '</td>' +
      '<td class="td-right">' +
        '<button class="btn-ghost" style="padding:6px;margin-right:4px;" data-edit="' + safeId +
          '" title="Edit"><i data-lucide="edit-2" style="width:15px;height:15px;"></i></button>' +
        actionButton(u) +
      '</td>' +
    '</tr>';
  }

  function recomputeStats() {
    document.getElementById('stat-total').textContent = users.length;
    var pendingEl = document.getElementById('stat-pending-count');
    if (pendingEl) {
      pendingEl.textContent = users.filter(function(u){ return u.status === 'pending'; }).length;
    }
  }

  function renderTable() {
    document.getElementById('users-tbody').innerHTML = users.map(renderRow).join('');
    recomputeStats();
    bindRowActions();
    if (window.lucide) window.lucide.createIcons();
  }

  function bindRowActions() {
    document.querySelectorAll('[data-mfa]').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        var u = users.find(function(x) { return x.id === btn.dataset.mfa; });
        if (!u) return;
        btn.disabled = true;
        try {
          var updated = await Auth.put('/api/users/' + u.id, { mfaEnabled: !u.mfaEnabled });
          if (updated) {
            Object.assign(u, updated);
            renderTable();
            showToast('Policy Updated', 'MFA ' + (u.mfaEnabled ? 'enforced' : 'set optional') + ' for ' + u.name + '.', 'default');
          } else {
            showToast('Action Failed', 'No response from server. Please refresh and try again.', 'error');
          }
        } catch(e) {
          showToast('Error', e.message || 'Update failed.', 'error');
        } finally {
          btn.disabled = false;
        }
      });
    });

    document.querySelectorAll('[data-action]').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        var u = users.find(function(x) { return x.id === btn.dataset.action; });
        if (!u) return;
        var target = btn.dataset.target;
        var prev   = u.status;
        btn.disabled = true;
        try {
          var updated = await Auth.put('/api/users/' + u.id, { status: target });
          if (updated && updated.status === target) {
            Object.assign(u, updated);
            renderTable();
            var msg;
            if (prev === 'pending'   && target === 'active')    msg = { t: 'Account Approved', d: u.name + ' is now active.', k: 'success' };
            else if (target === 'suspended')                    msg = { t: 'Account Suspended', d: u.name + "'s access has been revoked.", k: 'error' };
            else                                                 msg = { t: 'Account Restored', d: u.name + ' is now active.', k: 'success' };
            showToast(msg.t, msg.d, msg.k);
          } else {
            showToast('Action Failed', 'Server did not confirm the change. Refreshing list…', 'error');
            await refreshUsers();
          }
        } catch(e) {
          showToast('Error', e.message || 'Update failed.', 'error');
        } finally {
          btn.disabled = false;
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
    var safeName = esc(u.name);
    var safeDept = esc(u.department || '');
    var modal = document.createElement('div');
    modal.id = 'edit-user-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:1000;';
    modal.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:380px;max-width:95vw;">' +
      '<h3 style="margin:0 0 20px;font-size:16px;">Edit User — ' + safeName + '</h3>' +
      '<div style="margin-bottom:14px;">' +
        '<label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:6px;">Role</label>' +
        '<select id="edit-role" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;">' +
          roles.map(function(r){ return '<option value="'+r+'"'+(u.role===r?' selected':'')+'>'+r+'</option>'; }).join('') +
        '</select></div>' +
      '<div style="margin-bottom:14px;">' +
        '<label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:6px;">Department</label>' +
        '<input id="edit-dept" type="text" value="'+safeDept+'" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;box-sizing:border-box;"/></div>' +
      '<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:20px;">' +
        '<button id="edit-cancel" class="btn-ghost" style="padding:8px 16px;">Cancel</button>' +
        '<button id="edit-save" class="btn-primary-sm">Save Changes</button>' +
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

  async function refreshUsers() {
    var refreshBtn = document.getElementById('refresh-users-btn');
    if (refreshBtn) refreshBtn.disabled = true;
    try {
      users = await Auth.get('/api/users') || [];
      renderTable();
    } catch(e) {
      showToast('Error', 'Failed to load users: ' + e.message, 'error');
      users = [];
      renderTable();
    } finally {
      if (refreshBtn) refreshBtn.disabled = false;
    }
  }

  // Initial load
  await refreshUsers();

  // Auto-refresh every 30s so newly registered users appear without manual reload
  setInterval(function() {
    if (document.visibilityState === 'visible') refreshUsers();
  }, 30000);

  document.getElementById('user-search').addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('#users-tbody tr').forEach(function(row) {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  var refreshBtn = document.getElementById('refresh-users-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', function() { refreshUsers(); });

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
    showToast('No Alerts', 'No new security alerts.', 'default');
  });
});
