/* ============================================
   IAM PANEL JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('admin');
  if (!user) return;
  Auth.populateUI(user);

  var users = [];
  var editUser = null;

  var permsByRole = {
    admin:   ['view_all_records', 'edit_users', 'manage_roles', 'view_audit_logs', 'force_logout', 'manage_mfa'],
    doctor:  ['view_patient_records', 'add_diagnosis', 'add_prescription', 'view_audit_logs'],
    staff:   ['view_assigned_patients', 'update_vitals'],
    patient: ['view_own_records', 'manage_consent'],
  };

  var allPerms = [
    { key: 'view_all_records',      label: 'View All Records' },
    { key: 'edit_users',            label: 'Edit Users' },
    { key: 'manage_roles',          label: 'Manage Roles' },
    { key: 'view_audit_logs',       label: 'View Audit Logs' },
    { key: 'force_logout',          label: 'Force Logout Sessions' },
    { key: 'manage_mfa',            label: 'Manage MFA Policies' },
    { key: 'view_patient_records',  label: 'View Patient Records' },
    { key: 'add_diagnosis',         label: 'Add Diagnosis' },
    { key: 'add_prescription',      label: 'Add Prescription' },
    { key: 'view_assigned_patients',label: 'View Assigned Patients' },
    { key: 'update_vitals',         label: 'Update Vitals' },
    { key: 'view_own_records',      label: 'View Own Records' },
    { key: 'manage_consent',        label: 'Manage Consent' },
  ];

  function renderTable() {
    document.getElementById('iam-tbody').innerHTML = users.map(function(u) {
      var perms = permsByRole[u.role] || [];
      var badges = perms.slice(0, 3).map(function(p) {
        return '<span class="badge badge-mfa" style="font-size:10px;margin-right:3px;">' + p.replace(/_/g,' ') + '</span>';
      }).join('') + (perms.length > 3 ? '<span class="text-xs text-muted">+' + (perms.length - 3) + ' more</span>' : '');

      return '<tr>' +
        '<td><div class="td-name">' + u.name + '</div><div class="td-email">' + u.email + '</div></td>' +
        '<td><span class="badge badge-' + u.role + '">' + u.role + '</span></td>' +
        '<td><span class="badge badge-' + u.status + '">' + u.status + '</span></td>' +
        '<td style="max-width:260px;">' + badges + '</td>' +
        '<td class="td-right"><button class="btn-outline" style="font-size:12px;padding:6px 12px;" data-edit="' + u.id + '"><i data-lucide="edit-2" style="width:13px;height:13px;"></i> Edit Role</button></td>' +
      '</tr>';
    }).join('');

    document.querySelectorAll('[data-edit]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        editUser = users.find(function(u) { return u.id === btn.dataset.edit; });
        if (!editUser) return;
        openModal(editUser);
      });
    });

    if (window.lucide) window.lucide.createIcons();
  }

  function openModal(u) {
    document.getElementById('modal-title').textContent = 'Edit — ' + u.name;
    document.getElementById('modal-role').value = u.role;
    renderPermList(u.role);
    document.getElementById('edit-modal').classList.remove('hidden');
  }

  function renderPermList(role) {
    var current = permsByRole[role] || [];
    document.getElementById('perm-list').innerHTML = allPerms.map(function(p) {
      return '<div class="perm-check-item">' +
        '<span class="perm-check-label">' + p.label + '</span>' +
        '<input type="checkbox" class="perm-checkbox" data-perm="' + p.key + '" ' + (current.includes(p.key) ? 'checked' : '') + '/>' +
      '</div>';
    }).join('');
  }

  document.getElementById('modal-role').addEventListener('change', function() {
    renderPermList(this.value);
  });

  function closeModal() {
    document.getElementById('edit-modal').classList.add('hidden');
    editUser = null;
  }

  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-cancel').addEventListener('click', closeModal);
  document.getElementById('edit-modal').addEventListener('click', function(e) {
    if (e.target === this) closeModal();
  });

  document.getElementById('modal-save').addEventListener('click', async function() {
    if (!editUser) return;
    var newRole = document.getElementById('modal-role').value;
    try {
      var updated = await Auth.put('/api/users/' + editUser.id, { role: newRole });
      if (updated) {
        Object.assign(editUser, updated);
        showToast('Role Updated', editUser.name + ' changed to ' + newRole + '.', 'success');
        closeModal();
        renderTable();
      }
    } catch(e) {
      showToast('Error', e.message, 'error');
    }
  });

  document.getElementById('iam-search').addEventListener('input', function() {
    var q = this.value.toLowerCase();
    document.querySelectorAll('#iam-tbody tr').forEach(function(row) {
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });

  document.getElementById('add-user-btn').addEventListener('click', function() {
    // Show a simple add user modal
    var existingModal = document.getElementById('add-user-modal');
    if (existingModal) existingModal.remove();

    var modal = document.createElement('div');
    modal.id = 'add-user-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:1000;';
    modal.innerHTML = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:28px;width:380px;max-width:95vw;">' +
      '<h3 style="margin:0 0 20px;font-size:16px;display:flex;align-items:center;gap:8px;"><i data-lucide="user-plus" style="width:18px;height:18px;color:var(--primary);"></i> Add User</h3>' +
      '<div style="margin-bottom:12px;"><label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:5px;">Full Name</label>' +
        '<input id="new-name" type="text" placeholder="e.g. Dr. John Smith" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;box-sizing:border-box;"/></div>' +
      '<div style="margin-bottom:12px;"><label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:5px;">Email</label>' +
        '<input id="new-email" type="email" placeholder="user@guardian.health" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;box-sizing:border-box;"/></div>' +
      '<div style="margin-bottom:12px;"><label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:5px;">Role</label>' +
        '<select id="new-role" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;">' +
          '<option value="staff">staff</option><option value="doctor">doctor</option><option value="patient">patient</option><option value="admin">admin</option>' +
        '</select></div>' +
      '<div style="margin-bottom:20px;"><label style="display:block;font-size:12px;color:var(--text-muted);margin-bottom:5px;">Department</label>' +
        '<input id="new-dept" type="text" placeholder="e.g. Cardiology" style="width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-size:13px;box-sizing:border-box;"/></div>' +
      '<div style="display:flex;gap:10px;justify-content:flex-end;">' +
        '<button id="new-cancel" class="btn-ghost" style="padding:8px 16px;">Cancel</button>' +
        '<button id="new-save" class="btn-primary" style="padding:8px 16px;">Create User</button>' +
      '</div>' +
    '</div>';

    document.body.appendChild(modal);
    if (window.lucide) window.lucide.createIcons();

    document.getElementById('new-cancel').addEventListener('click', function() { modal.remove(); });
    modal.addEventListener('click', function(e) { if (e.target === modal) modal.remove(); });

    document.getElementById('new-save').addEventListener('click', async function() {
      var name = document.getElementById('new-name').value.trim();
      var email = document.getElementById('new-email').value.trim();
      var role = document.getElementById('new-role').value;
      var dept = document.getElementById('new-dept').value.trim();
      if (!name || !email) { showToast('Missing Fields', 'Name and email are required.', 'error'); return; }
      try {
        var created = await Auth.post('/api/users', { name, email, role, department: dept });
        if (created) {
          users.push(created);
          showToast('User Created', name + ' added as ' + role + '. Temp password: TempPass123!', 'success');
          modal.remove();
          renderTable();
        }
      } catch(e) {
        showToast('Error', e.message, 'error');
      }
    });
  });

  // Load users from API
  try {
    users = await Auth.get('/api/users') || [];
  } catch(e) {
    showToast('Error', 'Failed to load users: ' + e.message, 'error');
  }

  renderTable();
});
