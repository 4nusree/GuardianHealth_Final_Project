/* ============================================
   PATIENT PORTFOLIO JS
   ============================================ */
document.addEventListener('DOMContentLoaded', function() {
  var user = Auth.requireRole('patient');
  if (!user) return;
  Auth.populateUI(user);

  var consents = [];

  function renderConsents() {
    if (!consents.length) {
      document.getElementById('consent-list').innerHTML = '<p class="text-sm text-muted">No provider consents configured.</p>';
      return;
    }
    document.getElementById('consent-list').innerHTML = consents.map(function(c, i) {
      return '<div class="consent-item">' +
        '<div><div class="consent-doc">' + c.doc + '</div><div class="consent-dept">' + c.dept + '</div></div>' +
        '<label class="toggle-switch">' +
          '<input type="checkbox" ' + (c.allowed ? 'checked' : '') + ' data-ci="' + i + '"/>' +
          '<div class="toggle-track"><div class="toggle-thumb"></div></div>' +
        '</label>' +
      '</div>';
    }).join('');

    document.querySelectorAll('[data-ci]').forEach(function(cb) {
      cb.addEventListener('change', function() {
        var i = parseInt(cb.dataset.ci);
        consents[i].allowed = cb.checked;
        showToast('Consent Updated', 'Access for ' + consents[i].doc + ' has been ' + (cb.checked ? 'granted' : 'revoked') + '.', cb.checked ? 'success' : 'error');
      });
    });
  }

  document.querySelectorAll('[data-report]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      showToast('Download Started', 'Securely decrypting ' + btn.dataset.report + '.', 'default');
    });
  });

  renderConsents();
  if (window.lucide) window.lucide.createIcons();
});
