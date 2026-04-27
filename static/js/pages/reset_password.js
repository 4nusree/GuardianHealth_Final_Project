/* ============================================
   RESET PASSWORD PAGE
   ============================================ */
(function() {
  function getToken() {
    var params = new URLSearchParams(window.location.search);
    return (params.get('token') || '').trim();
  }

  async function submit(token) {
    var pw  = document.getElementById('rp-pass').value;
    var pw2 = document.getElementById('rp-pass2').value;

    if (pw.length < 12) {
      showToast('Weak Password', 'Password must be at least 12 characters.', 'error');
      return;
    }
    if (pw !== pw2) {
      showToast('Mismatch', 'Passwords do not match.', 'error');
      return;
    }

    var btn = document.getElementById('rp-submit');
    btn.disabled = true;
    btn.childNodes[0].textContent = 'Updating...';

    try {
      var res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, new_password: pw }),
      });
      var data = await res.json();

      if (!res.ok) {
        showToast('Reset Failed', data.error || 'Could not reset password.', 'error');
        btn.disabled = false;
        btn.childNodes[0].textContent = 'Update Password';
        return;
      }

      document.getElementById('rp-form').classList.add('hidden');
      document.getElementById('rp-success').classList.remove('hidden');
      showToast('Password Updated', 'You can now sign in with your new password.', 'success');
    } catch (e) {
      showToast('Connection Error', 'Could not reach server. Please try again.', 'error');
      btn.disabled = false;
      btn.childNodes[0].textContent = 'Update Password';
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    var token = getToken();
    if (!token) {
      document.getElementById('rp-form').classList.add('hidden');
      document.getElementById('rp-missing').classList.remove('hidden');
      if (window.lucide) window.lucide.createIcons();
      return;
    }

    document.getElementById('rp-submit').addEventListener('click', function() { submit(token); });
    document.getElementById('rp-pass2').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') submit(token);
    });
    document.getElementById('rp-pass').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') document.getElementById('rp-pass2').focus();
    });
    if (window.lucide) window.lucide.createIcons();
  });
})();
