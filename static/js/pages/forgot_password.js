/* ============================================
   FORGOT PASSWORD PAGE
   ============================================ */
(function() {
  async function submit() {
    var email = document.getElementById('fp-email').value.trim();
    if (!email || email.indexOf('@') === -1) {
      showToast('Invalid Email', 'Please enter a valid email address.', 'error');
      return;
    }
    var btn = document.getElementById('fp-submit');
    btn.disabled = true;
    btn.childNodes[0].textContent = 'Sending...';

    try {
      var res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email }),
      });
      var data = await res.json();

      if (!res.ok) {
        showToast('Error', data.error || 'Could not process request.', 'error');
        btn.disabled = false;
        btn.childNodes[0].textContent = 'Send Reset Link';
        return;
      }

      var msgEl = document.getElementById('fp-success-msg');
      if (msgEl && data.message) msgEl.textContent = data.message;
      document.getElementById('fp-form').classList.add('hidden');
      document.getElementById('fp-success').classList.remove('hidden');
    } catch (e) {
      showToast('Connection Error', 'Could not reach server. Please try again.', 'error');
      btn.disabled = false;
      btn.childNodes[0].textContent = 'Send Reset Link';
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    var emailEl = document.getElementById('fp-email');
    emailEl.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') submit();
    });
    document.getElementById('fp-submit').addEventListener('click', submit);
    if (window.lucide) window.lucide.createIcons();
  });
})();
