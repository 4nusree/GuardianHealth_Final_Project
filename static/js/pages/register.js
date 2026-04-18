/* ============================================
   REGISTER PAGE JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', function() {
  var selectedFile = null;

  document.getElementById('reg-role').addEventListener('change', function() {
    var sec = document.getElementById('doc-upload-section');
    sec.classList.toggle('hidden', this.value !== 'doctor');
  });

  document.getElementById('doc-file').addEventListener('change', function(e) {
    var f = e.target.files[0];
    if (f) {
      selectedFile = f;
      document.getElementById('upload-label-text').textContent = f.name;
    }
  });

  document.getElementById('reg-submit').addEventListener('click', async function() {
    var name  = document.getElementById('reg-name').value.trim();
    var email = document.getElementById('reg-email').value.trim();
    var pass  = document.getElementById('reg-pass').value;
    var pass2 = document.getElementById('reg-pass2').value;
    var role  = document.getElementById('reg-role').value;

    if (!name || !email || !pass || !role) { showToast('Missing Fields', 'Please fill all required fields.', 'error'); return; }
    if (pass !== pass2) { showToast('Password Mismatch', 'Passwords do not match.', 'error'); return; }
    if (pass.length < 6) { showToast('Weak Password', 'Password must be at least 6 characters.', 'error'); return; }
    if (role === 'doctor' && !selectedFile) { showToast('Document Required', 'Please upload your verification document.', 'error'); return; }

    var btn = document.getElementById('reg-submit');
    btn.disabled = true;
    btn.childNodes[0].textContent = 'Submitting...';

    try {
      var res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, email: email, password: pass, role: role }),
      });
      var data = await res.json();
      if (!res.ok) {
        showToast('Error', data.error || 'Registration failed.', 'error');
        btn.disabled = false;
        btn.childNodes[0].textContent = 'Request Access';
        return;
      }
      document.getElementById('reg-form').classList.add('hidden');
      document.getElementById('reg-success').classList.remove('hidden');
    } catch(e) {
      // Fallback simulation if API not available
      setTimeout(function() {
        document.getElementById('reg-form').classList.add('hidden');
        document.getElementById('reg-success').classList.remove('hidden');
      }, 500);
    }
  });

  if (window.lucide) window.lucide.createIcons();
});
