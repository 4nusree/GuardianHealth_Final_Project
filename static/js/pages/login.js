/* ============================================
   LOGIN PAGE JS — Real API Auth
   ============================================ */
(function () {
  var otp = ['', '', '', '', '', ''];
  var timerInterval = null;
  var timeLeft = 60;
  var pendingEmail = '';
  var tempToken = '';
  var resendAfterSeconds = 60;
  var codeExpiresMinutes = 10;

  function getRisk(email) {
    if (!email) return null;
    if (email.includes('admin')) return { level: 'High', cls: 'risk-high', icon: '⚠' };
    if (email.includes('staff')) return { level: 'Medium', cls: 'risk-medium', icon: '!' };
    return { level: 'Low', cls: 'risk-low', icon: '✓' };
  }

  function showStep(step) {
    document.getElementById('step-credentials').classList.toggle('hidden', step !== 'credentials');
    document.getElementById('step-mfa').classList.toggle('hidden', step !== 'mfa');
    if (step === 'mfa') {
      otp = ['', '', '', '', '', ''];
      startTimer();
      setTimeout(function () {
        var f = document.getElementById('otp-0');
        if (f) f.focus();
      }, 50);
    }
  }

  function startTimer() {
    clearInterval(timerInterval);
    timeLeft = resendAfterSeconds;
    updateTimer();
    timerInterval = setInterval(function () {
      timeLeft--;
      updateTimer();
      if (timeLeft <= 0) clearInterval(timerInterval);
    }, 1000);
  }

  function updateTimer() {
    var el = document.getElementById('timer-val');
    if (el) el.textContent = timeLeft;
    var resend = document.getElementById('resend-btn');
    if (resend) {
      resend.disabled = timeLeft > 0;
      resend.textContent = timeLeft > 0 ? 'Resend Code' : 'Resend Code Now';
    }
  }

  async function submitCredentials() {
    var email = document.getElementById('login-email').value.trim();
    var pass = document.getElementById('login-password').value;
    if (!email || !pass) { showToast('Missing Fields', 'Please enter email and password.', 'error'); return; }
    pendingEmail = email;
    var btn = document.getElementById('login-btn');
    btn.disabled = true;
    btn.childNodes[0].textContent = 'Authenticating...';

    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: pass }),
      });
      var data = await res.json();

      if (!res.ok) {
        showToast('Error', data.error || 'Login failed.', 'error');
        btn.disabled = false;
        btn.childNodes[0].textContent = 'Continue to Verify';
        return;
      }

      if (data.mfa_required) {
        tempToken = data.temp_token;
        resendAfterSeconds = data.resend_after_seconds || 60;
        codeExpiresMinutes = data.expires_in_minutes || 10;
        var subtitle = document.getElementById('mfa-subtitle');
        if (subtitle) subtitle.textContent = 'Enter the 6-digit code sent to ' + (data.masked_email || 'your registered email') + '. It expires in ' + codeExpiresMinutes + ' minutes.';
        showToast('Code Sent', 'Check your registered email for the verification code.', 'default');
        showStep('mfa');
      } else {
        // No MFA required — direct login
        Auth.setSession(data.user, data.token, data.csrf_token);
        showToast('Access Granted', 'Welcome back, ' + data.user.name + '!', 'success');
        setTimeout(function () { Auth.redirectByRole(data.user.role); }, 600);
      }
    } catch (e) {
      showToast('Connection Error', 'Could not reach server. Please try again.', 'error');
    }

    btn.disabled = false;
    btn.childNodes[0].textContent = 'Continue to Verify';
  }

  async function submitMfa() {
    var code = otp.join('');
    if (code.length < 6) { showToast('Invalid Code', 'Please enter all 6 digits.', 'error'); return; }
    var btn = document.getElementById('mfa-btn');
    btn.disabled = true;
    var orig = btn.innerHTML;
    btn.innerHTML = 'Verifying...';
    clearInterval(timerInterval);

    try {
      var res = await fetch('/api/auth/verify-mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ temp_token: tempToken, code: code }),
      });
      var data = await res.json();

      if (!res.ok) {
        showToast('MFA Failed', data.error || 'Verification failed.', 'error');
        btn.disabled = false;
        btn.innerHTML = orig;
        return;
      }

      Auth.setSession(data.user, data.token, data.csrf_token);
      showToast('Access Granted', 'Welcome back, ' + data.user.name + '!', 'success');
      setTimeout(function () { Auth.redirectByRole(data.user.role); }, 600);
    } catch (e) {
      showToast('Connection Error', 'Could not verify MFA. Please try again.', 'error');
      btn.disabled = false;
      btn.innerHTML = orig;
    }
  }

  function initOtp() {
    [0, 1, 2, 3, 4, 5].forEach(function (i) {
      var inp = document.getElementById('otp-' + i);
      if (!inp) return;
      inp.addEventListener('input', function (e) {
        otp[i] = e.target.value.replace(/\D/g, '').slice(-1);
        inp.value = otp[i];
        if (otp[i] && i < 5) document.getElementById('otp-' + (i + 1)).focus();
      });
      inp.addEventListener('keydown', function (e) {
        if (e.key === 'Backspace' && !otp[i] && i > 0) {
          otp[i - 1] = '';
          var prev = document.getElementById('otp-' + (i - 1));
          prev.value = ''; prev.focus();
        }
        if (e.key === 'Enter') submitMfa();
      });
      inp.addEventListener('paste', function (e) {
        var pasted = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
        pasted.split('').forEach(function (ch, j) {
          var o = document.getElementById('otp-' + j);
          if (o) { o.value = ch; otp[j] = ch; }
        });
        e.preventDefault();
        var nextIdx = Math.min(pasted.length, 5);
        var nextEl = document.getElementById('otp-' + nextIdx);
        if (nextEl) nextEl.focus();
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    // Redirect if already logged in
    var existing = Auth.getUser();
    if (existing) { Auth.redirectByRole(existing.role); return; }


    // Handle OAuth error params from Google redirect
    var params = new URLSearchParams(window.location.search);
    var oauthError = params.get('error');
    if (oauthError) {
      var msgs = {
        google_denied: 'Google sign-in was cancelled.',
        oauth_state: 'Sign-in session expired. Please try again.',
        google_token: 'Could not complete Google sign-in. Please try again.',
        google_userinfo: 'Could not retrieve your Google profile. Please try again.',
        google_email: 'No email returned from Google. Please try again.',
        google_not_configured: 'Google sign-in is not configured. Contact your administrator.',
        suspended: 'Your account has been suspended. Contact your administrator.',
        pending: 'Your account is pending administrator approval.',
        email_exists: 'An account with this email already exists. Please sign in with your email and password.',
        rate_limited: 'Too many sign-in attempts. Please wait a few minutes and try again.',
      };
      showToast('Sign-in Error', msgs[oauthError] || 'An error occurred. Please try again.', 'error');
      window.history.replaceState({}, '', '/login');
    }

    // Risk indicator
    var emailEl = document.getElementById('login-email');
    var riskEl = document.getElementById('risk-indicator');
    emailEl.addEventListener('input', function () {
      var r = getRisk(emailEl.value);
      riskEl.innerHTML = r ? '<span class="risk-indicator ' + r.cls + '">' + r.icon + ' Session Risk: ' + r.level + '</span>' : '';
    });

    // Password enter key
    document.getElementById('login-password').addEventListener('keydown', function (e) {
      if (e.key === 'Enter') submitCredentials();
    });
    emailEl.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') document.getElementById('login-password').focus();
    });

    // Credentials button
    document.getElementById('login-btn').addEventListener('click', submitCredentials);

    // MFA buttons
    document.getElementById('mfa-btn').addEventListener('click', submitMfa);
    document.getElementById('back-btn').addEventListener('click', function () {
      clearInterval(timerInterval);
      showStep('credentials');
    });
    document.getElementById('resend-btn').addEventListener('click', async function () {
      if (timeLeft > 0) return;
      var btn = this;
      btn.disabled = true;
      try {
        var res = await fetch('/api/auth/resend-mfa', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ temp_token: tempToken }),
        });
        var data = await res.json();
        if (!res.ok) {
          showToast('Could Not Resend', data.error || 'Please try again later.', 'error');
          btn.disabled = false;
          return;
        }
        resendAfterSeconds = data.resend_after_seconds || 60;
        codeExpiresMinutes = data.expires_in_minutes || 10;
        var subtitle = document.getElementById('mfa-subtitle');
        if (subtitle) subtitle.textContent = 'Enter the 6-digit code sent to ' + (data.masked_email || 'your registered email') + '. It expires in ' + codeExpiresMinutes + ' minutes.';
        startTimer();
        showToast('Code Sent', 'A new verification code was sent to your registered email.', 'default');
      } catch (e) {
        showToast('Connection Error', 'Could not resend the verification code.', 'error');
        btn.disabled = false;
      }
    });

    initOtp();
    if (window.lucide) window.lucide.createIcons();
  });
})();
