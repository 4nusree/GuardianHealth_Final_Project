/* ============================================
   SECURITY CENTER JS — Real API
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireRole('admin');
  if (!user) return;
  Auth.populateUI(user);

  var sessions = [];

  function renderSessions() {
    var active = sessions.filter(function(s) { return s.status === 'Active'; });
    document.getElementById('stat-sessions').textContent = active.length;

    document.getElementById('sessions-list').innerHTML = sessions.map(function(s) {
      return '<div class="session-item">' +
        '<div>' +
          '<div class="session-device"><i data-lucide="monitor" style="width:16px;height:16px;"></i>' + s.device + '</div>' +
          '<div class="session-meta">' + s.ip + ' · ' + (s.location || 'Unknown') + ' · Started ' + s.startedAt + '</div>' +
        '</div>' +
        '<div class="flex gap-3" style="align-items:center;">' +
          '<span class="' + (s.status === 'Active' ? 'session-active' : 'session-terminated') + '">' + s.status + '</span>' +
          (s.status === 'Active' ? '<button class="session-logout-btn" data-sid="' + s.id + '">Logout Session</button>' : '') +
        '</div>' +
      '</div>';
    }).join('');

    document.querySelectorAll('[data-sid]').forEach(function(btn) {
      btn.addEventListener('click', async function() {
        var s = sessions.find(function(x) { return x.id === btn.dataset.sid; });
        if (!s) return;
        try {
          await Auth.del('/api/sessions/' + s.id);
          s.status = 'Terminated';
          showToast('Session Terminated', 'Device logged out: ' + s.device, 'error');
          renderSessions();
          if (window.lucide) window.lucide.createIcons();
        } catch(e) {
          showToast('Error', e.message, 'error');
        }
      });
    });

    if (window.lucide) window.lucide.createIcons();
  }

  function initCharts() {
    var days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    var opts = {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', font: { size: 11 } } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', font: { size: 11 } }, beginAtZero: true }
      }
    };

    var lc = document.getElementById('login-chart');
    if (lc && window.Chart) {
      new window.Chart(lc, {
        type: 'bar',
        data: { labels: days, datasets: [{ data: [42,38,55,47,61,29,45], backgroundColor: 'rgba(20,184,166,0.5)', borderColor: '#14b8a6', borderWidth: 1, borderRadius: 4 }] },
        options: opts
      });
    }

    var fc = document.getElementById('failed-chart');
    if (fc && window.Chart) {
      new window.Chart(fc, {
        type: 'line',
        data: { labels: days, datasets: [{ data: [3,1,5,2,4,1,3], fill: true, backgroundColor: 'rgba(239,68,68,0.1)', borderColor: '#ef4444', borderWidth: 2, pointBackgroundColor: '#ef4444', tension: 0.4 }] },
        options: opts
      });
    }
  }

  // Load sessions from API
  try {
    sessions = await Auth.get('/api/sessions') || [];
  } catch(e) {
    showToast('Error', 'Failed to load sessions: ' + e.message, 'error');
  }

  renderSessions();
  initCharts();
});
