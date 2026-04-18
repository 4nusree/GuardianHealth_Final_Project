/* ============================================
   BLOCKCHAIN EXPLORER JS
   ============================================ */
document.addEventListener('DOMContentLoaded', async function() {
  var user = Auth.requireAuth();
  if (!user || user.role !== 'admin') {
    window.location.href = '/' + (user ? user.role : 'login');
    return;
  }
  Auth.populateUI(user);

  var offset = 0;
  var limit  = 20;
  var total  = 0;

  function statusBadge(valid) {
    return valid
      ? '<span class="badge badge-verified" style="display:flex;align-items:center;gap:4px;"><i data-lucide="shield-check" style="width:11px;height:11px;"></i> Intact</span>'
      : '<span class="badge badge-flagged" style="display:flex;align-items:center;gap:4px;"><i data-lucide="alert-triangle" style="width:11px;height:11px;"></i> Issue</span>';
  }

  function renderBlock(b, isGenesis) {
    var dataStr = JSON.stringify(b.data, null, 2);
    var blockId = 'block-' + b.index;
    return (
      '<div style="border:1px solid var(--border);border-radius:10px;margin:8px 16px;overflow:hidden;">' +
        '<div style="background:var(--card-bg);padding:12px 16px;display:flex;align-items:center;gap:12px;cursor:pointer;" onclick="toggleBlock(\'' + blockId + '\')">' +
          '<div style="background:var(--primary);color:#fff;border-radius:8px;padding:4px 10px;font-size:12px;font-weight:700;flex-shrink:0;">' +
            (isGenesis ? 'GENESIS' : '#' + b.index) +
          '</div>' +
          '<div style="flex:1;min-width:0;">' +
            '<div style="font-family:monospace;font-size:12px;color:var(--primary);">' + b.hash.slice(0,48) + '…</div>' +
            '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">' +
              (isGenesis ? 'Chain initialised' : (b.data && b.data.action ? b.data.action : 'Audit event')) +
              ' &nbsp;·&nbsp; ' + (b.timestamp ? b.timestamp.replace('T', ' ').slice(0,19) + ' UTC' : '') +
            '</div>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">' +
            '<span style="font-size:11px;color:var(--text-muted);">nonce: ' + b.nonce + '</span>' +
            '<i data-lucide="chevron-down" style="width:14px;height:14px;color:var(--text-muted);" id="chevron-' + blockId + '"></i>' +
          '</div>' +
        '</div>' +
        '<div id="' + blockId + '" style="display:none;padding:16px;background:var(--sidebar-bg);border-top:1px solid var(--border);">' +
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">' +
            '<div>' +
              '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Block Hash</div>' +
              '<div style="font-family:monospace;font-size:11px;word-break:break-all;color:var(--primary);">' + b.hash + '</div>' +
            '</div>' +
            '<div>' +
              '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Previous Hash</div>' +
              '<div style="font-family:monospace;font-size:11px;word-break:break-all;color:var(--text-muted);">' + b.previous_hash + '</div>' +
            '</div>' +
            '<div>' +
              '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Difficulty / Nonce</div>' +
              '<div style="font-size:12px;">' + b.difficulty_used + ' leading zeros &nbsp;·&nbsp; nonce <strong>' + b.nonce + '</strong></div>' +
            '</div>' +
            '<div>' +
              '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">ECDSA Signature</div>' +
              '<div style="font-family:monospace;font-size:10px;word-break:break-all;color:var(--text-muted);">' + (b.signature ? b.signature.slice(0,40) + '…' : 'None') + '</div>' +
            '</div>' +
          '</div>' +
          '<div>' +
            '<div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">Block Data</div>' +
            '<pre style="font-size:11px;background:var(--card-bg);padding:10px;border-radius:6px;overflow-x:auto;border:1px solid var(--border);">' + dataStr + '</pre>' +
          '</div>' +
        '</div>' +
      '</div>'
    );
  }

  window.toggleBlock = function(id) {
    var el = document.getElementById(id);
    var ch = document.getElementById('chevron-' + id);
    if (el.style.display === 'none') {
      el.style.display = 'block';
      if (ch) ch.style.transform = 'rotate(180deg)';
    } else {
      el.style.display = 'none';
      if (ch) ch.style.transform = '';
    }
    if (window.lucide) window.lucide.createIcons();
  };

  async function loadBlocks(reset) {
    if (reset) { offset = 0; document.getElementById('block-list').innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted);">Loading blocks…</div>'; }
    try {
      var res = await Auth.get('/api/blockchain/chain?limit=' + limit + '&offset=' + offset);
      if (!res) return;
      total = res.total || 0;
      document.getElementById('stat-blocks').textContent = total;

      if (res.public_key) {
        var lines = res.public_key.split('\n').filter(function(l) { return l && !l.startsWith('---'); });
        document.getElementById('pub-key-badge').textContent = 'Pub: ' + lines.join('').slice(0, 32) + '…';
      }

      var blocks = res.blocks || [];
      if (reset) document.getElementById('block-list').innerHTML = '';
      var html = blocks.map(function(b) { return renderBlock(b, b.index === 0); }).join('');
      document.getElementById('block-list').insertAdjacentHTML('beforeend', html);
      offset += blocks.length;

      var loadMoreBtn = document.getElementById('load-more-btn');
      loadMoreBtn.style.display = offset < total ? 'block' : 'none';

      if (window.lucide) window.lucide.createIcons();
    } catch(e) {
      showToast('Error', 'Failed to load chain: ' + e.message, 'error');
    }
  }

  async function verifyChain() {
    document.getElementById('stat-chain-status').innerHTML = '<span style="color:var(--text-muted);">Verifying…</span>';
    try {
      var res = await Auth.get('/api/blockchain/verify');
      if (!res) return;

      document.getElementById('stat-blocks').textContent = res.total_blocks || 0;

      var anchorEl = document.getElementById('stat-anchor');
      anchorEl.innerHTML = res.anchor_intact
        ? '<span class="badge badge-verified" style="font-size:11px;">Intact</span>'
        : '<span class="badge badge-flagged" style="font-size:11px;">Mismatch</span>';

      var chainEl = document.getElementById('stat-chain-status');
      chainEl.innerHTML = res.valid
        ? '<span class="badge badge-verified" style="display:flex;align-items:center;gap:4px;"><i data-lucide="shield-check" style="width:11px;height:11px;"></i> All Verified</span>'
        : '<span class="badge badge-flagged" style="display:flex;align-items:center;gap:4px;"><i data-lucide="alert-triangle" style="width:11px;height:11px;"></i> Tampering Detected</span>';

      var issuesCard = document.getElementById('issues-card');
      var issuesList = document.getElementById('issues-list');
      if (!res.valid && res.issues && res.issues.length) {
        issuesCard.style.display = 'block';
        issuesList.innerHTML = res.issues.map(function(issue) {
          return '<div style="padding:8px 12px;margin-bottom:6px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:6px;">' +
            '<span style="font-weight:600;color:var(--danger);">Block ' + issue.block + ':</span> ' + issue.problem +
          '</div>';
        }).join('');
      } else {
        issuesCard.style.display = 'none';
      }

      if (window.lucide) window.lucide.createIcons();

      if (res.valid) {
        showToast('Chain Verified', 'All ' + res.total_blocks + ' blocks are intact and signed.', 'success');
      } else {
        showToast('Tampering Detected', res.issues.length + ' issue(s) found in the chain.', 'error');
      }
    } catch(e) {
      showToast('Error', 'Verification failed: ' + e.message, 'error');
    }
  }

  document.getElementById('verify-btn').addEventListener('click', verifyChain);
  document.getElementById('load-more-btn').addEventListener('click', function() { loadBlocks(false); });

  await loadBlocks(true);
  await verifyChain();
});
