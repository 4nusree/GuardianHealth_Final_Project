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

  // ── Helpers ─────────────────────────────────────────────────────────────────

  var CHECK_LABELS = {
    anchor_integrity:      { label: 'Anchor Integrity',       desc: 'External hash file matches chain tip' },
    sequential_index:      { label: 'Sequential Index',       desc: 'No replay or gap attack' },
    hash_integrity:        { label: 'Hash Integrity',         desc: 'Block data was not modified' },
    chain_linkage:         { label: 'Chain Linkage',          desc: 'Each block references its predecessor' },
    timestamp_monotonicity:{ label: 'Timestamp Monotonicity', desc: 'Blocks cannot be backdated' },
    proof_of_work:         { label: 'Proof-of-Work',          desc: 'Re-mining shortcut prevention' },
    ecdsa_signature:       { label: 'ECDSA Signature',        desc: 'Signed with server private key' },
  };

  function renderBlock(b, isGenesis) {
    var blockId  = 'block-' + b.index;
    var dataStr  = JSON.stringify(b.data, null, 2);
    var label    = isGenesis ? 'GENESIS' : '#' + b.index;
    var action   = b.data && b.data.action ? b.data.action : (isGenesis ? 'Chain initialised' : 'Audit event');
    var ts       = b.timestamp ? b.timestamp.replace('T', ' ').slice(0, 19) + ' UTC' : '';
    return (
      '<div style="border:1px solid var(--border);border-radius:10px;margin:8px 16px;overflow:hidden;">' +
        '<div style="background:var(--card-bg);padding:12px 16px;display:flex;align-items:center;gap:12px;cursor:pointer;" onclick="toggleBlock(\'' + blockId + '\')">' +
          '<div style="background:var(--primary);color:#fff;border-radius:8px;padding:4px 10px;font-size:12px;font-weight:700;flex-shrink:0;">' + label + '</div>' +
          '<div style="flex:1;min-width:0;">' +
            '<div style="font-family:monospace;font-size:12px;color:var(--primary);">' + b.hash.slice(0, 48) + '…</div>' +
            '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">' + action + ' &nbsp;·&nbsp; ' + ts + '</div>' +
          '</div>' +
          '<div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">' +
            (b.signature ? '<span style="font-size:10px;padding:2px 6px;background:rgba(16,185,129,.12);color:var(--success);border-radius:4px;">✓ Signed</span>' : '') +
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
              '<div style="font-family:monospace;font-size:10px;word-break:break-all;color:var(--text-muted);">' + (b.signature ? b.signature.slice(0, 48) + '…' : '<span style="color:var(--danger);">None</span>') + '</div>' +
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
    if (!el) return;
    var open = el.style.display !== 'none';
    el.style.display = open ? 'none' : 'block';
    if (ch) ch.style.transform = open ? '' : 'rotate(180deg)';
    if (window.lucide) window.lucide.createIcons();
  };

  // ── Load Blocks ──────────────────────────────────────────────────────────────

  async function loadBlocks(reset) {
    if (reset) {
      offset = 0;
      document.getElementById('block-list').innerHTML =
        '<div style="text-align:center;padding:40px;color:var(--text-muted);">Loading blocks…</div>';
    }
    try {
      var res = await Auth.get('/api/blockchain/chain?limit=' + limit + '&offset=' + offset);
      if (!res) return;
      total = res.total || 0;
      document.getElementById('stat-blocks').textContent = total;

      if (res.public_key) {
        document.getElementById('pub-key-pem').textContent = res.public_key.trim();
      }

      var blocks = res.blocks || [];
      if (reset) document.getElementById('block-list').innerHTML = '';
      document.getElementById('block-list').insertAdjacentHTML(
        'beforeend',
        blocks.map(function(b) { return renderBlock(b, b.index === 0); }).join('')
      );
      offset += blocks.length;
      document.getElementById('load-more-btn').style.display = offset < total ? 'block' : 'none';
      if (window.lucide) window.lucide.createIcons();
    } catch(e) {
      showToast('Error', 'Failed to load chain: ' + e.message, 'error');
    }
  }

  // ── Public Key ───────────────────────────────────────────────────────────────

  async function loadPublicKey() {
    try {
      var res = await Auth.get('/api/blockchain/public-key');
      if (res && res.public_key) {
        document.getElementById('pub-key-pem').textContent = res.public_key.trim();
      }
    } catch(e) { /* non-critical */ }
  }

  // ── Verify Chain ─────────────────────────────────────────────────────────────

  async function verifyChain() {
    document.getElementById('stat-chain-status').innerHTML =
      '<span style="color:var(--text-muted);">Verifying…</span>';
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

      // Checks panel
      if (res.checks_run && res.checks_run.length) {
        var checksCard = document.getElementById('checks-card');
        var checksList = document.getElementById('checks-list');
        var issueKeys  = new Set((res.issues || []).map(function(i) { return i.check; }));
        checksCard.style.display = 'block';
        document.getElementById('checks-summary').textContent =
          res.checks_run.length + ' checks run · ' + (res.valid ? 'All passed' : (res.issues || []).length + ' issue(s) found');
        checksList.innerHTML = res.checks_run.map(function(key) {
          var meta   = CHECK_LABELS[key] || { label: key, desc: '' };
          var failed = issueKeys.has(key);
          return '<div style="display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border-radius:6px;background:' +
            (failed ? 'rgba(239,68,68,.06)' : 'rgba(16,185,129,.06)') + ';border:1px solid ' +
            (failed ? 'rgba(239,68,68,.2)' : 'rgba(16,185,129,.2)') + ';">' +
            '<span style="font-size:14px;line-height:1.2;">' + (failed ? '✗' : '✓') + '</span>' +
            '<div>' +
              '<div style="font-size:12px;font-weight:600;color:' + (failed ? 'var(--danger)' : 'var(--success)') + ';">' + meta.label + '</div>' +
              '<div style="font-size:11px;color:var(--text-muted);">' + meta.desc + '</div>' +
            '</div>' +
          '</div>';
        }).join('');
      }

      // Issues panel
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
        showToast('Chain Verified', 'All ' + (res.checks_run || []).length + ' checks passed across ' + res.total_blocks + ' blocks.', 'success');
      } else {
        showToast('Tampering Detected', res.issues.length + ' issue(s) found in the chain.', 'error');
      }
    } catch(e) {
      showToast('Error', 'Verification failed: ' + e.message, 'error');
    }
  }

  // ── Tamper Demo ──────────────────────────────────────────────────────────────

  async function runTamperDemo() {
    if (total < 2) {
      showToast('Not enough blocks', 'Need at least 2 blocks to demo.', 'error');
      return;
    }
    var targetIndex = Math.max(1, Math.min(total - 1, 1));
    showToast('Demo Running', 'Simulating tamper on block #' + targetIndex + '…', 'info');
    try {
      var res = await Auth.post('/api/blockchain/tamper-demo', { block_index: targetIndex });
      if (!res) return;

      var card   = document.getElementById('tamper-card');
      var result = document.getElementById('tamper-result');
      card.style.display = 'block';

      result.innerHTML =
        '<div style="margin-bottom:12px;padding:10px 14px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:8px;">' +
          '<div style="font-size:12px;color:var(--text-muted);margin-bottom:4px;">Simulated attack on Block #' + res.tampered_block + '</div>' +
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;">' +
            '<div><span style="color:var(--text-muted);">Original:</span><br><strong>' + (res.original_action || '—') + '</strong></div>' +
            '<div><span style="color:var(--danger);">Forged:</span><br><strong style="color:var(--danger);">' + res.forged_action + '</strong></div>' +
          '</div>' +
        '</div>' +
        '<div style="margin-bottom:10px;font-weight:600;color:' + (res.detected ? 'var(--success)' : 'var(--danger)') + ';">' +
          (res.detected ? '✓ DETECTED — Tampering caught by ' + res.issues_found + ' check(s)' : '✗ NOT DETECTED — Review security implementation') +
        '</div>' +
        res.issues.map(function(issue) {
          var checkMeta = CHECK_LABELS[issue.check] || { label: issue.check || 'Check' };
          return '<div style="padding:7px 12px;margin-bottom:5px;background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);border-radius:6px;font-size:12px;">' +
            '<span style="font-weight:600;color:var(--danger);">[' + checkMeta.label + '] Block ' + issue.block + ':</span> ' + issue.problem +
          '</div>';
        }).join('') +
        '<div style="margin-top:10px;font-size:11px;color:var(--text-muted);font-style:italic;">' + res.note + '</div>';

      card.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (window.lucide) window.lucide.createIcons();

      showToast(
        res.detected ? 'Tampering Detected!' : 'Not Detected',
        res.detected
          ? res.issues_found + ' check(s) caught the attack on block #' + res.tampered_block
          : 'No issues found — review security.',
        res.detected ? 'success' : 'error'
      );
    } catch(e) {
      showToast('Error', 'Demo failed: ' + e.message, 'error');
    }
  }

  // ── Boot ─────────────────────────────────────────────────────────────────────

  document.getElementById('verify-btn').addEventListener('click', verifyChain);
  document.getElementById('demo-btn').addEventListener('click', runTamperDemo);
  document.getElementById('load-more-btn').addEventListener('click', function() { loadBlocks(false); });

  await loadBlocks(true);
  await Promise.all([verifyChain(), loadPublicKey()]);
});
