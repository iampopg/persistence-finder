/* ── State ── */
let currentScan   = null;
let allScans      = [];
let aiThreats     = [];       // parsed threat objects from AI
let investigatePath = '';
let currentInvestigationSession = null;

async function cancelInvestigation() {
  if (!currentInvestigationSession) return;
  try {
    await fetch('/api/cancel-investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: currentInvestigationSession }),
    });
  } catch (_) {}
  const btn = document.getElementById('modal-cancel-btn');
  if (btn) btn.style.display = 'none';
  currentInvestigationSession = null;
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadScans();
  setupTabs();
  setupSearch();
});

function switchToSettings() {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  const btn = document.querySelector('[data-tab="tab-settings"]');
  if (btn) btn.classList.add('active');
  const panel = document.getElementById('tab-settings');
  if (panel) panel.classList.add('active');
  loadSettingsPage();
  return false;
}

/* ── Settings: load from server on startup ── */
function onProviderChange() {
  const p = document.getElementById('ai-provider').value;
  document.getElementById('ollama-fields').style.display = p === 'ollama' ? 'flex' : 'none';
  document.getElementById('groq-fields').style.display   = p === 'groq'   ? 'flex' : 'none';
}

async function loadSettings() {
  try {
    const s = await api('/api/settings');
    const provider = s.provider || 'ollama';
    document.getElementById('ai-provider').value = provider;
    onProviderChange();
    if (s.endpoint) document.getElementById('ai-endpoint').value = s.endpoint;
    if (s.groq_api_key) document.getElementById('groq-api-key').value = s.groq_api_key;
    if (s.groq_model) document.getElementById('groq-model-select').value = s.groq_model;

    const sel = document.getElementById('ai-model');
    if (provider === 'groq' && s.groq_model) {
      // Groq: auto-populate model dropdown from saved groq_model — no Detect needed
      const label = s.groq_model.split('/').pop();
      sel.innerHTML = `<option value="${s.groq_model}">${label}</option>`;
    } else if (provider === 'ollama' && s.model) {
      sel.innerHTML = `<option value="${s.model}">${s.model}</option>`;
    }
  } catch (_) {}
}

function saveSettings() {
  // Redirect to Settings tab and save from there (single save path prevents key corruption)
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  const btn = document.querySelector('[data-tab="tab-settings"]');
  if (btn) btn.classList.add('active');
  const panel = document.getElementById('tab-settings');
  if (panel) panel.classList.add('active');
  loadSettingsPage();
  showToast('Go to Settings tab to save', 'success');
}

/* ── API ── */
async function api(url, opts = {}) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

/* ── Scan list ── */
async function loadScans() {
  try {
    allScans = await api('/api/scans');
    renderScanList();
    if (allScans.length) selectScan(allScans[0].filename);
  } catch (e) {
    showToast('Failed to load scans', 'error');
  }
}

function renderScanList() {
  const ul = document.getElementById('scan-list');
  if (!allScans.length) {
    ul.innerHTML = '<li style="color:var(--muted);font-size:0.8rem;padding:8px 12px">No scans yet — run one!</li>';
    return;
  }
  ul.innerHTML = allScans.map(s => `
    <li onclick="selectScan('${s.filename}')" data-file="${s.filename}">
      <div>${s.platform || 'Unknown'} — ${s.scan_time ? s.scan_time.slice(0,10) : ''}</div>
      <div class="scan-meta">${s.total} findings · <span style="color:var(--danger)">${s.suspicious} suspicious</span></div>
    </li>`).join('');
}

async function selectScan(filename) {
  document.querySelectorAll('#scan-list li').forEach(li =>
    li.classList.toggle('active', li.dataset.file === filename));
  try {
    const data = await api(`/api/scan/${filename}`);
    currentScan = data;
    renderDashboard(data);
  } catch (e) {
    showToast('Failed to load scan', 'error');
  }
}

/* ── Dashboard ── */
function renderDashboard(data) {
  const meta    = data.metadata || {};
  const results = data.results  || {};

  document.getElementById('scan-title').textContent = `Scan — ${meta.scan_time || ''}`;
  document.getElementById('platform-badge').textContent = (meta.platform || 'Unknown').toUpperCase();
  document.getElementById('report-btn').style.display = '';

  let total = 0, suspicious = 0, categories = 0;
  for (const items of Object.values(results)) {
    if (!items) continue;
    const arr = typeof items === 'object' && !Array.isArray(items)
      ? Object.values(items) : (Array.isArray(items) ? items : []);
    if (arr.length) { categories++; total += arr.length; }
    suspicious += arr.filter(v => v && v.is_suspicious).length;
  }
  document.getElementById('stat-total').textContent      = total;
  document.getElementById('stat-suspicious').textContent = suspicious;
  document.getElementById('stat-categories').textContent = categories;
  document.getElementById('stat-platform').textContent   = meta.platform || '—';

  // Show findings, hide hero
  document.getElementById('scan-hero').style.display    = 'none';
  document.getElementById('findings-wrap').style.display = '';

  renderFindings(results);
  renderRawJson(data);
  // Reset AI filter toggle
  const tog = document.getElementById('ai-filter-toggle');
  if (tog) tog.checked = false;
}

/* ── Findings ── */
function renderFindings(results, filter = '', aiFilterOn = false) {
  const container = document.getElementById('findings-container');
  const lower = filter.toLowerCase();
  // Build set of paths AI flagged as real threats
  const threatPaths = new Set(aiThreats.map(t => t.path).filter(Boolean));
  let html = '';

  for (const [cat, items] of Object.entries(results)) {
    if (!items) continue;
    const entries = typeof items === 'object' && !Array.isArray(items)
      ? Object.entries(items)
      : (Array.isArray(items) ? items.map((v, i) => [i, v]) : []);
    if (!entries.length) continue;

    let visible = filter
      ? entries.filter(([k, v]) =>
          String(k).toLowerCase().includes(lower) ||
          JSON.stringify(v).toLowerCase().includes(lower))
      : entries;

    // AI filter: when ON, show only items the AI flagged as real threats
    if (aiFilterOn && threatPaths.size > 0) {
      visible = visible.filter(([k]) => threatPaths.has(k));
    }

    if (!visible.length) continue;

    const suspCount = visible.filter(([, v]) => v && v.is_suspicious).length;
    const catId = cat.replace(/\W/g, '_');

    html += `
      <div class="category-block">
        <div class="category-header" onclick="toggleCat('${catId}')">
          <span class="category-title">${escHtml(cat)}</span>
          <span class="category-meta">
            <span class="count-badge ${suspCount ? 'has-suspicious' : ''}">
              ${visible.length} items${suspCount ? ` · ${suspCount} ⚠` : ''}
            </span>
            <span class="chevron">▼</span>
          </span>
        </div>
        <div class="category-body" id="body_${catId}">
          <table>
            <thead><tr><th>Item</th><th>Details</th><th>Status</th></tr></thead>
            <tbody>${visible.map(([k, v]) => renderRow(k, v, threatPaths)).join('')}</tbody>
          </table>
        </div>
      </div>`;
  }

  container.innerHTML = html ||
    '<div class="empty-state"><div class="icon">✅</div><p>No findings match your filter.</p></div>';
}

function renderRow(key, val, threatPaths = new Set()) {
  const susp      = val && val.is_suspicious;
  const aiThreat  = threatPaths.has(key);
  const cls       = susp ? 'suspicious' : '';
  const badge     = aiThreat
    ? '<span class="badge badge-danger">🤖 AI THREAT</span>'
    : susp
      ? '<span class="badge badge-danger">⚠ SUSPICIOUS</span>'
      : '<span class="badge badge-ok">✓ OK</span>';

  let details = '';
  if (val && typeof val === 'object') {
    const parts = [];
    if (val.modified)    parts.push(`<span style="color:var(--muted)">mod:</span> ${val.modified}`);
    if (val.size)        parts.push(`<span style="color:var(--muted)">size:</span> ${val.size}`);
    if (val.permissions) parts.push(`<span style="color:var(--muted)">perms:</span> ${val.permissions}`);
    if (val.program)     parts.push(`<span style="color:var(--muted)">prog:</span> ${escHtml(String(val.program).slice(0,80))}`);
    if (val.label)       parts.push(`<span style="color:var(--muted)">label:</span> ${escHtml(val.label)}`);
    if (val.key_count)   parts.push(`<span style="color:var(--muted)">keys:</span> ${val.key_count}`);
    if (val.suspicious_commands && val.suspicious_commands !== 'None')
      parts.push(`<span style="color:var(--danger)">cmds: ${escHtml(JSON.stringify(val.suspicious_commands))}</span>`);
    details = parts.join(' &nbsp;·&nbsp; ');
  } else if (typeof val === 'string') {
    details = escHtml(val.slice(0, 120));
  }

  const investigateBtn = (susp || aiThreat)
    ? `<button onclick="openInvestigate('${escHtml(String(key)).replace(/'/g,"&apos;")}','${escHtml(String(val?.ai_why||val?.suspicious_commands||''))}')" style="background:none;border:1px solid var(--border);border-radius:4px;color:var(--muted);font-size:0.7rem;padding:2px 7px;cursor:pointer;margin-left:4px" title="AI Investigate">🔬</button>`
    : '';
  return `<tr class="${cls}">
    <td style="max-width:320px">${escHtml(String(key))}${investigateBtn}</td>
    <td style="font-size:0.78rem;color:var(--muted)">${details}</td>
    <td>${badge}</td>
  </tr>`;
}

function toggleCat(id) {
  const header = document.querySelector(`[onclick="toggleCat('${id}')"]`);
  const body   = document.getElementById(`body_${id}`);
  header.classList.toggle('open');
  body.classList.toggle('open');
}

/* ── AI false-positive filter ── */
function applyAiFilter() {
  if (!currentScan) return;
  const tog = document.getElementById('ai-filter-toggle');
  const search = document.getElementById('search')?.value || '';
  renderFindings(currentScan.results || {}, search, tog?.checked);
}

/* ── Search ── */
function setupSearch() {
  const el = document.getElementById('search');
  if (el) el.addEventListener('input', e => {
    if (!currentScan) return;
    const tog = document.getElementById('ai-filter-toggle');
    renderFindings(currentScan.results || {}, e.target.value, tog?.checked);
  });
}

/* ── Tabs ── */
function setupTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });
}

/* ── Raw JSON ── */
function renderRawJson(data) {
  document.getElementById('raw-json').textContent = JSON.stringify(data, null, 2);
  document.getElementById('raw-label').textContent =
    `Scan: ${data.metadata?.scan_time || ''} · ${data.metadata?.platform || ''}`;
}

function downloadJson() {
  if (!currentScan) return;
  const blob = new Blob([JSON.stringify(currentScan, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'scan_export.json';
  a.click();
}

/* ── Live scan with animated steps ── */
const SCAN_STEPS = [
  'LaunchAgents & Daemons',
  'Login Items & Cron',
  'Shell Profiles',
  'Kernel Extensions',
  'SSH Keys & Sudoers',
  'Browser Extensions',
  'Quarantine DB',
];

async function runScan() {
  const overlay = document.getElementById('scan-overlay');
  const scanBtn = document.getElementById('run-scan-btn');
  const heroBtn = document.getElementById('hero-scan-btn');
  const label   = document.getElementById('scan-step-label');

  // Show live log panel
  let logEl = document.getElementById('scan-live-log');
  if (!logEl) {
    logEl = document.createElement('pre');
    logEl.id = 'scan-live-log';
    logEl.style.cssText = 'position:fixed;bottom:0;left:0;right:0;height:220px;background:#010409;color:#3fb950;font-size:0.72rem;padding:12px 16px;overflow-y:auto;z-index:99;border-top:1px solid #30363d;font-family:monospace;line-height:1.5';
    document.body.appendChild(logEl);
  }
  logEl.textContent = '';
  logEl.style.display = 'block';

  const addLog = (line, color) => {
    const span = document.createElement('span');
    span.style.color = color || '#3fb950';
    span.textContent = line + '\n';
    logEl.appendChild(span);
    logEl.scrollTop = logEl.scrollHeight;
  };

  overlay.classList.add('active');
  if (scanBtn) scanBtn.disabled = true;
  if (heroBtn) heroBtn.disabled = true;

  // Pass AI config if available
  const aiEndpoint = document.getElementById('ai-endpoint')?.value.trim() || '';
  const aiModel    = document.getElementById('ai-model')?.value.trim() || '';
  const params     = new URLSearchParams();
  if (aiEndpoint && aiModel) {
    params.set('ai_endpoint', aiEndpoint);
    params.set('ai_model', aiModel);
    addLog(`AI triage enabled: ${aiModel}`, '#58a6ff');
  } else {
    addLog('No AI configured — using rule-based detection only', '#d29922');
    addLog('Tip: set up Ollama in the AI Analysis tab for smarter results', '#8b949e');
  }

  try {
    await new Promise((resolve, reject) => {
      const url = '/api/run-scan-stream' + (params.toString() ? '?' + params.toString() : '');
      const es  = new EventSource(url);

      es.onmessage = async (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'step') {
            if (label) label.textContent = msg.msg;
            addLog('\u25b6 ' + msg.msg, '#58a6ff');
          } else if (msg.type === 'log') {
            addLog(msg.msg, '#8b949e');
          } else if (msg.type === 'ai_in') {
            addLog(msg.msg, '#d29922');
          } else if (msg.type === 'ai_out') {
            addLog(msg.msg, '#a371f7');
          } else if (msg.type === 'found') {
            addLog(`  ✓ ${msg.cat}: ${msg.items} items`, '#3fb950');
          } else if (msg.type === 'done') {
            es.close();
            addLog(`\n✅ Done — ${msg.total} items, ${msg.suspicious} suspicious`, '#3fb950');
            if (label) label.textContent = `Done — ${msg.suspicious} suspicious`;
            await new Promise(r => setTimeout(r, 500));
            showToast('Scan complete!', 'success');
            await loadScans();
            if (msg.filename) selectScan(msg.filename);
            resolve();
          } else if (msg.type === 'error') {
            es.close();
            addLog('ERROR: ' + msg.msg, '#f85149');
            reject(new Error(msg.msg));
          }
        } catch (_) {}
      };
      es.onerror = () => { es.close(); reject(new Error('Stream error')); };
    });
  } catch (e) {
    showToast('Scan failed: ' + e.message, 'error');
  } finally {
    overlay.classList.remove('active');
    if (scanBtn) scanBtn.disabled = false;
    if (heroBtn) heroBtn.disabled = false;
    // Keep log visible, add close button
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '× Close log';
    closeBtn.style.cssText = 'position:absolute;top:8px;right:12px;background:#21262d;border:1px solid #30363d;color:#8b949e;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:0.75rem';
    closeBtn.onclick = () => logEl.style.display = 'none';
    logEl.style.position = 'fixed';
    logEl.appendChild(closeBtn);
  }
}

/* ── AI: detect models ── */
async function detectModels() {
  const provider = document.getElementById('ai-provider').value;
  const endpoint = document.getElementById('ai-endpoint').value.trim();
  const btn      = document.getElementById('detect-btn');
  const select   = document.getElementById('ai-model');
  btn.disabled   = true;
  btn.textContent = '⟳…';
  try {
    if (provider === 'groq') {
      // Groq: populate from the groq-model-select dropdown (no API call needed)
      const groqSel = document.getElementById('groq-model-select');
      const opts = groqSel ? Array.from(groqSel.options) : [];
      if (opts.length) {
        select.innerHTML = opts.map(o => `<option value="${o.value}">${o.text}</option>`).join('');
        // Select the currently chosen groq model
        const saved = groqSel?.value;
        if (saved) select.value = saved;
        showToast(`${opts.length} Groq model(s) loaded`, 'success');
      }
    } else {
      const data = await api('/api/ai-models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, endpoint }),
      });
      if (data.error || !data.models.length) {
        showToast(data.error || 'No models found', 'error');
        select.innerHTML = '<option value="">No models found</option>';
        return;
      }
      select.innerHTML = data.models.map(m => `<option value="${m}">${m}</option>`).join('');
      showToast(`Found ${data.models.length} model(s)`, 'success');
    }
  } catch (e) {
    showToast('Detection failed: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '⟳ Detect';
  }
}

/* ── AI: build char-budget batches from ALL scan items ── */
// Token budgets per provider/model (input tokens, leaving room for prompt+response)
const MODEL_CHAR_BUDGETS = {
  'groq': {
    'meta-llama/llama-4-scout-17b-16e-instruct': 28000 * 4,  // 28K tokens * 4 chars
    'llama-3.3-70b-versatile':                    10000 * 4,
    'qwen/qwen3-32b':                              5000 * 4,
    'llama-3.1-8b-instant':                        5000 * 4,
    'default':                                     8000 * 4,
  },
  'ollama': { 'default': 80000 * 4 },
};

function getCharBudget(settings) {
  const provider = settings.provider || 'ollama';
  const model    = provider === 'groq' ? (settings.groq_model || '') : (settings.model || '');
  const budgets  = MODEL_CHAR_BUDGETS[provider] || MODEL_CHAR_BUDGETS.ollama;
  return budgets[model] || budgets['default'];
}

function buildAllItemBatches(results, settings) {
  const charBudget = getCharBudget(settings || {});

  // Collect every dict item — minimal format to save tokens
  const all = [];
  for (const [cat, items] of Object.entries(results)) {
    if (!items || typeof items !== 'object' || Array.isArray(items)) continue;
    for (const [itemPath, v] of Object.entries(items)) {
      if (!v || typeof v !== 'object') continue;
      // Minimal line: category + path only (program only if non-Apple)
      const prog = String(v.program || v.value || '').slice(0, 60);
      const isApple = itemPath.includes('/System/') || itemPath.includes('/usr/') ||
                      itemPath.includes('com.apple.');
      let line = `[${cat.replace(/^\d+\.\s*/,'')}] ${itemPath}`;
      if (prog && !isApple) line += ` | ${prog}`;
      all.push({ path: itemPath, category: cat, line });
    }
  }

  // Split into char-budget batches
  const batches = [];
  let cur = [], curChars = 0;
  for (const item of all) {
    if (curChars + item.line.length > charBudget && cur.length) {
      batches.push(cur);
      cur = []; curChars = 0;
    }
    cur.push(item);
    curChars += item.line.length;
  }
  if (cur.length) batches.push(cur);
  return { batches, total: all.length };
}

/* ── AI: run batch triage across all suspicious items ── */
async function runAI() {
  if (!currentScan) { showToast('Load a scan first', 'error'); return; }

  // Read settings from server — no UI fields needed in AI tab
  let settings;
  try { settings = await api('/api/settings'); } catch(e) { showToast('Failed to load settings', 'error'); return; }
  const provider = settings.provider || 'ollama';
  const model    = provider === 'groq' ? settings.groq_model : settings.model;
  if (!model) { showToast('No AI model configured — go to ⚙ Settings', 'error'); switchToSettings(); return; }
  if (provider === 'groq' && !settings.groq_api_key) { showToast('No Groq API key — go to ⚙ Settings', 'error'); switchToSettings(); return; }

  const streamBox  = document.getElementById('ai-stream-box');
  const liveLog    = document.getElementById('ai-live-log');
  const statusBadge = document.getElementById('ai-status-badge');
  const grid       = document.getElementById('threat-grid');
  const btn        = document.getElementById('ai-btn');

  // Show live log
  if (liveLog) { liveLog.style.display = 'block'; liveLog.textContent = ''; }
  const addLog = (text, color) => {
    if (!liveLog) return;
    const span = document.createElement('span');
    span.style.color = color || '#8b949e';
    span.textContent = text + '\n';
    liveLog.appendChild(span);
    liveLog.scrollTop = liveLog.scrollHeight;
  };
  addLog(`Provider: ${provider} | Model: ${model}`, '#58a6ff');
  if (statusBadge) statusBadge.textContent = 'Analyzing…';

  const { batches, total } = buildAllItemBatches(currentScan.results || {}, settings);
  if (!batches.length) {
    streamBox.style.display = '';
    streamBox.innerHTML = 'No scan data found. Run a scan first.';
    return;
  }

  streamBox.style.display = 'none';
  grid.innerHTML = '';
  btn.disabled   = true;
  aiThreats      = [];

  addLog(`Analyzing ALL ${total} items across ${batches.length} batch(es)…`, '#d29922');
  addLog(`AI will identify real threats vs false positives`, '#8b949e');

  for (let b = 0; b < batches.length; b++) {
    const batch = batches[b];
    addLog(`\n[Batch ${b+1}/${batches.length}] ${batch.length} items → AI…`, '#d29922');
    if (statusBadge) statusBadge.textContent = `Batch ${b+1}/${batches.length}…`;

    const linesText = batch.map(i => i.line).join('\n');
    const endpoint  = settings.provider === 'groq'
      ? 'https://api.groq.com/openai/v1/chat/completions'
      : (settings.endpoint || 'http://localhost:11434') + '/api/generate';

    try {
      const resp = await fetch('/api/ai-analyze-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings, items_text: linesText, batch_num: b+1, total_batches: batches.length }),
      });
      const data = await resp.json();
      if (data.error) { addLog('AI error: ' + data.error, '#f85149'); continue; }

      const threats = data.threats || [];
      addLog(`  ← ${threats.length} real threat(s) identified`, threats.length ? '#f85149' : '#3fb950');
      for (const t of threats) {
        addLog(`    ⚠ [${t.severity}] ${t.path} — ${t.why}`, '#d29922');
      }
      aiThreats.push(...threats);
      if (aiThreats.length) {
        grid.innerHTML = aiThreats.map(t => renderThreatCard(t)).join('');
      }
    } catch (e) {
      addLog(`  Batch ${b+1} error: ${e.message}`, '#f85149');
    }
  }

  // All batches done
  if (aiThreats.length) {
    streamBox.style.display = 'none';
    const lbl = document.getElementById('ai-filter-label');
    if (lbl) lbl.style.display = 'flex';
    const crit = aiThreats.filter(t => t.severity === 'Critical').length;
    addLog(`\n✅ Analysis complete — ${aiThreats.length} real threat(s) identified${crit ? ` (${crit} Critical)` : ''}`, '#3fb950');
    if (statusBadge) statusBadge.textContent = `${aiThreats.length} threat(s) found`;
    showToast(`Done — ${aiThreats.length} real threat(s)${crit ? `, ${crit} Critical` : ''}`, crit ? 'error' : 'success');
  } else {
    streamBox.style.display = '';
    streamBox.innerHTML = '✅ Analysis complete — no real threats found. All flagged items appear to be false positives.<br><small style="color:var(--muted)">Check the Findings tab — items are marked clean.</small>';
    addLog('\n✅ Analysis complete — 0 real threats (all false positives)', '#3fb950');
    if (statusBadge) statusBadge.textContent = '0 threats';
  }
  btn.disabled = false;
}

function parseAndRenderThreats(text) {
  const grid      = document.getElementById('threat-grid');
  const streamBox = document.getElementById('ai-stream-box');
  try {
    const match = text.match(/\[[\s\S]*\]/);
    if (!match) {
      // No JSON array found — show raw text nicely
      streamBox.style.display = '';
      streamBox.textContent = text;
      return;
    }
    const threats = JSON.parse(match[0]);
    if (!Array.isArray(threats) || !threats.length) return;
    aiThreats = threats;
    grid.innerHTML = threats.map(t => renderThreatCard(t)).join('');
    // Hide stream box now that cards are shown
    streamBox.style.display = 'none';
    // Show AI filter toggle in findings tab
    const lbl = document.getElementById('ai-filter-label');
    if (lbl) lbl.style.display = 'flex';
    const critCount = threats.filter(t => t.severity === 'Critical').length;
    showToast(`${threats.length} threat(s) identified${critCount ? ` — ${critCount} Critical` : ''}`,
              critCount ? 'error' : 'success');
  } catch (_) {
    // JSON parse failed — keep raw text visible
    streamBox.style.display = '';
    streamBox.textContent = text;
  }
}

function renderThreatCard(t) {
  const sevClass    = { Critical: 'sev-critical', High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low' }[t.severity] || 'sev-low';
  const borderColor = { Critical: '#f85149', High: '#d29922', Medium: '#58a6ff', Low: '#3fb950' }[t.severity] || '#8b949e';
  const pathSafe    = escHtml(t.path || '');
  // Encode investigate_cmd safely for onclick attribute
  const cmdEncoded  = encodeURIComponent(t.investigate_cmd || '');
  const pathEncoded = encodeURIComponent(t.path || '');
  return `
    <div class="threat-card" style="border-left-color:${borderColor}">
      <div class="threat-card-top">
        <span class="threat-sev ${sevClass}">${t.severity || '?'}</span>
        ${t.technique ? `<span class="threat-mitre">${escHtml(t.technique)}</span>` : ''}
      </div>
      <div class="threat-title">${escHtml(t.title || 'Unknown')}</div>
      ${t.path ? `<div class="threat-path">${pathSafe}</div>` : ''}
      <div class="threat-why">${escHtml(t.why || '')}</div>
      ${(t.path || t.investigate_cmd) ? `<button class="btn-investigate" onclick="openInvestigate(decodeURIComponent('${pathEncoded}'), decodeURIComponent('${encodeURIComponent(t.why||'')}'))">🔬 Investigate</button>` : ''}
    </div>`;
}

function clearAI() {
  aiThreats = [];
  document.getElementById('threat-grid').innerHTML = '';
  const box = document.getElementById('ai-stream-box');
  box.className = 'ai-stream-box';
  box.style.display = '';
  box.innerHTML = 'Click <strong>⚡ Analyze Scan with AI</strong> to triage all findings.<br>AI settings are configured in the <a href="#" onclick="switchToSettings()" style="color:var(--accent)">⚙ Settings</a> tab.';
  const log = document.getElementById('ai-live-log');
  if (log) { log.style.display = 'none'; log.textContent = ''; }
  const badge = document.getElementById('ai-status-badge');
  if (badge) badge.textContent = '';
  const lbl = document.getElementById('ai-filter-label');
  if (lbl) lbl.style.display = 'none';
  const tog = document.getElementById('ai-filter-toggle');
  if (tog) tog.checked = false;
}

/* ── Investigate modal — AI-driven loop ── */
function openInvestigate(path, context) {
  investigatePath = path;
  document.getElementById('modal-title').textContent  = '🔬 AI Investigation';
  document.getElementById('modal-path').textContent   = path;
  document.getElementById('modal-cmd-btns').innerHTML = '';
  const out = document.getElementById('modal-output');
  out.textContent = 'Starting AI investigation…';
  document.getElementById('investigate-modal').classList.add('open');
  runAiInvestigation(path, context || '');
}

function closeModal() {
  document.getElementById('investigate-modal').classList.remove('open');
}

async function runAiInvestigation(path, context) {
  const out    = document.getElementById('modal-output');
  const title  = document.getElementById('modal-title');
  const cancelBtn = document.getElementById('modal-cancel-btn');
  out.textContent = '';
  currentInvestigationSession = null;
  if (cancelBtn) cancelBtn.style.display = 'inline-block';

  const addLine = (text, color) => {
    const span = document.createElement('span');
    span.style.color = color || '#c9d1d9';
    span.textContent = text + '\n';
    out.appendChild(span);
    out.scrollTop = out.scrollHeight;
  };

  try {
    const resp = await fetch('/api/ai-investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, context }),
    });

    if (!resp.ok) {
      const err = await resp.json();
      addLine('Error: ' + (err.error || 'Unknown'), '#f85149');
      return;
    }

    const reader = resp.body.getReader();
    const dec    = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const parts = buf.split('\n\n');
      buf = parts.pop();
      for (const part of parts) {
        if (!part.startsWith('data: ')) continue;
        try {
          const msg = JSON.parse(part.slice(6));
          if (msg.type === 'session') { currentInvestigationSession = msg.session_id; }
          if (msg.type === 'log')     addLine(msg.msg, '#8b949e');
          if (msg.type === 'step')    addLine('\n▶ ' + msg.msg, '#58a6ff');
          if (msg.type === 'ai_out')  addLine('🤖 ' + msg.msg, '#a371f7');
          if (msg.type === 'cmd') {
            addLine('\n$ ' + msg.msg, '#d29922');
          }
          if (msg.type === 'output') {
            // Show full command output — this is the most important part
            addLine(msg.msg, '#e6edf3');
          }
          if (msg.type === 'blocked') addLine('❌ ' + msg.msg, '#f85149');
          if (msg.type === 'verdict') {
            let color, icon;
            if (msg.malicious)                    { color = '#f85149'; icon = '🚨 MALICIOUS'; }
            else if (msg.suspicious)              { color = '#d29922'; icon = '⚠ SUSPICIOUS'; }
            else if (msg.msg === 'Cancelled')     { color = '#8b949e'; icon = '⏹ CANCELLED'; }
            else                                  { color = '#3fb950'; icon = '✅ CLEAN'; }
            title.textContent = '🔬 ' + icon;
            title.style.color = color;
            addLine('', '#30363d');
            addLine('━'.repeat(50), '#30363d');
            addLine(icon + ': ' + msg.msg, color);
            if (cancelBtn) cancelBtn.style.display = 'none';
            currentInvestigationSession = null;
          }
        } catch (_) {}
      }
    }
  } catch (e) {
    out.textContent = 'Investigation failed: ' + e.message;
  } finally {
    if (cancelBtn) cancelBtn.style.display = 'none';
    currentInvestigationSession = null;
  }
}

// Close modal on backdrop click
document.addEventListener('click', e => {
  const modal = document.getElementById('investigate-modal');
  if (e.target === modal) closeModal();
});

/* ── Report — open in new tab ── */
async function downloadReport() {
  if (!currentScan) return;
  try {
    const resp = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan: currentScan, threats: aiThreats }),
    });
    const html = await resp.text();
    const win  = window.open('', '_blank');
    win.document.write(html);
    win.document.close();
    showToast('Report opened in new tab', 'success');
  } catch (e) {
    showToast('Report failed: ' + e.message, 'error');
  }
}

/* ── Helpers ── */
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast ${type} show`;
  setTimeout(() => t.classList.remove('show'), 3000);
}

/* ── Settings page ── */

// Sync provider change across both the AI tab and Settings tab
function onProviderChange() {
  // Read from whichever element triggered the change
  const pAI  = document.getElementById('ai-provider');
  const pSet = document.getElementById('s-provider');
  const provider = (document.activeElement === pSet ? pSet : pAI)?.value || 'ollama';

  // Sync both selects
  if (pAI)  pAI.value  = provider;
  if (pSet) pSet.value = provider;

  // AI tab fields
  const ollamaAI = document.getElementById('ollama-fields');
  const groqAI   = document.getElementById('groq-fields');
  if (ollamaAI) ollamaAI.style.display = provider === 'ollama' ? 'flex' : 'none';
  if (groqAI)   groqAI.style.display   = provider === 'groq'   ? 'flex' : 'none';

  // Settings tab sections
  const ollamaSec = document.getElementById('s-ollama-section');
  const groqSec   = document.getElementById('s-groq-section');
  if (ollamaSec) ollamaSec.style.display = provider === 'ollama' ? 'block' : 'none';
  if (groqSec)   groqSec.style.display   = provider === 'groq'   ? 'block' : 'none';
}

// Load settings into the Settings page fields
async function loadSettingsPage() {
  try {
    const s = await api('/api/settings');
    const provider = s.provider || 'ollama';

    const pSet = document.getElementById('s-provider');
    if (pSet) pSet.value = provider;
    onProviderChange();

    if (s.endpoint) {
      const el = document.getElementById('s-endpoint');
      if (el) el.value = s.endpoint;
    }
    if (s.groq_api_key) {
      const el = document.getElementById('s-groq-key');
      if (el) el.value = s.groq_api_key;
    }
    if (s.groq_model) {
      const el = document.getElementById('s-groq-model');
      if (el) el.value = s.groq_model;
    }
    if (s.model) {
      const el = document.getElementById('s-model');
      if (el) el.innerHTML = `<option value="${s.model}">${s.model}</option>`;
    }

    // Show current config (mask API key)
    const display = { ...s };
    if (display.groq_api_key) display.groq_api_key = display.groq_api_key.slice(0, 8) + '…';
    const pre = document.getElementById('s-current-config');
    if (pre) pre.textContent = JSON.stringify(display, null, 2);
  } catch (_) {}
}

async function settingsDetect() {
  const endpoint = document.getElementById('s-endpoint')?.value.trim() || '';
  const sel      = document.getElementById('s-model');
  if (!sel) return;
  sel.innerHTML = '<option>Detecting…</option>';
  try {
    const data = await api('/api/ai-models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'ollama', endpoint }),
    });
    if (data.models?.length) {
      sel.innerHTML = data.models.map(m => `<option value="${m}">${m}</option>`).join('');
      showToast(`Found ${data.models.length} model(s)`, 'success');
    } else {
      sel.innerHTML = '<option value="">No models found</option>';
      showToast(data.error || 'No models found', 'error');
    }
  } catch (e) {
    sel.innerHTML = '<option value="">Error</option>';
    showToast('Detection failed: ' + e.message, 'error');
  }
}

async function saveSettingsPage() {
  const provider    = document.getElementById('s-provider')?.value || 'ollama';
  const endpoint    = document.getElementById('s-endpoint')?.value.trim() || '';
  const model       = document.getElementById('s-model')?.value.trim() || '';
  const groq_api_key = document.getElementById('s-groq-key')?.value.trim() || '';
  const groq_model  = document.getElementById('s-groq-model')?.value || '';

  if (provider === 'ollama' && !model) { showToast('Select a model first', 'error'); return; }
  if (provider === 'groq' && !groq_api_key) { showToast('Enter Groq API key', 'error'); return; }

  await api('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, endpoint, model, groq_api_key, groq_model }),
  });

  // Sync AI tab fields too
  const pAI = document.getElementById('ai-provider');
  if (pAI) pAI.value = provider;
  const epAI = document.getElementById('ai-endpoint');
  if (epAI && endpoint) epAI.value = endpoint;
  if (model) {
    const sel = document.getElementById('ai-model');
    if (sel) sel.innerHTML = `<option value="${model}">${model}</option>`;
  }
  if (groq_api_key) {
    const el = document.getElementById('groq-api-key');
    if (el) el.value = groq_api_key;
  }
  onProviderChange();

  // Refresh config display
  const display = { provider, endpoint, model,
    groq_api_key: groq_api_key ? groq_api_key.slice(0,8)+'…' : '',
    groq_model };
  const pre = document.getElementById('s-current-config');
  if (pre) pre.textContent = JSON.stringify(display, null, 2);

  showToast('Settings saved ✓', 'success');
}

async function testAiConnection() {
  const result = document.getElementById('s-test-result');
  if (result) { result.textContent = 'Testing…'; result.style.color = 'var(--muted)'; }
  const provider = document.getElementById('s-provider')?.value || 'ollama';
  try {
    const data = await api('/api/ai-models', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider,
        endpoint: document.getElementById('s-endpoint')?.value.trim() || '',
      }),
    });
    if (data.models?.length) {
      if (result) { result.textContent = `✓ Connected — ${data.models.length} model(s) available`; result.style.color = 'var(--accent2)'; }
    } else {
      if (result) { result.textContent = '✗ ' + (data.error || 'No models found'); result.style.color = 'var(--danger)'; }
    }
  } catch (e) {
    if (result) { result.textContent = '✗ ' + e.message; result.style.color = 'var(--danger)'; }
  }
}

// Load settings page when Settings tab is clicked
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    if (btn.dataset.tab === 'tab-settings') {
      btn.addEventListener('click', loadSettingsPage);
    }
  });
});
