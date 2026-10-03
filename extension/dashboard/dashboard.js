// Forensic Browser Extractor: dashboard application.
// Reads the evidence store directly; all chain writes go through the
// background capture engine via command messages.

import { api, TOOL, fmtTime, fmtBytes, midTruncate } from '../lib/util.js';
import { open, getEvents, allSnapshots, getMeta } from '../lib/db.js';
import { verifyChain, GENESIS_HASH } from '../lib/chain.js';
import { runDiagnostics } from '../lib/diagnostics.js';
import { buildEvidencePackage, buildTimeline, buildTimelineCsv, downloadText, getCaseMeta, saveCaseMeta } from '../lib/export.js';

const $ = (id) => document.getElementById(id);
const PAGE = 300;

const state = {
  events: [],
  snapshot: null,
  settings: null,
  caseMeta: null,
  findings: null,      // diagnostics result (lazy)
  chain: null,         // verification result (lazy)
  timeline: null,      // unified rows (lazy)
  view: 'overview',
  artifact: 'history',
  tlShown: PAGE,
  artShown: PAGE,
  chainShown: PAGE,
};

/* ------------------------------------------------------------------ utils */

function esc(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function send(cmd, extra = {}) {
  return new Promise((resolve, reject) => {
    api.runtime.sendMessage({ cmd, ...extra }, (res) => {
      const err = api.runtime.lastError;
      if (err) reject(new Error(err.message));
      else if (!res?.ok) reject(new Error(res?.error || 'command failed'));
      else resolve(res);
    });
  });
}

let toastTimer = null;
function toast(msg, isError = false) {
  const chip = $('chainChip');
  chip.textContent = msg;
  chip.className = 'chip wide ' + (isError ? 'bad' : 'ok');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(renderChainChip, 4000);
}

async function renderChainChip() {
  const chip = $('chainChip');
  if (!state.chain) {
    chip.textContent = `chain: ${state.events.length} events`;
    chip.className = 'chip wide';
    return;
  }
  chip.textContent = state.chain.ok
    ? `chain verified ✓ ${state.chain.length}`
    : `CHAIN BROKEN @ ${state.chain.firstBreak}`;
  chip.className = 'chip wide ' + (state.chain.ok ? 'ok' : 'bad');
}

/* ------------------------------------------------------------------ data */

async function loadAll() {
  await open();
  const [events, snaps, settings, caseMeta] = await Promise.all([
    getEvents(),
    allSnapshots(),
    getMeta('settings', {}),
    getCaseMeta(),
  ]);
  state.events = events;
  state.snapshot = snaps.length ? snaps[snaps.length - 1] : null;
  state.settings = settings;
  state.caseMeta = caseMeta;
  state.timeline = null;      // invalidate derived caches
  state.findings = null;
  state.chain = null;

  const capChip = $('capChip');
  const on = state.settings.capture !== false;
  capChip.textContent = on ? '● capture live' : '○ capture paused';
  capChip.className = 'chip ' + (on ? 'on' : 'off');
  $('verLine').textContent = `v${TOOL.version}`;
}

function countsByType() {
  const c = {};
  for (const e of state.events) c[e.type] = (c[e.type] || 0) + 1;
  return c;
}

/* ------------------------------------------------------------------ nav */

const TITLES = {
  overview: 'Overview', timeline: 'Unified Timeline', artifacts: 'Artifacts',
  findings: 'Findings', chain: 'Chain of Custody', reports: 'Reports', settings: 'Settings',
};

function showView(view) {
  state.view = view;
  for (const btn of document.querySelectorAll('.nav-btn')) {
    btn.classList.toggle('active', btn.dataset.view === view);
  }
  for (const v of document.querySelectorAll('.view')) v.classList.add('hidden');
  $(`view-${view}`).classList.remove('hidden');
  $('viewTitle').textContent = TITLES[view];
  ({ overview: renderOverview, timeline: renderTimeline, artifacts: renderArtifacts,
     findings: renderFindings, chain: renderChainView, reports: renderReports,
     settings: renderSettings })[view]();
}

/* ------------------------------------------------------------- overview */

function renderOverview() {
  const c = countsByType();
  const base = state.snapshot?.counts || { history: 0, downloads: 0, cookies: 0 };
  const visits = (c.visit || 0) + base.history;
  const incog = c['incognito-visit'] || 0;
  const downloads = (c.download || 0) + base.downloads;
  const cookieEvts = (c['cookie-add'] || 0) + (c['cookie-del'] || 0);
  const deletions = c['history-delete'] || 0;
  const chainOk = state.chain == null ? null : state.chain.ok;

  const sevClass = (n) => (n > 0 ? 'danger' : '');
  const cards = [
    { b: visits.toLocaleString(), s: 'History visits', cls: '' },
    { b: incog.toLocaleString(), s: 'Private navigations', cls: incog ? 'warn' : '' },
    { b: downloads.toLocaleString(), s: 'Downloads', cls: '' },
    { b: cookieEvts.toLocaleString(), s: 'Cookie events', cls: '' },
    { b: deletions.toLocaleString(), s: 'History deletions', cls: sevClass(deletions) },
    {
      b: chainOk == null ? '-' : chainOk ? '✓' : 'BROKEN',
      s: `Chain (${state.events.length} events)`, cls: chainOk === false ? 'danger' : '',
    },
  ];
  $('statCards').innerHTML = cards.map((c2) =>
    `<div class="stat ${c2.cls}"><b>${esc(c2.b)}</b><span>${esc(c2.s)}</span></div>`
  ).join('');

  renderActivityChart();
  renderTopDomains();

  if (state.findings) {
    const s = state.findings.summary;
    $('findingsSummary').innerHTML = Object.entries(s)
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => `<span class="sev ${sev}">${sev}: ${n}</span>`)
      .join('') || '<span class="muted">No findings recorded.</span>';
  } else {
    $('findingsSummary').innerHTML = '<span class="muted">Run Analysis to compute findings.</span>';
  }

  const recent = [...state.events].slice(-8).reverse();
  $('recentEvents').innerHTML = recent.length
    ? recent.map((e) => `<div class="row"><span>${esc(fmtTime(e.ts))} · <span class="badge ${esc(e.type)}">${esc(e.type)}</span></span><span class="mono" style="color:var(--muted)">${esc(e.hash.slice(0, 10))}…</span></div>`).join('')
    : '<span class="muted">No live events captured yet.</span>';
}

function renderActivityChart() {
  const days = new Map();
  const start = new Date();
  start.setHours(0, 0, 0, 0);
  start.setDate(start.getDate() - 29);
  for (let i = 0; i < 30; i++) {
    const d = new Date(start);
    d.setDate(start.getDate() + i);
    days.set(d.toISOString().slice(0, 10), 0);
  }
  const feed = (ts) => {
    if (!ts) return;
    const k = ts.slice(0, 10);
    if (days.has(k)) days.set(k, days.get(k) + 1);
  };
  for (const e of state.events) feed(e.ts);
  for (const h of state.snapshot?.artifacts?.history || []) feed(h.lastVisitTime);

  const vals = [...days.values()];
  const max = Math.max(1, ...vals);
  const W = 640, H = 160, padB = 18, padL = 26;
  const bw = (W - padL) / 30;
  let bars = '';
  [...days.entries()].forEach(([day, n], i) => {
    const h = n ? Math.max(2, ((H - padB - 8) * n) / max) : 0;
    const x = padL + i * bw + 1.5;
    bars += `<rect class="bar" x="${x.toFixed(1)}" y="${(H - padB - h).toFixed(1)}" width="${(bw - 3).toFixed(1)}" height="${h.toFixed(1)}" rx="1.5"><title>${day}: ${n} events</title></rect>`;
  });
  const grid = [0, 0.5, 1].map((f) => {
    const y = H - padB - f * (H - padB - 8);
    return `<line class="axis" x1="${padL}" y1="${y}" x2="${W}" y2="${y}"></line>` +
      `<text class="lbl" x="0" y="${y + 3}">${Math.round(f * max)}</text>`;
  }).join('');
  $('activityChart').innerHTML =
    `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${grid}${bars}` +
    `<text class="lbl" x="${padL}" y="${H - 4}">${esc([...days.keys()][0])}</text>` +
    `<text class="lbl" x="${W - 76}" y="${H - 4}">${esc([...days.keys()][29])}</text></svg>`;
}

function renderTopDomains() {
  const counts = new Map();
  const add = (d, w = 1) => { if (d) counts.set(d, (counts.get(d) || 0) + w); };
  for (const e of state.events) {
    if (e.type === 'visit' || e.type === 'incognito-visit') add(e.data.domain);
  }
  for (const h of state.snapshot?.artifacts?.history || []) add(h.domain, h.visitCount || 1);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  const max = top.length ? top[0][1] : 1;
  $('topDomains').innerHTML = top.length
    ? top.map(([d, n]) =>
        `<div class="brow"><span class="name" title="${esc(d)}">${esc(d)}</span>` +
        `<span class="track"><span class="fill" style="width:${Math.max(2, (100 * n) / max).toFixed(1)}%"></span></span>` +
        `<span class="num">${n.toLocaleString()}</span></div>`).join('')
    : '<span class="muted">No domains recorded yet.</span>';
}

/* ------------------------------------------------------------- timeline */

const TL_TYPES = ['visit', 'incognito-visit', 'tab-session', 'download', 'download-state',
  'cookie-add', 'cookie-del', 'history-delete', 'snapshot', 'history'];

async function renderTimeline() {
  if (!state.timeline) state.timeline = await buildTimeline();
  const sel = $('tlType');
  if (sel.options.length <= 1) {
    const present = [...new Set(state.timeline.map((r) => r.type))]
      .sort((a, b) => a.localeCompare(b));
    for (const t of present) {
      const o = document.createElement('option');
      o.value = t; o.textContent = t;
      sel.appendChild(o);
    }
  }
  paintTimeline();
}

function timelineFiltered() {
  const q = $('tlSearch').value.trim().toLowerCase();
  const type = $('tlType').value;
  const source = $('tlSource').value;
  const from = $('tlFrom').value ? `${$('tlFrom').value}T00:00:00` : null;
  const to = $('tlTo').value ? `${$('tlTo').value}T23:59:59` : null;
  return (state.timeline || []).filter((r) => {
    if (type && r.type !== type) return false;
    if (source && !r.source.startsWith(source)) return false;
    if (from && (r.ts || '') < from) return false;
    if (to && (r.ts || '') > to) return false;
    if (q) {
      const hay = `${r.domain} ${r.detail} ${r.type} ${r.hash || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function paintTimeline() {
  const rows = timelineFiltered();
  $('tlCount').textContent = `${rows.length.toLocaleString()} / ${(state.timeline || []).length.toLocaleString()} rows`;
  $('tlBody').innerHTML = rows.slice(0, state.tlShown).map((r) =>
    `<tr><td class="mono">${r.seq != null ? r.seq : '·'}</td>` +
    `<td class="mono">${esc(fmtTime(r.ts))}</td>` +
    `<td><span class="badge ${esc(r.type)}">${esc(r.type)}</span></td>` +
    `<td>${esc(r.domain || '')}</td>` +
    `<td>${esc(midTruncate(r.detail, 96))}</td>` +
    `<td class="mono">${r.hash ? esc(r.hash.slice(0, 12)) + '…' : ''}</td></tr>`
  ).join('') || '<tr><td colspan="6" class="muted">No matching events.</td></tr>';
  $('tlMore').style.display = rows.length > state.tlShown ? '' : 'none';
}

/* ------------------------------------------------------------ artifacts */

const ART_COLUMNS = {
  history: [
    ['Last visit', (h) => fmtTime(h.lastVisitTime)], ['URL', (h) => h.url],
    ['Title', (h) => h.title], ['Visits', (h) => h.visitCount], ['Typed', (h) => h.typedCount],
  ],
  downloads: [
    ['Started', (d) => fmtTime(d.startTime)], ['File', (d) => d.filename || d.url],
    ['Source', (d) => d.url], ['Size', (d) => fmtBytes(d.bytes || d.totalBytes)],
    ['State', (d) => d.state ?? ''], ['Risk', (d) => d.danger && d.danger !== 'safe' ? d.danger : ''],
  ],
  cookies: [
    ['Domain', (c) => c.domain], ['Name', (c) => c.name],
    ['Value', (c) => midTruncate(c.value, 28)], ['Path', (c) => c.path],
    ['Expires', (c) => (c.expiryIso ? fmtTime(c.expiryIso) : 'session')],
    ['Flags', (c) => [c.secure && 'secure', c.httpOnly && 'httpOnly', c.session && 'session'].filter(Boolean).join(', ')],
  ],
};

function renderArtifacts() {
  const cols = ART_COLUMNS[state.artifact];
  $('artHead').innerHTML = '<tr>' + cols.map(([label]) => `<th>${esc(label)}</th>`).join('') + '</tr>';
  paintArtifacts();
}

function artifactRows() {
  const art = state.artifact;
  let rows = [];
  if (art === 'history') rows = state.snapshot?.artifacts?.history || [];
  else if (art === 'downloads') rows = state.snapshot?.artifacts?.downloads || [];
  else rows = state.snapshot?.artifacts?.cookies || [];

  const q = $('artSearch').value.trim().toLowerCase();
  if (q) {
    rows = rows.filter((r) =>
      JSON.stringify(r).toLowerCase().includes(q));
  }
  return rows;
}

function paintArtifacts() {
  const cols = ART_COLUMNS[state.artifact];
  const rows = artifactRows();
  $('artCount').textContent = `${rows.length.toLocaleString()} rows (latest baseline)`;
  $('artBody').innerHTML = rows.slice(0, state.artShown).map((r) =>
    '<tr>' + cols.map(([, get]) => `<td>${esc(get(r))}</td>`).join('') + '</tr>'
  ).join('') || `<tr><td colspan="${cols.length}" class="muted">No rows; acquire a baseline first.</td></tr>`;
  $('artMore').style.display = rows.length > state.artShown ? '' : 'none';
}

/* ------------------------------------------------------------- findings */

async function renderFindings() {
  const box = $('findingsList');
  const chips = $('findingsChips');
  if (!state.findings) {
    chips.innerHTML = '';
    box.innerHTML = '<p class="muted">Diagnostics have not been run in this session. Click “Run Analysis” in the top bar.</p>';
    $('findingsMeta').textContent = 'not analyzed';
    return;
  }
  const d = state.findings;
  $('findingsMeta').textContent = `generated ${fmtTime(d.generatedAt)} · chain ${d.chain.ok ? 'verified' : 'BROKEN'} (${d.chain.length} events)`;
  chips.innerHTML = Object.entries(d.summary)
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `<span class="sev ${sev}">${sev}: ${n}</span>`)
    .join('') || '<span class="sev Info">no findings</span>';
  box.innerHTML = d.findings.map((f, i) =>
    `<div class="finding ${esc(f.severity)}">` +
    `<div class="fhead"><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span><span class="fcat">${esc(f.category)}</span></div>` +
    `<p>${esc(f.message)}</p><div class="ev">${esc(f.evidence)}</div></div>`
  ).join('') || '<p class="muted">No anomalies detected.</p>';
}

/* ---------------------------------------------------------------- chain */

function renderChainView() {
  const head = state.chain?.head || (state.events.length ? null : GENESIS_HASH);
  $('chainMeta').innerHTML = [
    ['Events', state.events.length.toLocaleString()],
    ['Genesis', `${GENESIS_HASH.slice(0, 16)}…`],
    ['Head', head ? `${head.slice(0, 24)}…` : 'verify to display'],
    ['Last event', state.events.length ? fmtTime(state.events[state.events.length - 1].ts) : '-'],
  ].map(([k, v]) => `<div><span>${esc(k)}</span><b class="mono">${esc(v)}</b></div>`).join('');
  paintChainTable();
}

function paintChainTable() {
  const rows = [...state.events].reverse().slice(0, state.chainShown);
  $('chainBody').innerHTML = rows.map((e) =>
    `<tr><td class="mono">${e.seq}</td><td class="mono">${esc(fmtTime(e.ts))}</td>` +
    `<td><span class="badge ${esc(e.type)}">${esc(e.type)}</span></td>` +
    `<td class="mono" title="${esc(e.hash)}">${esc(e.hash.slice(0, 20))}…</td>` +
    `<td class="mono" title="${esc(e.prev)}">${esc(e.prev.slice(0, 20))}…</td></tr>`
  ).join('') || '<tr><td colspan="5" class="muted">Chain is empty.</td></tr>';
  $('chainMore').style.display = state.events.length > state.chainShown ? '' : 'none';
}

async function verifyNow() {
  toast('verifying chain…');
  state.events = await getEvents();   // verify against the persisted store, never a stale cache
  state.chain = await verifyChain(state.events);
  renderChainChip();
  const box = $('verifyResult');
  if (state.chain.ok) {
    box.className = 'banner ok';
    box.textContent = `Chain verified ✓ · ${state.chain.length} events, head ${state.chain.head.slice(0, 32)}…`;
  } else {
    box.className = 'banner bad';
    box.textContent = `CHAIN BROKEN at event #${state.chain.firstBreak}. Evidence from this point onward must be treated as untrustworthy.`;
  }
  renderChainView();
  renderOverview();
  return state.chain;
}

/* -------------------------------------------------------------- reports */

function renderReports() {
  const m = state.caseMeta;
  $('caseId').value = m.caseId || '';
  $('suspectName').value = m.suspectName || '';
  $('deviceName').value = m.deviceName || '';
  $('investigator').value = m.investigator || '';
  $('notes').value = m.notes || '';
  $('caseSaved').textContent = '';

  const c = countsByType();
  const base = state.snapshot?.counts || { history: 0, downloads: 0, cookies: 0 };
  $('reportSummary').innerHTML = [
    ['Live events', state.events.length.toLocaleString()],
    ['Baseline history URLs', base.history.toLocaleString()],
    ['Baseline downloads', base.downloads.toLocaleString()],
    ['Baseline cookies', base.cookies.toLocaleString()],
    ['Captured visits', (c.visit || 0).toLocaleString()],
    ['Private navigations', (c['incognito-visit'] || 0).toLocaleString()],
    ['History deletions', (c['history-delete'] || 0).toLocaleString()],
    ['Findings', state.findings ? state.findings.findings.length : 'not analyzed'],
  ].map(([k, v]) => `<div class="row"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('');
}

async function exportJson() {
  const pkg = await buildEvidencePackage();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  downloadText(`fbex-evidence-${stamp}.json`, 'application/json', JSON.stringify(pkg, null, 2));
  toast('evidence package exported');
}

async function exportCsv() {
  if (!state.timeline) state.timeline = await buildTimeline();
  const csv = await buildTimelineCsv();
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  downloadText(`fbex-timeline-${stamp}.csv`, 'text/csv', csv);
  toast('timeline CSV exported');
}

async function exportPrint() {
  if (!state.findings) {
    toast('running analysis first…');
    state.findings = await runDiagnostics();
  }
  const pkg = await buildEvidencePackage();
  const rows = await buildTimeline();
  const m = pkg.case;
  const sevRow = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;

  $('print-root').innerHTML = `
    <h1>${esc(TOOL.name)} · Forensic Case Report</h1>
    <div class="ph">${esc(TOOL.name)} v${esc(TOOL.version)} · generated ${esc(fmtTime(pkg.generatedAt))} · all times local to the examiner machine</div>
    <h2>Case information</h2>
    <table class="kv">
      <tr><td>Case ID</td><td>${esc(m.caseId || '-')}</td></tr>
      <tr><td>Subject / suspect</td><td>${esc(m.suspectName || '-')}</td></tr>
      <tr><td>Device</td><td>${esc(m.deviceName || '-')}</td></tr>
      <tr><td>Investigator</td><td>${esc(m.investigator || '-')}</td></tr>
      <tr><td>Notes</td><td>${esc(m.notes || '-')}</td></tr>
    </table>
    <h2>Evidence summary</h2>
    <table>
      <tr><th>Item</th><th>Count</th></tr>
      <tr><td>Hash-chained evidence events</td><td>${pkg.summary.eventCount}</td></tr>
      <tr><td>Baseline history URLs / downloads / cookies</td><td>${pkg.summary.baselineCounts ? `${pkg.summary.baselineCounts.history} / ${pkg.summary.baselineCounts.downloads} / ${pkg.summary.baselineCounts.cookies}` : 'no baseline'}</td></tr>
      <tr><td>Unified timeline rows</td><td>${rows.length}</td></tr>
      <tr><td>Chain integrity</td><td>${pkg.chain.ok ? `VERIFIED (${pkg.chain.length} events, head ${esc(pkg.chain.head.slice(0, 24))}…)` : 'FAILED'}</td></tr>
    </table>
    <h2>Findings (${pkg.findings.length})</h2>
    <table>
      <tr><th>Severity</th><th>Category</th><th>Finding</th></tr>
      ${pkg.findings.map((f) => `<tr><td>${esc(f.severity)}</td><td>${esc(f.category)}</td><td>${esc(f.message)}</td></tr>`).join('') || '<tr><td colspan="3">No findings.</td></tr>'}
    </table>
    <h2>Unified timeline (most recent ${Math.min(rows.length, 200)} of ${rows.length})</h2>
    <table>
      <tr><th>Timestamp</th><th>Type</th><th>Domain</th><th>Detail</th></tr>
      ${rows.slice(0, 200).map((r) => `<tr><td>${esc(fmtTime(r.ts))}</td><td>${esc(r.type)}</td><td>${esc(r.domain || '')}</td><td>${esc(midTruncate(r.detail, 90))}</td></tr>`).join('')}
    </table>
    <div class="sig"><div>Investigator signature</div><div>Date</div></div>
    <p style="margin-top:10px;font-size:9px;color:#555">Evidence hash chain: ${pkg.chain.ok ? `verified, head ${esc(pkg.chain.head)}` : `VERIFICATION FAILED (first break at event ${pkg.chain.firstBreak})`}. Generated locally by ${esc(TOOL.name)}; no data left the examiner machine.</p>
  `;
  window.print();
}

/* ------------------------------------------------------------- settings */

const TOGGLES = [
  ['capture', 'Live capture (master)', 'When off, no new evidence events are recorded.'],
  ['visits', 'Visit capture', 'Record every navigation that reaches browser history.'],
  ['incognito', 'Private browsing capture', 'Record navigations in private/incognito tabs (requires "Allow in incognito" for this extension).'],
  ['tabSessions', 'Tab session dwell time', 'Record how long each page was kept open.'],
  ['downloads', 'Download capture', 'Record downloads and their state transitions.'],
  ['cookies', 'Cookie change capture', 'Record cookie creation/removal events.'],
  ['storeCookieValues', 'Store plaintext cookie values', 'Off by default: cookie values are session secrets; lengths/metadata are usually sufficient.'],
];

function renderSettings() {
  $('settingsToggles').innerHTML = TOGGLES.map(([key, label, hint]) => `
    <label class="tg">
      <input type="checkbox" data-key="${esc(key)}" ${state.settings[key] ? 'checked' : ''} />
      <div>${esc(label)}<small>${esc(hint)}</small></div>
    </label>`).join('');
  $('aboutBox').innerHTML = [
    ['Version', `v${TOOL.version} (MV3)`],
    ['Storage', 'IndexedDB, local only'],
    ['Chain', `SHA-256 linked list, ${state.events.length} events`],
    ['Telemetry', 'none (no network calls)'],
  ].map(([k, v]) => `<div class="row"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join('');
  $('settingsSaved').textContent = '';
}

/* ----------------------------------------------------------------- boot */

function wire() {
  document.querySelectorAll('.nav-btn').forEach((b) =>
    b.addEventListener('click', () => showView(b.dataset.view)));

  // timeline filters
  for (const id of ['tlSearch', 'tlType', 'tlSource', 'tlFrom', 'tlTo']) {
    $(id).addEventListener('input', () => { state.tlShown = PAGE; paintTimeline(); });
  }
  $('tlMore').addEventListener('click', () => { state.tlShown += PAGE; paintTimeline(); });

  // artifacts
  document.querySelectorAll('.subtab').forEach((b) =>
    b.addEventListener('click', () => {
      document.querySelectorAll('.subtab').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      state.artifact = b.dataset.art;
      state.artShown = PAGE;
      renderArtifacts();
    }));
  $('artSearch').addEventListener('input', () => { state.artShown = PAGE; paintArtifacts(); });
  $('artMore').addEventListener('click', () => { state.artShown += PAGE; paintArtifacts(); });

  // chain
  $('chainMore').addEventListener('click', () => { state.chainShown += PAGE; paintChainTable(); });
  $('btnVerify').addEventListener('click', () => verifyNow().catch((e) => toast(e.message, true)));

  // topbar actions
  $('btnAcquire').addEventListener('click', async () => {
    const btn = $('btnAcquire');
    btn.disabled = true; toast('acquiring baseline…');
    try {
      const res = await send('acquire');
      toast(`baseline ✓ ${res.counts.history} URLs · ${res.counts.downloads} downloads · ${res.counts.cookies} cookies`);
      await loadAll();
      showView(state.view);
    } catch (e) { toast(`acquire failed: ${e.message}`, true); }
    finally { btn.disabled = false; }
  });

  $('btnAnalyze').addEventListener('click', async () => {
    const btn = $('btnAnalyze');
    btn.disabled = true; toast('running diagnostics…');
    try {
      state.events = await getEvents();   // analyze fresh evidence, not a stale cache
      state.chain = await verifyChain(state.events);
      state.findings = await runDiagnostics();
      renderChainChip();
      showView('findings');
      toast(`analysis ✓ ${state.findings.findings.length} findings`);
    } catch (e) { toast(`analysis failed: ${e.message}`, true); }
    finally { btn.disabled = false; }
  });

  // reports
  $('btnSaveCase').addEventListener('click', async () => {
    state.caseMeta = await saveCaseMeta({
      caseId: $('caseId').value, suspectName: $('suspectName').value,
      deviceName: $('deviceName').value, investigator: $('investigator').value,
      notes: $('notes').value,
    });
    $('caseSaved').textContent = 'saved ✓';
  });
  $('btnJson').addEventListener('click', () => exportJson().catch((e) => toast(e.message, true)));
  $('btnCsv').addEventListener('click', () => exportCsv().catch((e) => toast(e.message, true)));
  $('btnPdf').addEventListener('click', () => exportPrint().catch((e) => toast(e.message, true)));

  // settings
  $('btnSaveSettings').addEventListener('click', async () => {
    const settings = { ...state.settings };
    for (const input of document.querySelectorAll('#settingsToggles input')) {
      settings[input.dataset.key] = input.checked;
    }
    try {
      const res = await send('settings:set', { settings });
      state.settings = res.settings;
      await loadAll();
      renderSettings();
      $('settingsSaved').textContent = 'saved ✓';
    } catch (e) { $('settingsSaved').textContent = e.message; }
  });

  $('btnReset').addEventListener('click', async () => {
    const confirmation = prompt(
      'This destroys the ENTIRE evidence store (events, chain, snapshots) and starts a new chain.\n\nType RESET to confirm:'
    );
    if (confirmation !== 'RESET') return;
    try {
      await send('reset', { reason: 'dashboard reset' });
      await loadAll();
      showView('overview');
      toast('evidence store reset · new genesis chain');
    } catch (e) { toast(e.message, true); }
  });

  document.title = `${TOOL.name} · Dashboard`;
}

async function main() {
  wire();
  await loadAll();
  renderChainChip();
  showView('overview');
}

main().catch((err) => {
  document.body.insertAdjacentHTML(
    'afterbegin',
    `<div class="banner bad" style="margin:14px">Dashboard failed to load: ${esc(err.message)}</div>`
  );
});
