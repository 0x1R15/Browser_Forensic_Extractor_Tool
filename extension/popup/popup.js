// Popup: live status card. Reads via command channel; never writes the chain.

import { api, TOOL } from '../lib/util.js';
import { open, getEvents } from '../lib/db.js';
import { verifyChain } from '../lib/chain.js';

const $ = (id) => document.getElementById(id);

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

async function refresh() {
  try {
    const status = await send('status');
    await renderStatus(status);

    // Independent chain verification (popup reads the store directly).
    await open();
    const events = await getEvents();
    const chain = await verifyChain(events);
    const line = $('chainLine');
    if (chain.ok && chain.length > 0) {
      line.textContent = `Chain verified ✓ ${chain.length} events`;
      line.className = 'ok';
    } else if (chain.length === 0) {
      line.textContent = 'Chain empty — no evidence yet';
      line.className = '';
    } else {
      line.textContent = `CHAIN BROKEN at #${chain.firstBreak}`;
      line.className = 'bad';
    }
  } catch (err) {
    $('hint').textContent = `Status error: ${err.message}`;
    $('hint').className = 'hint err';
  }
}

async function renderStatus(status) {
  const on = status.capture;
  $('captureDot').className = 'dot ' + (on ? 'on' : 'off');
  $('captureLabel').textContent = on ? 'Live capture active' : 'Capture paused';
  $('captureToggle').checked = on;

  $('stVisits').textContent = status.counts.visit || 0;
  $('stIncognito').textContent = status.counts['incognito-visit'] || 0;
  $('stDownloads').textContent =
    (status.counts.download || 0) + (status.counts['download-state'] || 0);
  $('stCookies').textContent =
    (status.counts['cookie-add'] || 0) + (status.counts['cookie-del'] || 0);
  $('stTotal').textContent = status.total;
  $('stLast').textContent = status.lastTs
    ? new Date(status.lastTs).toLocaleTimeString()
    : '—';
  $('stHead').textContent = status.chainHead
    ? status.chainHead.slice(0, 16) + '…'
    : '(genesis)';
}

$('captureToggle').addEventListener('change', async (e) => {
  e.target.disabled = true;
  try {
    await send('capture:toggle', { enabled: e.target.checked });
    await refresh();
  } catch (err) {
    $('hint').textContent = err.message;
    $('hint').className = 'hint err';
  } finally {
    e.target.disabled = false;
  }
});

$('btnScan').addEventListener('click', async () => {
  const btn = $('btnScan');
  btn.disabled = true;
  $('hint').textContent = 'Acquiring baseline (history, downloads, cookies)…';
  $('hint').className = 'hint';
  try {
    const res = await send('acquire');
    $('hint').textContent =
      `Baseline ✓ ${res.counts.history} URLs · ${res.counts.downloads} downloads · ${res.counts.cookies} cookies`;
    $('hint').className = 'hint ok';
    await refresh();
  } catch (err) {
    $('hint').textContent = `Acquisition failed: ${err.message}`;
    $('hint').className = 'hint err';
  } finally {
    btn.disabled = false;
  }
});

$('btnOpen').addEventListener('click', () => {
  api.tabs.create({ url: api.runtime.getURL('dashboard/dashboard.html') });
  window.close();
});

document.title = `${TOOL.shortName} — Status`;
refresh();
