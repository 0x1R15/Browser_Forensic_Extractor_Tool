// Forensic Browser Extractor: background capture engine (MV3 service worker).
//
// Owns ALL writes to the evidence store (single-writer discipline). Every
// observation is appended to the tamper-evident hash chain (lib/chain.js)
// before the handler returns. Dashboard/popup contexts only read and send
// command messages.
//
// Captured signals:
//   visit           history.onVisited        normal navigations (has title)
//   incognito-visit webNavigation.onCommitted  navigations in private tabs
//   tab-session     tabs.onRemoved           dwell time per browsing session
//   download        downloads.onCreated
//   download-state  downloads.onChanged      terminal state transitions
//   cookie-add/del  cookies.onChanged
//   history-delete  history.onVisitRemoved   manual clears + removals
//   snapshot        (on demand)              baseline acquisition digest
//   capture-start/stop, heartbeat, reset    chain-of-custody bookkeeping

import { api, nowIso, domainOf, TOOL } from '../lib/util.js';
import * as db from '../lib/db.js';
import { acquireBaseline } from '../lib/acquisition.js';

const MAINTENANCE_ALARM = 'fbex-maintenance';
const HEARTBEAT_PERIOD_MIN = 720; // 12h: proves chain continuity while capture runs

const DEFAULT_SETTINGS = {
  capture: true,
  visits: true,
  downloads: true,
  cookies: true,
  incognito: true,
  tabSessions: true,
  storeCookieValues: false, // plaintext cookie values off by default (secret hygiene)
};

// --- in-memory session state (rebuilt cheaply on SW wake) --------------
/** tabId -> {url, ts, incognito} : last top-frame navigation per tab. */
const tabNav = new Map();
/** downloadId -> {url} : join key for state-change events. */
const downloadMeta = new Map();

let settings = { ...DEFAULT_SETTINGS };

async function loadSettings() {
  const stored = await db.getMeta('settings', null);
  settings = { ...DEFAULT_SETTINGS, ...(stored || {}) };
  return settings;
}

async function saveSettings(next) {
  settings = { ...DEFAULT_SETTINGS, ...next };
  await db.setMeta('settings', settings);
  return settings;
}

async function captureActive() {
  return settings.capture === true;
}

// --- install / lifecycle ------------------------------------------------

api.runtime.onInstalled.addListener((details) => {
  (async () => {
    await loadSettings();
    await db.setMeta('installedAt', nowIso());
    await db.setMeta('version', TOOL.version);
    if (settings.capture) {
      await db.appendEvent('capture-start', { reason: details.reason, version: TOOL.version });
    }
    await api.alarms.clear(MAINTENANCE_ALARM);
    await api.alarms.create(MAINTENANCE_ALARM, { periodInMinutes: HEARTBEAT_PERIOD_MIN });
  })();
});

api.runtime.onStartup.addListener(() => {
  loadSettings();
});

// --- visits (history API: authoritative for normal browsing) ------------

api.history.onVisited.addListener((item) => {
  if (!captureActive() || !settings.visits) return;
  db.appendEvent('visit', {
    url: item.url,
    domain: domainOf(item.url),
    title: item.title || '',
    visitCount: item.visitCount || 0,
    typedCount: item.typedCount || 0,
    lastVisitTime: item.lastVisitTime ? new Date(item.lastVisitTime).toISOString() : null,
  });
});

api.history.onVisitRemoved.addListener((removed) => {
  if (!captureActive()) return;
  db.appendEvent('history-delete', {
    allHistory: !!removed.allHistory,
    count: removed.urls ? removed.urls.length : 0,
    urls: removed.allHistory ? [] : (removed.urls || []).slice(0, 50),
  });
});

// --- incognito detection (private tabs never reach history API) ---------

api.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!/^(https?|file|ftp):/i.test(details.url)) return;

  const entry = { url: details.url, ts: nowIso(), incognito: false };
  tabNav.set(details.tabId, entry);

  if (!captureActive() || !settings.incognito) return;
  // Private navigation leaves no history trace; record it directly.
  try {
    api.tabs.get(details.tabId, (tab) => {
      if (api.runtime.lastError) return;
      const incognito = !!tab?.incognito;
      const nav = tabNav.get(details.tabId);
      if (nav) nav.incognito = incognito;
      if (incognito) {
        db.appendEvent('incognito-visit', {
          url: details.url,
          domain: domainOf(details.url),
          transition: details.transitionType || '',
          tabId: details.tabId,
        });
      }
    });
  } catch {
    /* tabs.get unavailable; skip incognito enrichment */
  }
});

// --- tab sessions (dwell time) ------------------------------------------

api.tabs.onRemoved.addListener((tabId) => {
  const nav = tabNav.get(tabId);
  tabNav.delete(tabId);
  if (!nav || !captureActive() || !settings.tabSessions) return;
  const dwellSec = Math.max(0, Math.round((Date.now() - Date.parse(nav.ts)) / 1000));
  db.appendEvent('tab-session', {
    url: nav.url,
    domain: domainOf(nav.url),
    dwellSec,
    incognito: nav.incognito,
  });
});

// --- downloads -----------------------------------------------------------

api.downloads.onCreated.addListener((item) => {
  downloadMeta.set(item.id, { url: item.finalUrl || item.url });
  if (!captureActive() || !settings.downloads) return;
  db.appendEvent('download', {
    id: item.id,
    url: item.finalUrl || item.url,
    domain: domainOf(item.finalUrl || item.url),
    referrer: item.referrer || '',
    filename: item.filename || '',
    mime: item.mime || '',
    bytes: item.fileSize ?? item.bytesReceived ?? 0,
    state: item.state || 'in_progress',
    danger: item.danger || 'safe',
    startTime: item.startTime ? new Date(item.startTime).toISOString() : null,
  });
});

api.downloads.onChanged.addListener((delta) => {
  const state = delta.state && delta.state.current;
  if (state !== 'complete' && state !== 'interrupted') return;
  const meta = downloadMeta.get(delta.id) || {};
  if (!captureActive() || !settings.downloads) return;
  db.appendEvent('download-state', {
    id: delta.id,
    url: meta.url || '',
    state,
    error: delta.error && delta.error.current,
    bytesReceived: (delta.bytesReceived && delta.bytesReceived.current) ?? null,
    filename: (delta.filename && delta.filename.current) || '',
  });
  if (state === 'complete') downloadMeta.delete(delta.id);
});

// --- cookies -------------------------------------------------------------

api.cookies.onChanged.addListener((change) => {
  if (!captureActive() || !settings.cookies) return;
  const c = change.cookie;
  const data = {
    domain: c.domain,
    name: c.name,
    path: c.path,
    secure: !!c.secure,
    httpOnly: !!c.httpOnly,
    session: !!c.session,
    sameSite: c.sameSite || '',
    cause: change.cause || '',
    expirationDate: c.expirationDate || null,
  };
  if (settings.storeCookieValues && !change.removed) {
    data.value = c.value || '';
  }
  db.appendEvent(change.removed ? 'cookie-del' : 'cookie-add', { cookie: data });
});

// --- maintenance heartbeat (chain continuity) ---------------------------

api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== MAINTENANCE_ALARM) return;
  if (captureActive()) {
    db.appendEvent('heartbeat', { version: TOOL.version });
  }
});

// --- command channel (popup / dashboard) ---------------------------------

api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  handleCommand(msg)
    .then((result) => sendResponse({ ok: true, ...result }))
    .catch((err) => sendResponse({ ok: false, error: String(err?.message || err) }));
  return true; // async response
});

async function handleCommand(msg) {
  await loadSettings();
  switch (msg?.cmd) {
    case 'status': {
      const [seq, chainHead, last] = await Promise.all([
        db.getMeta('seq', 0),
        db.getMeta('chainHead', null),
        db.getEvents({ limit: 1 }),
      ]);
      const events = await db.getEvents();
      const counts = {};
      for (const e of events) counts[e.type] = (counts[e.type] || 0) + 1;
      return {
        capture: settings.capture,
        settings,
        seq,
        chainHead,
        counts,
        total: events.length,
        lastTs: last.length ? last[0].ts : null,
        installedAt: await db.getMeta('installedAt', null),
      };
    }

    case 'acquire': {
      const snap = await acquireBaseline();
      await db.addSnapshot(snap);
      await db.appendEvent('snapshot', { id: snap.id, digest: snap.digest, counts: snap.counts });
      return { counts: snap.counts, digest: snap.digest };
    }

    case 'capture:toggle': {
      settings.capture = !!msg.enabled;
      await saveSettings(settings);
      await db.appendEvent(msg.enabled ? 'capture-start' : 'capture-stop', {
        reason: 'user',
        version: TOOL.version,
      });
      return { capture: settings.capture };
    }

    case 'settings:set': {
      const next = await saveSettings({ ...settings, ...(msg.settings || {}) });
      return { settings: next };
    }

    case 'reset': {
      await db.wipeAll();
      downloadMeta.clear();
      tabNav.clear();
      await loadSettings();
      await db.setMeta('installedAt', nowIso());
      if (settings.capture) {
        await db.appendEvent('reset', { reason: msg.reason || 'user' });
        await db.appendEvent('capture-start', { reason: 'post-reset', version: TOOL.version });
      }
      return { reset: true };
    }

    default:
      throw new Error(`Unknown command: ${msg?.cmd}`);
  }
}
