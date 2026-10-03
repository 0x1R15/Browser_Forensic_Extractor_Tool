// IndexedDB evidence store.
//
// Database layout (`fbex-evidence` v1):
//   meta      keyPath 'key'  : case metadata, settings, chain head, sequence counter
//   events    keyPath 'seq'  : append-only hash-chained evidence events
//                             (indexes: 'by-ts' on ts, 'by-type' on type)
//   snapshots keyPath 'id'   : baseline acquisition artifacts (history/downloads/cookies)
//
// Single-writer discipline: only the background service worker appends chain
// events. Dashboard/popup contexts read directly and mutate only `meta`.

import { nowIso } from './util.js';
import { GENESIS_HASH, eventHash } from './chain.js';

const DB_NAME = 'fbex-evidence';
const DB_VERSION = 1;

let dbPromise = null;

/** Opens (and if needed upgrades) the evidence database. Cached per context. */
export function open() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('meta')) {
        db.createObjectStore('meta', { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains('events')) {
        const events = db.createObjectStore('events', { keyPath: 'seq' });
        events.createIndex('by-ts', 'ts');
        events.createIndex('by-type', 'type');
      }
      if (!db.objectStoreNames.contains('snapshots')) {
        db.createObjectStore('snapshots', { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function tx(db, store, mode) {
  return db.transaction(store, mode).objectStore(store);
}

function reqAsPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// ---------------------------------------------------------------- meta

/** Reads a meta record's value (or `fallback` when absent). */
export async function getMeta(key, fallback = null) {
  const db = await open();
  const row = await reqAsPromise(tx(db, 'meta', 'readonly').get(key));
  return row ? row.value : fallback;
}

/** Writes a meta record. */
export async function setMeta(key, value) {
  const db = await open();
  await reqAsPromise(tx(db, 'meta', 'readwrite').put({ key, value }));
  return value;
}

// ------------------------------------------------------------- events

/**
 * Appends a chained event. Assigns `seq`, links `prev` to the current chain
 * head, computes `hash`, and persists atomically. The caller-visible record
 * (with seq/prev/hash attached) is returned.
 *
 * Appends are serialized through an in-module promise queue so concurrent
 * event fires cannot race on the sequence counter.
 */
const appendQueue = Promise.resolve();

export function appendEvent(type, data) {
  const run = appendQueue.then(() => appendEventInternal(type, data));
  // Keep the queue alive even if one append fails.
  appendQueue.catch(() => {});
  return run;
}

async function appendEventInternal(type, data) {
  const db = await open();
  const seq = (await getMeta('seq', 0)) + 1;
  const prev = await getMeta('chainHead', GENESIS_HASH);
  const event = { seq, ts: nowIso(), type, data: data ?? {}, prev };
  event.hash = await eventHash(event);

  await reqAsPromise(tx(db, 'events', 'readwrite').put(event));
  await setMeta('seq', seq);
  await setMeta('chainHead', event.hash);
  return event;
}

/** Reads events ordered by seq. Optional `type` filter and cap. */
export async function getEvents({ type = null, limit = null } = {}) {
  const db = await open();
  const store = tx(db, 'events', 'readonly');
  const source = type ? store.index('by-type') : store;
  const rows = await reqAsPromise(source.getAll());
  rows.sort((a, b) => a.seq - b.seq);
  return limit ? rows.slice(-limit) : rows;
}

/** Number of chained events currently stored. */
export async function countEvents() {
  const db = await open();
  return reqAsPromise(tx(db, 'events', 'readonly').count());
}

// ---------------------------------------------------------- snapshots

/** Persists a baseline snapshot record. */
export async function addSnapshot(snapshot) {
  const db = await open();
  await reqAsPromise(tx(db, 'snapshots', 'readwrite').put(snapshot));
  return snapshot;
}

/** Most recent baseline snapshot or null. */
export async function latestSnapshot() {
  const db = await open();
  const rows = await reqAsPromise(tx(db, 'snapshots', 'readonly').getAll());
  if (!rows.length) return null;
  return rows.reduce((a, b) => (a.id >= b.id ? a : b));
}

/** All snapshots, oldest first. */
export async function allSnapshots() {
  const db = await open();
  const rows = await reqAsPromise(tx(db, 'snapshots', 'readonly').getAll());
  return rows.sort((a, b) => a.id - b.id);
}

// -------------------------------------------------------------- admin

/**
 * Destroys the entire evidence database (events, snapshots, meta) and
 * recreates it empty. Used exclusively by the explicit user "Reset" action.
 */
export async function wipeAll() {
  const db = await open();
  db.close();
  dbPromise = null;
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
  await open();
}
