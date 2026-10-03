// Tamper-evident SHA-256 hash chain for evidence events.
//
// Every event record carries:
//   seq   — monotonically increasing sequence number (1-based)
//   ts    — ISO-8601 UTC capture time
//   type  — event type discriminator
//   data  — arbitrary JSON payload
//   prev  — hash of the previous event ('0'*64 for the genesis event)
//   hash  — SHA-256 over `${seq}|${ts}|${type}|${canonicalize(data)}|${prev}`
//
// Any retroactive modification of an event breaks its own hash and every
// subsequent hash, making silent tampering detectable by re-walking the chain.

import { canonicalize } from './util.js';

export const GENESIS_HASH = '0'.repeat(64);

/** SHA-256 of a UTF-8 string, hex-encoded. */
export async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Canonical pre-image for an event's hash. */
export function eventPreimage(seq, ts, type, data, prev) {
  return `${seq}|${ts}|${type}|${canonicalize(data)}|${prev}`;
}

/** Computes an event's hash from its fields. */
export async function eventHash(event) {
  return sha256Hex(eventPreimage(event.seq, event.ts, event.type, event.data, event.prev));
}

/** SHA-256 over the canonical form of an arbitrary object (snapshot digests). */
export async function digestObject(obj) {
  return sha256Hex(canonicalize(obj));
}

/**
 * Re-walks an ordered event list and verifies every link.
 * @returns {{ok: boolean, length: number, head: string|null, firstBreak: number|null}}
 */
export async function verifyChain(events) {
  let prev = GENESIS_HASH;
  let expectedSeq = 1;
  for (const event of events) {
    if (event.seq !== expectedSeq || event.prev !== prev) {
      return { ok: false, length: events.length, head: prev, firstBreak: event.seq ?? expectedSeq };
    }
    const h = await eventHash(event);
    if (h !== event.hash) {
      return { ok: false, length: events.length, head: prev, firstBreak: event.seq };
    }
    prev = event.hash;
    expectedSeq += 1;
  }
  return { ok: true, length: events.length, head: prev || null, firstBreak: null };
}
