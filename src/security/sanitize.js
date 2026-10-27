'use strict';

/**
 * Output encoding (anti-XSS) and input normalisation.
 *
 * XSS is an *output* problem: the same string is safe in a JSON body and
 * dangerous when concatenated into HTML.  This module therefore exposes an
 * explicit encoder that is applied at the last moment, when data leaves the
 * API, plus a recursive helper used by the response middleware.
 */

/**
 * Escape a single string for HTML element/attribute context.
 *
 * Implemented with an explicit switch instead of a lookup table: the set of
 * replaced characters is visible in one place, there is no prototype chain to
 * traverse, and no dynamic property access to reason about.
 */
function escapeHtml(value) {
  return String(value).replace(/[&<>"'`=/]/g, (ch) => {
    switch (ch) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      case "'": return '&#x27;';
      case '/': return '&#x2F;';
      case '`': return '&#x60;';
      case '=': return '&#x3D;';
      default: return ch;
    }
  });
}

/** Recursively escape every string (and object key) in a value. */
function escapeDeep(value) {
  if (typeof value === 'string') return escapeHtml(value);
  if (Array.isArray(value)) return value.map(escapeDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[escapeHtml(key)] = escapeDeep(val);
    }
    return out;
  }
  return value;
}

/**
 * Strip control characters (except \n, \r, \t) and NUL bytes from user input.
 * Prevents log injection / terminal escape injection and keeps stored text sane.
 * This is *normalisation*, not sanitisation: it never tries to "clean" HTML.
 */
function normaliseText(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .normalize('NFC')
    .trim();
}

module.exports = { escapeHtml, escapeDeep, normaliseText };
