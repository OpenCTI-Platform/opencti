// Utility to refang defanged IOCs (Indicators of Compromise)
// Supports common defanging techniques: [.] -> ., hxxp -> http, etc.

import { URL } from 'url';

/**
 * Refang, clean, normalize, and optionally truncate an indicator value for Defender API submission.
 * - Refangs common obfuscations
 * - Extracts and sanitizes URLs
 * - Encodes path/query safely
 * - Strips trailing garbage and punctuation
 * @param {string} input - The potentially defanged string.
 * @returns {string} - The refanged string.
 */
export function refang(input) {
  if (!input || typeof input !== 'string') return input;

  // Trim first
  let output = input.trim();

  // Normalize Unicode (NFKC)
  if (typeof output.normalize === 'function') {
    output = output.normalize('NFKC');
  }

  // Refang common obfuscations (all patterns from both functions)
  output = output
    // Replace [.] and (.) and [dot] or (dot) with .
    // eslint-disable-next-line no-useless-escape
    .replace(/\[(\.|dot)\]|\((\.|dot)\)/gi, '.')
    // Replace [at] or (at) with @
    // eslint-disable-next-line no-useless-escape
    .replace(/\[at\]|\(at\)/gi, '@')
    // Replace [dash] or (dash) with -
    // eslint-disable-next-line no-useless-escape
    .replace(/\[dash\]|\(dash\)/gi, '-')
    // Replace hxxp/hxp/hxxps/hxps (with optional brackets/colons) -> http/https
    // eslint-disable-next-line no-useless-escape
    .replace(/(\s*)h([x]{1,2})p([s]?)[\[\]:]*\/\//gi, (m, pre, xx, s) => `${pre}http${s}://`)
    // Replace fxp/sfxp/fxps (with optional brackets/colons) -> ftp/ftps
    // eslint-disable-next-line no-useless-escape
    .replace(/(\s*)(s?)fxp(s?)[\[\]:]*\/\//gi, (m, pre, s1, s2) => `${pre}${s1}ftp${s2}://`)
    // Replace (protocol)[://] or similar -> protocol://
    // eslint-disable-next-line no-useless-escape
    .replace(/(\s*)\(([-.+a-zA-Z0-9]{1,12})\)[\[\]:]*\/\//gi, (m, pre, proto) => `${pre}${proto}://`)
    // Replace [://] or similar with ://
    // eslint-disable-next-line no-useless-escape
    .replace(/\[:\/]{3,}/g, '://')
    // Remove any stray brackets around single characters
    // eslint-disable-next-line no-useless-escape
    .replace(/\[([a-zA-Z0-9])\]/g, '$1')
    // Remove literal ellipsis character
    .replace(/\u2026/g, '');

  // Remove common placeholder endings (e.g., trailing [.] or ...)
  // eslint-disable-next-line no-useless-escape
  output = output.replace(/(\[\.\]|\.{2,}|…)+$/g, '');

  // Extract valid URL if present and sanitize
  const urlMatch = output.match(/https?:\/\/[^\s'"<>]+/i);
  if (urlMatch) {
    try {
      let extractedUrl = urlMatch[0];
      // Clean trailing punctuation early
      extractedUrl = extractedUrl.replace(/[.,;!?…]+$/, '');

      const parsed = new URL(extractedUrl);
      if (!parsed.protocol || !parsed.hostname) return null;

      // Decode and normalize
      let decodedPath = decodeURIComponent(parsed.pathname || '');
      let decodedQuery = decodeURIComponent(parsed.search ? parsed.search.slice(1) : '');

      // Remove dangerous or non-printable chars from path/query
      decodedPath = decodedPath.replace(/[^\x20-\x7E/]/g, '');
      decodedQuery = decodedQuery.replace(/[^\x20-\x7E\-=&]/g, '');

      // Encode path/query safely
      const safePath = encodeURI(decodedPath);
      const safeQuery = encodeURIComponent(decodedQuery).replace(/%3D/g, '=').replace(/%26/g, '&');

      // Rebuild URL
      const rebuilturl = `${
        parsed.protocol
      }//${
        parsed.hostname
      }${
        parsed.port ? `:${parsed.port}` : ''
      }${
        parsed.username || parsed.password ? `@${parsed.username || ''}${parsed.password ? `:${parsed.password}` : ''}` : ''
      }${
        safePath.startsWith('/') ? '' : '/'
      }${
        safePath.endsWith('/') ? safePath.slice(0, -1) : safePath
      }${
        safeQuery && safeQuery.length > 0 ? `?${safeQuery}` : ''
      }`;

      // Replace original URL in output with rebuilt URL
      output = output.replace(urlMatch[0], rebuilturl);
    } catch (e) {
      // On URL parse error, return the original input (not null)
      return input.trim();
    }
  }

  return output;
}
