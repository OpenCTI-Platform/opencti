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
    // [:/] should map to /
    // eslint-disable-next-line no-useless-escape
    .replace(/\[:\/\]/g, '/')
    // // Remove literal ellipsis character
    // .replace(/\u2026/g, '')
    // Remove common placeholder endings (e.g., trailing [.] or ...)
    // eslint-disable-next-line no-useless-escape
    .replace(/(\[\.\]|\.{2,}|…)+$/g, '');

  // Extract valid URL if present and sanitize
  const urlRegex = /https?:\/\/[^\s'"<>[\](){},;!?…]+/gi;
  const urlMatchesArr = output.match(urlRegex);

  if (urlMatchesArr && urlMatchesArr.length > 0) {
    urlMatchesArr.forEach((matchedUrl) => {
      try {
        let extractedUrl = matchedUrl;
        // Clean trailing punctuation early
        extractedUrl = extractedUrl.replace(/[.,;!?…]+$/, '');

        const parsed = new URL(extractedUrl);
        if (!parsed.protocol || !parsed.hostname) return;

        // Decode and normalize
        let decodedPath = decodeURIComponent(parsed.pathname || '');
        let decodedQuery = decodeURIComponent(parsed.search ? parsed.search.slice(1) : '');

        // Remove dangerous or non-printable chars from path/query
        // eslint-disable-next-line no-control-regex
        decodedPath = decodedPath.replace(/[\u0000-\u001F\u007F]/g, '');
        decodedQuery = decodedQuery.replace(/[^\x20-\x7E\-=&]/g, '');

        // Encode path/query safely
        const safePath = encodeURI(decodedPath);
        const safeQuery = encodeURIComponent(decodedQuery).replace(/%3D/g, '=').replace(/%26/g, '&');

        // Rebuild URL
        const rebuilturl = `${
          parsed.protocol
        }//${
          parsed.username ? `${parsed.username}${parsed.password ? `:${parsed.password}` : ''}@` : ''
        }${
          parsed.hostname
        }${
          parsed.port ? `:${parsed.port}` : ''
        }${
          safePath.startsWith('/') ? '' : '/'
        }${
          safePath.endsWith('/') ? safePath.slice(0, -1) : safePath
        }${
          safeQuery && safeQuery.length > 0 ? `?${safeQuery}` : ''
        }`;

        // Replace original URL in output with rebuilt URL
        output = output.replace(matchedUrl, rebuilturl);
      } catch (_e) {
        // Skip malformed match, continue processing the rest
        // Do NOT reset output or lose prior replacements
      }
    });
  }

  return output;
}
