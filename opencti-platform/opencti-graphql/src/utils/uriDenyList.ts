import { FunctionalError } from '../config/errors';
import { uriDenyList } from '../config/uriDenyList';

/**
 * Extracts hostname/host/port from a URI-like string.
 * Handles URIs with or without a protocol scheme.
 */
type UriHostParts = {
  hostname: string;
  host: string;
  port: string;
};

const extractHostParts = (uri: string): UriHostParts => {
  try {
    const normalizedUri = uri.includes('://') ? uri : `http://${uri}`;
    const parsed = new URL(normalizedUri);
    return {
      hostname: parsed.hostname.toLowerCase(),
      host: parsed.host.toLowerCase(),
      port: parsed.port,
    };
  } catch {
    const normalizedUri = uri.toLowerCase();
    return {
      hostname: normalizedUri,
      host: normalizedUri,
      port: '',
    };
  }
};

/**
 * Checks if a given host matches a deny list pattern.
 * Supports:
 * - Exact match: 'mydomain.com' matches 'mydomain.com'
 * - Wildcard match: '*.mydomain.com' matches both 'sub.mydomain.com' and 'mydomain.com'
 * - Host with port: 'localhost:4200' matches 'http://localhost:4200/path'
 */
const matchesDenyPattern = (hostParts: UriHostParts, pattern: string): boolean => {
  const normalizedPattern = pattern.toLowerCase().trim();
  const normalizedPatternParts = extractHostParts(normalizedPattern);

  if (normalizedPattern.startsWith('*.')) {
    const domainSuffix = extractHostParts(normalizedPattern.slice(2)).hostname;
    return hostParts.hostname === domainSuffix || hostParts.hostname.endsWith(`.${domainSuffix}`);
  }

  if (normalizedPatternParts.port.length > 0) {
    return hostParts.host === normalizedPatternParts.host;
  }
  return hostParts.hostname === normalizedPatternParts.hostname;
};

/**
 * Verifies that the given URI is not in the application URI deny list.
 * Throws a FunctionalError if the URI matches a denied pattern.
 */
export const verifyUriWithDenyList = (uri: string, denyList: string[], errorMessage = 'This URI is not allowed.'): void => {
  if (denyList.length === 0) return;

  const hostParts = extractHostParts(uri);
  for (const pattern of denyList) {
    if (matchesDenyPattern(hostParts, pattern)) {
      throw FunctionalError(errorMessage, { field: 'uri', uri, denied_pattern: pattern });
    }
  }
};

export const verifyUri = (uri: string): void => {
  verifyUriWithDenyList(uri, uriDenyList());
};
