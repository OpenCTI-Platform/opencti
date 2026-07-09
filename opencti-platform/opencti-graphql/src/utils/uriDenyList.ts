import { FunctionalError } from '../config/errors';
import { uriDenyList } from '../config/uriDenyList';

/**
 * Extracts the host (with optional port) from a URI string.
 * Handles URIs with or without a protocol scheme.
 */
const extractHostFromUri = (uri: string): string => {
  try {
    const normalizedUri = uri.includes('://') ? uri : `http://${uri}`;
    const parsed = new URL(normalizedUri);
    return parsed.host.toLowerCase();
  } catch {
    return uri.toLowerCase();
  }
};

/**
 * Checks if a given host matches a deny list pattern.
 * Supports:
 * - Exact match: 'mydomain.com' matches 'mydomain.com'
 * - Wildcard match: '*.mydomain.com' matches 'sub.mydomain.com'
 * - Host with port: 'localhost:4200' matches 'http://localhost:4200/path'
 */
const matchesDenyPattern = (host: string, pattern: string): boolean => {
  const normalizedPattern = pattern.toLowerCase().trim();
  const normalizedHost = host.toLowerCase();

  const patternHasPort = normalizedPattern.includes(':');
  const hostWithoutPort = normalizedHost.includes(':') && !patternHasPort
    ? normalizedHost.slice(0, normalizedHost.lastIndexOf(':'))
    : normalizedHost;

  if (normalizedPattern.startsWith('*.')) {
    const domainSuffix = normalizedPattern.slice(2);
    return hostWithoutPort === domainSuffix || hostWithoutPort.endsWith(`.${domainSuffix}`);
  }

  return hostWithoutPort === normalizedPattern;
};

/**
 * Verifies that the given URI is not in the application URI deny list.
 * Throws a FunctionalError if the URI matches a denied pattern.
 */
export const verifyUri = (uri: string): void => {
  const denyList = uriDenyList();
  if (denyList.length === 0) return;

  const host = extractHostFromUri(uri);
  for (const pattern of denyList) {
    if (matchesDenyPattern(host, pattern)) {
      throw FunctionalError('This URI is not allowed.', { field: 'uri', uri, denied_pattern: pattern });
    }
  }
};
