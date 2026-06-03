import { IngestionAuthType } from '../../generated/graphql';
import { FunctionalError } from '../../config/errors';
import { decryptValue, encryptValue, getPlatformCrypto } from '../../utils/platformCrypto';
import { memoize } from '../../utils/memoize';
import { ingestionUriDenyList } from '../../manager/ingestionManager/ingestionManagerConfiguration';

/**
 * Extracts the host (with optional port) from a URI string.
 * Handles URIs with or without a protocol scheme.
 */
const extractHostFromUri = (uri: string): string => {
  try {
    // If no protocol, prepend one to allow URL parsing
    const normalizedUri = uri.includes('://') ? uri : `http://${uri}`;
    const parsed = new URL(normalizedUri);
    // Return host which includes port if specified (e.g. "localhost:4200")
    return parsed.host.toLowerCase();
  } catch {
    // If URL parsing fails, return the uri as-is for matching
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

  if (normalizedPattern.startsWith('*.')) {
    // Wildcard: *.mydomain.com should match sub.mydomain.com and deep.sub.mydomain.com
    const domainSuffix = normalizedPattern.slice(2); // Remove '*.'
    return normalizedHost === domainSuffix || normalizedHost.endsWith(`.${domainSuffix}`);
  }

  // Exact match (including port if specified in pattern)
  return normalizedHost === normalizedPattern;
};

/**
 * Verifies that the given URI is not in the ingestion URI deny list.
 * Throws a FunctionalError if the URI matches a denied pattern.
 */
export const verifyIngestionUri = (uri: string): void => {
  const denyList = ingestionUriDenyList();
  if (denyList.length === 0) return;

  const host = extractHostFromUri(uri);
  for (const pattern of denyList) {
    if (matchesDenyPattern(host, pattern)) {
      throw FunctionalError('This URI is not allowed for ingestion.', { field: 'uri', uri, denied_pattern: pattern });
    }
  }
};

export const getIngestionKeyPair = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveAesKey(['ingestion', 'credentials'], 1);
});

export const encryptIngestionCredential = async (value: string | undefined | null) => {
  return encryptValue(await getIngestionKeyPair(), value);
};

export const decryptIngestionCredential = async (value: string | undefined | null) => {
  return decryptValue(await getIngestionKeyPair(), value);
};

export const isIngestionCredentialEncrypted = async (value: string): Promise<boolean> => {
  try {
    const keyPair = await getIngestionKeyPair();
    await keyPair.decrypt(Buffer.from(value, 'base64'));
    return true;
  } catch {
    return false;
  }
};

export const verifyIngestionAuthenticationContent = (authenticationType: string, authenticationValue: string) => {
  if (authenticationType && authenticationValue) {
    if (authenticationType === IngestionAuthType.Basic && authenticationValue.split(':').length !== 2) {
      throw FunctionalError('Username and password cannot have : character.', { authenticationType });
    }

    if (authenticationType === IngestionAuthType.Certificate && authenticationValue.split(':').length !== 3) {
      throw FunctionalError('Certificate, CA and Key cannot have : character.', { authenticationType });
    }
  }
};

export const removeAuthenticationCredentials = (authentication_type: IngestionAuthType | undefined | null, authentication_value: string | undefined | null) => {
  if (!authentication_value || !authentication_type) {
    return authentication_value;
  }
  if (authentication_type === IngestionAuthType.Bearer) {
    return 'undefined';
  }
  const authenticationValueSplit = authentication_value.split(':');
  if (authentication_type === IngestionAuthType.Basic) {
    return [authenticationValueSplit[0], 'undefined'].join(':');
  }
  if (authentication_type === IngestionAuthType.Certificate) {
    return [authenticationValueSplit[0], 'undefined', authenticationValueSplit[2]].join(':');
  }
  return authentication_value;
};

export const addAuthenticationCredentials = (currentValue: string | undefined | null, newValue: string | undefined | null, authType: IngestionAuthType) => {
  if (!newValue) {
    return currentValue;
  }
  if (!currentValue) {
    return newValue;
  }
  if (authType === IngestionAuthType.Bearer) {
    // For bearer, the entire value is just the token
    return newValue !== 'undefined' ? newValue : currentValue;
  }

  const currentParts = currentValue.split(':');
  const newParts = newValue.split(':');

  if (authType === IngestionAuthType.Basic) {
    // Basic auth format: username:password
    return [
      newParts[0],
      newParts[1] && newParts[1] !== 'undefined' ? newParts[1] : currentParts[1],
    ].join(':');
  }

  if (authType === IngestionAuthType.Certificate) {
    // Certificate format: cert:key:ca
    return [
      newParts[0],
      newParts[1] && newParts[1] !== 'undefined' ? newParts[1] : currentParts[1],
      newParts[2],
    ].join(':');
  }

  return currentValue;
};
