import crypto from 'node:crypto';
import { isIPv6 } from 'node:net';
import * as R from 'ramda';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL } from '../../../schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../../indicator/indicator-types';
import { ENTITY_TYPE_VULNERABILITY } from '../../vulnerability/vulnerability-types';
import { cleanupIndicatorPattern, extractObservablesFromIndicatorPattern, STIX_PATTERN_TYPE } from '../../../utils/syntax';
import { PULSE_MAX_KEYS_PER_OBJECT, PULSE_OBJECT_TYPE_BY_ENTITY_TYPE, type PulseObjectType } from './pulse-types';

// Every OpenCTI platform must derive the same stable key for the same value, otherwise the network cannot match it:
// the domain, the separator and the canonical forms below are part of the Threat Pulse contract (version 1).
const STABLE_KEY_DOMAIN = 'opencti-pulse-v1';
const KEY_BYTES = 16;
const HEX_KEY_REGEX = /^[0-9a-f]{32}$/;

// Observable types whose value is case-insensitive.
const CASE_INSENSITIVE_OBSERVABLE_TYPES = ['domain-name', 'hostname', 'email-addr', 'mac-addr', 'windows-registry-key'];
// The outbound contract keys an attack pattern by its MITRE ID (an ATT&CK or ATLAS technique) and a vulnerability by
// its CVE identifier, nothing else: a custom name or identifier never leaves the platform, the object has no key.
const MITRE_TECHNIQUE_ID_REGEX = /^(?:AML\.)?T\d{4}(?:\.\d{3})?$/;
const CVE_IDENTIFIER_REGEX = /^CVE-\d{4}-\d{4,}$/;

// The compressed lower-case form of an IPv6 address or network (2001:0DB8:0:0::1/64 -> 2001:db8::1/64), so that
// every spelling of one address yields one key. A value that is not an IPv6 address is only lower-cased.
const canonicalIpv6 = (value: string): string => {
  const [address, prefix, ...rest] = value.split('/');
  if (rest.length > 0 || !isIPv6(address) || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) {
    return value.toLowerCase();
  }
  try {
    const canonical = new URL(`http://[${address}]`).hostname.slice(1, -1);
    return prefix === undefined ? canonical : `${canonical}/${Number(prefix)}`;
  } catch {
    // A zone index (fe80::1%eth0) has no URL form.
    return value.toLowerCase();
  }
};

export interface PulseHashableEntity {
  entity_type: string;
  name?: string;
  aliases?: string[];
  x_mitre_id?: string;
  pattern?: string;
  pattern_type?: string;
}

const collapseWhitespace = (value: string) => value.replace(/\s+/g, ' ').trim();

// STIX patterns: whitespace is insignificant outside the single-quoted literals and kept as written inside them, so
// that two values differing by a space never share a key.
export const collapseStixPatternWhitespace = (pattern: string) => {
  let result = '';
  let quoted = false;
  let space = false;
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (quoted) {
      result += char;
      if (char === '\\' && index + 1 < pattern.length) {
        index += 1;
        result += pattern[index];
      } else if (char === '\'') {
        quoted = false;
      }
    } else if (/\s/.test(char)) {
      space = true;
    } else {
      if (space && result.length > 0) {
        result += ' ';
      }
      space = false;
      result += char;
      quoted = char === '\'';
    }
  }
  return result;
};

// Other pattern languages (YARA, Sigma, Snort...): whitespace can be part of a string or a regular expression, so the
// text is kept as written but for its line endings and its outer whitespace.
const normalizePatternText = (pattern: string) => pattern.replace(/\r\n?/g, '\n').trim();

export const normalizeThreatName = (name: string): string => {
  return name.normalize('NFKC').toLowerCase().replace(/[\s\-_.]+/g, '');
};

const flattenObservable = (observable: Record<string, any>, prefix = ''): Array<[string, string]> => {
  return Object.entries(observable).flatMap(([key, value]) => {
    if (!prefix && key === 'type') {
      return [];
    }
    const path = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === 'object') {
      return flattenObservable(value, path);
    }
    return [[path, String(value)] as [string, string]];
  });
};

const toStixObservableType = (formattedType: string) => (formattedType === 'StixFile' ? 'file' : formattedType.toLowerCase());

const normalizeObservableValue = (stixType: string, path: string, value: string): string => {
  const trimmed = value.trim();
  if (stixType === 'ipv6-addr') {
    return canonicalIpv6(trimmed);
  }
  if (CASE_INSENSITIVE_OBSERVABLE_TYPES.includes(stixType) || path.startsWith('hashes.')) {
    return trimmed.toLowerCase();
  }
  if (stixType === 'url') {
    try {
      const url = new URL(trimmed);
      const credentials = url.password ? `${url.username}:${url.password}` : url.username;
      const userinfo = credentials ? `${credentials}@` : '';
      return `${url.protocol}//${userinfo}${url.host.toLowerCase()}${url.pathname}${url.search}${url.hash}`;
    } catch {
      return trimmed;
    }
  }
  return trimmed;
};

export const computeIndicatorCanonicalValue = (pattern: string | undefined, patternType: string | undefined): string | undefined => {
  if (!pattern || !patternType) {
    return undefined;
  }
  const type = patternType.toLowerCase();
  if (type !== STIX_PATTERN_TYPE) {
    return `pattern:${type}:${normalizePatternText(pattern)}`;
  }
  try {
    const observables = extractObservablesFromIndicatorPattern(pattern);
    if (observables.length === 1) {
      const [observable] = observables;
      const entries = flattenObservable(observable);
      if (entries.length === 1) {
        const stixType = toStixObservableType(observable.type);
        const [path, value] = entries[0];
        const normalizedPath = path.toLowerCase();
        return `observable:${stixType}:${normalizedPath}:${normalizeObservableValue(stixType, normalizedPath, value)}`;
      }
    }
    return `pattern:${type}:${collapseStixPatternWhitespace(cleanupIndicatorPattern(patternType, pattern))}`;
  } catch {
    return `pattern:${type}:${collapseStixPatternWhitespace(pattern)}`;
  }
};

export const computeCanonicalValues = (entity: PulseHashableEntity): string[] => {
  switch (entity.entity_type) {
    case ENTITY_TYPE_INDICATOR: {
      const value = computeIndicatorCanonicalValue(entity.pattern, entity.pattern_type);
      return value ? [value] : [];
    }
    case ENTITY_TYPE_ATTACK_PATTERN: {
      const mitreId = (entity.x_mitre_id ?? '').trim().toUpperCase();
      return MITRE_TECHNIQUE_ID_REGEX.test(mitreId) ? [mitreId] : [];
    }
    case ENTITY_TYPE_VULNERABILITY: {
      const name = collapseWhitespace(entity.name ?? '').toUpperCase();
      return CVE_IDENTIFIER_REGEX.test(name) ? [name] : [];
    }
    case ENTITY_TYPE_INTRUSION_SET:
    case ENTITY_TYPE_MALWARE:
    case ENTITY_TYPE_TOOL: {
      const names = [entity.name ?? '', ...(entity.aliases ?? [])].map(normalizeThreatName).filter((name) => name.length > 0);
      return R.uniq(names).slice(0, PULSE_MAX_KEYS_PER_OBJECT);
    }
    default:
      return [];
  }
};

export const computeStableKey = (objectType: PulseObjectType, canonicalValue: string): string => {
  return crypto.createHmac('sha256', STABLE_KEY_DOMAIN)
    .update(`${objectType}\n${canonicalValue}`)
    .digest()
    .subarray(0, KEY_BYTES)
    .toString('hex');
};

export const computeStableKeys = (entity: PulseHashableEntity): string[] => {
  const objectType = PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[entity.entity_type];
  if (!objectType) {
    return [];
  }
  return computeCanonicalValues(entity).map((value) => computeStableKey(objectType, value));
};

const assertHexKey = (value: string, label: string) => {
  if (!HEX_KEY_REGEX.test(value)) {
    throw new Error(`Invalid Threat Pulse ${label}: expected 32 lowercase hexadecimal characters`);
  }
};

// AES-128 on a single block is a keyed permutation: the output rotates with the daily salt, and only a holder of the
// salt can map it back to the stable key (XTM Hub does it to aggregate a value across days).
const aesBlock = (saltHex: string, inputHex: string, decrypt: boolean): string => {
  assertHexKey(saltHex, 'salt');
  assertHexKey(inputHex, decrypt ? 'hash' : 'key');
  const key = Buffer.from(saltHex, 'hex');
  const cipher = decrypt ? crypto.createDecipheriv('aes-128-ecb', key, null) : crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(Buffer.from(inputHex, 'hex')), cipher.final()]).toString('hex');
};

export const computeTransportHash = (saltHex: string, stableKeyHex: string): string => aesBlock(saltHex, stableKeyHex, false);

export const decodeTransportHash = (saltHex: string, hashHex: string): string => aesBlock(saltHex, hashHex, true);

export const isValidPulseHash = (value: string): boolean => HEX_KEY_REGEX.test(value);
