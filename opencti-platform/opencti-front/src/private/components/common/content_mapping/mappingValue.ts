// Turns a text selection into what can be created from it: the refanged value, and the object types
// whose shape the value fits (US.2 / US.3 of content mapping v2). Patterns are aligned with the
// backend detection (opencti-graphql/src/utils/observable.ts), but several candidates are kept,
// since a value such as "some-example.zip" is both a file name and a domain name.

export type HashAlgorithm = 'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512';

// Bracket and protocol defanging only: the words "dot" / "at" are too common in entity names.
const DEFANG_PATTERNS: [RegExp, string][] = [
  [/\bh[xX]{2}p(s?)\[?:\]?\/\//g, 'http$1://'],
  [/\[:\/\/\]/g, '://'],
  [/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.'],
  [/\[@\]|\(@\)|\{@\}|\[at\]|\(at\)/gi, '@'],
  [/\[:\]|\(:\)/g, ':'],
  [/\[\/\]|\(\/\)/g, '/'],
];

export const isDefanged = (value: string) => DEFANG_PATTERNS.some(([pattern]) => {
  pattern.lastIndex = 0;
  return pattern.test(value);
});

export const refangValue = (value: string) => DEFANG_PATTERNS
  .reduce((refanged, [pattern, replacement]) => refanged.replace(pattern, replacement), value)
  .trim();

const HASH_LENGTHS: Record<number, HashAlgorithm> = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' };

export const hashAlgorithmOf = (value: string): HashAlgorithm | null => (
  /^[a-fA-F0-9]+$/.test(value) ? HASH_LENGTHS[value.length] ?? null : null
);

export interface TypeCandidate {
  type: string;
  // Whether the value has the shape of this type; others are shown greyed with `reason`.
  compatible: boolean;
  reason?: string;
}

interface Shape {
  type: string;
  test: (value: string) => boolean;
  expected: string;
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\/\d{1,2})?$/;
const IPV6 = /^(?=.*:)[0-9a-fA-F:]{2,39}(?:\/\d{1,3})?$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;
const URL = /^(?:https?|ftp):\/\/\S+$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// The extension has a letter: "203.0.113.7" is not a file name.
const FILE_NAME = /^[^\s/\\:*?"<>|]+\.(?=[a-z0-9]{1,8}$)[a-z0-9]*[a-z][a-z0-9]*$/i;
const MAC = /^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;
const AUTONOMOUS_SYSTEM = /^AS\d{1,10}$/i;
const CVE = /^CVE-\d{4}-\d{4,}$/i;
const MITRE_TECHNIQUE = /^T\d{4}(?:\.\d{3})?$/;

const OBSERVABLE_SHAPES: Shape[] = [
  { type: 'IPv4-Addr', test: (v) => IPV4.test(v), expected: 'an IPv4 address' },
  { type: 'IPv6-Addr', test: (v) => IPV6.test(v) && !MAC.test(v), expected: 'an IPv6 address' },
  { type: 'Domain-Name', test: (v) => DOMAIN.test(v) && !IPV4.test(v), expected: 'a domain name' },
  { type: 'Url', test: (v) => URL.test(v), expected: 'a URL starting with a protocol' },
  { type: 'Email-Addr', test: (v) => EMAIL.test(v), expected: 'an email address' },
  { type: 'StixFile', test: (v) => !!hashAlgorithmOf(v) || FILE_NAME.test(v), expected: 'a file name or a hash' },
  { type: 'Mac-Addr', test: (v) => MAC.test(v), expected: 'a MAC address' },
  { type: 'Autonomous-System', test: (v) => AUTONOMOUS_SYSTEM.test(v), expected: 'an AS number (AS1234)' },
];

const DOMAIN_OBJECT_SHAPES: Shape[] = [
  { type: 'Vulnerability', test: (v) => CVE.test(v), expected: 'a CVE identifier' },
  { type: 'Attack-Pattern', test: (v) => MITRE_TECHNIQUE.test(v), expected: 'a MITRE technique id (T1059)' },
];

// Named objects any text can be the name of; offered after the ones the shape points to.
const NAMED_TYPES = ['Malware', 'Intrusion-Set', 'Threat-Actor-Group', 'Tool', 'Campaign', 'Organization'];

// Observable-looking values are not offered as names: "203.0.113.7" is not a malware.
const looksLikeObservable = (value: string) => OBSERVABLE_SHAPES.some((shape) => shape.test(value));

export const typeCandidates = (rawValue: string): TypeCandidate[] => {
  const value = refangValue(rawValue);
  const shapes = [...DOMAIN_OBJECT_SHAPES, ...OBSERVABLE_SHAPES].map(({ type, test, expected }) => (
    test(value) ? { type, compatible: true } : { type, compatible: false, reason: `Not ${expected}` }
  ));
  const named = NAMED_TYPES.map((type) => (
    looksLikeObservable(value) || /\s{2,}|[\r\n]/.test(value)
      ? { type, compatible: false, reason: 'Looks like an observable' }
      : { type, compatible: true }
  ));
  const candidates = [...shapes, ...named];
  return [...candidates.filter((c) => c.compatible), ...candidates.filter((c) => !c.compatible)];
};

// The creation input of a candidate type, with the value in the field it belongs to (US.3).
export const creationInputFor = (type: string, rawValue: string): Record<string, unknown> => {
  const value = refangValue(rawValue);
  if (type === 'StixFile') {
    const algorithm = hashAlgorithmOf(value);
    return algorithm ? { hashes: [{ algorithm, hash: value.toLowerCase() }] } : { name: value };
  }
  if (type === 'Autonomous-System') return { number: Number(value.replace(/^AS/i, '')) };
  if (OBSERVABLE_SHAPES.some((shape) => shape.type === type)) return { value };
  return { name: value };
};
