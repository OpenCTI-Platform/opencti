import { describe, expect, it } from 'vitest';
import {
  collapseStixPatternWhitespace,
  computeCanonicalValues,
  computeIndicatorCanonicalValue,
  computeStableKey,
  computeStableKeys,
  computeTransportHash,
  decodeTransportHash,
  normalizeThreatName,
} from '../../../../../src/modules/xtm/pulse/pulse-hashing';
import { PULSE_MAX_KEYS_PER_OBJECT } from '../../../../../src/modules/xtm/pulse/pulse-types';

const SALT_DAY_1 = '000102030405060708090a0b0c0d0e0f';
const SALT_DAY_2 = 'f0e0d0c0b0a090807060504030201000';

// Shared with XTM Hub (contract test vectors): both sides must derive exactly these values.
const CONTRACT_VECTORS = [
  { objectType: 'indicator', canonical: 'observable:ipv4-addr:value:198.51.100.7', stable: 'aa134d3de491d5f3730d7fbbf9721582', day1: '9913881f71e8c61c79d05b20cf144d42', day2: '473d3d6874e64808b27015023eb31ab0' },
  { objectType: 'attack_pattern', canonical: 'T1059.001', stable: '35b0088f1df3589a4d813145fed71859', day1: '541df1cb0fe4d5b0a879c3ead7dcde0f', day2: '62056e1fe59c9b896896e1bc3e426175' },
  { objectType: 'vulnerability', canonical: 'CVE-2024-3400', stable: '87655e1708ad94e5fa57eb00f06d0f82', day1: '002b59d753f94f8d6a7fc1a63689c794', day2: '137a0f53839b5e88968d277683333d7a' },
  { objectType: 'malware', canonical: 'lockbit', stable: '556ee18dbe0c4cf9e89515b7bd0755e5', day1: '8e3360dcb471a38402e9e4d356d0654a', day2: 'f5f48415bbd0546791c774dc0f287052' },
] as const;

describe('Threat Pulse hashing', () => {
  it.each(CONTRACT_VECTORS)('should derive the contract vectors for $objectType', ({ objectType, canonical, stable, day1, day2 }) => {
    expect(computeStableKey(objectType, canonical)).toBe(stable);
    expect(computeTransportHash(SALT_DAY_1, stable)).toBe(day1);
    expect(computeTransportHash(SALT_DAY_2, stable)).toBe(day2);
    expect(decodeTransportHash(SALT_DAY_1, day1)).toBe(stable);
    expect(decodeTransportHash(SALT_DAY_2, day2)).toBe(stable);
  });

  it('should rotate the transport hash with the daily salt', () => {
    const stable = computeStableKey('indicator', 'observable:domain-name:value:example.com');
    expect(computeTransportHash(SALT_DAY_1, stable)).not.toBe(computeTransportHash(SALT_DAY_2, stable));
  });

  it('should refuse malformed salts, keys and hashes', () => {
    expect(() => computeTransportHash('abc', CONTRACT_VECTORS[0].stable)).toThrow();
    expect(() => computeTransportHash(SALT_DAY_1, 'not-a-key')).toThrow();
    expect(() => decodeTransportHash(SALT_DAY_1, 'ABCDEF')).toThrow();
  });

  it('should canonicalize single observable STIX indicators', () => {
    expect(computeIndicatorCanonicalValue("[ipv4-addr:value = '198.51.100.7']", 'stix')).toBe('observable:ipv4-addr:value:198.51.100.7');
    expect(computeIndicatorCanonicalValue("[domain-name:value = 'Evil.Example.COM']", 'stix')).toBe('observable:domain-name:value:evil.example.com');
    expect(computeIndicatorCanonicalValue("[file:hashes.'SHA-256' = 'ABCDEF0123']", 'stix')).toBe('observable:file:hashes.sha-256:abcdef0123');
    expect(computeIndicatorCanonicalValue("[url:value = 'HTTPS://Example.COM/Path?q=A']", 'stix')).toBe('observable:url:value:https://example.com/Path?q=A');
  });

  it('should keep the user information of a URL in its canonical form', () => {
    expect(computeIndicatorCanonicalValue("[url:value = 'HTTPS://Alice@Example.COM/a']", 'stix')).toBe('observable:url:value:https://Alice@example.com/a');
    expect(computeIndicatorCanonicalValue("[url:value = 'https://bob:Secret@example.com/a']", 'stix')).toBe('observable:url:value:https://bob:Secret@example.com/a');
    expect(computeIndicatorCanonicalValue("[url:value = 'https://alice@example.com/a']", 'stix'))
      .not.toBe(computeIndicatorCanonicalValue("[url:value = 'https://bob@example.com/a']", 'stix'));
  });

  it('should give the same key to the same observable written differently', () => {
    const first = computeStableKeys({ entity_type: 'Indicator', pattern: "[domain-name:value = 'evil.example.com']", pattern_type: 'stix' });
    const second = computeStableKeys({ entity_type: 'Indicator', pattern: "[domain-name:value='EVIL.example.com']", pattern_type: 'STIX' });
    expect(first).toEqual(second);
    expect(first).toHaveLength(1);
  });

  it('should give one key to every spelling of an IPv6 address or network', () => {
    const keysOf = (value: string) => computeStableKeys({ entity_type: 'Indicator', pattern: `[ipv6-addr:value = '${value}']`, pattern_type: 'stix' });
    expect(computeIndicatorCanonicalValue("[ipv6-addr:value = '2001:0DB8:0:0:0:0:0:1']", 'stix')).toBe('observable:ipv6-addr:value:2001:db8::1');
    expect(keysOf('2001:0db8:0:0:0:0:0:1')).toEqual(keysOf('2001:db8::1'));
    expect(keysOf('2001:DB8:0000::1')).toEqual(keysOf('2001:db8::1'));
    expect(keysOf('2001:db8:0:0::/032')).toEqual(keysOf('2001:db8::/32'));
    expect(keysOf('2001:db8::1')).not.toEqual(keysOf('2001:db8::2'));
    // An address with a zone index has no compressed form: kept as written, lower-cased
    expect(computeIndicatorCanonicalValue("[ipv6-addr:value = 'FE80::1%ETH0']", 'stix')).toBe('observable:ipv6-addr:value:fe80::1%eth0');
  });

  it('should canonicalize complex and non STIX patterns on the normalized pattern', () => {
    const complex = computeIndicatorCanonicalValue("[ipv4-addr:value = '198.51.100.7'] OR [ipv4-addr:value = '198.51.100.8']", 'stix');
    expect(complex?.startsWith('pattern:stix:')).toBe(true);
    // Other languages are kept as written but for line endings and outer whitespace: a space can be part of a string
    expect(computeIndicatorCanonicalValue('  rule test {\r\n strings: $a = "a  b" condition: $a }\n', 'yara'))
      .toBe('pattern:yara:rule test {\n strings: $a = "a  b" condition: $a }');
    const yaraKeys = (literal: string) => computeStableKeys({ entity_type: 'Indicator', pattern: `rule t { strings: $a = "${literal}" condition: $a }`, pattern_type: 'yara' });
    expect(yaraKeys('a b')).not.toEqual(yaraKeys('a  b'));
    expect(computeIndicatorCanonicalValue(undefined, 'stix')).toBeUndefined();
  });

  it('should collapse the whitespace of a STIX pattern outside its literals only', () => {
    expect(collapseStixPatternWhitespace("[file:name = 'a  b']   OR\n [file:name = 'it\\'s  x']"))
      .toBe("[file:name = 'a  b'] OR [file:name = 'it\\'s  x']");
  });

  it('should canonicalize attack patterns, vulnerabilities and threats', () => {
    expect(computeCanonicalValues({ entity_type: 'Attack-Pattern', x_mitre_id: ' t1059.001 ', name: 'PowerShell' })).toEqual(['T1059.001']);
    expect(computeCanonicalValues({ entity_type: 'Attack-Pattern', x_mitre_id: 'aml.t0051.000', name: 'LLM Prompt Injection' })).toEqual(['AML.T0051.000']);
    expect(computeCanonicalValues({ entity_type: 'Vulnerability', name: ' cve-2024-3400 ' })).toEqual(['CVE-2024-3400']);
    // Only a MITRE ID and a CVE identifier leave the platform: a custom name or identifier has no key.
    expect(computeCanonicalValues({ entity_type: 'Attack-Pattern', name: 'Custom Technique' })).toEqual([]);
    expect(computeCanonicalValues({ entity_type: 'Attack-Pattern', x_mitre_id: 'INTERNAL-42', name: 'Custom Technique' })).toEqual([]);
    expect(computeCanonicalValues({ entity_type: 'Vulnerability', name: 'Log4Shell' })).toEqual([]);
    expect(computeCanonicalValues({ entity_type: 'Vulnerability', name: 'CVE-2024-3400 (PAN-OS)' })).toEqual([]);
    expect(computeStableKeys({ entity_type: 'Attack-Pattern', name: 'Custom Technique' })).toEqual([]);
    expect(computeStableKeys({ entity_type: 'Vulnerability', name: 'Log4Shell' })).toEqual([]);
    expect(computeCanonicalValues({ entity_type: 'Intrusion-Set', name: 'APT 28', aliases: ['Fancy Bear', 'APT-28', 'apt28'] }))
      .toEqual(['apt28', 'fancybear']);
    expect(normalizeThreatName('Lock_Bit 3.0')).toBe('lockbit30');
  });

  it('should cap the number of keys of a threat', () => {
    const aliases = Array.from({ length: 30 }, (_, index) => `alias ${index}`);
    expect(computeCanonicalValues({ entity_type: 'Malware', name: 'Emotet', aliases })).toHaveLength(PULSE_MAX_KEYS_PER_OBJECT);
  });

  it('should not derive keys for out of scope types', () => {
    expect(computeStableKeys({ entity_type: 'Report', name: 'Monthly report' })).toEqual([]);
  });
});
