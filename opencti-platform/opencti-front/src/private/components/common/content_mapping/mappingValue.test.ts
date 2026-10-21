import { describe, expect, it } from 'vitest';
import { creationInputFor, hashAlgorithmOf, isDefanged, refangValue, typeCandidates } from './mappingValue';

const compatibleTypes = (value: string) => typeCandidates(value).filter((c) => c.compatible).map((c) => c.type);

describe('refangValue', () => {
  it.each([
    ['update-check[.]net', 'update-check.net'],
    ['hxxp://evil[.]com/path', 'http://evil.com/path'],
    ['hXXps[:]//bad(.)site/x', 'https://bad.site/x'],
    ['john[at]example[dot]org', 'john@example.org'],
    ['203[.]0[.]113[.]7', '203.0.113.7'],
  ])('should refang %s', (input, expected) => {
    expect(isDefanged(input)).toBe(true);
    expect(refangValue(input)).toBe(expected);
  });

  it('should leave clean values and entity names unchanged', () => {
    expect(isDefanged('APT41 at large')).toBe(false);
    expect(refangValue('APT41 at large')).toBe('APT41 at large');
    expect(refangValue('evil.com')).toBe('evil.com');
  });
});

describe('hashAlgorithmOf', () => {
  it('should find the algorithm from the hash length', () => {
    expect(hashAlgorithmOf('d41d8cd98f00b204e9800998ecf8427e')).toBe('MD5');
    expect(hashAlgorithmOf('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe('SHA-1');
    expect(hashAlgorithmOf('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe('SHA-256');
    expect(hashAlgorithmOf('a'.repeat(128))).toBe('SHA-512');
    expect(hashAlgorithmOf('not-a-hash')).toBeNull();
    expect(hashAlgorithmOf('abc')).toBeNull();
  });
});

describe('typeCandidates', () => {
  it('should offer both a file and a domain name for an ambiguous value', () => {
    expect(compatibleTypes('some-example.zip')).toEqual(expect.arrayContaining(['StixFile', 'Domain-Name']));
  });

  it('should only offer network types for an IP, and explain the others', () => {
    const candidates = typeCandidates('203.0.113.7');
    expect(compatibleTypes('203.0.113.7')).toEqual(['IPv4-Addr']);
    expect(candidates.find((c) => c.type === 'Malware')).toEqual({ type: 'Malware', compatible: false, reason: 'Looks like an observable' });
    expect(candidates.find((c) => c.type === 'Url')?.reason).toBe('Not a URL starting with a protocol');
  });

  it('should detect types on the refanged value', () => {
    expect(compatibleTypes('hxxp://evil[.]com/payload')).toContain('Url');
  });

  it('should offer a vulnerability for a CVE, and named objects for a name', () => {
    expect(compatibleTypes('CVE-2024-3400')).toContain('Vulnerability');
    expect(compatibleTypes('DeedRAT')).toEqual(expect.arrayContaining(['Malware', 'Intrusion-Set', 'Tool']));
  });

  it('should list compatible types first', () => {
    const candidates = typeCandidates('DeedRAT');
    const firstIncompatible = candidates.findIndex((c) => !c.compatible);
    expect(candidates.slice(firstIncompatible).every((c) => !c.compatible)).toBe(true);
  });
});

describe('creationInputFor', () => {
  it('should put a hash in the field of its algorithm', () => {
    expect(creationInputFor('StixFile', 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'))
      .toEqual({ hashes: [{ algorithm: 'SHA-256', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }] });
  });

  it('should use the file name, the observable value or the entity name otherwise', () => {
    expect(creationInputFor('StixFile', 'payload.zip')).toEqual({ name: 'payload.zip' });
    expect(creationInputFor('Domain-Name', 'update-check[.]net')).toEqual({ value: 'update-check.net' });
    expect(creationInputFor('Autonomous-System', 'AS13335')).toEqual({ number: 13335 });
    expect(creationInputFor('Malware', 'DeedRAT')).toEqual({ name: 'DeedRAT' });
  });
});
