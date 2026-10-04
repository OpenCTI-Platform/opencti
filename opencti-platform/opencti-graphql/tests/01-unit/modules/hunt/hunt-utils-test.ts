import { describe, expect, it } from 'vitest';
import {
  clampInteger,
  huntRunRestrictions,
  isAutonomousHunt,
  maskEvidencePreview,
  normalizeNativeQueries,
  parseHuntFilterGroup,
  sanitizeEvidence,
  sha256,
  techniqueValidationStatus,
  truncate,
} from '../../../../src/modules/hunt/hunt-utils';
import { mergeHuntDetectedCoverage, preservePlatformCoverage } from '../../../../src/modules/hunt/hunt-coverage-utils';
import { parseIncidentProposal } from '../../../../src/modules/hunt/hunt-incident';

const HASH = 'a'.repeat(64);

describe('Hunt run restrictions', () => {
  it('should give a run the markings of its hunt and of its security platform', () => {
    const hunt = { 'object-marking': ['tlp-green', 'pap-green'] };
    const platform = { 'object-marking': ['tlp-red', 'tlp-green'] };
    expect(huntRunRestrictions(hunt, platform)).toEqual({ objectMarking: ['tlp-green', 'pap-green', 'tlp-red'], objectOrganization: [] });
    expect(huntRunRestrictions(hunt, null)).toEqual({ objectMarking: ['tlp-green', 'pap-green'], objectOrganization: [] });
    expect(huntRunRestrictions({}, undefined)).toEqual({ objectMarking: [], objectOrganization: [] });
  });

  it('should share a run only with the organizations both its hunt and its security platform are shared with', () => {
    expect(huntRunRestrictions({ granted: ['org-a', 'org-b'] }, { granted: ['org-b', 'org-c'] })?.objectOrganization).toEqual(['org-b']);
    expect(huntRunRestrictions({ granted: ['org-a'] }, {})?.objectOrganization).toEqual(['org-a']);
    expect(huntRunRestrictions({}, { granted: ['org-c'] })?.objectOrganization).toEqual(['org-c']);
  });

  it('should refuse a run whose hunt and security platform are shared with disjoint organizations', () => {
    expect(huntRunRestrictions({ granted: ['org-a'] }, { granted: ['org-c'] })).toBeNull();
  });
});

describe('Hunt evidence sanitization', () => {
  it('should keep hashes, cap previews and merge duplicates', () => {
    const evidence = sanitizeEvidence([
      { field: 'process.command_line', value_hash: HASH.toUpperCase(), value_preview: 'powershell -enc AAAA', count: 2 },
      { field: 'process.command_line', value_hash: HASH, value_preview: 'powershell -enc AAAA', count: 3 },
      { field: 'source.ip', value_hash: 'b'.repeat(64), value_preview: 'x'.repeat(50), count: 10 },
    ], 10, 10);
    expect(evidence).toEqual([
      { field: 'source.ip', value_hash: 'b'.repeat(64), value_preview: 'xxxxxxx...', count: 10 },
      { field: 'process.command_line', value_hash: HASH, value_preview: 'powersh...', count: 5 },
    ]);
  });

  it('should hash again a value that is not a sha256 digest so that raw values are never stored as hashes', () => {
    const [item] = sanitizeEvidence([{ field: 'user.name', value_hash: 'john.doe', count: 1 }]);
    expect(item.value_hash).toBe(sha256('john.doe'));
    expect(item.value_preview).toBeNull();
  });

  it('should drop invalid items, default counts and cap the number of items', () => {
    const evidence = sanitizeEvidence([
      { field: '', value_hash: HASH, count: 1 },
      { field: 'a', value_hash: '', count: 1 },
      { field: 'a', value_hash: HASH, count: -4 },
      { field: 'b', value_hash: HASH, count: 2 },
      { field: 'c', value_hash: HASH, count: 3 },
    ], 2);
    expect(evidence.map((item) => [item.field, item.count])).toEqual([['c', 3], ['b', 2]]);
    expect(sanitizeEvidence(null)).toEqual([]);
  });

  it('should mask the secrets and personal data of a preview before storing it', () => {
    expect(maskEvidencePreview('curl -u admin -H "Authorization: Bearer abcdef1234567890" https://198.51.100.7/api?api_key=s3cr3tValue&x=1'))
      .toBe('curl -u admin -H "Authorization: Bearer [masked]" https://198.51.100.7/api?api_key=[masked]&x=1');
    expect(maskEvidencePreview('net user backup password=Winter2026! /add')).toBe('net user backup password=[masked] /add');
    expect(maskEvidencePreview('jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N')).toBe('jwt [masked token]');
    expect(maskEvidencePreview('key AKIAIOSFODNN7EXAMPLE used')).toBe('key [masked key] used');
    expect(maskEvidencePreview('mail from john.doe@mail.example.com')).toBe('mail from [masked]@mail.example.com');
    expect(maskEvidencePreview('card 4111111111111111 event 4688')).toBe('card [masked number] event 4688');
    expect(maskEvidencePreview('-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----')).toBe('[masked private key]');
    // Indicators stay readable, and masking an already masked value changes nothing
    expect(maskEvidencePreview('powershell -nop -enc SQBFAFgA 198.51.100.7 c2.example.com')).toBe('powershell -nop -enc SQBFAFgA 198.51.100.7 c2.example.com');
    expect(maskEvidencePreview('password=[masked] [masked]@example.com')).toBe('password=[masked] [masked]@example.com');
    const [item] = sanitizeEvidence([{ field: 'process.command_line', value_hash: HASH, value_preview: 'runas /user:svc password=Hunter22', count: 1 }]);
    expect(item.value_preview).toBe('runas /user:svc password=[masked]');
  });
});

describe('Hunt native queries', () => {
  it('should normalize native queries, JSON strings included', () => {
    const queries = normalizeNativeQueries([
      { platform: ' splunk ', language: ' spl ', query: ' index=main | head 10 ', pipeline: ' ' },
      JSON.stringify({ platform: 'internet', language: 'internet', query: 'jarm:abc', pipeline: 'censys' }),
    ]);
    expect(queries).toEqual([
      { platform: 'splunk', language: 'spl', query: 'index=main | head 10', pipeline: null },
      { platform: 'internet', language: 'internet', query: 'jarm:abc', pipeline: 'censys' },
    ]);
    expect(normalizeNativeQueries(null)).toEqual([]);
    expect(normalizeNativeQueries('')).toEqual([]);
  });

  it('should refuse unknown platforms, duplicates, empty languages and queries', () => {
    expect(() => normalizeNativeQueries([{ platform: 'unknown', language: 'x', query: 'y' }])).toThrow('platform must be one of');
    expect(() => normalizeNativeQueries([
      { platform: 'splunk', language: 'spl', query: 'a' },
      { platform: 'splunk', language: 'spl', query: 'b' },
    ])).toThrow('only one native query per platform');
    expect(() => normalizeNativeQueries([{ platform: 'splunk', language: '', query: 'a' }])).toThrow('a language is required');
    expect(() => normalizeNativeQueries([{ platform: 'splunk', language: 'spl', query: ' ' }])).toThrow('the query is required');
    expect(() => normalizeNativeQueries([{ platform: 'splunk', language: 'spl', query: 'a', pipeline: 'p'.repeat(300) }])).toThrow('pipeline name is too long');
  });
});

describe('Hunt helpers', () => {
  it('should parse filter groups and treat blank or empty groups as no filter', () => {
    expect(parseHuntFilterGroup(null, 'hunt_scope')).toBeNull();
    expect(parseHuntFilterGroup('  ', 'hunt_scope')).toBeNull();
    expect(parseHuntFilterGroup(JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }), 'hunt_scope')).toBeNull();
    const group = { mode: 'and', filters: [{ key: ['security_platform_type'], values: ['SIEM'] }], filterGroups: [] };
    expect(parseHuntFilterGroup(JSON.stringify(group), 'hunt_scope')).toEqual(group);
    expect(() => parseHuntFilterGroup('{not json', 'hunt_scope')).toThrow('valid JSON filter group');
    expect(() => parseHuntFilterGroup('{"mode":"and"}', 'hunt_scope')).toThrow('must be a filter group');
  });

  it('should tell autonomous hunts apart', () => {
    expect(isAutonomousHunt({ hunt_schedule: 'manual' })).toBe(false);
    expect(isAutonomousHunt({ hunt_schedule: 'manual', hunt_pir_activation: true })).toBe(true);
    expect(isAutonomousHunt({ hunt_schedule: 'standing' })).toBe(true);
    expect(isAutonomousHunt({ hunt_schedule: '0 * * * *' })).toBe(true);
  });

  it('should clamp integers and truncate strings', () => {
    expect(clampInteger('12.6', 1, 10, 5)).toBe(10);
    expect(clampInteger(-3, 1, 10, 5)).toBe(1);
    expect(clampInteger('abc', 1, 10, 5)).toBe(5);
    expect(clampInteger(4.4, 1, 10, 5)).toBe(4);
    expect(truncate('abcdef', 10)).toBe('abcdef');
    expect(truncate('abcdefghijkl', 6)).toBe('abc...');
  });

  it('should derive the validation of a technique from the counts of all its emulation runs', () => {
    expect(techniqueValidationStatus({ runs: 0, detected: 0, active: 0, completed: 0 })).toBe('not_validated');
    expect(techniqueValidationStatus({ runs: 250, detected: 1, active: 3, completed: 240 })).toBe('validated');
    expect(techniqueValidationStatus({ runs: 4, detected: 0, active: 1, completed: 3 })).toBe('in_progress');
    expect(techniqueValidationStatus({ runs: 3, detected: 0, active: 0, completed: 3 })).toBe('not_detected');
    expect(techniqueValidationStatus({ runs: 2, detected: 0, active: 0, completed: 0 })).toBe('not_validated');
  });
});

describe('Hunt coverage entries', () => {
  it('should keep platform owned entries through a full replacement by an integration', () => {
    const current = [{ coverage_name: 'detection', coverage_score: 50 }, { coverage_name: 'hunt_detected', coverage_score: 100 }];
    const incoming = [{ coverage_name: 'detection', coverage_score: 80 }, { coverage_name: 'prevention', coverage_score: 20 }];
    expect(preservePlatformCoverage(current, incoming)).toEqual([...incoming, { coverage_name: 'hunt_detected', coverage_score: 100 }]);
    // An integration sending hunt_detected itself wins
    const explicit = [{ coverage_name: 'hunt_detected', coverage_score: 0 }];
    expect(preservePlatformCoverage(current, explicit)).toEqual(explicit);
    expect(preservePlatformCoverage(null, null)).toEqual([]);
  });

  it('should write a single hunt_detected entry', () => {
    const merged = mergeHuntDetectedCoverage([{ coverage_name: 'detection', coverage_score: 50 }, { coverage_name: 'hunt_detected', coverage_score: 0 }], true);
    expect(merged).toEqual([{ coverage_name: 'detection', coverage_score: 50 }, { coverage_name: 'hunt_detected', coverage_score: 100 }]);
    expect(mergeHuntDetectedCoverage(undefined, false)).toEqual([{ coverage_name: 'hunt_detected', coverage_score: 0 }]);
  });
});

describe('Hunt incident proposals', () => {
  it('should parse stored proposals and ignore invalid ones', () => {
    expect(parseIncidentProposal('{"name":"n","severity":"high"}')).toEqual({ name: 'n', severity: 'high' });
    expect(parseIncidentProposal('not json')).toBeNull();
    expect(parseIncidentProposal('42')).toBeNull();
    expect(parseIncidentProposal(null)).toBeNull();
  });
});
