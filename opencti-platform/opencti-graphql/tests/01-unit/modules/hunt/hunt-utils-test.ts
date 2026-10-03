import { describe, expect, it } from 'vitest';
import { clampInteger, isAutonomousHunt, normalizeNativeQueries, parseHuntFilterGroup, sanitizeEvidence, sha256, truncate } from '../../../../src/modules/hunt/hunt-utils';
import { mergeHuntDetectedCoverage, preservePlatformCoverage } from '../../../../src/modules/hunt/hunt-coverage-utils';
import { parseIncidentProposal } from '../../../../src/modules/hunt/hunt-incident';

const HASH = 'a'.repeat(64);

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
