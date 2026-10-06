import { describe, expect, it } from 'vitest';
import { huntHitKey, identifyingHitKeys, sanitizeHitKeys, sanitizeHits } from '../../../../src/modules/hunt/hunt-utils';
import { classifyHuntHits } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain';
import { computeHuntRunWindow, huntIocKeysByHit, huntRunNewHits } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import { huntSightingStandardId, nextHuntSightingCount } from '../../../../src/modules/hunt/hunt-sightings';

// The vectors the connectors SDK asserts as well (connectors-sdk tests/test_connectors/test_internal_hunt/test_analysis.py):
// both sides compute the same key for the same reported hit
const HIT_KEY_VECTORS = {
  detection: '3b02b63d8af62713440dd85ed25dd3f88e81e03c977896d7cfe34d2943c1fd56',
  event: '377ad8ff94d918dc181777c7885fe87b097ce4d00ce135abbdd484463d07fe0c',
  fields: 'fad50c3a235a2707741dadfd8948e0eead646c7e2f5d997093a6cc306e79e418',
  empty: 'd3cfa790c1b204d5670ff28bab8eb2e65a0ed4df3f129240fca7fd570560e132',
};

describe('Hit key shared with the connectors SDK', () => {
  it('should compute the vectors of the SDK from the hits as the SDK reports them', () => {
    expect(huntHitKey({ detection: 'de_8f2c', event_id: 'e1' })).toEqual(HIT_KEY_VECTORS.detection);
    expect(huntHitKey({ event_id: 'evt "42"' })).toEqual(HIT_KEY_VECTORS.event);
    // A hit known by its fields only: non-UTC time with sub-seconds (as pydantic serializes it), accents, quotes,
    // an upper-case hash and fields out of order
    expect(huntHitKey({
      event_id: null,
      timestamp: '2026-10-05T23:59:59.750000+02:00',
      detection: null,
      matched: [
        { field: 'process.command_line', value_hash: 'AB'.repeat(32), value_preview: 'x' },
        { field: 'destination.ip', value_hash: 'cd'.repeat(32), value_preview: '"q"' },
      ],
      host: 'WKS-01',
      user: 'j\u00e9r\u00f4me',
      process: 'powershell.exe',
    })).toEqual(HIT_KEY_VECTORS.fields);
    expect(huntHitKey({ detection: '', event_id: '' })).toEqual(HIT_KEY_VECTORS.empty);
  });

  it('should key a sampled hit as reported, whatever the platform masks or truncates when storing it', () => {
    const reported = { event_id: 'evt-1 password=Hunter22', timestamp: '2026-10-05T10:00:00Z', host: 'ws1' };
    const [stored] = sanitizeHits([reported]);
    expect(stored.event_id).not.toContain('Hunter22');
    expect(stored.hit_key).toEqual(huntHitKey(reported));
  });

  it('should keep the well-formed distinct keys only, bounded', () => {
    const key = 'a'.repeat(64);
    expect(sanitizeHitKeys(undefined)).toBeNull();
    expect(sanitizeHitKeys([key, key.toUpperCase(), ` ${key} `, 'not a key', 42, 'b'.repeat(64)], 10)).toEqual([key, 'b'.repeat(64)]);
    expect(sanitizeHitKeys([key, 'b'.repeat(64)], 1)).toEqual([key]);
  });

  it('should use the reported keys only when they identify the hits of the report', () => {
    const [first, second, third] = ['a', 'b', 'c'].map((digit) => digit.repeat(64));
    // Fewer keys than hits: hits of one detection share a key, and the keys stop at the maximum results
    expect(identifyingHitKeys([first, second, first.toUpperCase()], { hitsCount: 28, sampledKeys: [first] })).toEqual([first, second]);
    expect(identifyingHitKeys([first, second, third], { hitsCount: 5000 }, 2)).toEqual([first, second]);
    expect(identifyingHitKeys([], { hitsCount: 0 })).toEqual([]);
    // No list, no key for a report with hits, an entry that is not a key, a sampled hit missing from the list
    expect(identifyingHitKeys(undefined, { hitsCount: 3 })).toBeNull();
    expect(identifyingHitKeys([], { hitsCount: 28 })).toBeNull();
    expect(identifyingHitKeys([first, 'not a key'], { hitsCount: 2 })).toBeNull();
    expect(identifyingHitKeys([first, 42], { hitsCount: 2 })).toBeNull();
    expect(identifyingHitKeys([first], { hitsCount: 2, sampledKeys: [first, second] })).toBeNull();
    // More distinct keys than hits: one key per hit read, never more, even for a report without hits
    expect(identifyingHitKeys([first], { hitsCount: 0 })).toBeNull();
    expect(identifyingHitKeys([first, second, third], { hitsCount: 2 })).toBeNull();
    expect(identifyingHitKeys([first, second, third], { hitsCount: 2 }, 1)).toBeNull();
    // An indicator hunt reports the keys of each value
    expect(identifyingHitKeys([], { hitsCount: 2, extraKeys: [first, second], sampledKeys: [second] })).toEqual([first, second]);
    expect(identifyingHitKeys([third], { hitsCount: 2, extraKeys: [first, second] })).toBeNull();
  });
});

describe('Time window of a recurring run', () => {
  const end = new Date('2026-10-05T12:00:00.000Z');

  it('should search since the end of the previous run minus the overlap', () => {
    const window = computeHuntRunWindow(end, 24, 15, '2026-10-05T06:00:00.000Z');
    expect(window).toEqual({ start: new Date('2026-10-05T05:45:00.000Z'), continued: true });
  });

  it('should search the full window without a previous run, or after one older than the window', () => {
    expect(computeHuntRunWindow(end, 24, 15, null)).toEqual({ start: new Date('2026-10-04T12:00:00.000Z'), continued: false });
    expect(computeHuntRunWindow(end, 24, 15, '2026-10-01T00:00:00.000Z')).toEqual({ start: new Date('2026-10-04T12:00:00.000Z'), continued: false });
    expect(computeHuntRunWindow(end, 24, 15, 'not a date')).toEqual({ start: new Date('2026-10-04T12:00:00.000Z'), continued: false });
  });

  it('should still search the overlap when the previous window ends after now', () => {
    expect(computeHuntRunWindow(end, 24, 15, '2026-10-05T12:30:00.000Z')).toEqual({ start: new Date('2026-10-05T11:45:00.000Z'), continued: true });
  });
});

describe('Known hits ledger', () => {
  it('should count as new the hits no earlier run found, as recurring the others', () => {
    const known = new Map([
      ['k1', { first_run_id: 'run-1', last_run_id: 'run-1' }],
      ['k2', { first_run_id: 'run-1', last_run_id: 'run-1' }],
    ]);
    expect(classifyHuntHits('run-2', ['k1', 'k2', 'k3'], known)).toEqual({ newCount: 1, recurringCount: 2, toWrite: ['k1', 'k2', 'k3'] });
  });

  it('should give the same counts when the same run is matched again, writing nothing twice', () => {
    const known = new Map([
      ['k1', { first_run_id: 'run-1', last_run_id: 'run-2' }],
      ['k3', { first_run_id: 'run-2', last_run_id: 'run-2' }],
    ]);
    expect(classifyHuntHits('run-2', ['k1', 'k3'], known)).toEqual({ newCount: 1, recurringCount: 1, toWrite: [] });
  });

  it('should write nothing for a run matched again after later runs found its hits', () => {
    const known = new Map([
      ['k1', { first_run_id: 'run-1', last_run_id: 'run-3', counted_run_ids: ['run-1', 'run-2', 'run-3'] }],
      ['k2', { first_run_id: 'run-2', last_run_id: 'run-3', counted_run_ids: ['run-2', 'run-3'] }],
    ]);
    expect(classifyHuntHits('run-2', ['k1', 'k2'], known)).toEqual({ newCount: 1, recurringCount: 1, toWrite: [] });
    expect(classifyHuntHits('run-4', ['k1', 'k2'], known)).toEqual({ newCount: 0, recurringCount: 2, toWrite: ['k1', 'k2'] });
  });

  it('should count every hit of a run whose connector identifies none as new', () => {
    expect(huntRunNewHits({ hits_count: 28, hits_new_count: null })).toEqual(28);
    expect(huntRunNewHits({ hits_count: 28, hits_new_count: 0 })).toEqual(0);
  });

  it('should attribute the hits of an indicator run to the values holding them', () => {
    const shared = 'c'.repeat(64);
    const byHit = huntIocKeysByHit([
      { key: 'ioc-ip', hit_keys: ['a'.repeat(64), shared] },
      { key: 'ioc-domain', hit_keys: [shared] },
      { key: 'ioc-unseen', hit_keys: null },
    ]);
    expect(byHit.get('a'.repeat(64))).toEqual(['ioc-ip']);
    expect(byHit.get(shared)).toEqual(['ioc-ip', 'ioc-domain']);
    expect(byHit.size).toEqual(2);
  });
});

describe('One sighting per hunt, sighted object and platform', () => {
  it('should hold the distinct known hits of identified runs, never fewer than stored', () => {
    expect(nextHuntSightingCount(null, 'run-1', { identified: true, knownHits: 12, runHits: 12 })).toEqual(12);
    // A second run over overlapping events: the same 12 hits, the count stays
    expect(nextHuntSightingCount({ attribute_count: 12, x_opencti_hunt_run_id: 'run-1' }, 'run-2', { identified: true, knownHits: 12, runHits: 12 })).toEqual(12);
    expect(nextHuntSightingCount({ attribute_count: 12, x_opencti_hunt_run_id: 'run-2' }, 'run-3', { identified: true, knownHits: 15, runHits: 7 })).toEqual(15);
    // Hits forgotten by the retention stay counted
    expect(nextHuntSightingCount({ attribute_count: 40 }, 'run-4', { identified: true, knownHits: 3, runHits: 3 })).toEqual(40);
  });

  it('should give each hunt its own sighting of an object on a platform, whatever the dates', () => {
    const id = huntSightingStandardId('hunt-1', 'technique-1', 'platform-1');
    expect(id).toMatch(/^sighting--[0-9a-f-]{36}$/);
    expect(huntSightingStandardId('hunt-1', 'technique-1', 'platform-1')).toEqual(id);
    expect(huntSightingStandardId('hunt-2', 'technique-1', 'platform-1')).not.toEqual(id);
    expect(huntSightingStandardId('hunt-1', 'technique-1', 'platform-2')).not.toEqual(id);
  });

  it('should add the hits of a run that identifies none once', () => {
    expect(nextHuntSightingCount({ attribute_count: 12, x_opencti_hunt_run_id: 'run-1' }, 'run-2', { identified: false, knownHits: 0, runHits: 5 })).toEqual(17);
    expect(nextHuntSightingCount({ attribute_count: 17, x_opencti_hunt_run_id: 'run-2' }, 'run-2', { identified: false, knownHits: 0, runHits: 5 })).toEqual(17);
  });
});
